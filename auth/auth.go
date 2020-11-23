package auth

import (
	"bytes"
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"

	"hash"
)

//HTTPClientSettings HTTPClientSettings
type HTTPClientSettings struct {
    Connect          time.Duration
    ConnKeepAlive    time.Duration
    ExpectContinue   time.Duration
    IdleConn         time.Duration
    MaxAllIdleConns  int
    MaxHostIdleConns int
    ResponseHeader   time.Duration
    TLSHandshake     time.Duration
}

// GetClientConfig get transport settings 
func GetClientConfig() (*HTTPClientSettings, error) {
	defaultClientConfig := &HTTPClientSettings {
		Connect:          5 * time.Second,
    	ExpectContinue:   1 * time.Second,
    	IdleConn:         90 * time.Second,
    	ConnKeepAlive:    30 * time.Second,
    	MaxAllIdleConns:  100,
    	MaxHostIdleConns: 10,
    	ResponseHeader:   5 * time.Second,
    	TLSHandshake:     5 * time.Second,
	}
	return defaultClientConfig, nil
}
//SetupClient SetupClient
func SetupClient(httpSettings *HTTPClientSettings) *http.Transport {
    tr := &http.Transport{
        ResponseHeaderTimeout: httpSettings.ResponseHeader,
        Proxy:                 http.ProxyFromEnvironment,
        DialContext: (&net.Dialer{
            KeepAlive: httpSettings.ConnKeepAlive,
            DualStack: true,
            Timeout:   httpSettings.Connect,
        }).DialContext,
        MaxIdleConns:          httpSettings.MaxAllIdleConns,
        IdleConnTimeout:       httpSettings.IdleConn,
        TLSHandshakeTimeout:   httpSettings.TLSHandshake,
        MaxIdleConnsPerHost:   httpSettings.MaxHostIdleConns,
        ExpectContinueTimeout: httpSettings.ExpectContinue,
    }
    return tr
}

// Endpoint represents an OAuth1 provider's (server's) request token,
// owner authorization, and access token request URLs.
type Endpoint struct {
	// Request URL (Temporary Credential Request URI)
	RequestTokenURL string
	// Authorize URL (Resource Owner Authorization URI)
	AuthorizeURL string
	// Access Token URL (Token Request URI)
	AccessTokenURL string
}

// Noncer provides random nonce strings.
type Noncer interface {
	Nonce() string
}

// Base64Noncer reads 32 bytes from crypto/rand and
// returns those bytes as a base64 encoded string.
type Base64Noncer struct{}

// Nonce provides a random nonce string.
func (n Base64Noncer) Nonce() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

// HexNoncer reads 32 bytes from crypto/rand and
// returns those bytes as a base64 encoded string.
type HexNoncer struct{}

// Nonce provides a random nonce string.
func (n HexNoncer) Nonce() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// Transport is an http.RoundTripper which makes OAuth1 HTTP requests. It
// wraps a base RoundTripper and adds an Authorization header using the
// token from a TokenSource.
//
// Transport is a low-level component, most users should use Config to create
// an http.Client instead.
type Transport struct {
	Connect          time.Duration
    ConnKeepAlive    time.Duration
    ExpectContinue   time.Duration
    IdleConn         time.Duration
    MaxAllIdleConns  int
    MaxHostIdleConns int
    ResponseHeader   time.Duration
    TLSHandshake     time.Duration
	// Base is the base RoundTripper used to make HTTP requests. If nil, then
	// http.DefaultTransport is used
	Base http.RoundTripper
	// source supplies the token to use when signing a request
	source TokenSource
	// auther adds OAuth1 Authorization headers to requests
	auther *auther
}

// RoundTrip authorizes the request with a signed OAuth1 Authorization header
// using the auther and TokenSource.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.source == nil {
		return nil, fmt.Errorf("oauth1: Transport's source is nil")
	}
	accessToken, err := t.source.Token()
	if err != nil {
		return nil, err
	}
	if t.auther == nil {
		return nil, fmt.Errorf("oauth1: Transport's auther is nil")
	}
	// RoundTripper should not modify the given request, clone it
	req2 := cloneRequest(req)
	err = t.auther.SetRequestAuthHeader(req2, accessToken)
	if err != nil {
		return nil, err
	}
	return t.base().RoundTrip(req2)
}

func (t *Transport) base() http.RoundTripper {
	if t.Base != nil {
		return t.Base
	}
	return http.DefaultTransport
}

// cloneRequest returns a clone of the given *http.Request with a shallow
// copy of struct fields and a deep copy of the Header map.
func cloneRequest(req *http.Request) *http.Request {
	// shallow copy the struct
	r2 := new(http.Request)
	*r2 = *req
	// deep copy Header so setting a header on the clone does not affect original
	r2.Header = make(http.Header, len(req.Header))
	for k, s := range req.Header {
		r2.Header[k] = append([]string(nil), s...)
	}
	return r2
}

// A TokenSource can return a Token.
type TokenSource interface {
	Token() (*Token, error)
}

// Token is an AccessToken (token credential) which allows a consumer (client)
// to access resources from an OAuth1 provider server.
type Token struct {
	Token       string
	TokenSecret string
}

// NewToken returns a new Token with the given token and token secret.
func NewToken(token, tokenSecret string) *Token {
	return &Token{
		Token:       token,
		TokenSecret: tokenSecret,
	}
}

// StaticTokenSource returns a TokenSource which always returns the same Token.
// This is appropriate for tokens which do not have a time expiration.
func StaticTokenSource(token *Token) TokenSource {
	return staticTokenSource{token}
}

// staticTokenSource is a TokenSource that always returns the same Token.
type staticTokenSource struct {
	token *Token
}

func (s staticTokenSource) Token() (*Token, error) {
	if s.token == nil {
		return nil, errors.New("oauth1: Token is nil")
	}
	return s.token, nil
}

// A Signer signs messages to create signed OAuth1 Requests.
type Signer interface {
	// Name returns the name of the signing method.
	Name() string
	// Sign signs the message using the given secret key.
	Sign(key string, message string) (string, error)
}

// HMACSigner signs messages with an HMAC SHA1 digest, using the concatenated
// consumer secret and token secret as the key.
type HMACSigner struct {
	ConsumerSecret string
}

// Name returns the HMAC-SHA1 method.
func (s *HMACSigner) Name() string {
	return "HMAC-SHA1"
}

func hmacSign(consumerSecret, tokenSecret, message string, algo func() hash.Hash) (string, error) {
	signingKey := strings.Join([]string{consumerSecret, tokenSecret}, "&")
	mac := hmac.New(algo, []byte(signingKey))
	mac.Write([]byte(message))
	signatureBytes := mac.Sum(nil)
	return base64.StdEncoding.EncodeToString(signatureBytes), nil
}

// Sign creates a concatenated consumer and token secret key and calculates
// the HMAC digest of the message. Returns the base64 encoded digest bytes.
func (s *HMACSigner) Sign(tokenSecret, message string) (string, error) {
	return hmacSign(s.ConsumerSecret, tokenSecret, message, sha1.New)
}

// HMAC256Signer signs messages with an HMAC SHA256 digest, using the concatenated
// consumer secret and token secret as the key.
type HMAC256Signer struct {
	ConsumerSecret string
}

// Name returns the HMAC-SHA256 method.
func (s *HMAC256Signer) Name() string {
	return "HMAC-SHA256"
}

// Sign creates a concatenated consumer and token secret key and calculates
// the HMAC digest of the message. Returns the base64 encoded digest bytes.
func (s *HMAC256Signer) Sign(tokenSecret, message string) (string, error) {
	return hmacSign(s.ConsumerSecret, tokenSecret, message, sha256.New)
}

// RSASigner RSA PKCS1-v1_5 signs SHA1 digests of messages using the given
// RSA private key.
type RSASigner struct {
	PrivateKey *rsa.PrivateKey
}

// Name returns the RSA-SHA1 method.
func (s *RSASigner) Name() string {
	return "RSA-SHA1"
}

// Sign uses RSA PKCS1-v1_5 to sign a SHA1 digest of the given message. The
// tokenSecret is not used with this signing scheme.
func (s *RSASigner) Sign(tokenSecret, message string) (string, error) {
	digest := sha1.Sum([]byte(message))
	signature, err := rsa.SignPKCS1v15(rand.Reader, s.PrivateKey, crypto.SHA1, digest[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(signature), nil
}

type contextKey struct{}

// HTTPClient is the context key to associate an *http.Client value with
// a context.
var HTTPClient contextKey

// NoContext is the default context to use in most cases.
var NoContext = context.TODO()

// contextTransport gets the Transport from the context client or nil.
func contextTransport(ctx context.Context) http.RoundTripper {
	if client, ok := ctx.Value(HTTPClient).(*http.Client); ok {
		return client.Transport
	}
	return nil
}

// PercentEncode percent encodes a string according to RFC 3986 2.1.
func PercentEncode(input string) string {
	var buf bytes.Buffer
	for _, b := range []byte(input) {
		// if in unreserved set
		if shouldEscape(b) {
			buf.Write([]byte(fmt.Sprintf("%%%02X", b)))
		} else {
			// do not escape, write byte as-is
			buf.WriteByte(b)
		}
	}
	return buf.String()
}

// shouldEscape returns false if the byte is an unreserved character that
// should not be escaped and true otherwise, according to RFC 3986 2.1.
func shouldEscape(c byte) bool {
	// RFC3986 2.3 unreserved characters
	if 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' {
		return false
	}
	switch c {
	case '-', '.', '_', '~':
		return false
	}
	// all other bytes must be escaped
	return true
}

const (
	oauthTokenSecretParam       = "oauth_token_secret"
	oauthCallbackConfirmedParam = "oauth_callback_confirmed"
)

// Config represents an OAuth1 consumer's (client's) key and secret, the
// callback URL, and the provider Endpoint to which the consumer corresponds.
type Config struct {
	// Consumer Key (Client Identifier)
	ConsumerKey string
	// Consumer Secret (Client Shared-Secret)
	ConsumerSecret string
	// Callback URL
	CallbackURL string
	// Provider Endpoint specifying OAuth1 endpoint URLs
	Endpoint Endpoint
	// Realm of authorization
	Realm string
	// OAuth1 Signer (defaults to HMAC-SHA1)
	Signer Signer
	// Noncer creates request nonces (defaults to DefaultNoncer)
	Noncer Noncer
}

// NewConfig returns a new Config with the given consumer key and secret.
func NewConfig(consumerKey, consumerSecret string) *Config {
	return &Config{
		ConsumerKey:    consumerKey,
		ConsumerSecret: consumerSecret,
	}
}

// Client returns an HTTP client which uses the provided ctx and access Token.
func (c *Config) Client(ctx context.Context, t *Token) *http.Client {
	return NewClient(ctx, c, t)
}

// NewClient returns a new http Client which signs requests via OAuth1.
func NewClient(ctx context.Context, config *Config, token *Token) *http.Client {
	transport := &Transport{
		Base:   contextTransport(ctx),
		source: StaticTokenSource(token),
		auther: newAuther(config),
	}
	return &http.Client{Transport: transport}
}

// RequestToken obtains a Request token and secret (temporary credential) by
// POSTing a request (with oauth_callback in the auth header) to the Endpoint
// RequestTokenURL. The response body form is validated to ensure
// oauth_callback_confirmed is true. Returns the request token and secret
// (temporary credentials).
// See RFC 5849 2.1 Temporary Credentials.
func (c *Config) RequestToken() (requestToken, requestSecret string, err error) {
	req, err := http.NewRequest("POST", c.Endpoint.RequestTokenURL, nil)
	if err != nil {
		return "", "", err
	}//newAuther auth
	err = newAuther(c).SetRequestTokenAuthHeader(req)
	if err != nil {
		return "", "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", err
	}
	// when err is nil, resp contains a non-nil resp.Body which must be closed
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return "", "", fmt.Errorf("oauth1: Server returned status %d", resp.StatusCode)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", "", err
	}
	// ParseQuery to decode URL-encoded application/x-www-form-urlencoded body
	values, err := url.ParseQuery(string(body))
	if err != nil {
		return "", "", err
	}
	requestToken = values.Get(oauthTokenParam)
	requestSecret = values.Get(oauthTokenSecretParam)
	if requestToken == "" || requestSecret == "" {
		return "", "", errors.New("oauth1: Response missing oauth_token or oauth_token_secret")
	}
	if values.Get(oauthCallbackConfirmedParam) != "true" {
		return "", "", errors.New("oauth1: oauth_callback_confirmed was not true")
	}
	return requestToken, requestSecret, nil
}

// AuthorizationURL accepts a request token and returns the *url.URL to the
// Endpoint's authorization page that asks the user (resource owner) for to
// authorize the consumer to act on his/her/its behalf.
// See RFC 5849 2.2 Resource Owner Authorization.
func (c *Config) AuthorizationURL(requestToken string) (*url.URL, error) {
	authorizationURL, err := url.Parse(c.Endpoint.AuthorizeURL)
	if err != nil {
		return nil, err
	}
	values := authorizationURL.Query()
	values.Add(oauthTokenParam, requestToken)
	authorizationURL.RawQuery = values.Encode()
	return authorizationURL, nil
}

// ParseAuthorizationCallback parses an OAuth1 authorization callback request
// from a provider server. The oauth_token and oauth_verifier parameters are
// parsed to return the request token from earlier in the flow and the
// verifier string.
// See RFC 5849 2.2 Resource Owner Authorization.
func ParseAuthorizationCallback(req *http.Request) (requestToken, verifier string, err error) {
	// parse the raw query from the URL into req.Form
	err = req.ParseForm()
	if err != nil {
		return "", "", err
	}
	requestToken = req.Form.Get(oauthTokenParam)
	verifier = req.Form.Get(oauthVerifierParam)
	if requestToken == "" || verifier == "" {
		return "", "", errors.New("oauth1: Request missing oauth_token or oauth_verifier")
	}
	return requestToken, verifier, nil
}

// AccessToken obtains an access token (token credential) by POSTing a
// request (with oauth_token and oauth_verifier in the auth header) to the
// Endpoint AccessTokenURL. Returns the access token and secret (token
// credentials).
// See RFC 5849 2.3 Token Credentials.
func (c *Config) AccessToken(requestToken, requestSecret, verifier string) (accessToken, accessSecret string, err error) {
	accessToken = os.Getenv("NETSUITE_ACCESS_KEY")
	accessSecret = os.Getenv("NETSUITE_ACCESS_SECRET")
	if accessToken == "" || accessSecret == "" {
		return "", "", errors.New("oauth1: Response missing oauth_token or oauth_token_secret")
	}
	return accessToken, accessSecret, nil
}

const (
	authorizationHeaderParam  = "Authorization"
	authorizationPrefix       = "OAuth " // trailing space is intentional
	oauthConsumerKeyParam     = "oauth_consumer_key"
	oauthNonceParam           = "oauth_nonce"
	oauthSignatureParam       = "oauth_signature"
	oauthSignatureMethodParam = "oauth_signature_method"
	oauthTimestampParam       = "oauth_timestamp"
	oauthTokenParam           = "oauth_token"
	oauthVersionParam         = "oauth_version"
	oauthCallbackParam        = "oauth_callback"
	oauthVerifierParam        = "oauth_verifier"
	defaultOauthVersion       = "1.0"
	contentType               = "Content-Type"
	formContentType           = "application/x-www-form-urlencoded"
	realmParam                = "realm"
)

// clock provides a interface for current time providers. A Clock can be used
// in place of calling time.Now() directly.
type clock interface {
	Now() time.Time
}

// A noncer provides random nonce strings.
type noncer interface {
	Nonce() string
}

// auther adds an "OAuth" Authorization header field to requests.
type auther struct {
	config *Config
	clock  clock
	noncer noncer
}
//newAuther auth
func newAuther(config *Config) *auther {
	return &auther{
		config: config,
	}
}

// SetRequestTokenAuthHeader adds the OAuth1 header for the request token
// request (temporary credential) according to RFC 5849 2.1.
func (a *auther) SetRequestTokenAuthHeader(req *http.Request) error {
	oauthParams := a.commonOAuthParams()
	oauthParams[oauthCallbackParam] = a.config.CallbackURL
	params, err := CollectParameters(req, oauthParams)
	if err != nil {
		return err
	}
	signatureBase := SignatureBase(req, params)
	signature, err := a.signer().Sign("", signatureBase)
	if err != nil {
		return err
	}
	oauthParams[oauthSignatureParam] = signature
	if a.config.Realm != "" {
		oauthParams[realmParam] = a.config.Realm
	}
	req.Header.Set(authorizationHeaderParam, AHeaderValue(oauthParams))
	return nil
}

// setAccessTokenAuthHeader sets the OAuth1 header for the access token request
// (token credential) according to RFC 5849 2.3.
func (a *auther) setAccessTokenAuthHeader(req *http.Request, requestToken, requestSecret, verifier string) error {
	oauthParams := a.commonOAuthParams()
	oauthParams[oauthTokenParam] = requestToken
	oauthParams[oauthVerifierParam] = verifier
	params, err := CollectParameters(req, oauthParams)
	if err != nil {
		return err
	}
	signatureBase := SignatureBase(req, params)
	signature, err := a.signer().Sign(requestSecret, signatureBase)
	if err != nil {
		return err
	}
	oauthParams[oauthSignatureParam] = signature
	req.Header.Set(authorizationHeaderParam, AHeaderValue(oauthParams))
	return nil
}

// SetRequestAuthHeader sets the OAuth1 header for making authenticated
// requests with an AccessToken (token credential) according to RFC 5849 3.1.
func (a *auther) SetRequestAuthHeader(req *http.Request, accessToken *Token) error {
	oauthParams := a.commonOAuthParams()
	oauthParams[oauthTokenParam] = accessToken.Token
	params, err := CollectParameters(req, oauthParams)
	if err != nil {
		return err
	}
	signatureBase := SignatureBase(req, params)
	signature, err := a.signer().Sign(accessToken.TokenSecret, signatureBase)
	if err != nil {
		return err
	}
	oauthParams[oauthSignatureParam] = signature
	req.Header.Set(authorizationHeaderParam, AHeaderValue(oauthParams))
	return nil
}

// SetAuthHeaders SetAuthHeaders
func SetAuthHeaders(config *Config, req *http.Request, accessToken *Token) error {
	s := &HMACSigner{ConsumerSecret: config.ConsumerSecret}
	oauthParams := CommonOAuthParams(config)
	oauthParams[oauthTokenParam] = accessToken.Token
	params, err := CollectParameters(req, oauthParams)

	if err != nil {
		return err
	}
	signatureBase := SignatureBase(req, params)
	signature, err := s.Sign(accessToken.TokenSecret, signatureBase)

	if err != nil {
		return err
	}
	oauthParams[oauthSignatureParam] = signature
	req.Header.Set(authorizationHeaderParam, AHeaderValue(oauthParams))
	return nil
}

// commonOAuthParams returns a map of the common OAuth1 protocol parameters,
// excluding the oauth_signature parameter. This includes the realm parameter
// if it was set in the config. The realm parameter will not be included in
// the signature base string as specified in RFC 5849 3.4.1.3.1.
func (a *auther) commonOAuthParams() map[string]string {
	params := map[string]string{
		oauthConsumerKeyParam:     a.config.ConsumerKey,
		oauthSignatureMethodParam: a.signer().Name(),
		oauthTimestampParam:       strconv.FormatInt(a.epoch(), 10),
		oauthNonceParam:           a.nonce(),
		oauthVersionParam:         defaultOauthVersion,
	}
	if a.config.Realm != "" {
		params[realmParam] = a.config.Realm
	}
	return params
}
// CommonOAuthParams CommonOAuthParams
func CommonOAuthParams(config *Config) map[string]string {
	s := &HMACSigner{ConsumerSecret: config.ConsumerSecret}
	b := make([]byte, 32)
	rand.Read(b)
	nonce := base64.StdEncoding.EncodeToString(b)
	params := map[string]string{
		oauthConsumerKeyParam:     config.ConsumerKey,
		oauthSignatureMethodParam: s.Name(),
		oauthTimestampParam:       strconv.FormatInt(time.Now().Unix(), 10),
		oauthNonceParam:           nonce,
		oauthVersionParam:         defaultOauthVersion,
	}
	if config.Realm != "" {
		params[realmParam] = config.Realm
	}
	return params
}

// Returns a base64 encoded random 32 byte string.
func (a *auther) nonce() string {
	if a.noncer != nil {
		return a.noncer.Nonce()
	}
	b := make([]byte, 32)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

// Returns the Unix epoch seconds.
func (a *auther) epoch() int64 {
	if a.clock != nil {
		return a.clock.Now().Unix()
	}
	return time.Now().Unix()
}

// Returns the Config's Signer or the default Signer.
func (a *auther) signer() Signer {
	if a.config.Signer != nil {
		return a.config.Signer
	}
	return &HMACSigner{ConsumerSecret: a.config.ConsumerSecret}
}

// AHeaderValue formats OAuth parameters according to RFC 5849 3.5.1. OAuth
// params are percent encoded, sorted by key (for testability), and joined by
// "=" into pairs. Pairs are joined with a ", " comma separator into a header
// string.
// The given OAuth params should include the "oauth_signature" key.
func AHeaderValue(oauthParams map[string]string) string {
	pairs := SortParameters(EncodeParameters(oauthParams), `%s="%s"`)

	return authorizationPrefix + strings.Join(pairs, ", ")
}

// EncodeParameters percent encodes parameter keys and values according to
// RFC5849 3.6 and RFC3986 2.1 and returns a new map.
func EncodeParameters(params map[string]string) map[string]string {
	encoded := map[string]string{}
	for key, value := range params {
		encoded[PercentEncode(key)] = PercentEncode(value)
	}
	return encoded
}

// SortParameters sorts parameters by key and returns a slice of key/value
// pairs formatted with the given format string (e.g. "%s=%s").
func SortParameters(params map[string]string, format string) []string {
	// sort by key
	keys := make([]string, len(params))
	i := 0
	for key := range params {
		keys[i] = key
		i++
	}
	sort.Strings(keys)
	// parameter join
	pairs := make([]string, len(params))
	for i, key := range keys {
		pairs[i] = fmt.Sprintf(format, key, params[key])
	}
	return pairs
}

// CollectParameters collects request parameters from the request query, OAuth
// parameters (which should exclude oauth_signature), and the request body
// provided the body is single part, form encoded, and the form content type
// header is set. The returned map of collected parameter keys and values
// follow RFC 5849 3.4.1.3, except duplicate parameters are not supported.
func CollectParameters(req *http.Request, oauthParams map[string]string) (map[string]string, error) {
	// add oauth, query, and body parameters into params
	params := map[string]string{}
	for key, value := range req.URL.Query() {
		// most backends do not accept duplicate query keys
		params[key] = value[0]
	}
	if req.Body != nil && req.Header.Get(contentType) == formContentType {
		// reads data to a []byte, draining req.Body
		b, err := ioutil.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		values, err := url.ParseQuery(string(b))
		if err != nil {
			return nil, err
		}
		for key, value := range values {
			// not supporting params with duplicate keys
			params[key] = value[0]
		}
		// reinitialize Body with ReadCloser over the []byte
		req.Body = ioutil.NopCloser(bytes.NewReader(b))
	}
	for key, value := range oauthParams {
		// according to 3.4.1.3.1. the realm parameter is excluded
		if key != realmParam {
			params[key] = value
		}
	}
	return params, nil
}

// SignatureBase combines the uppercase request method, percent encoded base
// string URI, and normalizes the request parameters int a parameter string.
// Returns the OAuth1 signature base string according to RFC5849 3.4.1.
func SignatureBase(req *http.Request, params map[string]string) string {
	method := strings.ToUpper(req.Method)
	baseURL := BaseURI(req)
	parameterString := NormalizedParameterString(params)
	// signature base string constructed accoding to 3.4.1.1
	baseParts := []string{method, PercentEncode(baseURL), PercentEncode(parameterString)}
	return strings.Join(baseParts, "&")
}

// BaseURI returns the base string URI of a request according to RFC 5849
// 3.4.1.2. The scheme and host are lowercased, the port is dropped if it
// is 80 or 443, and the path minus query parameters is included.
func BaseURI(req *http.Request) string {
	scheme := strings.ToLower(req.URL.Scheme)
	host := strings.ToLower(req.URL.Host)
	if hostPort := strings.Split(host, ":"); len(hostPort) == 2 && (hostPort[1] == "80" || hostPort[1] == "443") {
		host = hostPort[0]
	}
	// TODO: use req.URL.EscapedPath() once Go 1.5 is more generally adopted
	// For now, hacky workaround accomplishes the same internal escaping mode
	// escape(u.Path, encodePath) for proper compliance with the OAuth1 spec.
	path := req.URL.Path
	if path != "" {
		path = strings.Split(req.URL.RequestURI(), "?")[0]
	}
	return fmt.Sprintf("%v://%v%v", scheme, host, path)
}

// NormalizedParameterString normalizes collected OAuth parameters (which should exclude
// oauth_signature) into a parameter string as defined in RFC 5894 3.4.1.3.2.
// The parameters are encoded, sorted by key, keys and values joined with "&",
// and pairs joined with "=" (e.g. foo=bar&q=gopher).
func NormalizedParameterString(params map[string]string) string {
	return strings.Join(SortParameters(EncodeParameters(params), "%s=%s"), "&")
}