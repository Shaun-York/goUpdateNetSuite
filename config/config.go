package config

import (
	"os"
)

// NSOAuth1a ConfigInt
type NSOAuth1a struct {
	Config
	Consumer map[string]string
	Token map[string]string
	Options map[string]interface{}
	OAuthData map[string]interface{}
}
// Config keys tokens
type Config struct {
	//A value used by the Consumer to identify itself to the Service Provider.
	ConsumerKey string
	//A secret used by the Consumer to establish ownership of the Consumer Key.
	ConsumerSecret string
	//A value used by the Consumer to gain access to the Protected Resources on
	//behalf of the User, instead of using the User's Service Provider credentials.
	AccessToken string
	//A secret used by the Consumer to establish ownership of a given Token.
	AccessSecret string
	NetSuiteAccount string
}

// GetNOAuth1a get oauth
func (x *NSOAuth1a) GetNOAuth1a() *NSOAuth1a {
	x.Config = Config{
		ConsumerKey: os.Getenv("NETSUITE_CONSUMER_KEY"),
		ConsumerSecret: os.Getenv("NETSUITE_CONSUMER_SECRET"),
		AccessToken: os.Getenv("NETSUITE_ACCESS_KEY"),
		AccessSecret: os.Getenv("NETSUITE_ACCESS_SECRET"),
		NetSuiteAccount: os.Getenv("NETSUITE_ACCOUNT"),
	}
	x.Consumer = map[string]string{
		"public": x.Config.ConsumerKey,
		"secret": x.Config.ConsumerSecret,
	}
	x.Token = map[string]string{
		"public": x.Config.AccessToken,
		"secret": x.Config.AccessSecret,
	}
	x.Options = map[string]interface{}{
		"consumer": x.Consumer,
		"signature_method": "HMAC-SHA1",
		"nonce_length": 32,
		"version": "1.0",
		"parameter_seperator": ", ",
	}
	x.OAuthData = map[string]interface{}{
		"oauth_consumer_key": x.Consumer["public"],
		"oauth_signature_method": x.Options["signature_method"].(string),
		"oauth_version": x.Options["version"].(string),
	}
	return x
}
