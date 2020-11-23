package netsuitehandler

import (
	"encoding/json"
	"errors"
	"fmt"
	"goUpdateNetSuite/completion"
	"goUpdateNetSuite/goauth1anetsuite"
	"io/ioutil"
	"log"
	"math"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"time"
)

const (
	sssBadRequestArgs = "REQUEST_PARAM_REQD"
	sssRequestLimitExceeded = "SSS_REQUEST_LIMIT_EXCEEDED"
	internalNetSuiteError = "INTERNAL_NETSUITE_ERROR"
	etimeout = "ETIMEDOUT"
)

type badNetSuiteRequest struct {
	Code string `json:"code"`
	Message string `json:"message"`
}

type netSuiteError struct {
	NSError badNetSuiteRequest `json:"error"`
}
//RandMs (attempt) => Math.round(((2 ** (attempt - 1)) * 64) + (Math.random() * 100))
func RandMs(n int64) int64 {
    v := float64(n)
    rand.Seed(time.Now().UnixNano())
    x := v - 1
    ms := math.Pow(2, x) * 64 + float64(rand.Intn(100 - 0 + 1) + 1)
    return int64(math.Round(ms))
}

func waitABit(n int64) {
	ms := RandMs(n)
	log.Printf("Waiting for %dms...", ms)
	duration := time.Duration(ms) * time.Millisecond
	time.Sleep(duration)
}

// SendCompletion send completion to Restlet in NetSuite ret bool true if success
func SendCompletion(compl *completion.Completion) (*completion.Completion, error) {
	var failed error
	retries, err := strconv.ParseInt(os.Getenv("NETSUITE_RETRIES"), 10, 64)
	if (err != nil) {
		return nil, err
	}

	request, client, mkerr := goauth1anetsuite.GetClient(compl)
	if mkerr != nil {
		return nil, mkerr
	}
	
	var n int64

	for {
		for {
			n = n + 1
			if (n >= retries) {
				log.Println(failed)
				failed = fmt.Errorf("failed to complete workorder completion after %d trys", retries)
				break 
			}

			resp, reqerr := client.Transport.RoundTrip(request)
			log.Println(resp.Status)

			if reqerr != nil {
				failed = reqerr
				break
			}

			// 400 bad request
			if (resp.StatusCode == http.StatusBadRequest) {
				bad, rberr := ioutil.ReadAll(resp.Body)
				if (rberr != nil) {
					failed = rberr
					break
				}
				ne := &netSuiteError{}
				jmarerr := json.Unmarshal(bad, &ne)
				if jmarerr != nil {
					failed = jmarerr
					break
				}

				if ne.NSError.Code == sssBadRequestArgs {
					keys := request.URL.Query()["key"]
					log.Println("Keys in Request:")
					for i, k := range keys {
						log.Printf("key %d,\t %s\n", i, k)
					}
					failed = fmt.Errorf("NetSuite error: %s, %s", ne.NSError.Code, ne.NSError.Message)
					break
				} else if ne.NSError.Code == sssRequestLimitExceeded {
					log.Printf("Got %s from NetSuite (%s).\n", ne.NSError.Code, ne.NSError.Message)
					waitABit(n)
					continue
				} else {
					failed = fmt.Errorf("NetSuite error: %s, %s", ne.NSError.Code, ne.NSError.Message)
					break
				}
			}
		
			// 504 gw time out
			if (resp.StatusCode == http.StatusGatewayTimeout) {
				log.Print("GatewayTimeout 504")
				waitABit(n)
				continue
			}
			// 200 Successful return 
			if (resp.StatusCode == http.StatusOK) {
				var respPayload = make(map[string]interface{})
				payload, rberr := ioutil.ReadAll(resp.Body)

				if (rberr != nil) {
					failed = rberr
					break
				}

				jdocerr := json.Unmarshal(payload, &respPayload)

				if (jdocerr != nil) {
					failed = jdocerr
					break
				}

				if ID, wocID := respPayload["workordercompletion_id"]; wocID {
					if len(ID.(string)) > 0 {
						compl.WorkorderCompletionID = ID.(string)
						break
					} else {
						failed = errors.New("netsuite didn't return a wocid, check restlet logs")
						break
					}
				}
			}
		}
		break
	}
	return compl, failed
}
