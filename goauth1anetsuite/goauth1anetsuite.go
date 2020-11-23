package goauth1anetsuite

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"strconv"

	"goUpdateNetSuite/auth"
	"goUpdateNetSuite/completion"
	"goUpdateNetSuite/config"
)

var nsoauth = &config.NSOAuth1a{}
var nsauth = nsoauth.GetNOAuth1a()


// GetURL get request url
func GetURL(c *completion.Completion) *url.URL {
	account := nsauth.NetSuiteAccount
	requrla := fmt.Sprintf("https://%s.restlets.api.netsuite.com/app/site/hosting/restlet.nl?", account)
	requrl, err := url.Parse(requrla)
	if (err != nil) {
		log.Fatalf("Failed to parse requrl %s", err)
	}
	q := requrl.Query()
	q.Add("script", os.Getenv("SCRIPT"))
	q.Add("deploy", os.Getenv("DEPLOY"))
	q.Add("workordercompletion_id", c.WorkorderCompletionID)
	q.Add("operation_sequence", c.OperationSequence)

	b := strconv.FormatBool(c.LastCompletion)
	q.Add("last_completion", b)

	var n64 int64
	n64 = int64(c.RemainingQty)
	n := strconv.FormatInt(n64, 10)
	q.Add("remaining_qty", n)

	q.Add("mfgoptask_id", c.MfgOpTaskID)
	q.Add("completedQty", c.CompletedQty)

	var w64 int64
	w64 = int64(c.WorkTimeID)
	wn := strconv.FormatInt(w64, 10)
	q.Add("worktime_id", wn)
	
	q.Add("operator_id", c.OperatorID)
	q.Add("workorder_id", c.WorkorderID)
	q.Add("location_id", c.LocationID)
	q.Add("machine_id", c.MachineID)
	q.Add("updated_at", c.UpdatedAt)
	q.Add("created_at", c.CreatedAt)
	q.Add("workcenter", c.WorkCenter)
	q.Add("scrapQty", c.ScrapQty)
	q.Add("item_id", c.ItemID)
	q.Add("action", c.Action)

	var id64 int64
	id64 = int64(c.ID)
	id := strconv.FormatInt(id64, 10)
	q.Add("id", id)
	requrl.RawQuery = q.Encode()
	return requrl
}

//GetClient for Doer
func GetClient(c *completion.Completion) (*http.Request, *http.Client, error) {
	config := auth.NewConfig(os.Getenv("NETSUITE_CONSUMER_KEY"), os.Getenv("NETSUITE_CONSUMER_SECRET"))
	token := auth.NewToken(os.Getenv("NETSUITE_ACCESS_KEY"), os.Getenv("NETSUITE_ACCESS_SECRET"))
	config.Realm = os.Getenv("NETSUITE_ACCOUNT")
	client := config.Client(auth.NoContext, token)
	client.Timeout = 65 * time.Second

	urlwparams := GetURL(c)
	headers := http.Header{}
	headers.Set("Content-Type", "application/json")

	request := &http.Request{
		Method: "GET",
		URL: urlwparams,
		Header: headers,
		Close: true,
	}

	grr := auth.SetAuthHeaders(config, request, token)

	if grr != nil {
		return nil, nil, grr
	}

	return request, client, nil
}
