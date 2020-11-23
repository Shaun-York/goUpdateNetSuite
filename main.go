package main

import (
	"context"
	"encoding/json"
	"goUpdateNetSuite/completion"
	"goUpdateNetSuite/netsuitehandler"
	S "goUpdateNetSuite/sqssrv"
	"log"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
)

// Handle Handles AWS SQS Messages in a Lambda.
// Required Enviroment variables:
// INPUT_QUEUE - SQS url to pull input payloads.
// OUTPUT_QUEUE - SQS url for successful payloads.
// NETSUITE_CONSUMER_KEY - NetSuite Intergration consumer key.
// NETSUITE_CONSUMER_SECRET - NetSuite Intergration consumer secret.
// NETSUITE_ACCESS_KEY - NetSuite User access key with Intergration permissions.
// NETSUITE_ACCESS_SECRET - NetSuite User access secret with Intergration permissions.
// NETSUITE_ACCOUNT - NetSuite customer account number.
// SCRIPT - NetSuite Restlet script interalid.
// DEPLOY - NetSuite Restlet script deployment internalid.
// NETSUITE_RETIRES - Number of trys before fail.
func Handle(ctx context.Context, event events.SQSEvent) (string, error) {
    var failed error
    var msgID string
    for _, sqsmsg := range event.Records {
        msgID = sqsmsg.MessageId
        complpb := completion.Completion{
            MessageBody: sqsmsg.Body,
            ReceiptHandle: sqsmsg.ReceiptHandle,
        }
        
        err := json.Unmarshal([]byte(sqsmsg.Body), &complpb)

        if err != nil {
            failed = err
            break
        }

        complWwocID, reqerr := netsuitehandler.SendCompletion(&complpb)

        if (reqerr != nil) {
            failed = reqerr
            break
        }

        srv := S.CompletionsToNetSuite{}
        srv.GetSrv()
        toQueueMsg, tqerr := complWwocID.SqsMsg()

        if (tqerr != nil) {
            failed = tqerr
            break
        }

        delop, sederr := srv.Send(toQueueMsg, complWwocID.SqsDelMsg())

        if sederr != nil {
            failed = sederr
            break
        }
        
        log.Printf("Sent %s and deleted %s Successfully!", msgID, delop.String())
    }
    return msgID, failed
}

func main() {
    lambda.Start(Handle)
}