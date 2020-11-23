package sqssrv

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sqs"
)

// CompletionsToNetSuite stiff
type CompletionsToNetSuite struct {
    srv *sqs.SQS
}

// GetSrv return sqs
func (c *CompletionsToNetSuite) GetSrv() (*CompletionsToNetSuite, error) {
    region := "us-east-1" 
    awsSession, err := session.NewSession(&aws.Config{
        Region: aws.String(region)},
    )
    if err != nil {
        return c, err
    }
    c.srv = sqs.New(awsSession)
    return c, nil
}

// Send send sqs message and remove from queue
func (c *CompletionsToNetSuite) Send(msg *sqs.SendMessageInput, delmsg *sqs.DeleteMessageInput) (*sqs.DeleteMessageOutput, error) {
    _, serr := c.srv.SendMessage(msg)
    if (serr != nil) {
        return nil, serr
    }
    deloutput, derr := c.srv.DeleteMessage(delmsg)
    if (derr != nil) {
         return nil, derr 
    }
    return deloutput, nil
}