package completion

import (
	json "encoding/json"
	"os"

	"github.com/fatih/structs"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sqs"
)

// ToQueue stuff TODO set with env
var outputQueue = os.Getenv("OUTPUT_QUEUE")
// FromQueue stuff TODO set with env
var inputQueue = os.Getenv("INPUT_QUEUE")

//Completion stuff
type Completion struct {
    // WorkOrder Completion Props
    WorkorderCompletionID 	string 	`json:"workordercompletion_id"`
    OperationSequence 		string 	`json:"operation_sequence"`
    LastCompletion 			bool    `json:"last_completion"`
	RemainingQty   			int     `json:"remaining_qty"`
	MfgOpTaskID    			string  `json:"mfgoptask_id"`
    CompletedQty    		string  `json:"completedQty"`
    WorkorderID 			string 	`json:"workorder_id"`
	OperatorID     			string  `json:"operator_id"`
    WorkTimeID     			int     `json:"worktime_id"`
    LocationID     			string  `json:"location_id"`
	MachineID      			string  `json:"machine_id"`
    UpdatedAt      			string  `json:"updated_at"`
    CreatedAt      			string  `json:"created_at"`
    WorkCenter      		string  `json:"workcenter"`
    ScrapQty 	    		string  `json:"scrapQty"`
	ItemID 	    			string  `json:"item_id"`
	Action		    		string  `json:"action"`
    ID 						int 	`json:"id"`
    // SQS Attributes
    MessageBody             string
    ReceiptHandle           string
    // 
}

// Init assign Completion fields props from Json string
func (x *Completion) Init() error {
    err := json.Unmarshal([]byte(x.MessageBody), &x); 
    return err
}

// ToJdoc return json string
func (x *Completion) ToJdoc() (string, error) {
    jdoc, err := json.Marshal(&x)
    if (err != nil) {
        return "", err
    }
    doc := string(jdoc)
	return doc, err
}

//ToMap return map['string']interface{} of Completion
func (x *Completion) ToMap() (map[string]interface{}) {
    mapped := structs.Map(x)
    return mapped
}

// SqsMsgAttr return Completion attributes
func (x *Completion) SqsMsgAttr() (map[string]*sqs.MessageAttributeValue) {
	return map[string]*sqs.MessageAttributeValue{
		"MfgOpTaskID": {
            DataType:    aws.String("String"),
            StringValue: aws.String(x.MfgOpTaskID),
        },
		"WorkorderCompletionID": {
            DataType:    aws.String("String"),
            StringValue: aws.String(x.WorkorderCompletionID),
        },
		"LocationID": {
            DataType:    aws.String("String"),
            StringValue: aws.String(x.LocationID),
        },
		"MachineID": {
            DataType:    aws.String("String"),
            StringValue: aws.String(x.MachineID),
        },
		"UpdatedAt": {
            DataType:    aws.String("String"),
            StringValue: aws.String(x.UpdatedAt),
        },
		"CreatedAt": {
            DataType:    aws.String("String"),
            StringValue: aws.String(x.CreatedAt),
        },
    }
}

// SqsMsg return message to put into SQS.
func (x *Completion) SqsMsg() (*sqs.SendMessageInput, error) {
    var msg *sqs.SendMessageInput
	jdoc, err := x.ToJdoc()
	if (err != nil) {
        return nil, err
	}
    msg = &sqs.SendMessageInput{
        QueueUrl: &outputQueue,
        MessageAttributes: x.SqsMsgAttr(),
        MessageBody: &jdoc,
    }
    return msg, nil
}

// SqsDelMsg remove msg for processed message
func (x *Completion) SqsDelMsg() *sqs.DeleteMessageInput {
    return &sqs.DeleteMessageInput{
        QueueUrl: &inputQueue,
        ReceiptHandle: &x.ReceiptHandle,
    }
}
