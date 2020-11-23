# goUpdateNetSuite AWS Lambda 2 of 3

Consume AWS SQS messages. mk NetSuite Work Order Completions via Restlet pass to next sqs queue

AWSAPI Gateway -> SQS -> [goUpdateTaskQty](https://github.com/Shaun-York/goUpdateTaskQty) -> SQS -> [goUpdateNetSuite](https://github.com/Shaun-York/goUpdateNetSuite) -> SQS -> [goUpdateCompletion](https://github.com/Shaun-York/goUpdateCompletion)
