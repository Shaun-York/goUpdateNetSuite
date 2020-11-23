## This script should be added to your .gitignore and chmod 700 or clear after deploy

# AWS SQS URL that feeds this function (the sqs thats this functions trigger)
C_INPUT_QUEUE=""
# AWS SQS URL to send successful payloads (ones that include the NetSuite WOC internalid) to.
C_OUTPUT_QUEUE=""
# NetSuite Integration record TBA consumer token
C_NETSUITE_CONSUMER_KEY=""
# NetSuite Integration record TBA consumer secret
C_NETSUITE_CONSUMER_SECRET=""
# NetSuite user w/ required privileges access token
C_NETSUITE_ACCESS_KEY=""
# NetSuite user w/ required privileges access secret
C_NETSUITE_ACCESS_SECRET=""
# NetSuite Account number where integration is deployed
C_NETSUITE_ACCOUNT=""
# NetSuite Completions Restlet script ID
C_SCRIPT=""
# NetSuite Completions Restlet deployment ID (usually 1)
C_DEPLOY=""
# How many times to try the rest round trip (5 is enough)
C_NETSUITE_RETIRES="5"

ENVS="{\
INPUT_QUEUE=$C_INPUT_QUEUE,\
OUTPUT_QUEUE=$C_OUTPUT_QUEUE,\
NETSUITE_CONSUMER_KEY=$C_NETSUITE_CONSUMER_KEY,\
NETSUITE_CONSUMER_SECRET=$C_NETSUITE_CONSUMER_SECRET,\
NETSUITE_ACCESS_KEY=$C_NETSUITE_ACCESS_KEY,\
NETSUITE_ACCESS_SECRET=$C_NETSUITE_ACCESS_SECRET,\
NETSUITE_ACCOUNT=$C_NETSUITE_ACCOUNT,\
SCRIPT=$C_SCRIPT,\
DEPLOY=$C_DEPLOY,\
NETSUITE_RETIRES=$C_NETSUITE_RETIRES\
}"

aws lambda update-function-configuration \
    --function-name  goUpdateNetSuite \
    --environment Variables=$ENVS