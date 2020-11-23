# AWS account number
AWS_ACCOUNT=""
# AWS Role with proper privileges
AWS_ROLE=""
GOARCH="amd64"
GOOS="linux"

GOARCH=amd64 GOOS=linux go build -ldflags="-s -w"

zip -r goUpdateNetSuite.zip goUpdateNetSuite

aws lambda update-function-code \
    --function-name goUpdateNetSuite \
    --zip-file fileb://goUpdateNetSuite.zip