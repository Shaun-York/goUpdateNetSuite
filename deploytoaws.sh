# aws-cli needs to be install and authenticated 
# AWS account number
AWS_ACCOUNT=""
# AWS Role with proper privileges
AWS_ROLE=""
GOARCH="amd64"
GOOS="linux"

go build .

zip -r goUpdateNetSuite.zip ./goUpdateNetSuite

aws lambda create-function --function-name goUpdateNetSuite \
    --runtime go1.x \
    --zip-file fileb://goUpdateNetSuite.zip \
    --handler goUpdateNetSuite \
    --role arn:aws:iam::$AWS_ACCOUNT:role/service-role/$AWS_ROLE