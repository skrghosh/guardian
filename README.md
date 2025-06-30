# Guardian - Serverless Security Runbook Automation

This repository contains **Guardian**, a small serverless incident-response framework built on AWS Lambda. Guardian listens for security events via EventBridge, executes YAML-defined runbooks (playbooks) to remediate issues, logs actions in DynamoDB, and notifies teams via SNS.

---

## Architecture

* **AWS Lambda**: Runs the dispatcher and executor logic (`src/handler.py`).
* **EventBridge Rules**: Triggers Lambda for S3 and IAM events.
* **Amazon S3**: Stores runbook YAML definitions in the bucket `guardian-runbooks-<AccountId>`.
* **Amazon DynamoDB**: Audit table `guardian-audit-<AccountId>` records each runbook execution with a 7-day TTL.
* **Amazon SNS**: Topic `guardian-notifications-<AccountId>` sends notifications to subscribed endpoints.

---

## Prerequisites

1. **AWS Account** (I did it with my free-tier)
2. **AWS CLI v2** installed and configured.
3. **AWS SAM CLI** installed.
4. **Python 3.12** (for local packaging).
5. An IAM user or role (`guardian-deployer`) with these managed policies attached:

   * `AdministratorAccess` (or at minimum: `AWSCloudFormationFullAccess`, `IAMFullAccess`, `AmazonS3FullAccess`, `AmazonDynamoDBFullAccess`, `AmazonSNSFullAccess`)

---

## Setup

```bash
# Clone the repo
git clone https://github.com/YOUR_USER/guardian.git
git checkout main
cd guardian

# Create & activate a virtual environment (optional)
python3 -m venv .venv && source .venv/bin/activate

# Install local dependencies
pip install -r src/requirements.txt
```

Configure your AWS CLI profile:

```bash
aws configure --profile guardian-deployer
# Enter Access Key, Secret, and Region (e.g. us-east-1)
```

---

## Deploy

Build and deploy the SAM application:

```bash
sam build
sam deploy --guided --profile guardian-deployer
```

During prompts, accept defaults or specify:

* **Stack Name**: `guardian-stack`
* **Region**: your AWS region
* **Confirm changes before deploy**: `N`
* **Allow SAM IAM role creation**: `Y`
* **Disable rollback**: `Y`
* **Confirm public simulate endpoint**: `Y`
* **Save settings**: `Y`

After deployment, note the CloudFormation outputs:

* `ApiUrl`: e.g. `https://<api-id>.execute-api.<region>.amazonaws.com/Prod/simulate`
* `RunbooksBucket`: e.g. `guardian-runbooks-588738589030`

---

## Upload Runbooks

The folder `runbooks/` contains two playbook definitions:

* **public\_s3\_bucket.yaml**: Remediates public S3 bucket settings.
* **suspicious\_iam\_activity.yaml**: Disables IAM login profile and detaches policies.

Upload them to your S3 bucket:

```bash
export ACCOUNT_ID=$(aws sts get-caller-identity --profile guardian-deployer --query Account --output text)
export BUCKET=guardian-runbooks-$ACCOUNT_ID

aws s3 cp runbooks/public_s3_bucket.yaml s3://$BUCKET/public_s3_bucket.yaml --profile guardian-deployer
aws s3 cp runbooks/suspicious_iam_activity.yaml s3://$BUCKET/suspicious_iam_activity.yaml --profile guardian-deployer
```

---

## Subscribe to Notifications

Subscribe an email (or HTTPS/Slack webhook) to your SNS topic:

```bash
aws sns subscribe \
  --topic-arn arn:aws:sns:<region>:$ACCOUNT_ID:guardian-notifications-$ACCOUNT_ID \
  --protocol email \
  --notification-endpoint you@example.com \
  --profile guardian-deployer
```

Confirm the subscription link sent to your inbox.

---

## Testing Runbooks

### Public S3 Bucket Remediation

1. **Create a test bucket** (allow ACLs):

   ```bash
   aws s3api create-bucket --bucket guardian-acl-demo-$ACCOUNT_ID --create-bucket-configuration LocationConstraint=us-east-1 --profile guardian-deployer
   aws s3api put-public-access-block --bucket guardian-acl-demo-$ACCOUNT_ID --public-access-block-configuration BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false --profile guardian-deployer
   ```

2. **Simulate event**:

   ```bash
   curl -X POST $ApiUrl \
     -H "Content-Type: application/json" \
     -d '{"detail":{"eventName":"PutBucketAcl","requestParameters":{"bucketName":"guardian-acl-demo-'$ACCOUNT_ID'"}}}'
   ```

3. **Verify**:

   * **S3**: `aws s3api get-public-access-block --bucket guardian-acl-demo-$ACCOUNT_ID --profile guardian-deployer`
   * **Email**: check SNS notification
   * **DynamoDB**: `aws dynamodb query --table-name guardian-audit-$ACCOUNT_ID --key-condition-expression "RunbookId = :r" --expression-attribute-values '{":r":{"S":"public_s3_bucket.yaml"}}'`

### Suspicious IAM Activity Remediation

1. **Create test IAM user**:

   ```bash
   aws iam create-user --user-name guardian-demo-user --profile guardian-deployer
   aws iam create-login-profile --user-name guardian-demo-user --password 'TempP@ssw0rd!' --password-reset-required --profile guardian-deployer
   aws iam attach-user-policy --user-name guardian-demo-user --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess --profile guardian-deployer
   ```

2. **Simulate event**:

   ```bash
   curl -X POST $ApiUrl \
     -H "Content-Type: application/json" \
     -d '{"detail":{"eventName":"AttachUserPolicy","requestParameters":{"userName":"guardian-demo-user","policyArn":"arn:aws:iam::aws:policy/ReadOnlyAccess"}}}'
   ```

3. **Verify**:

   * **Login profile**: `aws iam get-login-profile --user-name guardian-demo-user --profile guardian-deployer` → expects `NoSuchEntity`
   * **Policies**: `aws iam list-attached-user-policies --user-name guardian-demo-user --profile guardian-deployer` → expects empty list
   * **Email**: check SNS notification
   * **DynamoDB**: query for `suspicious_iam_activity.yaml`

---

## Cleanup

To avoid lingering resources on the Free Tier:

1. **Delete stack** (removes Lambda, EventBridge rules, DynamoDB, SNS):

   ```bash
   sam delete --profile guardian-deployer
   ```
2. **Empty & delete buckets**:

   ```bash
   aws s3 rb s3://guardian-acl-demo-$ACCOUNT_ID --force --profile guardian-deployer
   aws s3 rb s3://guardian-runbooks-$ACCOUNT_ID --force --profile guardian-deployer
   ```
3. **Delete test IAM user**:

   ```bash
   aws iam delete-user --user-name guardian-demo-user --profile guardian-deployer
   ```
4. **Remove SNS subscriptions** in the Console if needed.

---