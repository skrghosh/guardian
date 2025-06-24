import os
import json
import time
import boto3
import yaml
import re
from botocore.exceptions import ClientError

# AWS clients
s3 = boto3.client('s3')
sns = boto3.client('sns')
dynamodb = boto3.resource('dynamodb')
audit_table = dynamodb.Table(os.environ['AUDIT_TABLE'])

# Map CloudWatch eventName to runbook file
RUNBOOK_MAP = {
    'PutBucketAcl': 'public_s3_bucket.yaml',
    'PutBucketPublicAccessBlock': 'public_s3_bucket.yaml',
    'CreateUser': 'suspicious_iam_activity.yaml',
    'UpdateLoginProfile': 'suspicious_iam_activity.yaml',
    'AttachUserPolicy': 'suspicious_iam_activity.yaml'
}

def dispatcher(event, context):
    # Support API Gateway proxy: parse JSON body if present
    if 'body' in event and isinstance(event['body'], str):
        try:
            payload = json.loads(event['body'])
        except json.JSONDecodeError as e:
            return respond(400, {'status': 'error', 'message': 'Invalid JSON body'})
        detail = payload.get('detail', {})
    else:
        detail = event.get('detail', {})

    event_name = detail.get('eventName')
    runbook_key = RUNBOOK_MAP.get(event_name)
    if not runbook_key:
        print(f"No matching runbook for eventName: {event_name}")
        return respond(200, {'status': 'no-op'})

    # Load runbook YAML from S3
    bucket = os.environ['RUNBOOKS_BUCKET']
    try:
        obj = s3.get_object(Bucket=bucket, Key=runbook_key)
        content = obj['Body'].read()
        runbook = yaml.safe_load(content)
    except ClientError as e:
        print(f"Error loading runbook {runbook_key}: {e}")
        return respond(500, {'status': 'error', 'message': str(e)})

    # Execute playbook steps
    results = execute_runbook(runbook, detail)
    audit_runbook(runbook_key, event, results)
    return respond(200, {'status': 'completed', 'results': results})


def execute_runbook(steps, detail):
    results = []
    for step in steps:
        name = step.get('name')
        action = step.get('action')
        raw_params = step.get('params', {})
        params = substitute_params(raw_params, detail)

        service, method = action.split('.', 1)
        client = boto3.client(service)
        try:
            func = getattr(client, method)
            func(**params)
            results.append({'step': name, 'status': 'success'})
        except ClientError as e:
            results.append({'step': name, 'status': 'error', 'error': str(e)})
            break
        except AttributeError as e:
            results.append({'step': name, 'status': 'error', 'error': str(e)})
            break
    return results


def substitute_params(obj, detail):
    """Recursively replace {{ expr }} with values from detail."""
    if isinstance(obj, dict):
        return {k: substitute_params(v, detail) for k, v in obj.items()}
    if isinstance(obj, list):
        return [substitute_params(v, detail) for v in obj]
    if isinstance(obj, str):
        def repl(match):
            expr = match.group(1).strip()
            parts = expr.split('.')
            val = detail
            for p in parts:
                val = val.get(p) if isinstance(val, dict) else None
                if val is None:
                    break
            return str(val) if val is not None else ''
        return re.sub(r'{{\s*([^}]+)\s*}}', repl, obj)
    return obj


def audit_runbook(runbook_key, event, results):
    timestamp = event.get('time', time.strftime('%Y-%m-%dT%H:%M:%SZ'))
    expire_at = int(time.time() + 7*24*3600)
    item = {
        'RunbookId': runbook_key,
        'Timestamp': timestamp,
        'Event': json.dumps(event),
        'Results': json.dumps(results),
        'ExpireAt': expire_at
    }
    audit_table.put_item(Item=item)
    msg = f"Runbook '{runbook_key}' executed at {timestamp} with {len(results)} steps."
    sns.publish(TopicArn=os.environ['SNS_TOPIC_ARN'], Message=msg)


def respond(status_code, body):
    return {
        'statusCode': status_code,
        'headers': {'Content-Type': 'application/json'},
        'body': json.dumps(body)
    }
