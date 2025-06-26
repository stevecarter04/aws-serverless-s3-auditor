import boto3
import os
import json
from datetime import datetime

s3_client = boto3.client('s3')
sns_client = boto3.client('sns')
dynamodb_client = boto3.client('dynamodb')

SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN')
DYNAMODB_TABLE_NAME = os.environ.get('DYNAMODB_TABLE_NAME') 
# confirm envioriment varibales are set
if not SNS_TOPIC_ARN or not DYNAMODB_TABLE_NAME:
    raise ValueError("SNS_TOPIC_ARN and/or DYNAMODB_TABLE_NAME environment variables are not set.")

def lambda_handler(event, context):
    print(f"Starting S3 Public Bucket Audit at {datetime.now()}")
    public_buckets = []

    try:
        # 1. List all S3 buckets
        response = s3_client.list_buckets()
        buckets = response['Buckets']

        for bucket in buckets:
            bucket_name = bucket['Name']
            is_public = False
            reasons = []

            print(f"Checking bucket: {bucket_name}")

            # Check 1: Public Access Block (PAB) configuration
            try:
                pab_response = s3_client.get_public_access_block(Bucket=bucket_name)
                pab_config = pab_response['PublicAccessBlockConfiguration']
                # If any of these are False, it means public access is NOT blocked
                if not pab_config['BlockPublicAcls'] or \
                   not pab_config['IgnorePublicAcls'] or \
                   not pab_config['BlockPublicPolicy'] or \
                   not pab_config['RestrictPublicBuckets']:
                    is_public = True
                    reasons.append("Public Access Block (PAB) not fully enabled.")
            except s3_client.exceptions.ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                    # No PAB configuration means public access is NOT blocked by PAB
                    is_public = True
                    reasons.append("No Public Access Block (PAB) configuration found.")
                else:
                    print(f"Error checking PAB for {bucket_name}: {e}")
                    continue # Skip to next bucket if we can't check PAB

            # Check 2: Bucket ACL (Access Control List)
            try:
                acl_response = s3_client.get_bucket_acl(Bucket=bucket_name)
                for grant in acl_response['Grants']:
                    grantee = grant.get('Grantee', {})
                    if grantee.get('Type') == 'Group' and \
                       grantee.get('URI') in ['http://acs.amazonaws.com/groups/global/AllUsers',
                                              'http://acs.amazonaws.com/groups/global/AuthenticatedUsers']:
                        is_public = True
                        reasons.append(f"ACL grants {grantee.get('URI').split('/')[-1]} access.")
                        break # No need to check other ACL grants if one is public
            except s3_client.exceptions.ClientError as e:
                print(f"Error checking ACL for {bucket_name}: {e}")
                # Continue as PAB might already flag it, or policy check is next

            # Check 3: Bucket Policy
            try:
                policy_response = s3_client.get_bucket_policy(Bucket=bucket_name)
                policy = json.loads(policy_response['Policy'])
                for statement in policy.get('Statement', []):
                    if statement.get('Effect') == 'Allow' and \
                       statement.get('Principal') == '*' and \
                       's3:GetObject' in statement.get('Action', []): # Check for public read
                        is_public = True
                        reasons.append("Bucket policy grants public read access.")
                        break
            except s3_client.exceptions.ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                    # No bucket policy is common, not necessarily a public issue on its own
                    pass
                else:
                    print(f"Error checking policy for {bucket_name}: {e}")


            if is_public:
                public_buckets.append({
                    'BucketName': bucket_name,
                    'Reasons': reasons,
                    'Timestamp': datetime.now().isoformat()
                })
                print(f"  --> Identified as public due to: {', '.join(reasons)}")
            else:
                print(f"  --> Bucket {bucket_name} appears secure.")

        # 2. Process Findings
        if public_buckets:
            message = f"Cloud Security Alert: Found {len(public_buckets)} potentially public S3 bucket(s)!\n\n"
            for bucket_info in public_buckets:
                message += f"Bucket: {bucket_info['BucketName']}\n"
                message += f"Reasons: {', '.join(bucket_info['Reasons'])}\n"
                message += f"Timestamp: {bucket_info['Timestamp']}\n\n"

                # Store in DynamoDB (if table name is set)
                if DYNAMODB_TABLE_NAME:
                    try:
                        dynamodb_client.put_item(
                            TableName=DYNAMODB_TABLE_NAME,
                            Item={
                                'bucketName': {'S': bucket_info['BucketName']},
                                'timestamp': {'S': bucket_info['Timestamp']},
                                'reasons': {'L': [{'S': reason} for reason in bucket_info['Reasons']]}
                            }
                        )
                        print(f"Stored finding for {bucket_info['BucketName']} in DynamoDB.")
                    except Exception as e:
                        print(f"Error storing in DynamoDB for {bucket_info['BucketName']}: {e}")


            print(message)
            # Publish to SNS
            if SNS_TOPIC_ARN:
                sns_client.publish(
                    TopicArn=SNS_TOPIC_ARN,
                    Subject="AWS Security Alert: Public S3 Bucket(s) Detected!",
                    Message=message
                )
                print("Published alert to SNS.")
            else:
                print("SNS_TOPIC_ARN not configured, skipping SNS notification.")

        else:
            print("No public S3 buckets found. Your S3 posture looks good!")
            if SNS_TOPIC_ARN:
                # Optionally, send a "all clear" message or just log it
                sns_client.publish(
                    TopicArn=SNS_TOPIC_ARN,
                    Subject="AWS Security Audit: S3 Buckets All Clear",
                    Message=f"S3 Public Bucket audit completed at {datetime.now()}. No publicly accessible buckets found."
                )
                print("Published 'all clear' to SNS.")

    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        if SNS_TOPIC_ARN:
            sns_client.publish(
                TopicArn=SNS_TOPIC_ARN,
                Subject="AWS Security Audit Error!",
                Message=f"An error occurred during S3 public bucket audit: {e}"
            )

    return {
        'statusCode': 200,
        'body': json.dumps('S3 audit completed.')
    }