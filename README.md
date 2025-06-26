# Free-Tier Serverless Cloud Security Auditor on AWS

## Project Overview
This project demonstrates the design and implementation of a cost-efficient, serverless security auditor on AWS, specifically engineered to operate entirely within the AWS Free Tier. Its primary function is to continuously monitor and identify critical cloud security misconfigurations, starting with publicly accessible Amazon S3 buckets.

## Problem Solved
Manually auditing cloud resource configurations for security compliance is time-consuming, error-prone, and not scalable. This solution automates the detection of common "low-hanging fruit" vulnerabilities, such as public S3 buckets, providing proactive alerts to mitigate data exposure risks.

## Architecture & AWS Services Used

The solution leverages the following AWS services, deployed and managed with a focus on security and cost-efficiency:

* **AWS Lambda:** Core compute service for executing the security audit logic.
* **Amazon S3:** Used for storing Lambda function code and potentially future audit reports (though minimized for Free Tier).
* **Amazon SNS (Simple Notification Service):** For sending real-time email alerts when security misconfigurations are detected.
* **Amazon DynamoDB:** (Optional but included) Stores a historical log of identified public S3 buckets.
* **Amazon EventBridge (CloudWatch Events):** Schedules the Lambda function to run daily, ensuring continuous monitoring.
* **AWS IAM (Identity and Access Management):** Critical for defining granular, least-privilege permissions for all components, ensuring the auditor itself is secure.
* **AWS CloudWatch Logs:** For logging Lambda function execution and audit findings, crucial for debugging and operational visibility.

## Key Features

* **Automated S3 Public Access Detection:** Scans all S3 buckets in the AWS account to identify public read/write access granted via ACLs, bucket policies, or disabled Public Access Block (PAB) settings.
* **Real-time Email Notifications:** Sends immediate alerts via SNS to a subscribed email address upon detection of a public S3 bucket.
* **Findings History:** (Optional) Records details of identified public buckets in a DynamoDB table.
* **Cost-Efficient Design:** Built from the ground up to operate within the AWS Free Tier limits for all utilized services.
* **Security-First Approach:** Implemented with least-privilege IAM roles to minimize the attack surface of the auditor itself.

## How It Works

1.  An **EventBridge** rule triggers the `S3PublicBucketAuditor` Lambda function on a daily schedule.
2.  The **Lambda function** (written in Python) uses the `boto3` SDK to:
    * List all S3 buckets in the AWS account.
    * For each bucket, check its Public Access Block (PAB) configuration, Bucket ACL, and Bucket Policy for public access grants.
3.  If a publicly accessible bucket is identified, the Lambda function:
    * Publishes an alert message to the `S3PublicBucketAlerts` **SNS Topic**.
    * (If configured) Stores the finding details (bucket name, reason, timestamp) in the `S3PublicBucketsFound` **DynamoDB Table**.
4.  Subscribed users receive an email notification from SNS.
5.  All Lambda execution logs are sent to **CloudWatch Logs** for auditing and debugging.

## Setup & Deployment (Console-Based)
This project was initially deployed and configured manually via the AWS Management Console to demonstrate direct service interaction and configuration.

**Manual Setup Steps (High-Level):**

1.  **Create IAM Role:** `S3BucketAuditorLambdaRole` with `AWSLambdaBasicExecutionRole` and custom inline policy for `s3:ListAllMyBuckets`, `s3:GetBucketAcl`, `s3:GetBucketPolicy`, `s3:GetBucketPublicAccessBlock`, plus `sns:Publish` and `dynamodb:PutItem` permissions (scoped to specific resources for production).
2.  **Create SNS Topic:** `S3PublicBucketAlerts` and subscribe your email.
3.  **Create DynamoDB Table:** `S3PublicBucketsFound` with `bucketName` as partition key.
4.  **Create Lambda Function:** `S3PublicBucketAuditor` (Python runtime), attaching the IAM role. Paste the `lambda_function.py` code. Configure `SNS_TOPIC_ARN` and `DYNAMODB_TABLE_NAME` as environment variables.
5.  **Create EventBridge Rule:** `DailyS3PublicBucketAudit` scheduled to trigger the Lambda function daily.

*(Consider adding a note here if you plan to convert to IaC later: "Future iterations will include Infrastructure as Code (IaC) templates for automated deployment.")*

## Files in this Repository

* `lambda_function.py`: The Python code for the AWS Lambda function.
* `README.md`: This file, providing an overview of the project.

## Future Enhancements

* **Expand Audit Checks:** Add checks for other misconfigurations (e.g., overly permissive security groups, unencrypted resources).
* **Infrastructure as Code (IaC):** Convert manual console setup to AWS SAM or CloudFormation templates for automated and repeatable deployments.
* **Customizable Targets:** Allow specifying specific accounts or regions to audit.
* **Reporting Dashboard:** Build a simple dashboard (e.g., using AWS QuickSight or a static S3 website) to visualize findings over time.
* **Slack/Teams Notifications:** Integrate with collaboration tools for alerts.

---