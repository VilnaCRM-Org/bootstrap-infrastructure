import pulumi
import pulumi_aws as aws

from .config import central_logging_bucket_name
from .utils.tags import base_tags


region = aws.get_region()
account = aws.get_caller_identity()

bucket = aws.s3.Bucket(
  "centralLogs",
  bucket=central_logging_bucket_name(region.name),
  acl="private",
  versioning=aws.s3.BucketVersioningArgs(enabled=True),
  lifecycle_rules=[
    aws.s3.BucketLifecycleRuleArgs(
      id="logs-lifecycle",
      enabled=True,
      transitions=[
        aws.s3.BucketLifecycleRuleTransitionArgs(
          days=30,
          storage_class="STANDARD_IA",
        )
      ],
      expiration=aws.s3.BucketLifecycleRuleExpirationArgs(days=365),
    )
  ],
  server_side_encryption_configuration=aws.s3.BucketServerSideEncryptionConfigurationArgs(
    rule=aws.s3.BucketServerSideEncryptionConfigurationRuleArgs(
      apply_server_side_encryption_by_default=aws.s3.BucketServerSideEncryptionConfigurationRuleApplyServerSideEncryptionByDefaultArgs(
        sse_algorithm="AES256"
      )
    )
  ),
  tags=base_tags({"Purpose": "central-logging"}),
)

aws.s3.BucketPublicAccessBlock(
  "centralLogsPab",
  bucket=bucket.id,
  block_public_acls=True,
  block_public_policy=True,
  ignore_public_acls=True,
  restrict_public_buckets=True,
)


def _log_bucket_policy(bucket_arn: str) -> str:
  return f"""
{{
  "Version": "2012-10-17",
  "Statement": [
    {{
      "Sid": "RequireTLS",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["{bucket_arn}", "{bucket_arn}/*"],
      "Condition": {{
        "Bool": {{"aws:SecureTransport": "false"}}
      }}
    }},
    {{
      "Sid": "AllowCloudTrailWrites",
      "Effect": "Allow",
      "Principal": {{"Service": "cloudtrail.amazonaws.com"}},
      "Action": "s3:PutObject",
      "Resource": "{bucket_arn}/cloudtrail/AWSLogs/{account.account_id}/*",
      "Condition": {{
        "StringEquals": {{"s3:x-amz-acl": "bucket-owner-full-control"}}
      }}
    }},
    {{
      "Sid": "AllowLogDelivery",
      "Effect": "Allow",
      "Principal": {{"Service": "logging.s3.amazonaws.com"}},
      "Action": "s3:PutObject",
      "Resource": "{bucket_arn}/aws-logs/*",
      "Condition": {{
        "StringEquals": {{
          "s3:x-amz-acl": "bucket-owner-full-control",
          "aws:SourceAccount": "{account.account_id}"
        }}
      }}
    }}
  ]
}}
"""


aws.s3.BucketPolicy(
  "centralLogsPolicy",
  bucket=bucket.id,
  policy=bucket.arn.apply(_log_bucket_policy),
)

pulumi.export("centralLogBucket", bucket.bucket)
pulumi.export("centralLogBucketArn", bucket.arn)
