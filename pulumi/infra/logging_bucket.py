import json

import pulumi
import pulumi_aws as aws

from .config import central_logging_bucket_name
from .utils.tags import base_tags


region = aws.get_region()
account = aws.get_caller_identity()
replica_provider = aws.Provider("centralLogsReplicaProvider", region="us-east-1")

primary_bucket_name = central_logging_bucket_name(region.name)
replica_bucket_name = f"{primary_bucket_name}-replication"

bucket = aws.s3.Bucket(
  "centralLogs",
  bucket=primary_bucket_name,
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

replica_bucket = aws.s3.Bucket(
  "centralLogsReplica",
  bucket=replica_bucket_name,
  acl="private",
  versioning=aws.s3.BucketVersioningArgs(enabled=True),
  server_side_encryption_configuration=aws.s3.BucketServerSideEncryptionConfigurationArgs(
    rule=aws.s3.BucketServerSideEncryptionConfigurationRuleArgs(
      apply_server_side_encryption_by_default=aws.s3.BucketServerSideEncryptionConfigurationRuleApplyServerSideEncryptionByDefaultArgs(
        sse_algorithm="AES256"
      )
    )
  ),
  tags=base_tags({"Purpose": "central-logging-replica"}),
  opts=pulumi.ResourceOptions(provider=replica_provider),
)

aws.s3.BucketPublicAccessBlock(
  "centralLogsPab",
  bucket=bucket.id,
  block_public_acls=True,
  block_public_policy=True,
  ignore_public_acls=True,
  restrict_public_buckets=True,
)

aws.s3.BucketPublicAccessBlock(
  "centralLogsReplicaPab",
  bucket=replica_bucket.id,
  block_public_acls=True,
  block_public_policy=True,
  ignore_public_acls=True,
  restrict_public_buckets=True,
  opts=pulumi.ResourceOptions(provider=replica_provider),
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

replication_role = aws.iam.Role(
  "centralLogsReplicationRole",
  assume_role_policy=bucket.arn.apply(
    lambda arn: json.dumps(
      {
        "Version": "2012-10-17",
        "Statement": [
          {
            "Effect": "Allow",
            "Principal": {"Service": "s3.amazonaws.com"},
            "Action": "sts:AssumeRole",
            "Condition": {"StringEquals": {"aws:SourceArn": arn}},
          }
        ],
      }
    )
  ),
)

replication_role_policy = aws.iam.RolePolicy(
  "centralLogsReplicationRolePolicy",
  role=replication_role.id,
  policy=pulumi.Output.all(bucket.arn, replica_bucket.arn).apply(
    lambda arns: json.dumps(
      {
        "Version": "2012-10-17",
        "Statement": [
          {
            "Effect": "Allow",
            "Action": [
              "s3:GetReplicationConfiguration",
              "s3:ListBucket",
              "s3:GetObjectVersion",
              "s3:GetObjectVersionAcl",
              "s3:GetObjectVersionForReplication",
              "s3:GetObjectVersionTagging",
            ],
            "Resource": [arns[0], f"{arns[0]}/*"],
          },
          {
            "Effect": "Allow",
            "Action": [
              "s3:ReplicateObject",
              "s3:ReplicateDelete",
              "s3:ReplicateTags",
              "s3:GetObjectVersionTagging",
              "s3:PutObject",
            ],
            "Resource": [arns[1], f"{arns[1]}/*"],
          },
        ],
      }
    )
  ),
)

aws.s3.BucketReplicationConfig(
  "centralLogsReplicationConfiguration",
  bucket=bucket.id,
  role=replication_role.arn,
  rules=[
    aws.s3.BucketReplicationConfigRuleArgs(
      id="central-logs-to-useast1",
      status="Enabled",
      destination=aws.s3.BucketReplicationConfigRuleDestinationArgs(
        bucket=replica_bucket.arn,
        storage_class="STANDARD",
      ),
    )
  ],
  opts=pulumi.ResourceOptions(depends_on=[replication_role_policy]),
)

pulumi.export("centralLogBucket", bucket.bucket)
pulumi.export("centralLogBucketArn", bucket.arn)
