"""Central logging bucket infrastructure for the platform."""

import json

import pulumi
import pulumi_aws as aws

from .config import central_logging_bucket_name
from .utils.tags import base_tags


def _log_bucket_policy(bucket_arn: str, account_id: str) -> str:
  """Build the TLS-only policy with CloudTrail and log delivery permissions."""
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
      "Action": ["s3:GetBucketAcl", "s3:PutObject"],
      "Resource": "{bucket_arn}/cloudtrail/AWSLogs/{account_id}/*",
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
          "aws:SourceAccount": "{account_id}"
        }}
      }}
    }}
  ]
}}
"""


class CentralLoggingBuckets(pulumi.ComponentResource):
  """Provision primary and replica S3 buckets for centralized logging."""

  def __init__(
    self,
    name: str,
    *,
    replication_region: str = "us-east-1",
    opts: pulumi.ResourceOptions | None = None,
  ) -> None:
    """Initialize the central logging buckets component."""
    super().__init__("bootstrap:logging:CentralLoggingBuckets", name, None, opts)

    region = aws.get_region()
    account = aws.get_caller_identity()
    replica_provider = aws.Provider(
      f"{name}-replica-provider",
      region=replication_region,
      opts=pulumi.ResourceOptions(parent=self),
    )

    primary_bucket_name = central_logging_bucket_name(region.name)
    replica_bucket_name = f"{primary_bucket_name}-replication"
    if len(replica_bucket_name) > 63:
      raise ValueError("Replica logging bucket name exceeds S3 63-character limit.")

    base_opts = pulumi.ResourceOptions(parent=self)
    replica_opts = pulumi.ResourceOptions(parent=self, provider=replica_provider)

    bucket = aws.s3.Bucket(
      f"{name}-primary",
      bucket=primary_bucket_name,
      versioning=aws.s3.BucketVersioningArgs(enabled=True),
      lifecycle_rules=[
        aws.s3.BucketLifecycleRuleArgs(
          id="logs-lifecycle",
          enabled=True,
          abort_incomplete_multipart_upload=aws.s3.BucketLifecycleRuleAbortIncompleteMultipartUploadArgs(
            days_after_initiation=7
          ),
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
      opts=base_opts,
    )

    replica_bucket = aws.s3.Bucket(
      f"{name}-replica",
      bucket=replica_bucket_name,
      versioning=aws.s3.BucketVersioningArgs(enabled=True),
      lifecycle_rules=[
        aws.s3.BucketLifecycleRuleArgs(
          id="replica-lifecycle",
          enabled=True,
          abort_incomplete_multipart_upload=aws.s3.BucketLifecycleRuleAbortIncompleteMultipartUploadArgs(
            days_after_initiation=7
          ),
        )
      ],
      server_side_encryption_configuration=aws.s3.BucketServerSideEncryptionConfigurationArgs(
        rule=aws.s3.BucketServerSideEncryptionConfigurationRuleArgs(
          apply_server_side_encryption_by_default=aws.s3.BucketServerSideEncryptionConfigurationRuleApplyServerSideEncryptionByDefaultArgs(
            sse_algorithm="AES256"
          )
        )
      ),
      tags=base_tags({"Purpose": "central-logging-replica"}),
      opts=replica_opts,
    )

    aws.s3.BucketPublicAccessBlock(
      f"{name}-primary-pab",
      bucket=bucket.id,
      block_public_acls=True,
      block_public_policy=True,
      ignore_public_acls=True,
      restrict_public_buckets=True,
      opts=base_opts,
    )

    aws.s3.BucketPublicAccessBlock(
      f"{name}-replica-pab",
      bucket=replica_bucket.id,
      block_public_acls=True,
      block_public_policy=True,
      ignore_public_acls=True,
      restrict_public_buckets=True,
      opts=replica_opts,
    )

    aws.s3.BucketPolicy(
      f"{name}-policy",
      bucket=bucket.id,
      policy=pulumi.Output.all(bucket.arn, account.account_id).apply(
        lambda values: _log_bucket_policy(values[0], values[1])
      ),
      opts=base_opts,
    )

    aws.s3.BucketPolicy(
      f"{name}-replica-policy",
      bucket=replica_bucket.id,
      policy=pulumi.Output.all(replica_bucket.arn, account.account_id).apply(
        lambda values: _log_bucket_policy(values[0], values[1])
      ),
      opts=replica_opts,
    )

    replication_role = aws.iam.Role(
      f"{name}-replication-role",
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
      tags=base_tags({"Purpose": "central-logs-replication"}),
      opts=base_opts,
    )

    replication_role_policy = aws.iam.RolePolicy(
      f"{name}-replication-role-policy",
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
      opts=base_opts,
    )

    aws.s3.BucketReplicationConfig(
      f"{name}-replication-config",
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
      opts=pulumi.ResourceOptions(parent=self, depends_on=[replication_role_policy]),
    )

    self.bucket = bucket
    self.replica_bucket = replica_bucket
    self.replication_role = replication_role

    self.register_outputs(
      {
        "bucket_name": bucket.bucket,
        "bucket_arn": bucket.arn,
        "replica_bucket_name": replica_bucket.bucket,
        "replica_bucket_arn": replica_bucket.arn,
      }
    )
