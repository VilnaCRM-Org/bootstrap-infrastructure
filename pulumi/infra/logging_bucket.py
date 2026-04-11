"""Central logging bucket infrastructure for the platform."""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import cast

import pulumi_aws as aws

import pulumi

from .config import central_logging_bucket_name, settings
from .utils.outputs import apply_output
from .utils.tags import base_tags


def _bucket_exists(name: str, *, provider: aws.Provider | None = None) -> bool:
    """Return True when the S3 bucket already exists."""
    try:
        invoke_opts = (
            pulumi.InvokeOptions(provider=provider) if provider is not None else None
        )
        aws.s3.get_bucket(bucket=name, opts=invoke_opts)
    except Exception as exc:
        message = str(exc)
        if (
            "NotFound" in message
            or "NoSuchBucket" in message
            or "404" in message
            or "empty result" in message
            or "couldn't find resource" in message
        ):
            return False
        raise
    else:
        return True


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
      "Sid": "AllowCloudTrailAclCheck",
      "Effect": "Allow",
      "Principal": {{"Service": "cloudtrail.amazonaws.com"}},
      "Action": "s3:GetBucketAcl",
      "Resource": "{bucket_arn}",
      "Condition": {{
        "StringEquals": {{"aws:SourceAccount": "{account_id}"}}
      }}
    }},
    {{
      "Sid": "AllowCloudTrailPutObject",
      "Effect": "Allow",
      "Principal": {{"Service": "cloudtrail.amazonaws.com"}},
      "Action": "s3:PutObject",
      "Resource": "{bucket_arn}/cloudtrail/AWSLogs/{account_id}/*",
      "Condition": {{
        "StringEquals": {{
          "s3:x-amz-acl": "bucket-owner-full-control",
          "aws:SourceAccount": "{account_id}"
        }}
      }}
    }},
    {{
      "Sid": "AllowLogDeliveryAclCheck",
      "Effect": "Allow",
      "Principal": {{"Service": "logging.s3.amazonaws.com"}},
      "Action": "s3:GetBucketAcl",
      "Resource": "{bucket_arn}",
      "Condition": {{
        "StringEquals": {{"aws:SourceAccount": "{account_id}"}}
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


def _log_bucket_policy_from_values(values: Sequence[str]) -> str:
    """Build the logging bucket policy from Pulumi output values."""
    return _log_bucket_policy(values[0], values[1])


def _replication_assume_role_policy(arn: str) -> str:
    """Build the S3 replication trust policy for the logging bucket."""
    return json.dumps(
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


def _replication_role_policy(arns: Sequence[str]) -> str:
    """Build the S3 replication permissions policy for logging buckets."""
    return json.dumps(
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


class CentralLoggingBuckets(pulumi.ComponentResource):
    """Provision primary and replica S3 buckets for centralized logging."""

    def __init__(
        self,
        name: str,
        *,
        replication_region: str | None = None,
        opts: pulumi.ResourceOptions | None = None,
    ) -> None:
        """Initialize the central logging buckets component."""
        super().__init__("bootstrap:logging:CentralLoggingBuckets", name, None, opts)

        region = aws.get_region()
        account = aws.get_caller_identity()
        resolved_region = (
            replication_region or settings.replication_region or "us-east-1"
        )
        if resolved_region == region.name:
            raise ValueError(
                "replication_region "
                f"'{resolved_region}' must differ from primary region "
                f"'{region.name}'."
            )
        replica_provider = aws.Provider(
            f"{name}-replica-provider",
            region=resolved_region,
            opts=pulumi.ResourceOptions(parent=self),
        )

        primary_bucket_name = central_logging_bucket_name(region.name)
        replica_bucket_name = f"{primary_bucket_name}-replication"
        if len(replica_bucket_name) > 63:
            raise ValueError(
                "Replica logging bucket name exceeds S3 63-character limit."
            )

        primary_import_id = (
            primary_bucket_name if _bucket_exists(primary_bucket_name) else None
        )
        replica_import_id = (
            replica_bucket_name
            if _bucket_exists(replica_bucket_name, provider=replica_provider)
            else None
        )
        primary_bucket_opts = (
            pulumi.ResourceOptions(parent=self, import_=primary_import_id)
            if primary_import_id
            else pulumi.ResourceOptions(parent=self)
        )
        primary_resource_opts = pulumi.ResourceOptions(parent=self)
        replica_bucket_opts = (
            pulumi.ResourceOptions(
                parent=self,
                provider=replica_provider,
                import_=replica_import_id,
            )
            if replica_import_id
            else pulumi.ResourceOptions(parent=self, provider=replica_provider)
        )
        replica_resource_opts = pulumi.ResourceOptions(
            parent=self, provider=replica_provider
        )

        bucket = aws.s3.Bucket(
            f"{name}-primary",
            bucket=primary_bucket_name,
            server_side_encryption_configuration=aws.s3.BucketServerSideEncryptionConfigurationArgs(
                rule=aws.s3.BucketServerSideEncryptionConfigurationRuleArgs(
                    apply_server_side_encryption_by_default=aws.s3.BucketServerSideEncryptionConfigurationRuleApplyServerSideEncryptionByDefaultArgs(
                        sse_algorithm="AES256"
                    )
                )
            ),
            tags=base_tags(
                {
                    "Purpose": "central-logging",
                    "LoggingExempt": "true",
                    "LoggingExemptReason": "Centralized S3 access log sink",
                }
            ),
            opts=primary_bucket_opts,
        )

        replica_bucket = aws.s3.Bucket(
            f"{name}-replica",
            bucket=replica_bucket_name,
            server_side_encryption_configuration=aws.s3.BucketServerSideEncryptionConfigurationArgs(
                rule=aws.s3.BucketServerSideEncryptionConfigurationRuleArgs(
                    apply_server_side_encryption_by_default=aws.s3.BucketServerSideEncryptionConfigurationRuleApplyServerSideEncryptionByDefaultArgs(
                        sse_algorithm="AES256"
                    )
                )
            ),
            tags=base_tags(
                {
                    "Purpose": "central-logging-replica",
                    "LoggingExempt": "true",
                    "LoggingExemptReason": "Centralized S3 access log sink replica",
                }
            ),
            opts=replica_bucket_opts,
        )

        aws.s3.BucketVersioning(
            f"{name}-primary-versioning",
            bucket=bucket.id,
            versioning_configuration=aws.s3.BucketVersioningVersioningConfigurationArgs(
                status="Enabled"
            ),
            opts=primary_resource_opts,
        )

        aws.s3.BucketVersioning(
            f"{name}-replica-versioning",
            bucket=replica_bucket.id,
            versioning_configuration=aws.s3.BucketVersioningVersioningConfigurationArgs(
                status="Enabled"
            ),
            opts=replica_resource_opts,
        )

        aws.s3.BucketLifecycleConfiguration(
            f"{name}-primary-lifecycle",
            bucket=bucket.id,
            rules=[
                aws.s3.BucketLifecycleConfigurationRuleArgs(
                    id="logs-lifecycle",
                    status="Enabled",
                    prefix="",
                    abort_incomplete_multipart_upload=aws.s3.BucketLifecycleConfigurationRuleAbortIncompleteMultipartUploadArgs(
                        days_after_initiation=7
                    ),
                    transitions=[
                        aws.s3.BucketLifecycleConfigurationRuleTransitionArgs(
                            days=30,
                            storage_class="STANDARD_IA",
                        )
                    ],
                    expiration=aws.s3.BucketLifecycleConfigurationRuleExpirationArgs(
                        days=365
                    ),
                )
            ],
            opts=primary_resource_opts,
        )

        aws.s3.BucketLifecycleConfiguration(
            f"{name}-replica-lifecycle",
            bucket=replica_bucket.id,
            rules=[
                # Keep the replica as the longer-lived DR copy; only incomplete
                # multipart uploads are cleaned up automatically here.
                aws.s3.BucketLifecycleConfigurationRuleArgs(
                    id="replica-lifecycle",
                    status="Enabled",
                    prefix="",
                    abort_incomplete_multipart_upload=aws.s3.BucketLifecycleConfigurationRuleAbortIncompleteMultipartUploadArgs(
                        days_after_initiation=7
                    ),
                )
            ],
            opts=replica_resource_opts,
        )

        aws.s3.BucketPublicAccessBlock(
            f"{name}-primary-pab",
            bucket=bucket.id,
            block_public_acls=True,
            block_public_policy=True,
            ignore_public_acls=True,
            restrict_public_buckets=True,
            opts=primary_resource_opts,
        )

        aws.s3.BucketPublicAccessBlock(
            f"{name}-replica-pab",
            bucket=replica_bucket.id,
            block_public_acls=True,
            block_public_policy=True,
            ignore_public_acls=True,
            restrict_public_buckets=True,
            opts=replica_resource_opts,
        )

        aws.s3.BucketPolicy(
            f"{name}-policy",
            bucket=bucket.id,
            policy=apply_output(
                cast(
                    pulumi.Output[Sequence[str]],
                    pulumi.Output.all(bucket.arn, account.account_id),
                ),
                _log_bucket_policy_from_values,
            ),
            opts=primary_resource_opts,
        )

        aws.s3.BucketPolicy(
            f"{name}-replica-policy",
            bucket=replica_bucket.id,
            policy=apply_output(
                cast(
                    pulumi.Output[Sequence[str]],
                    pulumi.Output.all(replica_bucket.arn, account.account_id),
                ),
                _log_bucket_policy_from_values,
            ),
            opts=replica_resource_opts,
        )

        replication_role = aws.iam.Role(
            f"{name}-replication-role",
            assume_role_policy=apply_output(
                bucket.arn, _replication_assume_role_policy
            ),
            tags=base_tags({"Purpose": "central-logs-replication"}),
            opts=primary_resource_opts,
        )

        replication_role_policy = aws.iam.RolePolicy(
            f"{name}-replication-role-policy",
            role=replication_role.id,
            policy=apply_output(
                cast(
                    pulumi.Output[Sequence[str]],
                    pulumi.Output.all(bucket.arn, replica_bucket.arn),
                ),
                _replication_role_policy,
            ),
            opts=primary_resource_opts,
        )

        aws.s3.BucketReplicationConfig(
            f"{name}-replication-config",
            bucket=bucket.id,
            role=replication_role.arn,
            rules=[
                aws.s3.BucketReplicationConfigRuleArgs(
                    id=f"central-logs-to-{resolved_region.replace('-', '')}",
                    status="Enabled",
                    destination=aws.s3.BucketReplicationConfigRuleDestinationArgs(
                        bucket=replica_bucket.arn,
                        storage_class="STANDARD",
                    ),
                )
            ],
            opts=pulumi.ResourceOptions(
                parent=self, depends_on=[replication_role_policy]
            ),
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
