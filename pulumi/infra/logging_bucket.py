"""Central logging bucket infrastructure for the platform."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from typing import cast

import pulumi_aws as aws

import pulumi

from .bootstrap_settings import BootstrapSettings
from .config import settings
from .platform_iam import platform_boundary_arn, platform_role_name
from .utils.outputs import apply_output
from .utils.tags import base_tags

DEFAULT_REPLICATION_REGION = "eu-west-1"


def central_logging_bucket_name(region: str) -> str:
    """Compatibility wrapper for central logging bucket naming."""
    return settings.central_logging_bucket_name(region)


def _resolved_replication_region(
    replication_region: str | None,
    *,
    settings_obj: BootstrapSettings,
    primary_region: str,
) -> str:
    """Resolve and validate the replica region for centralized logging."""
    resolved_region = (
        replication_region
        or settings_obj.replication_region
        or DEFAULT_REPLICATION_REGION
    )
    if resolved_region == primary_region:
        raise ValueError(
            "replication_region "
            f"'{resolved_region}' must differ from primary region "
            f"'{primary_region}'."
        )
    return resolved_region


def _primary_bucket_name(settings_obj: BootstrapSettings, region_name: str) -> str:
    """Resolve the primary logging bucket name for the active settings source."""
    if settings_obj is globals()["settings"]:
        return central_logging_bucket_name(region_name)
    return settings_obj.central_logging_bucket_name(region_name)


def _replica_bucket_name(primary_bucket_name: str, replication_region: str) -> str:
    """Build the replica logging bucket name while enforcing S3 limits."""
    suffix = f"-{replication_region}-replication"
    max_prefix_length = 63 - len(suffix)
    if len(primary_bucket_name) <= max_prefix_length:
        return f"{primary_bucket_name}{suffix}"
    digest = hashlib.sha256(primary_bucket_name.encode("utf-8")).hexdigest()[:8]
    truncated_length = max(max_prefix_length - len(digest) - 1, 1)
    return f"{primary_bucket_name[:truncated_length]}-{digest}{suffix}"


def _import_id_if_bucket_exists(
    name: str, *, provider: aws.Provider | None = None
) -> str | None:
    """Return the import ID when the S3 bucket already exists."""
    return name if _bucket_exists(name, provider=provider) else None


def _resource_options(
    parent: pulumi.Resource,
    *,
    provider: aws.Provider | None = None,
    import_id: str | None = None,
) -> pulumi.ResourceOptions:
    """Build consistent resource options for logging-bucket resources."""
    kwargs: dict[str, object] = {"parent": parent}
    if provider is not None:
        kwargs["provider"] = provider
    if import_id is not None:
        kwargs["import_"] = import_id
    return pulumi.ResourceOptions(**kwargs)


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


def _replication_assume_role_policy(arn: str, account_id: str) -> str:
    """Build the S3 replication trust policy for the logging bucket."""
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "s3.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                    "Condition": {
                        "StringEquals": {
                            "aws:SourceArn": arn,
                            "aws:SourceAccount": account_id,
                        }
                    },
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
        settings: BootstrapSettings | None = None,
        replication_region: str | None = None,
        manage_replication_role: bool = True,
        opts: pulumi.ResourceOptions | None = None,
    ) -> None:
        """Initialize the central logging buckets component."""
        super().__init__("bootstrap:logging:CentralLoggingBuckets", name, None, opts)

        configured_settings = settings or globals()["settings"]
        region = aws.get_region()
        account = aws.get_caller_identity()
        resolved_region = _resolved_replication_region(
            replication_region,
            settings_obj=configured_settings,
            primary_region=region.region,
        )
        replica_provider = aws.Provider(
            f"{name}-replica-provider",
            region=resolved_region,
            opts=pulumi.ResourceOptions(parent=self),
        )

        primary_bucket_name = _primary_bucket_name(configured_settings, region.region)
        replica_bucket_name = _replica_bucket_name(primary_bucket_name, resolved_region)

        primary_bucket_opts = _resource_options(
            self,
            import_id=_import_id_if_bucket_exists(primary_bucket_name),
        )
        primary_resource_opts = _resource_options(self)
        replica_bucket_opts = _resource_options(
            self,
            provider=replica_provider,
            import_id=_import_id_if_bucket_exists(
                replica_bucket_name,
                provider=replica_provider,
            ),
        )
        replica_resource_opts = _resource_options(self, provider=replica_provider)

        bucket = aws.s3.Bucket(
            f"{name}-primary",
            bucket=primary_bucket_name,
            tags=base_tags(
                {
                    "Purpose": "central-logging",
                    "LoggingExempt": "true",
                    "LoggingExemptReason": "Centralized S3 access log sink",
                },
                settings=configured_settings,
            ),
            opts=primary_bucket_opts,
        )

        replica_bucket = aws.s3.Bucket(
            f"{name}-replica",
            bucket=replica_bucket_name,
            tags=base_tags(
                {
                    "Purpose": "central-logging-replica",
                    "LoggingExempt": "true",
                    "LoggingExemptReason": "Centralized S3 access log sink replica",
                },
                settings=configured_settings,
            ),
            opts=replica_bucket_opts,
        )

        aws.s3.BucketServerSideEncryptionConfiguration(
            f"{name}-primary-encryption",
            bucket=bucket.id,
            rules=[
                aws.s3.BucketServerSideEncryptionConfigurationRuleArgs(
                    blocked_encryption_types=["SSE-C"],
                    bucket_key_enabled=False,
                    apply_server_side_encryption_by_default=aws.s3.BucketServerSideEncryptionConfigurationRuleApplyServerSideEncryptionByDefaultArgs(
                        sse_algorithm="AES256"
                    ),
                )
            ],
            opts=primary_resource_opts,
        )

        aws.s3.BucketServerSideEncryptionConfiguration(
            f"{name}-replica-encryption",
            bucket=replica_bucket.id,
            rules=[
                aws.s3.BucketServerSideEncryptionConfigurationRuleArgs(
                    blocked_encryption_types=["SSE-C"],
                    bucket_key_enabled=False,
                    apply_server_side_encryption_by_default=aws.s3.BucketServerSideEncryptionConfigurationRuleApplyServerSideEncryptionByDefaultArgs(
                        sse_algorithm="AES256"
                    ),
                )
            ],
            opts=replica_resource_opts,
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

        if manage_replication_role:
            replication_role = aws.iam.Role(
                f"{name}-replication-role",
                name=platform_role_name(configured_settings, "log-replication"),
                permissions_boundary=platform_boundary_arn(
                    account.account_id,
                    configured_settings,
                    "log-replication",
                    partition=aws.get_partition().partition,
                ),
                assume_role_policy=apply_output(
                    bucket.arn,
                    lambda arn: _replication_assume_role_policy(
                        arn, account.account_id
                    ),
                ),
                tags=base_tags(
                    {"Purpose": "central-logs-replication"},
                    settings=configured_settings,
                ),
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

        else:
            replication_role = aws.iam.Role.get(
                f"{name}-replication-role",
                platform_role_name(configured_settings, "log-replication"),
                opts=primary_resource_opts,
            )
            replication_role_policy = None

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
                parent=self,
                depends_on=(
                    [replication_role_policy] if replication_role_policy else []
                ),
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
