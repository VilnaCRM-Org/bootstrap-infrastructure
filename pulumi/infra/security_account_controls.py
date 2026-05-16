"""Account-level security detection and configuration recording controls."""

from __future__ import annotations

import json
from collections.abc import Sequence

import pulumi_aws as aws

import pulumi

from .bootstrap_settings import BootstrapSettings
from .config import settings as default_settings
from .utils.tags import base_tags

AWS_CONFIG_SERVICE_PRINCIPAL = "config.amazonaws.com"
AWS_SOURCE_ACCOUNT_CONDITION_KEY = "aws:SourceAccount"
AWS_SOURCE_ARN_CONDITION_KEY = "aws:SourceArn"
CONFIG_RECORDER_MANAGED_POLICY = "service-role/AWS_ConfigRole"


def _environment_part(settings: BootstrapSettings) -> str:
    """Return a resource-name-safe environment segment."""
    return settings.sanitize_bucket_component(settings.environment, "environment")


def _config_bucket_name(
    settings: BootstrapSettings, account_id: str, region: str
) -> str:
    """Return the deterministic AWS Config delivery bucket name."""
    environment = _environment_part(settings).replace(".", "-")
    name = f"bootstrap-{account_id}-{region}-{environment}-aws-config"
    if len(name) > 63:
        raise ValueError("AWS Config bucket name exceeds S3 63-character limit.")
    return name


def _config_recorder_name(settings: BootstrapSettings) -> str:
    """Return the deterministic AWS Config recorder name."""
    return f"bootstrap-{_environment_part(settings)}-configuration-recorder"


def _config_delivery_channel_name(settings: BootstrapSettings) -> str:
    """Return the deterministic AWS Config delivery channel name."""
    return f"bootstrap-{_environment_part(settings)}-configuration-delivery"


def _config_role_name(settings: BootstrapSettings) -> str:
    """Return the deterministic AWS Config recorder role name."""
    name = f"aws-config-recorder-role-{_environment_part(settings)}"
    if len(name) > 64:
        raise ValueError("AWS Config recorder role name exceeds 64 characters.")
    return name


def _config_source_arn(account_id: str, partition: str, region: str) -> str:
    """Return the account and Region-scoped AWS Config source ARN pattern."""
    return f"arn:{partition}:config:{region}:{account_id}:*"


def _config_assume_role_policy(account_id: str, partition: str, region: str) -> str:
    """Allow AWS Config to assume the recorder role for this account and Region."""
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": AWS_CONFIG_SERVICE_PRINCIPAL},
                    "Action": "sts:AssumeRole",
                    "Condition": {
                        "StringEquals": {AWS_SOURCE_ACCOUNT_CONDITION_KEY: account_id},
                        "ArnLike": {
                            AWS_SOURCE_ARN_CONDITION_KEY: _config_source_arn(
                                account_id,
                                partition,
                                region,
                            )
                        },
                    },
                }
            ],
        },
        sort_keys=True,
    )


def _config_role_s3_policy(bucket_arn: str, account_id: str) -> str:
    """Allow the AWS Config recorder role to deliver snapshots to S3."""
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowConfigBucketLocationCheck",
                    "Effect": "Allow",
                    "Action": ["s3:ListBucket", "s3:GetBucketAcl"],
                    "Resource": bucket_arn,
                },
                {
                    "Sid": "AllowConfigBucketDelivery",
                    "Effect": "Allow",
                    "Action": ["s3:PutObject", "s3:PutObjectAcl"],
                    "Resource": f"{bucket_arn}/AWSLogs/{account_id}/Config/*",
                    "Condition": {
                        "StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}
                    },
                },
            ],
        },
        sort_keys=True,
    )


def _config_bucket_policy(
    bucket_arn: str,
    account_id: str,
    partition: str,
    region: str,
) -> str:
    """Allow AWS Config service delivery and require encrypted transport."""
    config_source_arn = _config_source_arn(account_id, partition, region)
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "RequireTLS",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "s3:*",
                    "Resource": [bucket_arn, f"{bucket_arn}/*"],
                    "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                },
                {
                    "Sid": "AWSConfigBucketPermissionsCheck",
                    "Effect": "Allow",
                    "Principal": {"Service": AWS_CONFIG_SERVICE_PRINCIPAL},
                    "Action": "s3:GetBucketAcl",
                    "Resource": bucket_arn,
                    "Condition": {
                        "StringEquals": {AWS_SOURCE_ACCOUNT_CONDITION_KEY: account_id},
                        "ArnLike": {AWS_SOURCE_ARN_CONDITION_KEY: config_source_arn},
                    },
                },
                {
                    "Sid": "AWSConfigBucketExistenceCheck",
                    "Effect": "Allow",
                    "Principal": {"Service": AWS_CONFIG_SERVICE_PRINCIPAL},
                    "Action": "s3:ListBucket",
                    "Resource": bucket_arn,
                    "Condition": {
                        "StringEquals": {AWS_SOURCE_ACCOUNT_CONDITION_KEY: account_id},
                        "ArnLike": {AWS_SOURCE_ARN_CONDITION_KEY: config_source_arn},
                    },
                },
                {
                    "Sid": "AWSConfigBucketDelivery",
                    "Effect": "Allow",
                    "Principal": {"Service": AWS_CONFIG_SERVICE_PRINCIPAL},
                    "Action": "s3:PutObject",
                    "Resource": f"{bucket_arn}/AWSLogs/{account_id}/Config/*",
                    "Condition": {
                        "StringEquals": {
                            "s3:x-amz-acl": "bucket-owner-full-control",
                            AWS_SOURCE_ACCOUNT_CONDITION_KEY: account_id,
                        },
                        "ArnLike": {AWS_SOURCE_ARN_CONDITION_KEY: config_source_arn},
                    },
                },
            ],
        },
        sort_keys=True,
    )


class SecurityAccountControls(pulumi.ComponentResource):
    """Provision account-local security detection and inventory controls."""

    def __init__(
        self,
        name: str,
        *,
        settings: BootstrapSettings | None = None,
        resource_dependencies: Sequence[pulumi.Resource] | None = None,
        opts: pulumi.ResourceOptions | None = None,
    ) -> None:
        """Initialize GuardDuty, Security Hub, and AWS Config resources."""
        super().__init__("bootstrap:security:AccountControls", name, None, opts)

        configured_settings = settings or default_settings
        account_id = aws.get_caller_identity().account_id
        partition = aws.get_partition().partition
        region = aws.get_region().name
        base_opts = pulumi.ResourceOptions(
            parent=self,
            depends_on=list(resource_dependencies or []),
        )

        self.guardduty_detector = aws.guardduty.Detector(
            f"{name}-guardduty-detector",
            enable=True,
            finding_publishing_frequency="FIFTEEN_MINUTES",
            tags=base_tags(
                {"Purpose": "security-detection"},
                settings=configured_settings,
            ),
            opts=base_opts,
        )
        self.security_hub_account = aws.securityhub.Account(
            f"{name}-security-hub",
            auto_enable_controls=True,
            control_finding_generator="SECURITY_CONTROL",
            enable_default_standards=True,
            opts=base_opts,
        )

        self.config_bucket = aws.s3.Bucket(
            f"{name}-config-bucket",
            bucket=_config_bucket_name(configured_settings, account_id, region),
            tags=base_tags(
                {
                    "Purpose": "aws-config-delivery",
                    "LoggingExempt": "true",
                    "LoggingExemptReason": "AWS Config delivery channel sink",
                },
                settings=configured_settings,
            ),
            opts=base_opts,
        )
        self.config_bucket_public_access = aws.s3.BucketPublicAccessBlock(
            f"{name}-config-bucket-pab",
            bucket=self.config_bucket.id,
            block_public_acls=True,
            block_public_policy=True,
            ignore_public_acls=True,
            restrict_public_buckets=True,
            opts=base_opts,
        )
        self.config_bucket_encryption = aws.s3.BucketServerSideEncryptionConfiguration(
            f"{name}-config-bucket-encryption",
            bucket=self.config_bucket.id,
            rules=[
                aws.s3.BucketServerSideEncryptionConfigurationRuleArgs(
                    blocked_encryption_types=["SSE-C"],
                    apply_server_side_encryption_by_default=aws.s3.BucketServerSideEncryptionConfigurationRuleApplyServerSideEncryptionByDefaultArgs(
                        sse_algorithm="AES256",
                    ),
                )
            ],
            opts=base_opts,
        )
        self.config_bucket_versioning = aws.s3.BucketVersioning(
            f"{name}-config-bucket-versioning",
            bucket=self.config_bucket.id,
            versioning_configuration=aws.s3.BucketVersioningVersioningConfigurationArgs(
                status="Enabled"
            ),
            opts=base_opts,
        )
        self.config_bucket_lifecycle = aws.s3.BucketLifecycleConfiguration(
            f"{name}-config-bucket-lifecycle",
            bucket=self.config_bucket.id,
            rules=[
                aws.s3.BucketLifecycleConfigurationRuleArgs(
                    id="aws-config-history",
                    status="Enabled",
                    abort_incomplete_multipart_upload=aws.s3.BucketLifecycleConfigurationRuleAbortIncompleteMultipartUploadArgs(
                        days_after_initiation=7
                    ),
                    expiration=aws.s3.BucketLifecycleConfigurationRuleExpirationArgs(
                        days=365
                    ),
                    noncurrent_version_expiration=aws.s3.BucketLifecycleConfigurationRuleNoncurrentVersionExpirationArgs(
                        noncurrent_days=90
                    ),
                )
            ],
            opts=base_opts,
        )

        self.config_role = aws.iam.Role(
            f"{name}-config-recorder-role",
            name=_config_role_name(configured_settings),
            assume_role_policy=_config_assume_role_policy(
                account_id,
                partition,
                region,
            ),
            tags=base_tags(
                {"Purpose": "aws-config-recorder"},
                settings=configured_settings,
            ),
            opts=base_opts,
        )
        self.config_role_attachment = aws.iam.RolePolicyAttachment(
            f"{name}-config-recorder-role-attachment",
            role=self.config_role.name,
            policy_arn=f"arn:{partition}:iam::aws:policy/{CONFIG_RECORDER_MANAGED_POLICY}",
            opts=base_opts,
        )
        self.config_role_s3_policy = aws.iam.RolePolicy(
            f"{name}-config-recorder-s3-policy",
            role=self.config_role.name,
            policy=self.config_bucket.arn.apply(
                lambda bucket_arn: _config_role_s3_policy(bucket_arn, account_id)
            ),
            opts=pulumi.ResourceOptions(
                parent=self,
                depends_on=[
                    self.config_bucket_public_access,
                    self.config_bucket_encryption,
                    self.config_bucket_versioning,
                    self.config_bucket_lifecycle,
                ],
            ),
        )
        self.config_bucket_policy = aws.s3.BucketPolicy(
            f"{name}-config-bucket-policy",
            bucket=self.config_bucket.id,
            policy=self.config_bucket.arn.apply(
                lambda bucket_arn: _config_bucket_policy(
                    bucket_arn,
                    account_id,
                    partition,
                    region,
                )
            ),
            opts=pulumi.ResourceOptions(
                parent=self,
                depends_on=[
                    self.config_bucket_public_access,
                    self.config_bucket_encryption,
                    self.config_bucket_versioning,
                    self.config_bucket_lifecycle,
                ],
            ),
        )

        self.config_recorder = aws.cfg.Recorder(
            f"{name}-configuration-recorder",
            name=_config_recorder_name(configured_settings),
            role_arn=self.config_role.arn,
            recording_group=aws.cfg.RecorderRecordingGroupArgs(
                all_supported=True,
                include_global_resource_types=True,
            ),
            recording_mode=aws.cfg.RecorderRecordingModeArgs(
                recording_frequency="DAILY"
            ),
            opts=pulumi.ResourceOptions(
                parent=self,
                depends_on=[
                    self.config_role_attachment,
                    self.config_role_s3_policy,
                ],
            ),
        )
        self.config_delivery_channel = aws.cfg.DeliveryChannel(
            f"{name}-configuration-delivery-channel",
            name=_config_delivery_channel_name(configured_settings),
            s3_bucket_name=self.config_bucket.bucket,
            snapshot_delivery_properties=aws.cfg.DeliveryChannelSnapshotDeliveryPropertiesArgs(
                delivery_frequency="TwentyFour_Hours"
            ),
            opts=pulumi.ResourceOptions(
                parent=self,
                depends_on=[
                    self.config_bucket_policy,
                    self.config_recorder,
                ],
            ),
        )
        self.config_recorder_status = aws.cfg.RecorderStatus(
            f"{name}-configuration-recorder-status",
            name=self.config_recorder.name,
            is_enabled=True,
            opts=pulumi.ResourceOptions(
                parent=self,
                depends_on=[self.config_delivery_channel],
            ),
        )

        self.register_outputs(
            {
                "guardduty_detector_id": self.guardduty_detector.id,
                "security_hub_account_arn": self.security_hub_account.arn,
                "config_bucket_name": self.config_bucket.bucket,
                "config_recorder_name": self.config_recorder.name,
                "config_delivery_channel_name": self.config_delivery_channel.name,
            }
        )
