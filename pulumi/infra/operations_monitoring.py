"""Operations alerting resources for bootstrap infrastructure control planes."""

from __future__ import annotations

import json
from collections.abc import Sequence

import pulumi_aws as aws
from pulumi_aws.cloudtrail.trail import Trail, TrailEventSelectorArgs

import pulumi

from .bootstrap_settings import BootstrapSettings
from .config import settings as default_settings
from .utils.tags import base_tags

CLOUDTRAIL_API_CALL_DETAIL_TYPE = "AWS API Call via CloudTrail"
CLOUDTRAIL_SERVICE_PRINCIPAL = "cloudtrail.amazonaws.com"
AWS_SOURCE_ACCOUNT_CONDITION_KEY = "aws:SourceAccount"
AWS_SOURCE_ARN_CONDITION_KEY = "aws:SourceArn"
KMS_DECRYPT_ACTION = "kms:Decrypt"
KMS_GENERATE_DATA_KEY_ACTION = "kms:GenerateDataKey*"
KMS_SNS_TOPIC_ACTIONS = (KMS_DECRYPT_ACTION, KMS_GENERATE_DATA_KEY_ACTION)
SNS_PUBLISH_ACTION = "sns:Publish"
SNS_TOPIC_OWNER_ACTIONS = (
    "sns:AddPermission",
    "sns:DeleteTopic",
    "sns:GetTopicAttributes",
    "sns:ListSubscriptionsByTopic",
    SNS_PUBLISH_ACTION,
    "sns:RemovePermission",
    "sns:SetTopicAttributes",
    "sns:Subscribe",
)


def _budget_source_arn(account_id: str, partition: str) -> str:
    """Return the account-scoped AWS Budgets source ARN pattern."""
    return f"arn:{partition}:budgets::{account_id}:*"


def _environment_part(settings: BootstrapSettings) -> str:
    """Return a resource-name-safe environment segment."""
    return settings.sanitize_bucket_component(settings.environment, "environment")


def _topic_name(settings: BootstrapSettings) -> str:
    """Return the deterministic operations SNS topic name."""
    environment = _environment_part(settings).replace(".", "-")
    return f"bootstrap-{environment}-operations"


def _topic_key_alias_name(settings: BootstrapSettings) -> str:
    """Return the deterministic KMS alias for the operations alert topic."""
    environment = _environment_part(settings).replace(".", "-")
    return f"alias/bootstrap-{environment}-operations-alerting"


def _cloudtrail_key_alias_name(settings: BootstrapSettings) -> str:
    """Return the deterministic KMS alias for CloudTrail log encryption."""
    environment = _environment_part(settings).replace(".", "-")
    return f"alias/bootstrap-{environment}-operations-cloudtrail"


def _queue_name(settings: BootstrapSettings) -> str:
    """Return the deterministic operations alert queue name."""
    environment = _environment_part(settings).replace(".", "-")
    return f"bootstrap-{environment}-operations-alerts"


def _cloudtrail_bucket_name(
    settings: BootstrapSettings, account_id: str, region: str
) -> str:
    """Return the deterministic management-event log bucket name."""
    environment = _environment_part(settings).replace(".", "-")
    name = f"bootstrap-{account_id}-{region}-{environment}-cloudtrail"
    if len(name) > 63:
        raise ValueError("CloudTrail bucket name exceeds S3 63-character limit.")
    return name


def _trail_name(settings: BootstrapSettings) -> str:
    """Return the deterministic account-management CloudTrail name."""
    return f"bootstrap-{_environment_part(settings)}-management-events"


def _rule_name(settings: BootstrapSettings, suffix: str) -> str:
    """Return an EventBridge rule name within the 64-character limit."""
    name = f"bootstrap-{_environment_part(settings)}-{suffix}"
    if len(name) > 64:
        raise ValueError(f"EventBridge rule name '{name}' exceeds 64 characters.")
    return name


def _topic_policy(topic_arn: str, account_id: str, partition: str) -> str:
    """Allow EventBridge to publish operational events to the alert topic."""
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowAccountTopicAdministration",
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:{partition}:iam::{account_id}:root"},
                    "Action": list(SNS_TOPIC_OWNER_ACTIONS),
                    "Resource": topic_arn,
                },
                {
                    "Sid": "AllowEventBridgePublish",
                    "Effect": "Allow",
                    "Principal": {"Service": "events.amazonaws.com"},
                    "Action": SNS_PUBLISH_ACTION,
                    "Resource": topic_arn,
                    "Condition": {
                        "StringEquals": {AWS_SOURCE_ACCOUNT_CONDITION_KEY: account_id},
                    },
                },
                {
                    "Sid": "AllowBudgetsPublish",
                    "Effect": "Allow",
                    "Principal": {"Service": "budgets.amazonaws.com"},
                    "Action": SNS_PUBLISH_ACTION,
                    "Resource": topic_arn,
                    "Condition": {
                        "StringEquals": {AWS_SOURCE_ACCOUNT_CONDITION_KEY: account_id},
                        "ArnLike": {
                            AWS_SOURCE_ARN_CONDITION_KEY: _budget_source_arn(
                                account_id,
                                partition,
                            )
                        },
                    },
                },
                {
                    "Sid": "AllowCostAnomalyPublish",
                    "Effect": "Allow",
                    "Principal": {"Service": "costalerts.amazonaws.com"},
                    "Action": SNS_PUBLISH_ACTION,
                    "Resource": topic_arn,
                    "Condition": {
                        "StringEquals": {AWS_SOURCE_ACCOUNT_CONDITION_KEY: account_id},
                    },
                },
            ],
        },
        sort_keys=True,
    )


def _queue_policy(queue_arn: str, topic_arn: str, account_id: str) -> str:
    """Allow only the account-local operations topic to send queue messages."""
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowOperationsTopicSendMessage",
                    "Effect": "Allow",
                    "Principal": {"Service": "sns.amazonaws.com"},
                    "Action": "sqs:SendMessage",
                    "Resource": queue_arn,
                    "Condition": {
                        "ArnEquals": {AWS_SOURCE_ARN_CONDITION_KEY: topic_arn},
                        "StringEquals": {AWS_SOURCE_ACCOUNT_CONDITION_KEY: account_id},
                    },
                },
            ],
        },
        sort_keys=True,
    )


def _topic_key_policy(account_id: str, partition: str) -> str:
    """Allow account administration and EventBridge publishing to encrypted SNS."""
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "EnableAccountPermissions",
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:{partition}:iam::{account_id}:root"},
                    "Action": "kms:*",
                    "Resource": "*",
                },
                {
                    "Sid": "AllowEventBridgeForEncryptedSns",
                    "Effect": "Allow",
                    "Principal": {"Service": "events.amazonaws.com"},
                    "Action": list(KMS_SNS_TOPIC_ACTIONS),
                    # EventBridge-to-encrypted-SNS KMS grants cannot rely on
                    # source-account/source-ARN conditions; the SNS topic
                    # policy constrains the publisher account instead.
                    "Resource": "*",
                },
                {
                    "Sid": "AllowBudgetsForEncryptedSns",
                    "Effect": "Allow",
                    "Principal": {"Service": "budgets.amazonaws.com"},
                    "Action": list(KMS_SNS_TOPIC_ACTIONS),
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {AWS_SOURCE_ACCOUNT_CONDITION_KEY: account_id},
                        "ArnLike": {
                            AWS_SOURCE_ARN_CONDITION_KEY: _budget_source_arn(
                                account_id,
                                partition,
                            )
                        },
                    },
                },
                {
                    "Sid": "AllowCostAnomalyForEncryptedSns",
                    "Effect": "Allow",
                    "Principal": {"Service": "costalerts.amazonaws.com"},
                    "Action": list(KMS_SNS_TOPIC_ACTIONS),
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {AWS_SOURCE_ACCOUNT_CONDITION_KEY: account_id},
                    },
                },
            ],
        },
        sort_keys=True,
    )


def _cloudtrail_api_event_pattern(
    *,
    source: str,
    event_source: str,
    event_names: Sequence[str],
) -> dict[str, object]:
    """Return a CloudTrail-backed EventBridge pattern."""
    return {
        "source": [source],
        "detail-type": [CLOUDTRAIL_API_CALL_DETAIL_TYPE],
        "detail": {
            "eventSource": [event_source],
            "eventName": list(event_names),
        },
    }


def _event_patterns() -> dict[str, dict[str, object]]:
    """Return EventBridge patterns for high-severity bootstrap events."""
    # Suffixes are reused as EventBridge target IDs, so keep them within the
    # 64-character alphanumeric, underscore, and hyphen constraint.
    return {
        "backup-failed": {
            "source": ["aws.backup"],
            "detail-type": [
                "Backup Job State Change",
                "Copy Job State Change",
                "Restore Job State Change",
            ],
            "detail": {"state": ["FAILED", "ABORTED", "EXPIRED"]},
        },
        "kms-risk": _cloudtrail_api_event_pattern(
            source="aws.kms",
            event_source="kms.amazonaws.com",
            event_names=[
                "CancelKeyDeletion",
                "DisableKey",
                "DisableKeyRotation",
                "PutKeyPolicy",
                "ScheduleKeyDeletion",
            ],
        ),
        "iam-oidc-risk": _cloudtrail_api_event_pattern(
            source="aws.iam",
            event_source="iam.amazonaws.com",
            event_names=[
                "CreateOpenIDConnectProvider",
                "DeleteOpenIDConnectProvider",
                "DeleteRolePolicy",
                "DetachRolePolicy",
                "PutRolePolicy",
                "UpdateAssumeRolePolicy",
                "UpdateOpenIDConnectProviderThumbprint",
            ],
        ),
        "s3-control-plane-risk": _cloudtrail_api_event_pattern(
            source="aws.s3",
            event_source="s3.amazonaws.com",
            event_names=[
                "DeleteBucketEncryption",
                "DeleteBucketPolicy",
                "DeleteBucketReplication",
                "PutBucketEncryption",
                "PutBucketLogging",
                "PutBucketPolicy",
                "PutBucketReplication",
            ],
        ),
    }


def _cloudtrail_bucket_policy(
    bucket_arn: str,
    account_id: str,
    partition: str,
    region: str,
    settings: BootstrapSettings,
) -> str:
    """Allow CloudTrail to write management events to the operations log bucket."""
    trail_arn = (
        f"arn:{partition}:cloudtrail:{region}:{account_id}:trail/"
        f"{_trail_name(settings)}"
    )
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
                    "Sid": "AllowCloudTrailAclCheck",
                    "Effect": "Allow",
                    "Principal": {"Service": CLOUDTRAIL_SERVICE_PRINCIPAL},
                    "Action": "s3:GetBucketAcl",
                    "Resource": bucket_arn,
                    "Condition": {
                        "StringEquals": {AWS_SOURCE_ACCOUNT_CONDITION_KEY: account_id},
                        "ArnLike": {AWS_SOURCE_ARN_CONDITION_KEY: trail_arn},
                    },
                },
                {
                    "Sid": "AllowCloudTrailPutObject",
                    "Effect": "Allow",
                    "Principal": {"Service": CLOUDTRAIL_SERVICE_PRINCIPAL},
                    "Action": "s3:PutObject",
                    "Resource": f"{bucket_arn}/AWSLogs/{account_id}/*",
                    "Condition": {
                        "StringEquals": {
                            "s3:x-amz-acl": "bucket-owner-full-control",
                            AWS_SOURCE_ACCOUNT_CONDITION_KEY: account_id,
                        },
                        "ArnLike": {AWS_SOURCE_ARN_CONDITION_KEY: trail_arn},
                    },
                },
            ],
        },
        sort_keys=True,
    )


def _cloudtrail_key_policy(
    account_id: str,
    partition: str,
    region: str,
    settings: BootstrapSettings,
) -> str:
    """Allow CloudTrail to encrypt management-event logs with a scoped KMS key."""
    trail_arn = (
        f"arn:{partition}:cloudtrail:{region}:{account_id}:trail/"
        f"{_trail_name(settings)}"
    )
    trail_encryption_context = (
        f"arn:{partition}:cloudtrail:*:{account_id}:trail/{_trail_name(settings)}"
    )
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "EnableAccountPermissions",
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:{partition}:iam::{account_id}:root"},
                    "Action": "kms:*",
                    "Resource": "*",
                },
                {
                    "Sid": "AllowCloudTrailDescribeKey",
                    "Effect": "Allow",
                    "Principal": {"Service": CLOUDTRAIL_SERVICE_PRINCIPAL},
                    "Action": "kms:DescribeKey",
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {AWS_SOURCE_ARN_CONDITION_KEY: trail_arn}
                    },
                },
                {
                    "Sid": "AllowCloudTrailEncryptLogs",
                    "Effect": "Allow",
                    "Principal": {"Service": CLOUDTRAIL_SERVICE_PRINCIPAL},
                    "Action": "kms:GenerateDataKey*",
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {AWS_SOURCE_ARN_CONDITION_KEY: trail_arn},
                        "StringLike": {
                            "kms:EncryptionContext:aws:cloudtrail:arn": (
                                trail_encryption_context
                            )
                        },
                    },
                },
            ],
        },
        sort_keys=True,
    )


class OperationsMonitoring(pulumi.ComponentResource):
    """Create EventBridge-to-SNS alerting for critical bootstrap events."""

    def __init__(
        self,
        name: str,
        *,
        settings: BootstrapSettings | None = None,
        opts: pulumi.ResourceOptions | None = None,
    ) -> None:
        """Initialize operational monitoring resources."""
        super().__init__("bootstrap:ops:OperationsMonitoring", name, None, opts)

        configured_settings = settings or default_settings
        base_opts = pulumi.ResourceOptions(parent=self)
        account_id = aws.get_caller_identity().account_id
        partition = aws.get_partition().partition
        region = aws.get_region().region
        trail: Trail | None = None
        trail_bucket: aws.s3.Bucket | None = None
        trail_key: aws.kms.Key | None = None
        trail_key_alias: aws.kms.Alias | None = None
        trail_dependencies: list[pulumi.Resource] = []
        if configured_settings.operations_cloudtrail_name:
            cloudtrail_name = pulumi.Output.from_input(
                configured_settings.operations_cloudtrail_name
            )
            cloudtrail_bucket_name = pulumi.Output.from_input(None)
            cloudtrail_key_alias_name = pulumi.Output.from_input(None)
        else:
            trail_key = aws.kms.Key(
                f"{name}-cloudtrail-key",
                description=(
                    "KMS key for bootstrap CloudTrail management events "
                    f"({_trail_name(configured_settings)})"
                ),
                deletion_window_in_days=30,
                enable_key_rotation=True,
                policy=_cloudtrail_key_policy(
                    account_id,
                    partition,
                    region,
                    configured_settings,
                ),
                tags=base_tags(
                    {"Purpose": "operations-cloudtrail"},
                    settings=configured_settings,
                ),
                opts=base_opts,
            )
            trail_key_alias = aws.kms.Alias(
                f"{name}-cloudtrail-key-alias",
                name=_cloudtrail_key_alias_name(configured_settings),
                target_key_id=trail_key.key_id,
                opts=base_opts,
            )
            trail_bucket = aws.s3.Bucket(
                f"{name}-cloudtrail-bucket",
                bucket=_cloudtrail_bucket_name(configured_settings, account_id, region),
                tags=base_tags(
                    {
                        "Purpose": "operations-cloudtrail",
                        "LoggingExempt": "true",
                        "LoggingExemptReason": "CloudTrail management event sink",
                    },
                    settings=configured_settings,
                ),
                opts=base_opts,
            )
            trail_bucket_public_access = aws.s3.BucketPublicAccessBlock(
                f"{name}-cloudtrail-bucket-pab",
                bucket=trail_bucket.id,
                block_public_acls=True,
                block_public_policy=True,
                ignore_public_acls=True,
                restrict_public_buckets=True,
                opts=base_opts,
            )
            trail_bucket_encryption = aws.s3.BucketServerSideEncryptionConfiguration(
                f"{name}-cloudtrail-bucket-encryption",
                bucket=trail_bucket.id,
                rules=[
                    aws.s3.BucketServerSideEncryptionConfigurationRuleArgs(
                        apply_server_side_encryption_by_default=aws.s3.BucketServerSideEncryptionConfigurationRuleApplyServerSideEncryptionByDefaultArgs(
                            kms_master_key_id=trail_key.arn,
                            sse_algorithm="aws:kms",
                        )
                    )
                ],
                opts=base_opts,
            )
            trail_bucket_versioning = aws.s3.BucketVersioning(
                f"{name}-cloudtrail-bucket-versioning",
                bucket=trail_bucket.id,
                versioning_configuration=aws.s3.BucketVersioningVersioningConfigurationArgs(
                    status="Enabled"
                ),
                opts=base_opts,
            )
            trail_bucket_lifecycle = aws.s3.BucketLifecycleConfiguration(
                f"{name}-cloudtrail-bucket-lifecycle",
                bucket=trail_bucket.id,
                rules=[
                    aws.s3.BucketLifecycleConfigurationRuleArgs(
                        id="cloudtrail-management-events",
                        status="Enabled",
                        abort_incomplete_multipart_upload=aws.s3.BucketLifecycleConfigurationRuleAbortIncompleteMultipartUploadArgs(
                            days_after_initiation=7
                        ),
                        expiration=aws.s3.BucketLifecycleConfigurationRuleExpirationArgs(
                            days=365
                        ),
                    )
                ],
                opts=base_opts,
            )
            trail_bucket_policy = aws.s3.BucketPolicy(
                f"{name}-cloudtrail-bucket-policy",
                bucket=trail_bucket.id,
                policy=trail_bucket.arn.apply(
                    lambda arn: _cloudtrail_bucket_policy(
                        arn,
                        account_id,
                        partition,
                        region,
                        configured_settings,
                    )
                ),
                opts=pulumi.ResourceOptions(
                    parent=self,
                    depends_on=[
                        trail_bucket_public_access,
                        trail_bucket_encryption,
                        trail_bucket_versioning,
                        trail_bucket_lifecycle,
                    ],
                ),
            )
            trail = Trail(
                f"{name}-cloudtrail",
                name=_trail_name(configured_settings),
                enable_log_file_validation=True,
                include_global_service_events=True,
                is_multi_region_trail=True,
                kms_key_id=trail_key.arn,
                s3_bucket_name=trail_bucket.id,
                event_selectors=[
                    TrailEventSelectorArgs(
                        include_management_events=True,
                        read_write_type="All",
                    )
                ],
                tags=base_tags(
                    {"Purpose": "operations-cloudtrail"},
                    settings=configured_settings,
                ),
                opts=pulumi.ResourceOptions(
                    parent=self, depends_on=[trail_bucket_policy]
                ),
            )
            cloudtrail_name = trail.name
            cloudtrail_bucket_name = trail_bucket.bucket
            cloudtrail_key_alias_name = trail_key_alias.name
            trail_dependencies = [trail]
        self.cloudtrail_key = trail_key
        self.cloudtrail_key_alias = trail_key_alias
        topic_key = aws.kms.Key(
            f"{name}-topic-key",
            description=(
                "KMS key for bootstrap operations alert SNS topic "
                f"({_topic_name(configured_settings)})"
            ),
            deletion_window_in_days=30,
            enable_key_rotation=True,
            policy=_topic_key_policy(account_id, partition),
            tags=base_tags(
                {"Purpose": "operations-alerting"},
                settings=configured_settings,
            ),
            opts=base_opts,
        )
        topic_key_alias = aws.kms.Alias(
            f"{name}-topic-key-alias",
            name=_topic_key_alias_name(configured_settings),
            target_key_id=topic_key.key_id,
            opts=base_opts,
        )
        topic = aws.sns.Topic(
            f"{name}-topic",
            name=_topic_name(configured_settings),
            kms_master_key_id=topic_key.arn,
            tags=base_tags(
                {"Purpose": "operations-alerting"},
                settings=configured_settings,
            ),
            opts=base_opts,
        )
        self.topic_key = topic_key
        self.topic_key_alias = topic_key_alias
        topic_policy = aws.sns.TopicPolicy(
            f"{name}-topic-policy",
            arn=topic.arn,
            policy=topic.arn.apply(
                lambda arn: _topic_policy(arn, account_id, partition)
            ),
            opts=base_opts,
        )

        self.topic = topic
        self.topic_policy = topic_policy
        self.cloudtrail_bucket = trail_bucket
        self.cloudtrail = trail
        self.cloudtrail_bucket_name = cloudtrail_bucket_name
        self.cloudtrail_key_alias_name = cloudtrail_key_alias_name
        self.cloudtrail_name = cloudtrail_name
        alert_queue = aws.sqs.Queue(
            f"{name}-alert-queue",
            name=_queue_name(configured_settings),
            sqs_managed_sse_enabled=True,
            tags=base_tags(
                {"Purpose": "operations-alerting"},
                settings=configured_settings,
            ),
            opts=base_opts,
        )
        alert_queue_policy = aws.sqs.QueuePolicy(
            f"{name}-alert-queue-policy",
            queue_url=alert_queue.url,
            policy=pulumi.Output.all(alert_queue.arn, topic.arn).apply(
                lambda values: _queue_policy(values[0], values[1], account_id)
            ),
            opts=base_opts,
        )
        alert_queue_subscription = aws.sns.TopicSubscription(
            f"{name}-alert-queue-subscription",
            topic=topic.arn,
            protocol="sqs",
            endpoint=alert_queue.arn,
            opts=pulumi.ResourceOptions(
                parent=self,
                depends_on=[alert_queue_policy],
            ),
        )
        self.alert_queue = alert_queue
        self.alert_queue_policy = alert_queue_policy
        self.alert_queue_subscription = alert_queue_subscription
        self.rules: dict[str, aws.cloudwatch.EventRule] = {}
        for suffix, pattern in _event_patterns().items():
            rule = aws.cloudwatch.EventRule(
                f"{name}-{suffix}-rule",
                name=_rule_name(configured_settings, suffix),
                description=f"Bootstrap infrastructure {suffix} alert.",
                event_pattern=json.dumps(pattern, sort_keys=True),
                tags=base_tags(
                    {"Purpose": "operations-alerting", "AlertType": suffix},
                    settings=configured_settings,
                ),
                opts=base_opts,
            )
            aws.cloudwatch.EventTarget(
                f"{name}-{suffix}-target",
                rule=rule.name,
                arn=topic.arn,
                target_id=f"{suffix}-sns",
                opts=pulumi.ResourceOptions(parent=self, depends_on=trail_dependencies),
            )
            self.rules[suffix] = rule

        self.register_outputs(
            {
                "cloudtrail_bucket_name": cloudtrail_bucket_name,
                "cloudtrail_key_alias_name": cloudtrail_key_alias_name,
                "cloudtrail_name": cloudtrail_name,
                "topic_arn": topic.arn,
                "topic_key_arn": topic_key.arn,
                "topic_key_alias_name": topic_key_alias.name,
                "alert_queue_arn": alert_queue.arn,
                "alert_queue_url": alert_queue.url,
                "alert_queue_name": alert_queue.name,
                "alert_queue_subscription_arn": alert_queue_subscription.arn,
                "rule_names": {
                    suffix: rule.name for suffix, rule in self.rules.items()
                },
            }
        )
