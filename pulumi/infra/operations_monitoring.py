"""Operations alerting resources for bootstrap infrastructure control planes."""

from __future__ import annotations

import json
from collections.abc import Sequence

import pulumi_aws as aws

import pulumi

from .bootstrap_settings import BootstrapSettings
from .config import settings as default_settings
from .utils.tags import base_tags

CLOUDTRAIL_API_CALL_DETAIL_TYPE = "AWS API Call via CloudTrail"
SNS_TOPIC_OWNER_ACTIONS = (
    "sns:AddPermission",
    "sns:DeleteTopic",
    "sns:GetTopicAttributes",
    "sns:ListSubscriptionsByTopic",
    "sns:Publish",
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
    return f"bootstrap-{_environment_part(settings)}-operations"


def _topic_key_alias_name(settings: BootstrapSettings) -> str:
    """Return the deterministic KMS alias for the operations alert topic."""
    environment = _environment_part(settings).replace(".", "-")
    return f"alias/bootstrap-{environment}-operations-alerting"


def _queue_name(settings: BootstrapSettings) -> str:
    """Return the deterministic operations alert queue name."""
    environment = _environment_part(settings).replace(".", "-")
    return f"bootstrap-{environment}-operations-alerts"


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
                    "Action": "sns:Publish",
                    "Resource": topic_arn,
                    "Condition": {
                        "StringEquals": {"aws:SourceAccount": account_id},
                    },
                },
                {
                    "Sid": "AllowBudgetsPublish",
                    "Effect": "Allow",
                    "Principal": {"Service": "budgets.amazonaws.com"},
                    "Action": "sns:Publish",
                    "Resource": topic_arn,
                    "Condition": {
                        "StringEquals": {"aws:SourceAccount": account_id},
                        "ArnLike": {
                            "aws:SourceArn": _budget_source_arn(
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
                    "Action": "sns:Publish",
                    "Resource": topic_arn,
                    "Condition": {
                        "StringEquals": {"aws:SourceAccount": account_id},
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
                        "ArnEquals": {"aws:SourceArn": topic_arn},
                        "StringEquals": {"aws:SourceAccount": account_id},
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
                    "Action": ["kms:Decrypt", "kms:GenerateDataKey*"],
                    # EventBridge-to-encrypted-SNS KMS grants cannot rely on
                    # aws:SourceAccount/aws:SourceArn conditions; the SNS topic
                    # policy constrains the publisher account instead.
                    "Resource": "*",
                },
                {
                    "Sid": "AllowBudgetsForEncryptedSns",
                    "Effect": "Allow",
                    "Principal": {"Service": "budgets.amazonaws.com"},
                    "Action": ["kms:Decrypt", "kms:GenerateDataKey*"],
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {"aws:SourceAccount": account_id},
                        "ArnLike": {
                            "aws:SourceArn": _budget_source_arn(
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
                    "Action": ["kms:Decrypt", "kms:GenerateDataKey*"],
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {"aws:SourceAccount": account_id},
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
                opts=base_opts,
            )
            self.rules[suffix] = rule

        self.register_outputs(
            {
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
