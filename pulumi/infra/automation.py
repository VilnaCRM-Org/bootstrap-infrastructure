"""GitHub automation role and ECR runner repository for bootstrap operations."""

from __future__ import annotations

import json

import pulumi_aws as aws

import pulumi

from .bootstrap_settings import BootstrapSettings
from .config import settings as default_settings
from .utils.outputs import apply_output
from .utils.tags import base_tags

AWS_REQUEST_TAG_ENVIRONMENT_KEY = "aws:RequestTag/Environment"
AWS_REQUEST_TAG_PURPOSE_KEY = "aws:RequestTag/Purpose"
AWS_RESOURCE_TAG_ENVIRONMENT_KEY = "aws:ResourceTag/Environment"
AWS_RESOURCE_TAG_PURPOSE_KEY = "aws:ResourceTag/Purpose"
IAM_CUSTOMER_MANAGED_POLICY_MAX_BYTES = 6_144

_AUTOMATION_MANAGED_POLICY_GROUPS: tuple[tuple[str, frozenset[str]], ...] = (
    (
        "policy",
        frozenset(
            {
                "ReadIdentity",
                "ManageBootstrapS3",
                "CreateBootstrapKmsKeys",
                "ListBootstrapKmsAliases",
                "ManageBootstrapKmsAliases",
                "ManageBootstrapKmsKeys",
            }
        ),
    ),
    (
        "iam-policy",
        frozenset(
            {
                "ManageBootstrapIam",
                "CreateBootstrapOidcProvider",
                "ListBootstrapOidcProviders",
                "PassBootstrapRolesToBackup",
                "PassBootstrapRolesToConfig",
                "ManageBootstrapBackup",
                "ManageBootstrapEcr",
            }
        ),
    ),
    (
        "operations-policy",
        frozenset(
            {
                "ManageBootstrapEventBridge",
                "ManageBootstrapCloudTrail",
                "ManageBootstrapSns",
                "ManageBootstrapSnsSubscriptions",
                "ManageBootstrapSqs",
            }
        ),
    ),
    (
        "cost-policy",
        frozenset(
            {
                "ManageBootstrapBudgets",
                "CreateBudgetServiceLinkedRole",
                "ReadBillingViewDataForBudgets",
                "CreateBootstrapCostAnomalyMonitor",
                "CreateBootstrapCostAnomalySubscription",
                "ManageBootstrapCostAnomalyMonitors",
                "ManageBootstrapCostAnomalySubscriptions",
                "ManageBootstrapCostAllocationTags",
            }
        ),
    ),
    (
        "security-policy",
        frozenset(
            {
                "CreateSecurityServiceLinkedRoles",
                "ReadGuardDutyDetectors",
                "CreateBootstrapGuardDutyDetector",
                "ManageBootstrapGuardDutyDetector",
                "ManageSecurityHubAccount",
                "ManageAwsConfigRecorder",
                "ManageAwsConfigDeliveryChannel",
            }
        ),
    ),
)

_AUTOMATION_S3_ACTIONS = (
    "s3:CreateBucket",
    "s3:DeleteBucket",
    "s3:DeleteBucketPolicy",
    "s3:GetBucketAcl",
    "s3:GetBucketCORS",
    "s3:GetBucketLocation",
    "s3:GetBucketLogging",
    "s3:GetBucketObjectLockConfiguration",
    "s3:GetBucketOwnershipControls",
    "s3:GetBucketPolicy",
    "s3:GetBucketPolicyStatus",
    "s3:GetBucketPublicAccessBlock",
    "s3:GetBucketRequestPayment",
    "s3:GetBucketTagging",
    "s3:GetBucketVersioning",
    "s3:GetBucketWebsite",
    "s3:GetEncryptionConfiguration",
    "s3:GetLifecycleConfiguration",
    "s3:GetReplicationConfiguration",
    "s3:ListBucket",
    "s3:PutBucketAcl",
    "s3:PutBucketCORS",
    "s3:PutBucketLogging",
    "s3:PutBucketObjectLockConfiguration",
    "s3:PutBucketOwnershipControls",
    "s3:PutBucketPolicy",
    "s3:PutBucketPublicAccessBlock",
    "s3:PutBucketRequestPayment",
    "s3:PutBucketTagging",
    "s3:PutBucketVersioning",
    "s3:PutBucketWebsite",
    "s3:PutEncryptionConfiguration",
    "s3:PutLifecycleConfiguration",
    "s3:PutReplicationConfiguration",
)
_AUTOMATION_KMS_ACTIONS = (
    "kms:CancelKeyDeletion",
    "kms:CreateAlias",
    "kms:CreateGrant",
    "kms:CreateKey",
    "kms:DeleteAlias",
    "kms:DescribeKey",
    "kms:DisableKey",
    "kms:EnableKey",
    "kms:EnableKeyRotation",
    "kms:GetKeyPolicy",
    "kms:GetKeyRotationStatus",
    "kms:ListAliases",
    "kms:ListGrants",
    "kms:ListResourceTags",
    "kms:PutKeyPolicy",
    "kms:RetireGrant",
    "kms:RevokeGrant",
    "kms:ScheduleKeyDeletion",
    "kms:TagResource",
    "kms:UntagResource",
    "kms:UpdateAlias",
    "kms:UpdateKeyDescription",
)
_AUTOMATION_BACKUP_ACTIONS = (
    "backup:CreateBackupPlan",
    "backup:CreateBackupSelection",
    "backup:CreateBackupVault",
    "backup:DeleteBackupPlan",
    "backup:DeleteBackupSelection",
    "backup:DeleteBackupVault",
    "backup:DescribeBackupVault",
    "backup:GetBackupPlan",
    "backup:GetBackupSelection",
    "backup:ListBackupSelections",
    "backup:ListTags",
    "backup:TagResource",
    "backup:UntagResource",
    "backup:UpdateBackupPlan",
)
_AUTOMATION_ECR_ACTIONS = (
    "ecr:CreateRepository",
    "ecr:DeleteLifecyclePolicy",
    "ecr:DeleteRepository",
    "ecr:DescribeRepositories",
    "ecr:GetLifecyclePolicy",
    "ecr:ListTagsForResource",
    "ecr:PutImageScanningConfiguration",
    "ecr:PutImageTagMutability",
    "ecr:PutLifecyclePolicy",
    "ecr:TagResource",
    "ecr:UntagResource",
)
_AUTOMATION_EVENTS_ACTIONS = (
    "events:DeleteRule",
    "events:DescribeRule",
    "events:DisableRule",
    "events:EnableRule",
    "events:ListTagsForResource",
    "events:ListTargetsByRule",
    "events:PutRule",
    "events:PutTargets",
    "events:RemoveTargets",
    "events:TagResource",
    "events:UntagResource",
)
_AUTOMATION_CLOUDTRAIL_ACTIONS = (
    "cloudtrail:AddTags",
    "cloudtrail:CreateTrail",
    "cloudtrail:DeleteTrail",
    "cloudtrail:GetEventSelectors",
    "cloudtrail:GetTrail",
    "cloudtrail:GetTrailStatus",
    "cloudtrail:ListTags",
    "cloudtrail:PutEventSelectors",
    "cloudtrail:RemoveTags",
    "cloudtrail:StartLogging",
    "cloudtrail:StopLogging",
    "cloudtrail:UpdateTrail",
)
_AUTOMATION_SNS_ACTIONS = (
    "sns:CreateTopic",
    "sns:DeleteTopic",
    "sns:GetTopicAttributes",
    "sns:ListSubscriptionsByTopic",
    "sns:ListTagsForResource",
    "sns:SetTopicAttributes",
    "sns:Subscribe",
    "sns:TagResource",
    "sns:UntagResource",
)
_AUTOMATION_SNS_SUBSCRIPTION_ACTIONS = (
    "sns:GetSubscriptionAttributes",
    "sns:Unsubscribe",
)
_AUTOMATION_SQS_ACTIONS = (
    "sqs:CreateQueue",
    "sqs:DeleteQueue",
    "sqs:GetQueueAttributes",
    "sqs:GetQueueUrl",
    "sqs:ListQueueTags",
    "sqs:SetQueueAttributes",
    "sqs:TagQueue",
    "sqs:UntagQueue",
)
_AUTOMATION_BUDGETS_ACTIONS = (
    "budgets:ModifyBudget",
    "budgets:DescribeBudget",
    "budgets:ViewBudget",
    "budgets:ListTagsForResource",
    "budgets:TagResource",
    "budgets:UntagResource",
)
_AUTOMATION_COST_EXPLORER_MONITOR_CREATE_ACTIONS = ("ce:CreateAnomalyMonitor",)
_AUTOMATION_COST_EXPLORER_SUBSCRIPTION_CREATE_ACTIONS = (
    "ce:CreateAnomalySubscription",
)
_AUTOMATION_COST_EXPLORER_MONITOR_RESOURCE_ACTIONS = (
    "ce:DeleteAnomalyMonitor",
    "ce:GetAnomalyMonitors",
    "ce:ListTagsForResource",
    "ce:TagResource",
    "ce:UntagResource",
    "ce:UpdateAnomalyMonitor",
)
_AUTOMATION_COST_EXPLORER_SUBSCRIPTION_RESOURCE_ACTIONS = (
    "ce:DeleteAnomalySubscription",
    "ce:GetAnomalySubscriptions",
    "ce:ListTagsForResource",
    "ce:TagResource",
    "ce:UntagResource",
    "ce:UpdateAnomalySubscription",
)
_AUTOMATION_COST_ALLOCATION_TAG_ACTIONS = (
    "ce:ListCostAllocationTags",
    "ce:UpdateCostAllocationTagsStatus",
)
_AUTOMATION_BILLING_ACTIONS = ("billing:GetBillingViewData",)
_AUTOMATION_GUARDDUTY_CREATE_ACTIONS = ("guardduty:CreateDetector",)
_AUTOMATION_GUARDDUTY_RESOURCE_ACTIONS = (
    "guardduty:DeleteDetector",
    "guardduty:GetDetector",
    "guardduty:TagResource",
    "guardduty:UntagResource",
    "guardduty:UpdateDetector",
)
_AUTOMATION_GUARDDUTY_READ_ACTIONS = ("guardduty:ListDetectors",)
_AUTOMATION_SECURITY_HUB_ACTIONS = (
    "securityhub:DescribeHub",
    "securityhub:DisableSecurityHub",
    "securityhub:EnableSecurityHub",
    "securityhub:GetEnabledStandards",
    "securityhub:UpdateSecurityHubConfiguration",
)
_AUTOMATION_AWS_CONFIG_RECORDER_ACTIONS = (
    "config:DeleteConfigurationRecorder",
    "config:DescribeConfigurationRecorders",
    "config:DescribeConfigurationRecorderStatus",
    "config:ListTagsForResource",
    "config:PutConfigurationRecorder",
    "config:StartConfigurationRecorder",
    "config:StopConfigurationRecorder",
    "config:TagResource",
    "config:UntagResource",
)
_AUTOMATION_AWS_CONFIG_DELIVERY_CHANNEL_ACTIONS = (
    "config:DeleteDeliveryChannel",
    "config:DescribeDeliveryChannels",
    "config:PutDeliveryChannel",
)
_AUTOMATION_SECURITY_SERVICE_LINKED_ROLE_SERVICES = (
    "guardduty.amazonaws.com",
    "securityhub.amazonaws.com",
)


def _environment_resource_part(settings: BootstrapSettings) -> str:
    """Return the environment as it appears in resource names."""
    return settings.sanitize_bucket_component(settings.environment, "environment")


def _sns_environment_resource_part(settings: BootstrapSettings) -> str:
    """Return the environment segment as it appears in SNS resource names."""
    return _environment_resource_part(settings).replace(".", "-")


def _ecr_repository_exists(name: str) -> bool:
    """Return True when the ECR repository already exists."""
    try:
        aws.ecr.get_repository(name=name)
    except Exception as exc:
        message = str(exc)
        if (
            "RepositoryNotFoundException" in message
            or "RepositoryNotFound" in message
            or "not found" in message.lower()
            or "couldn't find resource" in message
        ):
            return False
        raise
    return True


def _iam_role_exists(name: str) -> bool:
    """Return True when the IAM role already exists."""
    try:
        aws.iam.get_role(name=name)
    except Exception as exc:
        message = str(exc)
        if (
            "NoSuchEntity" in message
            or "NoSuchEntityException" in message
            or "not found" in message.lower()
            or "couldn't find resource" in message
        ):
            return False
        raise
    return True


def _resource_options(
    parent: pulumi.Resource,
    *,
    import_id: str | None = None,
) -> pulumi.ResourceOptions:
    """Build consistent resource options for automation resources."""
    kwargs: dict[str, object] = {"parent": parent}
    if import_id is not None:
        kwargs["import_"] = import_id
    return pulumi.ResourceOptions(**kwargs)


def _automation_s3_resources(settings: BootstrapSettings) -> list[str]:
    """Scope bootstrap S3 management to state and central logging buckets."""
    environment = _environment_resource_part(settings)
    logging_prefix = settings.sanitize_bucket_component(
        settings.logging_prefix,
        "loggingPrefix",
    )
    bucket_names = (
        f"pulumi-*-{environment}-state",
        f"pulumi-*-{environment}-state-*-replication",
        f"{logging_prefix}-central-logs-*-{environment}",
        f"{logging_prefix}-central-logs-*-{environment}-*-replication",
        f"bootstrap-*-{environment}-cloudtrail",
        f"bootstrap-*-{environment}-aws-config",
    )
    return [f"arn:aws:s3:::{bucket_name}" for bucket_name in bucket_names]


def _automation_kms_alias_resources(
    account_id: str, settings: BootstrapSettings
) -> list[str]:
    """Scope KMS alias management to Pulumi secrets aliases for this environment."""
    environment = _environment_resource_part(settings).replace(".", "-")
    return [
        f"arn:aws:kms:*:{account_id}:alias/pulumi-*-{environment}-secrets",
        f"arn:aws:kms:*:{account_id}:alias/bootstrap-{environment}-operations-alerting",
        f"arn:aws:kms:*:{account_id}:alias/bootstrap-{environment}-operations-cloudtrail",
    ]


def _automation_kms_key_resources(account_id: str) -> list[str]:
    """Scope KMS key management to keys tagged by the bootstrap stack."""
    return [f"arn:aws:kms:*:{account_id}:key/*"]


def _automation_ecr_resources(
    account_id: str, settings: BootstrapSettings, repo_name: str
) -> list[str]:
    """Scope ECR management to this repository's runner image repository."""
    repository_name = settings.runner_ecr_repository_name(repo_name)
    return [f"arn:aws:ecr:*:{account_id}:repository/{repository_name}"]


def _automation_iam_role_resources(
    account_id: str, settings: BootstrapSettings, repo_name: str
) -> list[str]:
    """Scope IAM management to deterministic bootstrap role families."""
    automation_role_name = settings.automation_role_name(repo_name)
    return [
        f"arn:aws:iam::{account_id}:role/{automation_role_name}",
        f"arn:aws:iam::{account_id}:role/PulumiDeploy-*",
        f"arn:aws:iam::{account_id}:role/PulumiStateRepl-*",
        f"arn:aws:iam::{account_id}:role/central-logging-replication-role-*",
        f"arn:aws:iam::{account_id}:role/s3-backup-role-*",
        f"arn:aws:iam::{account_id}:role/aws-config-recorder-role-*",
    ]


def _automation_backup_resources(account_id: str) -> list[str]:
    """Scope Backup management to account-local AWS Backup resource families."""
    return [
        f"arn:aws:backup:*:{account_id}:backup-plan:*",
        f"arn:aws:backup:*:{account_id}:backup-selection:*",
        f"arn:aws:backup:*:{account_id}:backup-vault:*",
        f"arn:aws:backup:*:{account_id}:recovery-point:*",
    ]


def _automation_eventbridge_resources(
    account_id: str, settings: BootstrapSettings
) -> list[str]:
    """Scope EventBridge management to bootstrap operations rules."""
    environment = _environment_resource_part(settings)
    return [f"arn:aws:events:*:{account_id}:rule/bootstrap-{environment}-*"]


def _automation_cloudtrail_resources(
    account_id: str, settings: BootstrapSettings
) -> list[str]:
    """Scope CloudTrail management to bootstrap operations trails."""
    environment = _environment_resource_part(settings)
    return [
        f"arn:aws:cloudtrail:*:{account_id}:trail/"
        f"bootstrap-{environment}-management-events"
    ]


def _automation_sns_resources(
    account_id: str, settings: BootstrapSettings
) -> list[str]:
    """Scope SNS management to the bootstrap operations alert topic."""
    environment = _sns_environment_resource_part(settings)
    return [f"arn:aws:sns:*:{account_id}:bootstrap-{environment}-operations"]


def _automation_sns_subscription_resources(
    account_id: str, settings: BootstrapSettings
) -> list[str]:
    """Scope SNS subscription management to operations alert subscriptions."""
    environment = _sns_environment_resource_part(settings)
    return [f"arn:aws:sns:*:{account_id}:bootstrap-{environment}-operations:*"]


def _automation_sqs_resources(
    account_id: str, settings: BootstrapSettings
) -> list[str]:
    """Scope SQS management to the bootstrap operations alert queue."""
    environment = _environment_resource_part(settings).replace(".", "-")
    return [f"arn:aws:sqs:*:{account_id}:bootstrap-{environment}-operations-alerts"]


def _automation_budget_resources(
    account_id: str, settings: BootstrapSettings
) -> list[str]:
    """Scope Budgets management to deterministic bootstrap budgets."""
    environment = _environment_resource_part(settings)
    return [f"arn:aws:budgets::{account_id}:budget/bootstrap-{environment}-*"]


def _automation_cost_explorer_monitor_resources(account_id: str) -> list[str]:
    """Scope Cost Explorer management to anomaly monitor resources."""
    return [f"arn:aws:ce::{account_id}:anomalymonitor/*"]


def _automation_cost_explorer_subscription_resources(account_id: str) -> list[str]:
    """Scope Cost Explorer management to anomaly subscription resources."""
    return [f"arn:aws:ce::{account_id}:anomalysubscription/*"]


def _automation_budget_service_linked_role_resource(account_id: str) -> str:
    """Return the exact AWS Budgets service-linked role ARN."""
    return (
        f"arn:aws:iam::{account_id}:role/aws-service-role/"
        "budgets.amazonaws.com/AWSServiceRoleForBudgets"
    )


def _automation_security_service_linked_role_resources(account_id: str) -> list[str]:
    """Return service-linked role ARNs for account security services."""
    return [f"arn:aws:iam::{account_id}:role/aws-service-role/*"]


def _automation_guardduty_resources(account_id: str) -> list[str]:
    """Scope GuardDuty management to account-local detectors."""
    return [f"arn:aws:guardduty:*:{account_id}:detector/*"]


def _automation_security_hub_resources(account_id: str) -> list[str]:
    """Scope Security Hub account management to the default account hub."""
    return [f"arn:aws:securityhub:*:{account_id}:hub/default"]


def _automation_aws_config_recorder_resources(
    account_id: str, settings: BootstrapSettings
) -> list[str]:
    """Scope AWS Config recorder management to the bootstrap recorder name."""
    environment = _environment_resource_part(settings)
    return [
        "arn:aws:config:*:"
        f"{account_id}:configuration-recorder/"
        f"bootstrap-{environment}-configuration-recorder/*"
    ]


def _automation_assume_role_policy(
    oidc_provider_arn: str, org: str, repo_name: str, environment: str
) -> str:
    """Build the GitHub OIDC trust policy for environment-scoped automation."""
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Federated": oidc_provider_arn},
                    "Action": "sts:AssumeRoleWithWebIdentity",
                    "Condition": {
                        "StringEquals": {
                            "token.actions.githubusercontent.com:aud": (
                                "sts.amazonaws.com"
                            ),
                            "token.actions.githubusercontent.com:sub": (
                                f"repo:{org}/{repo_name}:environment:{environment}"
                            ),
                        }
                    },
                }
            ],
        }
    )


def _automation_policy(
    account_id: str, settings: BootstrapSettings, repo_name: str
) -> str:
    """Return the policy used by GitHub automation for bootstrap operations."""
    oidc_provider_arn = (
        f"arn:aws:iam::{account_id}:oidc-provider/token.actions.githubusercontent.com"
    )
    iam_role_resources = _automation_iam_role_resources(account_id, settings, repo_name)
    kms_purposes = ["pulumi-secrets", "operations-alerting", "operations-cloudtrail"]
    kms_tag_condition = {
        "StringEquals": {
            AWS_RESOURCE_TAG_ENVIRONMENT_KEY: settings.environment,
            AWS_RESOURCE_TAG_PURPOSE_KEY: kms_purposes,
        }
    }
    kms_request_tag_condition = {
        "StringEquals": {
            AWS_REQUEST_TAG_ENVIRONMENT_KEY: settings.environment,
            AWS_REQUEST_TAG_PURPOSE_KEY: kms_purposes,
        }
    }
    kms_alias_condition = {
        "StringEqualsIfExists": {
            AWS_RESOURCE_TAG_ENVIRONMENT_KEY: settings.environment,
            AWS_RESOURCE_TAG_PURPOSE_KEY: kms_purposes,
        }
    }
    cost_explorer_monitor_request_tag_condition = {
        "StringEquals": {
            AWS_REQUEST_TAG_ENVIRONMENT_KEY: settings.environment,
            AWS_REQUEST_TAG_PURPOSE_KEY: "cost-anomaly-monitor",
        }
    }
    cost_explorer_subscription_request_tag_condition = {
        "StringEquals": {
            AWS_REQUEST_TAG_ENVIRONMENT_KEY: settings.environment,
            AWS_REQUEST_TAG_PURPOSE_KEY: "cost-anomaly-subscription",
        }
    }
    cost_explorer_monitor_resource_tag_condition = {
        "StringEquals": {
            AWS_RESOURCE_TAG_ENVIRONMENT_KEY: settings.environment,
            AWS_RESOURCE_TAG_PURPOSE_KEY: "cost-anomaly-monitor",
        }
    }
    cost_explorer_subscription_resource_tag_condition = {
        "StringEquals": {
            AWS_RESOURCE_TAG_ENVIRONMENT_KEY: settings.environment,
            AWS_RESOURCE_TAG_PURPOSE_KEY: "cost-anomaly-subscription",
        }
    }
    guardduty_request_tag_condition = {
        "StringEquals": {
            AWS_REQUEST_TAG_ENVIRONMENT_KEY: settings.environment,
            AWS_REQUEST_TAG_PURPOSE_KEY: "security-detection",
        }
    }
    guardduty_resource_tag_condition = {
        "StringEquals": {
            AWS_RESOURCE_TAG_ENVIRONMENT_KEY: settings.environment,
            AWS_RESOURCE_TAG_PURPOSE_KEY: "security-detection",
        }
    }
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "ReadIdentity",
                    "Effect": "Allow",
                    "Action": ["sts:GetCallerIdentity"],
                    "Resource": "*",
                },
                {
                    "Sid": "ManageBootstrapS3",
                    "Effect": "Allow",
                    "Action": list(_AUTOMATION_S3_ACTIONS),
                    "Resource": _automation_s3_resources(settings),
                },
                {
                    "Sid": "CreateBootstrapKmsKeys",
                    "Effect": "Allow",
                    "Action": ["kms:CreateKey"],
                    "Resource": "*",
                    "Condition": kms_request_tag_condition,
                },
                {
                    "Sid": "ListBootstrapKmsAliases",
                    "Effect": "Allow",
                    "Action": ["kms:ListAliases"],
                    "Resource": "*",
                },
                {
                    "Sid": "ManageBootstrapKmsAliases",
                    "Effect": "Allow",
                    "Action": [
                        "kms:CreateAlias",
                        "kms:DeleteAlias",
                        "kms:UpdateAlias",
                    ],
                    "Resource": [
                        *_automation_kms_alias_resources(account_id, settings),
                        *_automation_kms_key_resources(account_id),
                    ],
                    "Condition": kms_alias_condition,
                },
                {
                    "Sid": "ManageBootstrapKmsKeys",
                    "Effect": "Allow",
                    "Action": [
                        action
                        for action in _AUTOMATION_KMS_ACTIONS
                        if action
                        not in {
                            "kms:CreateAlias",
                            "kms:CreateKey",
                            "kms:DeleteAlias",
                            "kms:ListAliases",
                            "kms:UpdateAlias",
                        }
                    ],
                    "Resource": _automation_kms_key_resources(account_id),
                    "Condition": kms_tag_condition,
                },
                {
                    "Sid": "ManageBootstrapIam",
                    "Effect": "Allow",
                    "Action": [
                        "iam:AttachRolePolicy",
                        "iam:CreateRole",
                        "iam:DeleteOpenIDConnectProvider",
                        "iam:DeleteRole",
                        "iam:DeleteRolePolicy",
                        "iam:DetachRolePolicy",
                        "iam:GetOpenIDConnectProvider",
                        "iam:GetRole",
                        "iam:GetRolePolicy",
                        "iam:ListAttachedRolePolicies",
                        "iam:ListRolePolicies",
                        "iam:ListRoleTags",
                        "iam:PutRolePolicy",
                        "iam:TagOpenIDConnectProvider",
                        "iam:TagRole",
                        "iam:UntagOpenIDConnectProvider",
                        "iam:UntagRole",
                        "iam:UpdateAssumeRolePolicy",
                        "iam:UpdateOpenIDConnectProviderThumbprint",
                    ],
                    "Resource": [*iam_role_resources, oidc_provider_arn],
                },
                {
                    "Sid": "CreateBootstrapOidcProvider",
                    "Effect": "Allow",
                    "Action": ["iam:CreateOpenIDConnectProvider"],
                    "Resource": "*",
                },
                {
                    "Sid": "ListBootstrapOidcProviders",
                    "Effect": "Allow",
                    "Action": ["iam:ListOpenIDConnectProviders"],
                    "Resource": "*",
                },
                {
                    "Sid": "PassBootstrapRolesToBackup",
                    "Effect": "Allow",
                    "Action": ["iam:PassRole"],
                    "Resource": [f"arn:aws:iam::{account_id}:role/s3-backup-role-*"],
                    "Condition": {
                        "StringEquals": {"iam:PassedToService": "backup.amazonaws.com"}
                    },
                },
                {
                    "Sid": "PassBootstrapRolesToConfig",
                    "Effect": "Allow",
                    "Action": ["iam:PassRole"],
                    "Resource": [
                        f"arn:aws:iam::{account_id}:role/aws-config-recorder-role-*"
                    ],
                    "Condition": {
                        "StringEquals": {"iam:PassedToService": "config.amazonaws.com"}
                    },
                },
                {
                    "Sid": "ManageBootstrapBackup",
                    "Effect": "Allow",
                    "Action": list(_AUTOMATION_BACKUP_ACTIONS),
                    "Resource": _automation_backup_resources(account_id),
                },
                {
                    "Sid": "ManageBootstrapEcr",
                    "Effect": "Allow",
                    "Action": list(_AUTOMATION_ECR_ACTIONS),
                    "Resource": _automation_ecr_resources(
                        account_id, settings, repo_name
                    ),
                },
                {
                    "Sid": "ManageBootstrapEventBridge",
                    "Effect": "Allow",
                    "Action": list(_AUTOMATION_EVENTS_ACTIONS),
                    "Resource": _automation_eventbridge_resources(account_id, settings),
                },
                {
                    "Sid": "ManageBootstrapCloudTrail",
                    "Effect": "Allow",
                    "Action": list(_AUTOMATION_CLOUDTRAIL_ACTIONS),
                    "Resource": _automation_cloudtrail_resources(account_id, settings),
                },
                {
                    "Sid": "ManageBootstrapSns",
                    "Effect": "Allow",
                    "Action": list(_AUTOMATION_SNS_ACTIONS),
                    "Resource": _automation_sns_resources(account_id, settings),
                },
                {
                    "Sid": "ManageBootstrapSnsSubscriptions",
                    "Effect": "Allow",
                    "Action": list(_AUTOMATION_SNS_SUBSCRIPTION_ACTIONS),
                    "Resource": _automation_sns_subscription_resources(
                        account_id,
                        settings,
                    ),
                },
                {
                    "Sid": "ManageBootstrapSqs",
                    "Effect": "Allow",
                    "Action": list(_AUTOMATION_SQS_ACTIONS),
                    "Resource": _automation_sqs_resources(account_id, settings),
                },
                {
                    "Sid": "ManageBootstrapBudgets",
                    "Effect": "Allow",
                    "Action": list(_AUTOMATION_BUDGETS_ACTIONS),
                    "Resource": _automation_budget_resources(account_id, settings),
                },
                {
                    "Sid": "CreateBudgetServiceLinkedRole",
                    "Effect": "Allow",
                    "Action": ["iam:CreateServiceLinkedRole"],
                    "Resource": _automation_budget_service_linked_role_resource(
                        account_id
                    ),
                    "Condition": {
                        "StringEquals": {"iam:AWSServiceName": "budgets.amazonaws.com"}
                    },
                },
                {
                    "Sid": "CreateSecurityServiceLinkedRoles",
                    "Effect": "Allow",
                    "Action": ["iam:CreateServiceLinkedRole"],
                    "Resource": _automation_security_service_linked_role_resources(
                        account_id
                    ),
                    "Condition": {
                        "StringEquals": {
                            "iam:AWSServiceName": list(
                                _AUTOMATION_SECURITY_SERVICE_LINKED_ROLE_SERVICES
                            )
                        }
                    },
                },
                {
                    "Sid": "ReadBillingViewDataForBudgets",
                    "Effect": "Allow",
                    "Action": list(_AUTOMATION_BILLING_ACTIONS),
                    "Resource": "*",
                },
                {
                    "Sid": "CreateBootstrapCostAnomalyMonitor",
                    "Effect": "Allow",
                    "Action": list(_AUTOMATION_COST_EXPLORER_MONITOR_CREATE_ACTIONS),
                    "Resource": "*",
                    "Condition": cost_explorer_monitor_request_tag_condition,
                },
                {
                    "Sid": "CreateBootstrapCostAnomalySubscription",
                    "Effect": "Allow",
                    "Action": list(
                        _AUTOMATION_COST_EXPLORER_SUBSCRIPTION_CREATE_ACTIONS
                    ),
                    "Resource": "*",
                    "Condition": cost_explorer_subscription_request_tag_condition,
                },
                {
                    "Sid": "ManageBootstrapCostAnomalyMonitors",
                    "Effect": "Allow",
                    "Action": list(_AUTOMATION_COST_EXPLORER_MONITOR_RESOURCE_ACTIONS),
                    "Resource": _automation_cost_explorer_monitor_resources(account_id),
                    "Condition": cost_explorer_monitor_resource_tag_condition,
                },
                {
                    "Sid": "ManageBootstrapCostAnomalySubscriptions",
                    "Effect": "Allow",
                    "Action": list(
                        _AUTOMATION_COST_EXPLORER_SUBSCRIPTION_RESOURCE_ACTIONS
                    ),
                    "Resource": _automation_cost_explorer_subscription_resources(
                        account_id
                    ),
                    "Condition": cost_explorer_subscription_resource_tag_condition,
                },
                {
                    "Sid": "ReadGuardDutyDetectors",
                    "Effect": "Allow",
                    "Action": list(_AUTOMATION_GUARDDUTY_READ_ACTIONS),
                    "Resource": "*",
                },
                {
                    "Sid": "CreateBootstrapGuardDutyDetector",
                    "Effect": "Allow",
                    "Action": list(_AUTOMATION_GUARDDUTY_CREATE_ACTIONS),
                    "Resource": "*",
                    "Condition": guardduty_request_tag_condition,
                },
                {
                    "Sid": "ManageBootstrapGuardDutyDetector",
                    "Effect": "Allow",
                    "Action": list(_AUTOMATION_GUARDDUTY_RESOURCE_ACTIONS),
                    "Resource": _automation_guardduty_resources(account_id),
                    "Condition": guardduty_resource_tag_condition,
                },
                {
                    "Sid": "ManageSecurityHubAccount",
                    "Effect": "Allow",
                    "Action": list(_AUTOMATION_SECURITY_HUB_ACTIONS),
                    "Resource": _automation_security_hub_resources(account_id),
                },
                {
                    "Sid": "ManageAwsConfigRecorder",
                    "Effect": "Allow",
                    "Action": list(_AUTOMATION_AWS_CONFIG_RECORDER_ACTIONS),
                    "Resource": _automation_aws_config_recorder_resources(
                        account_id, settings
                    ),
                },
                {
                    "Sid": "ManageAwsConfigDeliveryChannel",
                    "Effect": "Allow",
                    "Action": list(_AUTOMATION_AWS_CONFIG_DELIVERY_CHANNEL_ACTIONS),
                    "Resource": "*",
                },
                *(
                    [
                        {
                            "Sid": "ManageBootstrapCostAllocationTags",
                            "Effect": "Allow",
                            "Action": list(_AUTOMATION_COST_ALLOCATION_TAG_ACTIONS),
                            "Resource": "*",
                        }
                    ]
                    if settings.manage_cost_allocation_tags
                    else []
                ),
            ],
        }
    )


def _compact_policy_document(statements: list[dict[str, object]]) -> str:
    """Return a compact IAM policy document for inline policy size limits."""
    return json.dumps(
        {"Version": "2012-10-17", "Statement": statements},
        separators=(",", ":"),
    )


def _automation_policy_documents(
    account_id: str, settings: BootstrapSettings, repo_name: str
) -> list[tuple[str, str]]:
    """Split automation permissions into customer-managed policies."""
    policy = json.loads(_automation_policy(account_id, settings, repo_name))
    statements_by_sid = {
        statement["Sid"]: statement for statement in policy["Statement"]
    }

    covered_sids = set().union(
        *(policy_sids for _name, policy_sids in _AUTOMATION_MANAGED_POLICY_GROUPS)
    )
    uncovered_sids = sorted(set(statements_by_sid) - covered_sids)
    if uncovered_sids:
        raise ValueError(
            "automation policy statements are missing a managed-policy group: "
            + ", ".join(uncovered_sids)
        )

    documents: list[tuple[str, str]] = []
    for policy_suffix, policy_sids in _AUTOMATION_MANAGED_POLICY_GROUPS:
        statements = [
            statement
            for statement in policy["Statement"]
            if statement["Sid"] in policy_sids
        ]
        if statements:
            documents.append((policy_suffix, _compact_policy_document(statements)))

    oversized = [
        name
        for name, document in documents
        if len(document.encode("utf-8")) > IAM_CUSTOMER_MANAGED_POLICY_MAX_BYTES
    ]
    if oversized:
        raise ValueError(
            "automation managed policy document exceeds AWS size limit: "
            + ", ".join(oversized)
        )
    return documents


class GitHubAutomation(pulumi.ComponentResource):
    """Provision the ECR runner repository and GitHub automation role."""

    def __init__(
        self,
        name: str,
        *,
        settings: BootstrapSettings | None = None,
        repository_project: str | None = None,
        oidc_provider_arn: pulumi.Input[str] | None = None,
        opts: pulumi.ResourceOptions | None = None,
    ) -> None:
        """Initialize automation resources for this repository/environment."""
        super().__init__("bootstrap:github:Automation", name, None, opts)

        configured_settings = settings or default_settings
        if not configured_settings.repo:
            raise ValueError("repoSlug config is required for GitHub automation.")
        provider_arn = oidc_provider_arn or configured_settings.github_oidc_provider_arn
        if provider_arn is None:
            raise ValueError(
                "githubOidcProviderArn config is required for GitHub automation."
            )

        repo_name = configured_settings.repo
        environment = configured_settings.environment
        repo_project = repository_project or repo_name
        ecr_repository_name = configured_settings.runner_ecr_repository_name(repo_name)
        role_name = configured_settings.automation_role_name(repo_name)
        base_opts = _resource_options(self)

        repository = aws.ecr.Repository(
            f"{name}-repository",
            name=ecr_repository_name,
            image_tag_mutability="IMMUTABLE",
            image_scanning_configuration=aws.ecr.RepositoryImageScanningConfigurationArgs(
                scan_on_push=True
            ),
            tags=base_tags(
                {
                    "Purpose": "pulumi-automation-runner",
                    "Repository": repo_name,
                    "App": repo_name,
                    "RepositoryProject": repo_project,
                },
                settings=configured_settings,
            ),
            opts=_resource_options(
                self,
                import_id=(
                    ecr_repository_name
                    if _ecr_repository_exists(ecr_repository_name)
                    else None
                ),
            ),
        )

        aws.ecr.LifecyclePolicy(
            f"{name}-lifecycle",
            repository=repository.name,
            policy=json.dumps(
                {
                    "rules": [
                        {
                            "rulePriority": 1,
                            "description": "Keep the 30 newest tagged runner images.",
                            "selection": {
                                "tagStatus": "tagged",
                                "tagPrefixList": ["sha-", "main"],
                                "countType": "imageCountMoreThan",
                                "countNumber": 30,
                            },
                            "action": {"type": "expire"},
                        },
                        {
                            "rulePriority": 2,
                            "description": "Expire untagged images after 7 days.",
                            "selection": {
                                "tagStatus": "untagged",
                                "countType": "sinceImagePushed",
                                "countUnit": "days",
                                "countNumber": 7,
                            },
                            "action": {"type": "expire"},
                        },
                    ]
                }
            ),
            opts=base_opts,
        )

        role = aws.iam.Role(
            f"{name}-role",
            name=role_name,
            assume_role_policy=apply_output(
                pulumi.Output.from_input(provider_arn),
                lambda arn: _automation_assume_role_policy(
                    arn,
                    configured_settings.org,
                    repo_name,
                    environment,
                ),
            ),
            tags=base_tags(
                {
                    "Purpose": "pulumi-automation",
                    "Repository": repo_name,
                    "App": repo_name,
                    "RepositoryProject": repo_project,
                },
                settings=configured_settings,
            ),
            opts=_resource_options(
                self,
                import_id=role_name if _iam_role_exists(role_name) else None,
            ),
        )

        policies: list[aws.iam.Policy] = []
        policy_attachments: list[aws.iam.RolePolicyAttachment] = []
        for policy_suffix, policy_document in _automation_policy_documents(
            aws.get_caller_identity().account_id,
            configured_settings,
            repo_name,
        ):
            policy_name = f"{name}-{policy_suffix}"
            policy = aws.iam.Policy(
                policy_name,
                name=policy_name,
                policy=policy_document,
                tags=base_tags(
                    {
                        "Purpose": "pulumi-automation-policy",
                        "Repository": repo_name,
                        "App": repo_name,
                        "RepositoryProject": repo_project,
                    },
                    settings=configured_settings,
                ),
                opts=base_opts,
            )
            policies.append(policy)
            policy_attachments.append(
                aws.iam.RolePolicyAttachment(
                    f"{policy_name}-attachment",
                    role=role.name,
                    policy_arn=policy.arn,
                    opts=pulumi.ResourceOptions(parent=self, depends_on=[policy]),
                )
            )

        self.repository = repository
        self.role = role
        self.policy = policies[0]
        self.policies = policies
        self.policy_attachments = policy_attachments
        self.policy_dependencies = policy_attachments

        self.register_outputs(
            {
                "repository_name": repository.name,
                "repository_url": repository.repository_url,
                "role_arn": role.arn,
                "policy_name": self.policy.name,
                "policy_names": [policy.name for policy in policies],
                "policy_arns": [policy.arn for policy in policies],
            }
        )
