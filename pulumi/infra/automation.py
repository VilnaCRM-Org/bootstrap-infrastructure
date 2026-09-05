"""GitHub automation role and ECR runner repository for bootstrap operations."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

import pulumi_aws as aws

import pulumi

from .bootstrap_settings import BootstrapSettings
from .config import settings as default_settings
from .github_identity import expand_subjects, identity_conditions
from .platform_iam import _role_families, platform_iam_statements
from .utils.outputs import apply_output
from .utils.tags import base_tags

AWS_REQUEST_TAG_ENVIRONMENT_KEY = "aws:RequestTag/Environment"
AWS_REQUEST_TAG_PURPOSE_KEY = "aws:RequestTag/Purpose"
AWS_RESOURCE_TAG_ENVIRONMENT_KEY = "aws:ResourceTag/Environment"
AWS_RESOURCE_TAG_PURPOSE_KEY = "aws:ResourceTag/Purpose"
IAM_ROLE_INLINE_POLICY_MAX_BYTES = 10_240
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
                "PassBootstrapRolesToBackup",
                "PassBootstrapRolesToConfig",
                "PassBootstrapRolesToS3Replication",
                "ReadPlatformCiSecrets",
                "ManageBootstrapBackup",
                "ManageBootstrapEcr",
            }
        ),
    ),
    (
        "iam-boundary-policy",
        frozenset(
            {
                "ReadPlatformIam",
                "TagPlatformServiceRoles",
                "ManageBoundedBackup",
                "DenyControllerIamChanges",
                "DenyPolicyAndIdentityProviderChanges",
                "DenyAdministratorAttachments",
                "DenyControllerPassRole",
                "DenyRuntimeSecrets",
                "DenyForeignRepositoryKms",
            }
        ),
    ),
    (
        "operations-policy",
        frozenset(
            {
                "ManageBootstrapEventBridge",
                "ManageBootstrapCloudTrail",
                "ReadCloudTrailTrailsForRefresh",
                "ManageBootstrapSns",
                "ManageBootstrapSnsSubscriptions",
                "ManageBootstrapSqs",
                "DenyBootstrapSqsConsumption",
            }
        ),
    ),
    (
        "cost-policy",
        frozenset(
            {
                "ManageBootstrapBudgets",
                "ReadAccountBudgetsForEvidence",
                "CreateBudgetServiceLinkedRole",
                "ReadBillingViewDataForBudgets",
                "CreateBootstrapCostAnomalyMonitor",
                "CreateBootstrapCostAnomalySubscription",
                "ReadCostAnomalyMonitorsForEvidence",
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
    "s3:GetAccelerateConfiguration",
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
KMS_CREATE_ALIAS_ACTION = "kms:CreateAlias"
KMS_CREATE_KEY_ACTION = "kms:CreateKey"
KMS_DELETE_ALIAS_ACTION = "kms:DeleteAlias"
KMS_LIST_ALIASES_ACTION = "kms:ListAliases"
KMS_UPDATE_ALIAS_ACTION = "kms:UpdateAlias"
KMS_ALIAS_ACTIONS = (
    KMS_CREATE_ALIAS_ACTION,
    KMS_DELETE_ALIAS_ACTION,
    KMS_UPDATE_ALIAS_ACTION,
)
KMS_SEPARATE_STATEMENT_ACTIONS = frozenset(
    (*KMS_ALIAS_ACTIONS, KMS_CREATE_KEY_ACTION, KMS_LIST_ALIASES_ACTION)
)
_AUTOMATION_KMS_ACTIONS = (
    "kms:CancelKeyDeletion",
    KMS_CREATE_ALIAS_ACTION,
    "kms:CreateGrant",
    KMS_CREATE_KEY_ACTION,
    KMS_DELETE_ALIAS_ACTION,
    "kms:DescribeKey",
    "kms:DisableKey",
    "kms:EnableKey",
    "kms:EnableKeyRotation",
    "kms:GetKeyPolicy",
    "kms:GetKeyRotationStatus",
    KMS_LIST_ALIASES_ACTION,
    "kms:ListGrants",
    "kms:ListResourceTags",
    "kms:PutKeyPolicy",
    "kms:RetireGrant",
    "kms:RevokeGrant",
    "kms:ScheduleKeyDeletion",
    "kms:TagResource",
    "kms:UntagResource",
    KMS_UPDATE_ALIAS_ACTION,
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
    "ecr:DescribeImages",
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
_AUTOMATION_CLOUDTRAIL_ACCOUNT_READ_ACTIONS = (
    # DescribeTrails does not support CloudTrail resource-level permissions.
    "cloudtrail:DescribeTrails",
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
    # These subscription APIs do not support SNS resource-level permissions.
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
_OPERATIONS_ALERT_TRIAGE_SQS_ACTIONS = (
    "sqs:GetQueueUrl",
    "sqs:ReceiveMessage",
    "sqs:DeleteMessage",
)
_OPERATIONS_ALERT_TRIAGE_CONSUME_ACTIONS = (
    "sqs:ReceiveMessage",
    "sqs:DeleteMessage",
)
_AUTOMATION_SECRETS_MANAGER_CREATE_ACTIONS = (
    "secretsmanager:CreateSecret",
    "secretsmanager:TagResource",
)
_AUTOMATION_SECRETS_MANAGER_RESOURCE_ACTIONS = (
    "secretsmanager:DeleteSecret",
    "secretsmanager:DescribeSecret",
    "secretsmanager:GetResourcePolicy",
    "secretsmanager:ListSecretVersionIds",
    "secretsmanager:RestoreSecret",
    "secretsmanager:TagResource",
    "secretsmanager:UntagResource",
)
_AUTOMATION_BUDGETS_ACTIONS = (
    "budgets:ModifyBudget",
    "budgets:ViewBudget",
    "budgets:ListTagsForResource",
    "budgets:TagResource",
    "budgets:UntagResource",
)
_AUTOMATION_BUDGETS_ACCOUNT_READ_ACTIONS = (
    # DescribeBudgets authorizes as ViewBudget against the account budget set.
    "budgets:ViewBudget",
)
_AUTOMATION_COST_EXPLORER_MONITOR_CREATE_ACTIONS = ("ce:CreateAnomalyMonitor",)
_AUTOMATION_COST_EXPLORER_SUBSCRIPTION_CREATE_ACTIONS = (
    "ce:CreateAnomalySubscription",
)
_AUTOMATION_COST_EXPLORER_MONITOR_READ_ACTIONS = (
    # GetAnomalyMonitors requires all-or-none access to account monitor ARNs.
    "ce:GetAnomalyMonitors",
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


@dataclass(frozen=True)
class AutomationResourceContext:
    """Shared inputs for repository-scoped automation resources."""

    parent: pulumi.Resource
    name: str
    settings: BootstrapSettings
    repo_name: str
    repo_project: str
    opts: pulumi.ResourceOptions


def _environment_resource_part(settings: BootstrapSettings) -> str:
    """Return the environment as it appears in resource names."""
    return settings.sanitize_bucket_component(settings.environment, "environment")


def _sns_environment_resource_part(settings: BootstrapSettings) -> str:
    """Return the environment segment as it appears in SNS resource names."""
    return _environment_resource_part(settings).replace(".", "-")


def _is_missing_lookup_error(message: str, markers: tuple[str, ...]) -> bool:
    """Return True when an AWS lookup error means the resource is absent."""
    return (
        any(marker in message for marker in markers)
        or "not found" in message.lower()
        or "couldn't find resource" in message
    )


def _aws_lookup_exists(
    lookup: Callable[[], object],
    *,
    missing_markers: tuple[str, ...],
) -> bool:
    """Return True when an AWS lookup succeeds, False for known missing errors."""
    try:
        lookup()
    except Exception as exc:
        message = str(exc)
        if _is_missing_lookup_error(message, missing_markers):
            return False
        raise
    return True


def _ecr_repository_exists(name: str) -> bool:
    """Return True when the ECR repository already exists."""
    return _aws_lookup_exists(
        lambda: aws.ecr.get_repository(name=name),
        missing_markers=("RepositoryNotFoundException", "RepositoryNotFound"),
    )


def _iam_role_exists(name: str) -> bool:
    """Return True when the IAM role already exists."""
    return _aws_lookup_exists(
        lambda: aws.iam.get_role(name=name),
        missing_markers=("NoSuchEntity", "NoSuchEntityException"),
    )


def _resource_options(
    parent: pulumi.Resource,
    *,
    import_id: str | None = None,
    depends_on: list[pulumi.Resource] | None = None,
) -> pulumi.ResourceOptions:
    """Build consistent resource options for automation resources."""
    kwargs: dict[str, object] = {"parent": parent}
    if import_id is not None:
        kwargs["import_"] = import_id
    if depends_on is not None:
        kwargs["depends_on"] = depends_on
    return pulumi.ResourceOptions(**kwargs)


def _automation_s3_resources(settings: BootstrapSettings) -> list[str]:
    """Scope bootstrap S3 management to state and central logging buckets."""
    environment = _environment_resource_part(settings)
    logging_prefix = settings.sanitize_bucket_component(
        settings.logging_prefix,
        "loggingPrefix",
    )
    from .pulumi_state import _replica_bucket_name

    state_bucket = settings.state_bucket_name()
    replica_bucket = _replica_bucket_name(
        state_bucket, settings.replication_region or "eu-west-1"
    )
    bucket_names = (
        state_bucket,
        replica_bucket,
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
        f"arn:aws:kms:*:{account_id}:alias/pulumi-{settings.repo}-{environment}-secrets",
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


def _automation_sqs_resources(
    account_id: str, settings: BootstrapSettings
) -> list[str]:
    """Scope SQS management to the bootstrap operations alert queue."""
    environment = _environment_resource_part(settings).replace(".", "-")
    return [f"arn:aws:sqs:*:{account_id}:bootstrap-{environment}-operations-alerts"]


def _automation_ci_secret_suffixes(environment: str) -> tuple[str, ...]:
    """Return CI secret suffixes owned by one bootstrap stack."""
    return {
        "test": ("test-pr", "test"),
        "prod": ("prod-preview", "prod"),
    }.get(environment, (environment,))


def _automation_ci_secret_resources(
    account_id: str,
    settings: BootstrapSettings,
    repo_name: str,
) -> list[str]:
    """Scope Secrets Manager management to CI config secret containers."""
    repo_part = settings.sanitize_bucket_component(repo_name, "repoSlug").replace(
        ".",
        "-",
    )
    return [
        f"arn:aws:secretsmanager:*:{account_id}:secret:/{repo_part}/ci/{suffix}-*"
        for suffix in _automation_ci_secret_suffixes(settings.environment)
    ]


def _automation_budget_resources(
    account_id: str, settings: BootstrapSettings
) -> list[str]:
    """Scope Budgets management to deterministic bootstrap budgets."""
    environment = _environment_resource_part(settings)
    return [f"arn:aws:budgets::{account_id}:budget/bootstrap-{environment}-*"]


def _automation_account_budget_resources(account_id: str) -> list[str]:
    """Scope read-only Budget evidence to account-local budgets."""
    return [f"arn:aws:budgets::{account_id}:budget/*"]


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
    oidc_provider_arn: str,
    org: str,
    repo_name: str,
    production_environment: str,
    branch_name: str,
    *,
    repository_id: str | None = None,
    owner_id: str | None = None,
) -> str:
    """Build the GitHub OIDC trust policy for fixed workflow automation."""
    subjects = [f"repo:{org}/{repo_name}:environment:{production_environment}"]
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
                            "token.actions.githubusercontent.com:sub": expand_subjects(
                                subjects, f"{org}/{repo_name}", repository_id, owner_id
                            ),
                            **identity_conditions(repository_id, owner_id),
                            "token.actions.githubusercontent.com:ref": (
                                f"refs/heads/{branch_name}"
                            ),
                            "token.actions.githubusercontent.com:repository": (
                                f"{org}/{repo_name}"
                            ),
                        },
                    },
                }
            ],
        }
    )


def _operations_alert_triage_role_name(
    settings: BootstrapSettings,
    repo_name: str,
) -> str:
    """Compute the dedicated operations-alert triage role name."""
    repo_part = settings.sanitize_bucket_component(repo_name, "repoSlug").replace(
        ".",
        "-",
    )
    env_part = settings.sanitize_bucket_component(
        settings.environment,
        "environment",
    ).replace(".", "-")
    name = f"OperationsAlertTriage-{repo_part}-{env_part}"
    if len(name) > 64:
        raise ValueError(
            "Combined repo/environment produce operations alert triage role name "
            f"'{name}' longer than 64 characters."
        )
    return name


def _operations_alert_triage_assume_role_policy(
    oidc_provider_arn: str,
    org: str,
    repo_name: str,
    branch_name: str,
    *,
    repository_id: str | None = None,
    owner_id: str | None = None,
) -> str:
    """Build the OIDC trust policy for the alert triage workflow only."""
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
                            "token.actions.githubusercontent.com:sub": expand_subjects(
                                [
                                    f"repo:{org}/{repo_name}:ref:refs/heads/{branch_name}"
                                ],
                                f"{org}/{repo_name}",
                                repository_id,
                                owner_id,
                            ),
                            **identity_conditions(repository_id, owner_id),
                            "token.actions.githubusercontent.com:workflow": (
                                "Operations Alert Issue Triage"
                            ),
                            "token.actions.githubusercontent.com:ref": (
                                f"refs/heads/{branch_name}"
                            ),
                            "token.actions.githubusercontent.com:repository": (
                                f"{org}/{repo_name}"
                            ),
                        },
                    },
                }
            ],
        }
    )


def _operations_alert_triage_policy(
    account_id: str,
    settings: BootstrapSettings,
) -> str:
    """Return the least-privilege SQS consume policy for alert triage."""
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "ConsumeOperationsAlertQueue",
                    "Effect": "Allow",
                    "Action": list(_OPERATIONS_ALERT_TRIAGE_SQS_ACTIONS),
                    "Resource": _automation_sqs_resources(account_id, settings),
                }
            ],
        }
    )


def _automation_policy(
    account_id: str, settings: BootstrapSettings, repo_name: str
) -> str:
    """Return the policy used by GitHub automation for bootstrap operations."""
    if settings.repo != repo_name:
        settings = replace(settings, repo=repo_name)
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
                    "Action": [KMS_CREATE_KEY_ACTION],
                    "Resource": "*",
                    "Condition": kms_request_tag_condition,
                },
                {
                    "Sid": "ListBootstrapKmsAliases",
                    "Effect": "Allow",
                    "Action": [KMS_LIST_ALIASES_ACTION],
                    "Resource": "*",
                },
                {
                    "Sid": "ManageBootstrapKmsAliases",
                    "Effect": "Allow",
                    "Action": list(KMS_ALIAS_ACTIONS),
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
                        if action not in KMS_SEPARATE_STATEMENT_ACTIONS
                    ],
                    "Resource": _automation_kms_key_resources(account_id),
                    "Condition": kms_tag_condition,
                },
                *platform_iam_statements(account_id, settings, repo_name),
                {
                    "Sid": "ReadPlatformCiSecrets",
                    "Effect": "Allow",
                    "Action": ["secretsmanager:DescribeSecret"],
                    "Resource": _automation_ci_secret_resources(
                        account_id, settings, repo_name
                    ),
                },
                {
                    "Sid": "PassBootstrapRolesToBackup",
                    "Effect": "Allow",
                    "Action": ["iam:PassRole"],
                    "Resource": [_role_families(account_id, settings)["backup"]],
                    "Condition": {
                        "StringEquals": {"iam:PassedToService": "backup.amazonaws.com"}
                    },
                },
                {
                    "Sid": "PassBootstrapRolesToConfig",
                    "Effect": "Allow",
                    "Action": ["iam:PassRole"],
                    "Resource": [
                        f"arn:aws:iam::{account_id}:role/aws-config-recorder-role-"
                        f"{settings.environment}"
                    ],
                    "Condition": {
                        "StringEquals": {"iam:PassedToService": "config.amazonaws.com"}
                    },
                },
                {
                    "Sid": "PassBootstrapRolesToS3Replication",
                    "Effect": "Allow",
                    "Action": ["iam:PassRole"],
                    "Resource": [
                        _role_families(account_id, settings)["state-replication"],
                        _role_families(account_id, settings)["log-replication"],
                    ],
                    "Condition": {
                        "StringEquals": {"iam:PassedToService": "s3.amazonaws.com"}
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
                    "Sid": "ReadCloudTrailTrailsForRefresh",
                    "Effect": "Allow",
                    "Action": list(_AUTOMATION_CLOUDTRAIL_ACCOUNT_READ_ACTIONS),
                    "Resource": "*",
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
                    "Resource": "*",
                },
                {
                    "Sid": "ManageBootstrapSqs",
                    "Effect": "Allow",
                    "Action": list(_AUTOMATION_SQS_ACTIONS),
                    "Resource": _automation_sqs_resources(account_id, settings),
                },
                {
                    "Sid": "DenyBootstrapSqsConsumption",
                    "Effect": "Deny",
                    "Action": list(_OPERATIONS_ALERT_TRIAGE_CONSUME_ACTIONS),
                    "Resource": _automation_sqs_resources(account_id, settings),
                },
                {
                    "Sid": "ManageBootstrapBudgets",
                    "Effect": "Allow",
                    "Action": list(_AUTOMATION_BUDGETS_ACTIONS),
                    "Resource": _automation_budget_resources(account_id, settings),
                },
                {
                    "Sid": "ReadAccountBudgetsForEvidence",
                    "Effect": "Allow",
                    "Action": list(_AUTOMATION_BUDGETS_ACCOUNT_READ_ACTIONS),
                    "Resource": _automation_account_budget_resources(account_id),
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
                    "Sid": "ReadCostAnomalyMonitorsForEvidence",
                    "Effect": "Allow",
                    "Action": list(_AUTOMATION_COST_EXPLORER_MONITOR_READ_ACTIONS),
                    "Resource": _automation_cost_explorer_monitor_resources(account_id),
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


def _automation_statement_by_sid(
    policy: dict[str, Any],
) -> dict[str, dict[str, object]]:
    """Index IAM statements by Sid while preserving policy statement order."""
    return {str(statement["Sid"]): statement for statement in policy["Statement"]}


def _automation_policy_group_sids() -> set[str]:
    """Return all statement Sids assigned to an automation policy group."""
    covered_sids: set[str] = set()
    for _name, policy_sids in _AUTOMATION_MANAGED_POLICY_GROUPS:
        covered_sids.update(policy_sids)
    return covered_sids


def _validate_automation_policy_coverage(
    statements_by_sid: dict[str, dict[str, object]],
) -> None:
    """Require every automation statement to be assigned to a policy document."""
    uncovered_sids = sorted(set(statements_by_sid) - _automation_policy_group_sids())
    if uncovered_sids:
        raise ValueError(
            "automation policy statements are missing a managed-policy group: "
            + ", ".join(uncovered_sids)
        )


def _automation_policy_document_for_group(
    statements_by_sid: dict[str, dict[str, object]],
    policy_sids: frozenset[str],
) -> str | None:
    """Build a compact policy document for the statements in one group."""
    statements = [
        statement for sid, statement in statements_by_sid.items() if sid in policy_sids
    ]
    if not statements:
        return None
    return _compact_policy_document(statements)


def _automation_policy_group_documents(
    statements_by_sid: dict[str, dict[str, object]],
) -> list[tuple[str, str]]:
    """Build non-empty policy documents in configured group order."""
    documents: list[tuple[str, str]] = []
    for policy_suffix, policy_sids in _AUTOMATION_MANAGED_POLICY_GROUPS:
        document = _automation_policy_document_for_group(statements_by_sid, policy_sids)
        if document is not None:
            documents.append((policy_suffix, document))
    return documents


def _policy_document_size(document: str) -> int:
    """Return an IAM policy document's UTF-8 size in bytes."""
    return len(document.encode("utf-8"))


def _validate_automation_inline_policy_document(
    policy_name: str, document: str
) -> None:
    """Validate the inline policy name and size contract."""
    if policy_name != "policy":
        raise ValueError("the first automation policy document must be policy.")
    if _policy_document_size(document) > IAM_ROLE_INLINE_POLICY_MAX_BYTES:
        raise ValueError("automation inline policy document exceeds AWS size limit.")


def _validate_automation_managed_policy_documents(
    documents: list[tuple[str, str]],
) -> None:
    """Validate customer-managed policy size limits."""
    oversized = [
        name
        for name, document in documents
        if _policy_document_size(document) > IAM_CUSTOMER_MANAGED_POLICY_MAX_BYTES
    ]
    if oversized:
        raise ValueError(
            "automation managed policy document exceeds AWS size limit: "
            + ", ".join(oversized)
        )


def _validate_automation_policy_documents(documents: list[tuple[str, str]]) -> None:
    """Validate split automation policy documents before provisioning."""
    inline_policy_name, inline_policy_document = documents[0]
    _validate_automation_inline_policy_document(
        inline_policy_name, inline_policy_document
    )
    _validate_automation_managed_policy_documents(documents)


def _automation_policy_documents(
    account_id: str, settings: BootstrapSettings, repo_name: str
) -> list[tuple[str, str]]:
    """Split automation permissions into customer-managed policies."""
    policy = json.loads(_automation_policy(account_id, settings, repo_name))
    statements_by_sid = _automation_statement_by_sid(policy)
    _validate_automation_policy_coverage(statements_by_sid)
    documents = _automation_policy_group_documents(statements_by_sid)
    _validate_automation_policy_documents(documents)
    return documents


def _automation_tags(
    configured_settings: BootstrapSettings,
    repo_name: str,
    repo_project: str,
    purpose: str,
) -> dict[str, str]:
    """Build common tags for repository-scoped automation resources."""
    return base_tags(
        {
            "Purpose": purpose,
            "Repository": repo_name,
            "App": repo_name,
            "RepositoryProject": repo_project,
        },
        settings=configured_settings,
    )


def _create_automation_repository(
    context: AutomationResourceContext,
) -> aws.ecr.Repository:
    """Create or adopt the automation runner ECR repository."""
    ecr_repository_name = context.settings.runner_ecr_repository_name(context.repo_name)
    return aws.ecr.Repository(
        f"{context.name}-repository",
        name=ecr_repository_name,
        image_tag_mutability="IMMUTABLE",
        image_scanning_configuration=aws.ecr.RepositoryImageScanningConfigurationArgs(
            scan_on_push=True
        ),
        tags=_automation_tags(
            context.settings,
            context.repo_name,
            context.repo_project,
            "pulumi-automation-runner",
        ),
        opts=_resource_options(
            context.parent,
            import_id=ecr_repository_name
            if _ecr_repository_exists(ecr_repository_name)
            else None,
        ),
    )


def _create_automation_lifecycle_policy(
    name: str,
    repository: aws.ecr.Repository,
    opts: pulumi.ResourceOptions,
) -> None:
    """Attach lifecycle rules to keep runner images bounded."""
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
        opts=opts,
    )


def _create_automation_role(
    context: AutomationResourceContext,
    provider_arn: pulumi.Input[str],
    permissions_boundary: pulumi.Input[str] | None = None,
) -> aws.iam.Role:
    """Create or adopt the GitHub Actions automation role."""
    role_name = context.settings.automation_role_name(context.repo_name)
    return aws.iam.Role(
        f"{context.name}-role",
        name=role_name,
        permissions_boundary=permissions_boundary,
        assume_role_policy=apply_output(
            pulumi.Output.from_input(provider_arn),
            lambda arn: _automation_assume_role_policy(
                arn,
                context.settings.org,
                context.repo_name,
                context.settings.environment,
                context.settings.github_branch or "main",
                repository_id=context.settings.github_repository_id,
                owner_id=context.settings.github_repository_owner_id,
            ),
        ),
        tags=_automation_tags(
            context.settings,
            context.repo_name,
            context.repo_project,
            "pulumi-automation",
        ),
        opts=_resource_options(
            context.parent,
            import_id=role_name if _iam_role_exists(role_name) else None,
        ),
    )


def _create_automation_managed_policy(
    context: AutomationResourceContext,
    policy_name: str,
    policy_document: str,
    *,
    adopt_existing: bool = False,
) -> aws.iam.Policy:
    """Create one customer-managed policy for automation permissions."""
    import_id = None
    if adopt_existing:
        arn = (
            f"arn:{aws.get_partition().partition}:iam::"
            f"{aws.get_caller_identity().account_id}:policy/{policy_name}"
        )
        if _aws_lookup_exists(
            lambda: aws.iam.get_policy(arn=arn), missing_markers=("NoSuchEntity",)
        ):
            import_id = arn
    return aws.iam.Policy(
        policy_name,
        name=policy_name,
        policy=policy_document,
        tags=_automation_tags(
            context.settings,
            context.repo_name,
            context.repo_project,
            "pulumi-automation-policy",
        ),
        opts=pulumi.ResourceOptions.merge(
            context.opts, pulumi.ResourceOptions(import_=import_id)
        ),
    )


def _attach_automation_managed_policy(
    parent: pulumi.Resource,
    policy_name: str,
    role: aws.iam.Role,
    policy: aws.iam.Policy,
    *,
    import_id: str | None = None,
) -> aws.iam.RolePolicyAttachment:
    """Attach a managed automation policy to the automation role."""
    return aws.iam.RolePolicyAttachment(
        f"{policy_name}-attachment",
        role=role.name,
        policy_arn=policy.arn,
        opts=pulumi.ResourceOptions(
            parent=parent, depends_on=[policy], import_=import_id
        ),
    )


def _manage_automation_role_policy_attachments_exclusively(
    parent: pulumi.Resource,
    resource_name: str,
    role: aws.iam.Role,
    managed_policies: list[aws.iam.Policy],
    policy_attachments: list[aws.iam.RolePolicyAttachment],
    *,
    import_id: str | None = None,
) -> aws.iam.RolePolicyAttachmentsExclusive:
    """Remove unmanaged managed policies from the automation role."""
    return aws.iam.RolePolicyAttachmentsExclusive(
        f"{resource_name}-managed-policy-attachments-exclusive",
        role_name=role.name,
        policy_arns=[policy.arn for policy in managed_policies],
        opts=pulumi.ResourceOptions(
            parent=parent, depends_on=policy_attachments, import_=import_id
        ),
    )


def _create_automation_role_policies(
    context: AutomationResourceContext,
    role: aws.iam.Role,
    *,
    adopt_existing: bool = False,
    preferred_inline_policy_name: str | None = None,
) -> tuple[
    aws.iam.RolePolicy,
    list[aws.iam.Policy],
    list[aws.iam.RolePolicyAttachment],
    aws.iam.RolePolicyAttachmentsExclusive,
]:
    """Create inline and customer-managed policies for the automation role."""
    policy_documents = _automation_policy_documents(
        aws.get_caller_identity().account_id,
        context.settings,
        context.repo_name,
    )
    inline_policy_suffix, inline_policy_document = policy_documents[0]
    inline_policy_name = f"{context.name}-{inline_policy_suffix}"
    role_name = context.settings.automation_role_name(context.repo_name)
    existing_inline = None
    if adopt_existing:
        from .iam.adoption import inline_policy_name as existing_inline_name

        existing_inline = existing_inline_name(
            role_name,
            inline_policy_name,
            **(
                {"preferred_name": preferred_inline_policy_name}
                if preferred_inline_policy_name is not None
                else {}
            ),
        )
    inline_policy = aws.iam.RolePolicy(
        inline_policy_name,
        name=existing_inline or inline_policy_name,
        role=role.id,
        policy=inline_policy_document,
        opts=pulumi.ResourceOptions.merge(
            context.opts,
            pulumi.ResourceOptions(
                import_=f"{role_name}:{existing_inline}" if existing_inline else None
            ),
        ),
    )

    managed_policies: list[aws.iam.Policy] = []
    policy_attachments: list[aws.iam.RolePolicyAttachment] = []
    for policy_suffix, policy_document in policy_documents[1:]:
        policy_name = f"{context.name}-{policy_suffix}"
        policy = _create_automation_managed_policy(
            context,
            policy_name,
            policy_document,
            adopt_existing=adopt_existing,
        )
        managed_policies.append(policy)
        attachment_import = None
        if adopt_existing:
            from .iam.adoption import attachment_exists

            policy_arn = (
                f"arn:{aws.get_partition().partition}:iam::"
                f"{aws.get_caller_identity().account_id}:policy/{policy_name}"
            )
            if attachment_exists(role_name, policy_arn):
                attachment_import = f"{role_name}/{policy_arn}"
        policy_attachments.append(
            _attach_automation_managed_policy(
                context.parent,
                policy_name,
                role,
                policy,
                import_id=attachment_import,
            )
        )

    exclusive_policy_attachments = (
        _manage_automation_role_policy_attachments_exclusively(
            context.parent,
            context.name,
            role,
            managed_policies,
            policy_attachments,
            import_id=(
                role_name if adopt_existing and _iam_role_exists(role_name) else None
            ),
        )
    )

    return (
        inline_policy,
        managed_policies,
        policy_attachments,
        exclusive_policy_attachments,
    )


def _create_operations_alert_triage_role(
    context: AutomationResourceContext,
    provider_arn: pulumi.Input[str],
    *,
    depends_on: list[pulumi.Resource],
    adopt_existing: bool = False,
) -> tuple[aws.iam.Role, aws.iam.RolePolicy]:
    """Create the dedicated GitHub Actions role that drains alert messages."""
    role_name = _operations_alert_triage_role_name(context.settings, context.repo_name)
    branch_name = context.settings.github_branch or "main"
    role = aws.iam.Role(
        f"{context.name}-operations-alert-triage-role",
        name=role_name,
        assume_role_policy=apply_output(
            pulumi.Output.from_input(provider_arn),
            lambda arn: _operations_alert_triage_assume_role_policy(
                arn,
                context.settings.org,
                context.repo_name,
                branch_name,
                repository_id=context.settings.github_repository_id,
                owner_id=context.settings.github_repository_owner_id,
            ),
        ),
        tags=_automation_tags(
            context.settings,
            context.repo_name,
            context.repo_project,
            "operations-alert-triage",
        ),
        opts=_resource_options(
            context.parent,
            import_id=role_name if _iam_role_exists(role_name) else None,
            depends_on=depends_on,
        ),
    )
    policy_name = f"{context.name}-operations-alert-triage-policy"
    existing_policy = None
    if adopt_existing:
        from .iam.adoption import inline_policy_name

        existing_policy = inline_policy_name(role_name, policy_name)
    role_policy = aws.iam.RolePolicy(
        policy_name,
        name=existing_policy or policy_name,
        role=role.id,
        policy=_operations_alert_triage_policy(
            aws.get_caller_identity().account_id,
            context.settings,
        ),
        opts=pulumi.ResourceOptions(
            parent=context.parent,
            import_=f"{role_name}:{existing_policy}" if existing_policy else None,
        ),
    )
    return role, role_policy


def _automation_configuration(settings, oidc_provider_arn):
    """Resolve and validate configuration before constructing control resources."""
    configured_settings = settings or default_settings
    if not configured_settings.repo:
        raise ValueError("repoSlug config is required for GitHub automation.")
    provider_arn = oidc_provider_arn or configured_settings.github_oidc_provider_arn
    if provider_arn is None:
        raise ValueError(
            "githubOidcProviderArn config is required for GitHub automation."
        )

    return configured_settings, provider_arn


class GitHubAutomation(pulumi.ComponentResource):
    """Provision the ECR runner repository and GitHub automation role."""

    def __init__(
        self,
        name: str,
        *,
        settings: BootstrapSettings | None = None,
        repository_project: str | None = None,
        oidc_provider_arn: pulumi.Input[str] | None = None,
        manage_roles: bool = True,
        manage_repository: bool = True,
        manage_triage: bool = True,
        permissions_boundary: pulumi.Input[str] | None = None,
        adopt_existing_policies: bool = False,
        preferred_inline_policy_name: str | None = None,
        role_guard_factory: Callable[[aws.iam.Role], pulumi.Resource] | None = None,
        opts: pulumi.ResourceOptions | None = None,
    ) -> None:
        """Initialize automation resources for this repository/environment."""
        super().__init__("bootstrap:github:Automation", name, None, opts)

        configured_settings, provider_arn = _automation_configuration(
            settings, oidc_provider_arn
        )

        repo_name = configured_settings.repo
        repo_project = repository_project or repo_name
        base_opts = _resource_options(self)
        resource_context = AutomationResourceContext(
            parent=self,
            name=name,
            settings=configured_settings,
            repo_name=repo_name,
            repo_project=repo_project,
            opts=base_opts,
        )

        repository = None
        if manage_repository:
            repository = _create_automation_repository(resource_context)
            _create_automation_lifecycle_policy(name, repository, base_opts)
        inline_policy = None
        managed_policies = []
        policy_attachments = []
        exclusive_policy_attachments = None
        policy_dependencies = []
        operations_alert_triage_policy = None
        if manage_roles:
            role = _create_automation_role(
                resource_context, provider_arn, permissions_boundary
            )
            if role_guard_factory is not None:
                guard = role_guard_factory(role)
                resource_context = replace(
                    resource_context,
                    opts=pulumi.ResourceOptions.merge(
                        resource_context.opts,
                        pulumi.ResourceOptions(depends_on=[guard]),
                    ),
                )
            (
                inline_policy,
                managed_policies,
                policy_attachments,
                exclusive_policy_attachments,
            ) = _create_automation_role_policies(
                resource_context,
                role,
                adopt_existing=adopt_existing_policies,
                preferred_inline_policy_name=preferred_inline_policy_name,
            )
            policy_dependencies = [
                inline_policy,
                *policy_attachments,
                exclusive_policy_attachments,
            ]
        else:
            role = aws.iam.Role.get(
                f"{name}-role",
                configured_settings.automation_role_name(repo_name),
                opts=base_opts,
            )
        if manage_roles and manage_triage:
            operations_alert_triage_role, operations_alert_triage_policy = (
                _create_operations_alert_triage_role(
                    resource_context,
                    provider_arn,
                    depends_on=policy_dependencies,
                    adopt_existing=adopt_existing_policies,
                )
            )
        else:
            operations_alert_triage_role = aws.iam.Role.get(
                f"{name}-operations-alert-triage-role",
                _operations_alert_triage_role_name(configured_settings, repo_name),
                opts=base_opts,
            )

        self.repository = repository
        self.role = role
        self.operations_alert_triage_role = operations_alert_triage_role
        self.policy = inline_policy
        self.operations_alert_triage_policy = operations_alert_triage_policy
        self.managed_policies = managed_policies
        self.policies = (
            [inline_policy] if inline_policy is not None else []
        ) + managed_policies
        self.policy_attachments = policy_attachments
        self.exclusive_policy_attachments = exclusive_policy_attachments
        self.policy_dependencies = policy_dependencies

        self._register_automation_outputs()

    def _register_automation_outputs(self) -> None:
        """Expose metadata from the managed or reference-only resource graph."""
        self.register_outputs(
            {
                "repository_name": (
                    self.repository.name if self.repository is not None else None
                ),
                "repository_url": (
                    self.repository.repository_url
                    if self.repository is not None
                    else None
                ),
                "role_arn": self.role.arn,
                "operations_alert_triage_role_arn": (
                    self.operations_alert_triage_role.arn
                ),
                "policy_name": self.policy.name if self.policy is not None else None,
                "policy_names": [policy.name for policy in self.policies],
                "managed_policy_arns": [policy.arn for policy in self.managed_policies],
            }
        )
