"""Operator-owned ceilings for platform controllers and service IAM roles."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from typing import Any

import pulumi_aws as aws

import pulumi

from .bootstrap_settings import BootstrapSettings
from .managed_repository import ManagedRepository
from .utils.tags import base_tags

PURPOSES = ("control", "state-replication", "log-replication", "backup")
ROLE_MUTATIONS = [
    "iam:CreateRole",
    "iam:DeleteRole",
    "iam:PutRolePolicy",
    "iam:DeleteRolePolicy",
    "iam:AttachRolePolicy",
    "iam:DetachRolePolicy",
    "iam:UpdateAssumeRolePolicy",
    "iam:UpdateRole",
    "iam:UpdateRoleDescription",
    "iam:PutRolePermissionsBoundary",
]

# Key-resource actions from AWS's KMS Service Authorization Reference. Global
# account/custom-store actions do not support key ResourceTag conditions.
_KMS_KEY_ACTIONS = [
    "kms:CancelKeyDeletion",
    "kms:CreateAlias",
    "kms:CreateGrant",
    "kms:Decrypt",
    "kms:DeleteAlias",
    "kms:DeleteImportedKeyMaterial",
    "kms:DeriveSharedSecret",
    "kms:DescribeKey",
    "kms:DisableKey*",
    "kms:EnableKey*",
    "kms:Encrypt",
    "kms:GenerateDataKey*",
    "kms:GenerateMac",
    "kms:GetKey*",
    "kms:GetParametersForImport",
    "kms:GetPublicKey",
    "kms:ImportKeyMaterial",
    "kms:ListGrants",
    "kms:ListKeyPolicies",
    "kms:ListKeyRotations",
    "kms:ListResourceTags",
    "kms:PutKeyPolicy",
    "kms:ReEncrypt*",
    "kms:ReplicateKey",
    "kms:RetireGrant",
    "kms:RevokeGrant",
    "kms:RotateKeyOnDemand",
    "kms:ScheduleKeyDeletion",
    "kms:Sign",
    "kms:SynchronizeMultiRegionKey",
    "kms:TagResource",
    "kms:UntagResource",
    "kms:UpdateAlias",
    "kms:UpdateKeyDescription",
    "kms:UpdatePrimaryRegion",
    "kms:Verify*",
]


def platform_boundary_arn(
    account_id: str,
    settings: BootstrapSettings,
    purpose: str,
    *,
    partition: str = "aws",
) -> str:
    """Return the immutable operator policy ARN for one platform purpose."""
    if purpose not in PURPOSES:
        raise ValueError(f"Unknown platform boundary purpose: {purpose}")
    environment = settings.sanitize_bucket_component(
        settings.environment, "environment"
    ).replace(".", "-")
    return (
        f"arn:{partition}:iam::{account_id}:policy/"
        f"PlatformBoundary-{purpose}-{environment}"
    )


def platform_role_name(settings: BootstrapSettings, purpose: str) -> str:
    """Pin imported auto-names; use deterministic names for fresh installations."""
    names = {
        "log-replication": settings.platform_logging_replication_role_name
        or f"central-logging-replication-role-{settings.environment}",
        "backup": settings.platform_backup_role_name
        or f"s3-backup-role-{settings.environment}",
    }
    name = names[purpose]
    if re.fullmatch(r"[A-Za-z0-9_+=,.@-]{1,64}", name) is None:
        raise ValueError("Invalid platform IAM role name")
    return name


def _role_families(account_id: str, settings: BootstrapSettings) -> dict[str, str]:
    """Return legacy physical name families; boundaries distinguish their power."""
    from .pulumi_state import _replication_role_name, _replication_role_suffix

    prefix = f"arn:aws:iam::{account_id}:role/"
    repo_role = _replication_role_name(
        _replication_role_suffix(settings.repo or "", settings_obj=settings)
    )
    return {
        "state-replication": prefix + repo_role,
        "log-replication": prefix + platform_role_name(settings, "log-replication"),
        "backup": prefix + platform_role_name(settings, "backup"),
    }


def platform_iam_statements(
    account_id: str, settings: BootstrapSettings, repo_name: str
) -> list[dict[str, Any]]:
    """Grant mutation only on bounded service roles; never on controller IAM."""
    del repo_name  # Explicit settings determine the account's platform repository.
    families = {"backup": _role_families(account_id, settings)["backup"]}
    statements: list[dict[str, Any]] = [
        {
            "Sid": "ReadPlatformIam",
            "Effect": "Allow",
            "Action": ["iam:Get*", "iam:List*"],
            "Resource": "*",
        },
        {
            "Sid": "TagPlatformServiceRoles",
            "Effect": "Allow",
            "Action": ["iam:TagRole", "iam:UntagRole"],
            "Resource": list(families.values()),
        },
    ]
    for purpose, resource in families.items():
        statements.append(
            {
                "Sid": "ManageBounded" + purpose.title().replace("-", ""),
                "Effect": "Allow",
                "Action": ROLE_MUTATIONS,
                "Resource": resource,
                "Condition": {
                    "StringEquals": {
                        "iam:PermissionsBoundary": platform_boundary_arn(
                            account_id, settings, purpose
                        )
                    }
                },
            }
        )
    statements.extend(platform_control_denies(account_id, settings))
    return statements


def platform_control_state_guard(
    account_id: str, settings: BootstrapSettings, *, purpose: str = "apply"
) -> str:
    """Deny controller object access outside its canonical platform checkpoint.

    The operator owns these inline denials. Explicit denial also overrides a
    bucket-policy grant to an assumed-role session, which a boundary's implicit
    denial does not. Retired, operator and governance backends stay inaccessible.
    """
    if purpose not in ("apply", "preview", "drift"):
        raise ValueError(f"Unknown platform guard purpose: {purpose}")
    bucket = f"arn:aws:s3:::{settings.state_bucket_name()}"
    prefix = f"{bucket}/state/{settings.environment}"
    object_actions = [
        "s3:GetObject*",
        "s3:PutObject*",
        "s3:DeleteObject*",
        "s3:RestoreObject",
        "s3:ReplicateObject",
        "s3:ObjectOwnerOverrideToBucketOwner",
        "s3:AbortMultipartUpload",
        "s3:ListMultipartUploadParts",
        "s3:ReplicateDelete",
        "s3:ReplicateTags",
    ]
    statements = [
        {
            "Sid": "DenyNoncanonicalPlatformState",
            "Effect": "Deny",
            "Action": object_actions,
            "NotResource": prefix + "/*",
        }
    ]
    if purpose != "apply":
        statements.extend(
            [
                {
                    "Sid": "DenyPreviewCheckpointMutation",
                    "Effect": "Deny",
                    "Action": [
                        "s3:PutObject*",
                        "s3:DeleteObject*",
                        "s3:RestoreObject",
                        "s3:ReplicateObject",
                        "s3:ReplicateDelete",
                        "s3:ReplicateTags",
                        "s3:AbortMultipartUpload",
                    ],
                    "NotResource": prefix + "/.pulumi/locks/*",
                },
                {
                    "Sid": "DenyPreviewObjectVersionDeletion",
                    "Effect": "Deny",
                    "Action": "s3:DeleteObjectVersion*",
                    "Resource": "*",
                },
            ]
        )
    denials = platform_control_denies(account_id, settings)
    # Preserve the exact compact ceiling's IAM denials when moving them into
    # the immutable guard. Identity grants are ordered after this resource.
    _compress_sensitive_statements(
        [item for item in denials if item["Sid"] in _GUARD_ONLY_IAM_DENIALS]
    )
    statements.extend(denials)
    return json.dumps(
        {"Version": "2012-10-17", "Statement": statements},
        separators=(",", ":"),
        sort_keys=True,
    )


def platform_control_denies(
    account_id: str, settings: BootstrapSettings
) -> list[dict[str, Any]]:
    """Explicit denials survive obsolete parallel identity-policy attachments."""
    iam = f"arn:aws:iam::{account_id}:"
    return [
        {
            "Sid": "DenyForeignRepositoryKms",
            "Effect": "Deny",
            "Action": _KMS_KEY_ACTIONS,
            "Resource": f"arn:aws:kms:*:{account_id}:key/*",
            "Condition": {
                "StringNotEquals": {"aws:ResourceTag/Repository": settings.repo},
                "Null": {"aws:ResourceTag/Repository": "false"},
            },
        },
        {
            "Sid": "DenyControllerIamChanges",
            "Effect": "Deny",
            "Action": [*ROLE_MUTATIONS, "iam:TagRole", "iam:UntagRole"],
            "NotResource": [_role_families(account_id, settings)["backup"]],
        },
        {
            "Sid": "DenyPolicyAndIdentityProviderChanges",
            "Effect": "Deny",
            "Action": [
                "iam:CreatePolicy*",
                "iam:DeletePolicy*",
                "iam:SetDefaultPolicyVersion",
                "iam:TagPolicy",
                "iam:UntagPolicy",
                "iam:CreateOpenIDConnectProvider",
                "iam:DeleteOpenIDConnectProvider",
                "iam:AddClientIDToOpenIDConnectProvider",
                "iam:RemoveClientIDFromOpenIDConnectProvider",
                "iam:UpdateOpenIDConnectProviderThumbprint",
                "iam:TagOpenIDConnectProvider",
                "iam:UntagOpenIDConnectProvider",
                "iam:*SAMLProvider*",
                "iam:DeleteRolePermissionsBoundary",
            ],
            "Resource": "*",
        },
        {
            "Sid": "DenyAdministratorAttachments",
            "Effect": "Deny",
            "Action": ["iam:AttachRolePolicy"],
            "Resource": "*",
            "Condition": {
                "ArnNotEquals": {
                    "iam:PolicyARN": (
                        "arn:aws:iam::aws:policy/AWSBackupServiceRolePolicyForS3Backup"
                    )
                }
            },
        },
        {
            "Sid": "DenyControllerPassRole",
            "Effect": "Deny",
            "Action": ["iam:PassRole"],
            "NotResource": [
                *_role_families(account_id, settings).values(),
                iam + f"role/aws-config-recorder-role-{settings.environment}",
            ],
        },
        {
            "Sid": "DenyRuntimeSecrets",
            "Effect": "Deny",
            "Resource": "*",
            "Action": [
                "secretsmanager:GetSecretValue",
                "secretsmanager:BatchGetSecretValue",
                "ssm:GetParameter*",
                "cognito-idp:AdminGetUser",
                "cognito-idp:ListUsers",
                "sts:AssumeRole",
            ],
        },
    ]


def _compact_policy(statements: list[dict[str, Any]]) -> str:
    """Serialize the managed boundary and fail before exceeding IAM's quota."""
    for statement in statements:
        for key in ("Action", "Resource", "NotResource"):
            value = statement.get(key)
            if isinstance(value, list) and len(value) == 1:
                statement[key] = value[0]
        for conditions in statement.get("Condition", {}).values():
            for key, value in conditions.items():
                if isinstance(value, list) and len(value) == 1:
                    conditions[key] = value[0]
    policy = json.dumps(
        {"Version": "2012-10-17", "Statement": statements},
        separators=(",", ":"),
        sort_keys=True,
    )
    if len(policy) > 6144:
        raise ValueError(
            f"Platform boundary exceeds IAM 6144-character limit: {len(policy)}"
        )
    return policy


def _is_control_role_denial(statement: dict[str, Any]) -> bool:
    """Distinguish role edits from the independent PassRole denial."""
    return (
        statement["Effect"] == "Deny"
        and "NotResource" in statement
        and statement.get("Action") != ["iam:PassRole"]
    )


def _is_key_management(actions: list[str]) -> bool:
    """Recognize only the tagged key-management action group."""
    return (
        bool(actions)
        and all(action.startswith("kms:") for action in actions)
        and ("kms:CancelKeyDeletion" in actions)
    )


def _compress_sensitive_statements(statements: list[dict[str, Any]]) -> None:
    """Compact safe verb families without relaxing IAM boundary requirements."""
    for statement in statements:
        actions = statement.get("Action", [])
        if statement["Effect"] == "Deny" and "secretsmanager:GetSecretValue" in actions:
            statement["Action"] = [
                "secretsmanager:*GetSecretValue",
                "ssm:GetParameter*",
                "cognito-idp:*User*",
                "sts:AssumeRole",
            ]
        elif actions == ROLE_MUTATIONS:
            statement["Action"] = [
                "iam:*RolePolicy",
                "iam:CreateRole",
                "iam:DeleteRole",
                "iam:UpdateAssumeRolePolicy",
                "iam:UpdateRole*",
                "iam:PutRolePermissionsBoundary",
            ]
        elif _is_control_role_denial(statement):
            statement["Action"] = [
                "iam:Put*",
                "iam:DeleteRole*",
                "iam:Attach*",
                "iam:Detach*",
                "iam:Update*",
                "iam:CreateRole",
                "iam:*tagRole",
            ]
        elif _is_key_management(actions):
            statement["Action"] = [
                "kms:CancelKeyDeletion",
                "kms:*Grant",
                "kms:DescribeKey",
                "kms:DisableKey",
                "kms:EnableKey*",
                "kms:GetKey*",
                "kms:ListGrants",
                "kms:ListResourceTags",
                "kms:PutKeyPolicy",
                "kms:ScheduleKeyDeletion",
                "kms:*tagResource",
                "kms:UpdateKeyDescription",
            ]


def _boundary_statement_group(statement: dict[str, Any], actions: list[str]) -> str:
    """Choose a compaction group while preserving sensitive conditions."""
    if actions == ["secretsmanager:DescribeSecret"]:
        return "global"
    service_allow = statement["Effect"] == "Allow" and all(
        not action.startswith(("iam:", "sts:", "kms:", "ce:")) for action in actions
    )
    if (
        service_allow
        and statement.get("Resource") != "*"
        and "Condition" not in statement
    ):
        return "service"
    if (
        statement["Effect"] == "Allow"
        and statement.get("Resource") == "*"
        and "Condition" not in statement
    ):
        return "global"
    return "sensitive"


_GUARD_ONLY_IAM_DENIALS = (
    "DenyControllerIamChanges",
    "DenyPolicyAndIdentityProviderChanges",
    "DenyControllerPassRole",
)


def _boundary_source_groups(
    source: dict[str, Any],
) -> tuple[list[dict[str, Any]], set[str], set[str], set[str]]:
    """Separate scoped service ceilings from IAM/KMS and explicit denials."""
    statements = []
    service_actions: set[str] = set()
    service_resources: set[str] = set()
    global_actions: set[str] = set()
    for statement in source["Statement"]:
        # Backup's immutable ceiling caps broad attachments. These two denials
        # remain in fine identity policies and immutable operator-owned guards.
        if statement["Sid"] in (
            "DenyAdministratorAttachments",
            "DenyForeignRepositoryKms",
            *_GUARD_ONLY_IAM_DENIALS,
        ):
            continue
        result = {key: value for key, value in statement.items() if key != "Sid"}
        actions = result.get("Action", [])
        actions = [actions] if isinstance(actions, str) else actions
        group = _boundary_statement_group(result, actions)
        if group == "service":
            service_actions.update(action.split(":")[0] + ":*" for action in actions)
            resources = result["Resource"]
            service_resources.update(
                [resources] if isinstance(resources, str) else resources
            )
        elif group == "global":
            global_actions.update(actions)
        else:
            statements.append(result)
    return statements, service_actions, service_resources, global_actions


def _is_tagged_creation(statement, settings):
    """Only combine the reviewed create shapes; retain any added restrictions."""
    purposes = {
        "ce:CreateAnomalyMonitor": "cost-anomaly-monitor",
        "ce:CreateAnomalySubscription": "cost-anomaly-subscription",
        "guardduty:CreateDetector": "security-detection",
    }
    actions = statement.get("Action", [])
    if len(actions) != 1 or actions[0] not in purposes:
        return False
    return statement.get("Effect") == "Allow" and statement.get("Condition") == {
        "StringEquals": {
            "aws:RequestTag/Environment": settings.environment,
            "aws:RequestTag/Purpose": purposes[actions[0]],
        }
    }


def _coalesce_tagged_creation(
    statements: list[dict[str, Any]], settings: BootstrapSettings
) -> list[dict[str, Any]]:
    """Keep exact create actions behind the common project/environment ceiling."""
    creates = [item for item in statements if _is_tagged_creation(item, settings)]
    if not creates:
        return statements
    statements = [statement for statement in statements if statement not in creates]
    statements.append(
        {
            "Effect": "Allow",
            "Action": [
                action for statement in creates for action in statement["Action"]
            ],
            "Resource": "*",
            "Condition": {
                "StringEquals": {
                    "aws:RequestTag/Environment": settings.environment,
                    "aws:RequestTag/Project": settings.repo,
                }
            },
        }
    )
    return statements


def _is_tagged_management(statement, settings):
    """Retain foreign service grants and any additional condition restrictions."""
    purpose = (
        statement.get("Condition", {})
        .get("StringEquals", {})
        .get("aws:ResourceTag/Purpose")
    )
    if purpose not in (
        "cost-anomaly-monitor",
        "cost-anomaly-subscription",
        "security-detection",
    ):
        return False
    return (
        statement.get("Effect") == "Allow"
        and all(
            action.startswith(("ce:", "guardduty:")) for action in statement["Action"]
        )
        and statement.get("Condition")
        == {
            "StringEquals": {
                "aws:ResourceTag/Environment": settings.environment,
                "aws:ResourceTag/Purpose": purpose,
            }
        }
    )


def _coalesce_tagged_management(
    statements: list[dict[str, Any]], settings: BootstrapSettings
) -> list[dict[str, Any]]:
    """Share the CE/GD ceiling; exact Purpose constraints stay in identities."""
    managed = [item for item in statements if _is_tagged_management(item, settings)]
    if not managed:
        return statements
    remaining = [statement for statement in statements if statement not in managed]
    remaining.append(
        {
            "Effect": "Allow",
            "Action": sorted({action for item in managed for action in item["Action"]}),
            "Resource": sorted({arn for item in managed for arn in item["Resource"]}),
            "Condition": {
                "StringEquals": {
                    "aws:ResourceTag/Environment": settings.environment,
                    "aws:ResourceTag/Project": settings.repo,
                }
            },
        }
    )
    return remaining


def _coalesced_service_grants(
    account_id: str,
    service_actions: set[str],
    service_resources: set[str],
    global_actions: set[str],
) -> list[dict[str, Any]]:
    """Combine scoped service grants and remove only redundant budget ARNs."""
    # Account-wide budget ViewBudget already requires the budget/* resource.
    # Remove only ARNs contained in that existing resource, without widening it.
    budget_all = f"arn:aws:budgets::{account_id}:budget/*"
    if budget_all in service_resources:
        service_resources = {
            arn
            for arn in service_resources
            if not arn.startswith(budget_all[:-1]) or arn == budget_all
        }
    return [
        {
            "Effect": "Allow",
            "Action": sorted(service_actions),
            "Resource": sorted(service_resources),
        },
        {"Effect": "Allow", "Action": sorted(global_actions), "Resource": "*"},
    ]


def _coalesce_service_linked_roles(
    statements: list[dict[str, Any]], account_id: str
) -> list[dict[str, Any]]:
    """Retain exact AWSServiceName values when combining linked-role grants."""
    linked_roles = [
        statement
        for statement in statements
        if statement.get("Action") == ["iam:CreateServiceLinkedRole"]
    ]
    statements = [
        statement for statement in statements if statement not in linked_roles
    ]
    linked_services = []
    for statement in linked_roles:
        names = statement["Condition"]["StringEquals"]["iam:AWSServiceName"]
        linked_services.extend([names] if isinstance(names, str) else names)
    statements.append(
        {
            "Effect": "Allow",
            "Action": "iam:CreateServiceLinkedRole",
            "Resource": f"arn:aws:iam::{account_id}:role/aws-service-role/*",
            "Condition": {
                "StringEquals": {"iam:AWSServiceName": sorted(set(linked_services))}
            },
        }
    )
    return statements


def platform_control_boundary(
    account_id: str, settings: BootstrapSettings, repo_name: str
) -> str:
    """Cap service/resource families; identity policies retain exact verb grants."""
    from .automation import _automation_policy

    source = json.loads(_automation_policy(account_id, settings, repo_name))
    statements, service_actions, service_resources, global_actions = (
        _boundary_source_groups(source)
    )
    _compress_sensitive_statements(statements)
    statements = _coalesce_tagged_creation(statements, settings)
    statements = _coalesce_tagged_management(statements, settings)
    statements.extend(
        _coalesced_service_grants(
            account_id, service_actions, service_resources, global_actions
        )
    )
    statements = _coalesce_service_linked_roles(statements, account_id)
    statements.append(
        {
            "Effect": "Allow",
            "Action": ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"],
            "Resource": f"arn:aws:kms:*:{account_id}:key/*",
            "Condition": {
                "ForAnyValue:StringEquals": {
                    "kms:ResourceAliases": _platform_secrets_alias(settings)
                }
            },
        }
    )
    bucket = f"arn:aws:s3:::{settings.state_bucket_name_for_repo(repo_name)}"
    statements.append(
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject*", "s3:PutObject", "s3:DeleteObject*"],
            "Resource": bucket + "/*",
        }
    )
    return _compact_policy(statements)


def _platform_secrets_alias(settings: BootstrapSettings) -> str:
    """Match the canonical provider's environment normalization."""
    environment = settings.sanitize_bucket_component(
        settings.environment, "environment"
    ).replace(".", "-")
    return f"alias/pulumi-platform-bootstrap-{environment}"


def platform_workload_boundaries(
    account_id: str,
    settings: BootstrapSettings,
    region: str,
    repositories: Sequence[ManagedRepository],
) -> dict[str, str]:
    """Build exact replication and bounded S3 Backup ceilings."""
    from .backup import _restore_drill_policy
    from .logging_bucket import _replica_bucket_name, _replication_role_policy

    replica_region = settings.replication_region or "eu-west-1"
    log_bucket = settings.central_logging_bucket_name(region)
    state_buckets = [
        settings.state_bucket_name_for_repo(repo.name) for repo in repositories
    ]
    state_statements = []
    for bucket in state_buckets:
        state_statements.extend(
            json.loads(
                _replication_role_policy(
                    [
                        f"arn:aws:s3:::{bucket}",
                        f"arn:aws:s3:::{_replica_bucket_name(bucket, replica_region)}",
                    ]
                )
            )["Statement"]
        )
    log_policy = _replication_role_policy(
        [
            f"arn:aws:s3:::{log_bucket}",
            f"arn:aws:s3:::{_replica_bucket_name(log_bucket, replica_region)}",
        ]
    )
    buckets = [f"arn:aws:s3:::{bucket}" for bucket in [log_bucket, *state_buckets]]
    backup: list[dict[str, Any]] = [
        {
            "Effect": "Allow",
            "Action": [
                "cloudwatch:GetMetricData",
                "events:ListRules",
                "s3:ListAllMyBuckets",
            ],
            "Resource": "*",
        },
        {
            "Effect": "Allow",
            "Action": [
                "events:DeleteRule",
                "events:PutTargets",
                "events:DescribeRule",
                "events:EnableRule",
                "events:PutRule",
                "events:RemoveTargets",
                "events:ListTargetsByRule",
                "events:DisableRule",
            ],
            "Resource": f"arn:aws:events:*:{account_id}:rule/AwsBackupManagedRule*",
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:GetBucketTagging",
                "s3:GetInventoryConfiguration",
                "s3:ListBucketVersions",
                "s3:ListBucket",
                "s3:GetBucketVersioning",
                "s3:GetBucketLocation",
                "s3:GetBucketAcl",
                "s3:PutInventoryConfiguration",
                "s3:GetBucketNotification",
                "s3:PutBucketNotification",
            ],
            "Resource": buckets,
        },
        {
            "Effect": "Allow",
            "Action": "s3:ListTagsForResource",
            "Resource": buckets,
            "Condition": {"StringEquals": {"aws:ResourceAccount": account_id}},
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:GetObjectAcl",
                "s3:GetObject",
                "s3:GetObjectVersionTagging",
                "s3:GetObjectVersionAcl",
                "s3:GetObjectTagging",
                "s3:GetObjectVersion",
            ],
            "Resource": [bucket + "/*" for bucket in buckets],
        },
        {
            "Effect": "Allow",
            "Action": "backup:TagResource",
            "Resource": f"arn:aws:backup:*:{account_id}:recovery-point:*",
        },
        *json.loads(_restore_drill_policy(account_id, "aws", settings))["Statement"],
    ]
    for statement in backup:
        if "kms:Decrypt" in statement.get("Action", []):
            statement["Condition"]["ForAnyValue:StringLike"]["kms:ResourceAliases"] = [
                settings.pulumi_secrets_alias_name_for_repo(repo.name)
                for repo in repositories
            ] + [
                _platform_secrets_alias(settings),
                f"alias/bootstrap-{settings.environment}-operations-cloudtrail",
            ]
    return {
        "state-replication": _compact_policy(state_statements),
        "log-replication": _compact_policy(json.loads(log_policy)["Statement"]),
        "backup": _compact_policy(backup),
    }


class PlatformIamBoundaries(pulumi.ComponentResource):
    """Provision immutable policy ceilings solely in the operator stack."""

    def __init__(
        self,
        name: str,
        *,
        settings: BootstrapSettings,
        account_id: str,
        region: str,
        repositories: Sequence[ManagedRepository],
        opts: pulumi.ResourceOptions | None = None,
    ) -> None:
        super().__init__("bootstrap:iam:PlatformIamBoundaries", name, None, opts)
        documents = platform_workload_boundaries(
            account_id, settings, region, repositories
        )
        documents["control"] = platform_control_boundary(
            account_id, settings, settings.repo or ""
        )
        self.policies = {}
        for purpose, document in documents.items():
            policy_name = platform_boundary_arn(account_id, settings, purpose).split(
                "/"
            )[-1]
            self.policies[purpose] = aws.iam.Policy(
                f"{name}-{purpose}",
                name=policy_name,
                policy=document,
                tags=base_tags(
                    {"Purpose": "platform-permissions-boundary"}, settings=settings
                ),
                opts=pulumi.ResourceOptions(parent=self, protect=True),
            )
        self.register_outputs(
            {"boundaryArns": {key: policy.arn for key, policy in self.policies.items()}}
        )


def _state_replication_logical_key(repository: str) -> str:
    """Preserve old URNs except the previously colliding reserved logs name."""
    return "state:logs" if repository == "logs" else repository


class PlatformReplicationIam(pulumi.ComponentResource):
    """Operator-owned fixed platform replication roles with independent ceilings."""

    def __init__(
        self,
        name: str,
        *,
        settings: BootstrapSettings,
        repositories: Sequence[ManagedRepository],
        account_id: str,
        region: str,
        boundary_arns: Mapping[str, pulumi.Input[str]],
        partition: str = "aws",
        adopt_existing: bool = False,
        opts: pulumi.ResourceOptions | None = None,
    ) -> None:
        super().__init__("bootstrap:iam:PlatformReplicationIam", name, None, opts)
        from .automation import _iam_role_exists
        from .iam.adoption import inline_policy_name
        from .logging_bucket import (
            _replica_bucket_name,
            _replication_assume_role_policy,
            _replication_role_policy,
        )
        from .pulumi_state import (
            _replication_role_name,
            _replication_role_suffix,
            _resource_suffix,
        )

        primary_log = settings.central_logging_bucket_name(region)
        entries = [
            (
                ("logs", ""),
                "logs",
                platform_role_name(settings, "log-replication"),
                primary_log,
                "central-logging-replication-role-policy",
                "log-replication",
            )
        ]
        entries.extend(
            (
                ("state", repo.name),
                _state_replication_logical_key(repo.name),
                _replication_role_name(
                    _replication_role_suffix(repo.name, settings_obj=settings)
                ),
                settings.state_bucket_name_for_repo(repo.name),
                (
                    "pulumi-state-replication-role-policy-"
                    f"{_resource_suffix(repo.name, settings)}"
                ),
                "state-replication",
            )
            for repo in repositories
        )
        self.roles = {}
        self.namespaced_roles = {}
        for identity, key, role_name, bucket, old_prefix, purpose in entries:
            source = f"arn:{partition}:s3:::{bucket}"
            replica = _replica_bucket_name(
                bucket, settings.replication_region or "eu-west-1"
            )
            existing_role = adopt_existing and _iam_role_exists(role_name)
            old_policy = (
                inline_policy_name(role_name, old_prefix) if existing_role else None
            )
            role = aws.iam.Role(
                f"{name}-{key}-role",
                name=role_name,
                assume_role_policy=_replication_assume_role_policy(source, account_id),
                permissions_boundary=boundary_arns[purpose],
                tags=base_tags({"Purpose": purpose}, settings=settings),
                opts=pulumi.ResourceOptions(
                    parent=self,
                    protect=True,
                    import_=role_name if existing_role else None,
                ),
            )
            aws.iam.RolePolicy(
                f"{name}-{key}-policy",
                role=role.name,
                name=old_policy,
                policy=_replication_role_policy(
                    [source, f"arn:{partition}:s3:::{replica}"]
                ),
                opts=pulumi.ResourceOptions(
                    parent=self,
                    protect=True,
                    import_=f"{role_name}:{old_policy}" if old_policy else None,
                ),
            )
            self.roles[key] = role
            self.namespaced_roles[identity] = role
        self.register_outputs(
            {"roleArns": {key: role.arn for key, role in self.roles.items()}}
        )
