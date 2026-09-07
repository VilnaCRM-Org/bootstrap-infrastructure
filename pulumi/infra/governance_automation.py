"""Operator-owned governance runners and immutable service IAM boundaries.

The bootstrap project owns these resources. Governance can manage only the
catalogued service resources and cannot edit these policies or its own roles.
The initial service boundary supports state access and CI configuration only;
new workload capabilities require an explicit reviewed boundary update.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from urllib.parse import urlsplit

import pulumi_aws as aws

import pulumi

from .bootstrap_settings import BootstrapSettings
from .ci_bootstrap import _ci_role_name, _ci_secret_suffixes
from .ci_config import (
    _ci_config_project,
    _ci_config_read_role_name,
    _role_permissions_boundary,
)
from .github_identity import (
    expand_subjects,
    identity_conditions,
    validate_trust_policy_size,
)
from .managed_repository import ManagedRepository
from .pulumi_state import (
    DEFAULT_REPLICATION_REGION,
    _replica_bucket_name,
    _replication_role_name,
    _replication_role_policy,
    _replication_role_suffix,
)
from .utils.outputs import apply_output
from .utils.tags import base_tags

_IAM_READ = (
    "iam:GetRole",
    "iam:GetRolePolicy",
    "iam:ListRolePolicies",
    "iam:ListAttachedRolePolicies",
    "iam:ListRoleTags",
)
_IAM_EDIT = (
    "iam:CreateRole",
    "iam:PutRolePolicy",
    "iam:DeleteRolePolicy",
    "iam:AttachRolePolicy",
    "iam:DetachRolePolicy",
    "iam:PutRolePermissionsBoundary",
)
_POLICY_READ = (
    "iam:GetPolicy",
    "iam:GetPolicyVersion",
    "iam:ListPolicyVersions",
    "iam:ListPolicyTags",
    "iam:ListEntitiesForPolicy",
)
_POLICY_EDIT = (
    "iam:CreatePolicy",
    "iam:CreatePolicyVersion",
    "iam:DeletePolicyVersion",
    "iam:SetDefaultPolicyVersion",
    "iam:DeletePolicy",
    "iam:TagPolicy",
    "iam:UntagPolicy",
)
_S3_READ = (
    "s3:ListBucket",
    "s3:GetBucketLocation",
    "s3:GetBucketVersioning",
    "s3:GetBucketTagging",
    "s3:GetBucketPolicy",
    "s3:GetBucketPublicAccessBlock",
    "s3:GetBucketOwnershipControls",
    "s3:GetEncryptionConfiguration",
    "s3:GetLifecycleConfiguration",
    "s3:GetBucketLogging",
    "s3:GetReplicationConfiguration",
    "s3:GetBucketAcl",
    "s3:GetBucketPolicyStatus",
    "s3:GetBucketWebsite",
    "s3:GetAccelerateConfiguration",
    "s3:GetBucketRequestPayment",
    "s3:GetBucketCORS",
    "s3:GetBucketObjectLockConfiguration",
)
_S3_EDIT = (
    "s3:CreateBucket",
    "s3:DeleteBucket",
    "s3:PutBucketVersioning",
    "s3:PutBucketTagging",
    "s3:PutBucketPolicy",
    "s3:DeleteBucketPolicy",
    "s3:PutBucketPublicAccessBlock",
    "s3:PutBucketOwnershipControls",
    "s3:PutEncryptionConfiguration",
    "s3:PutLifecycleConfiguration",
    "s3:PutBucketLogging",
    "s3:PutReplicationConfiguration",
)
_KMS_READ = (
    "kms:DescribeKey",
    "kms:GetKeyPolicy",
    "kms:GetKeyRotationStatus",
    "kms:ListResourceTags",
)
_KMS_USE = (
    "kms:Decrypt",
    "kms:Encrypt",
    "kms:GenerateDataKey",
    "kms:DescribeKey",
    "kms:ReEncryptFrom",
    "kms:ReEncryptTo",
)
_KMS_EDIT = (
    "kms:PutKeyPolicy",
    "kms:EnableKeyRotation",
    "kms:DisableKeyRotation",
    "kms:UpdateKeyDescription",
    "kms:ScheduleKeyDeletion",
    "kms:CancelKeyDeletion",
    "kms:EnableKey",
    "kms:DisableKey",
)
_SECRET_READ = (
    "secretsmanager:DescribeSecret",
    "secretsmanager:GetResourcePolicy",
    "secretsmanager:ListSecretVersionIds",
    "secretsmanager:GetSecretValue",
)
_SECRET_EDIT = (
    "secretsmanager:CreateSecret",
    "secretsmanager:UpdateSecret",
    "secretsmanager:DeleteSecret",
    "secretsmanager:RestoreSecret",
    "secretsmanager:PutSecretValue",
    "secretsmanager:UpdateSecretVersionStage",
    "secretsmanager:TagResource",
    "secretsmanager:UntagResource",
)


@dataclass(frozen=True)
class GovernanceAutomationArgs:
    """Explicit account, backend and catalog inputs; no ambient fallbacks.

    ``external_role_boundaries`` retains independently owned boundaries and must
    cover all three governor roles. Service-boundary creation is unchanged.
    """

    settings: BootstrapSettings
    repositories: Sequence[ManagedRepository]
    account_id: str
    region: str
    provider_arn: pulumi.Input[str]
    backend_url: str
    secrets_provider: str
    partition: str = "aws"
    protect_resources: bool = True
    external_role_boundaries: Mapping[str, str] | None = None


def assert_bootstrap_account(expected: str | None, actual: str) -> None:
    """Reject missing, malformed or mismatched account config before allocation."""
    if expected is None or re.fullmatch(r"[0-9]{12}", expected) is None:
        raise ValueError("github-ci-bootstrap requires a 12-digit awsAccountId")
    if actual != expected:
        raise ValueError(
            f"github-ci-bootstrap account mismatch: expected {expected}, got {actual}"
        )


def _document(statements: list[dict[str, object]]) -> str:
    """Render deterministic policy JSON and enforce the managed policy limit."""
    document = json.dumps(
        {"Version": "2012-10-17", "Statement": statements},
        sort_keys=True,
        separators=(",", ":"),
    )
    if len(document) > 6144:
        raise ValueError("governance policy exceeds the 6144-character IAM limit")
    return document


def _allow(
    actions: Sequence[str],
    resources: Sequence[str],
    condition: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Build one scoped Allow statement."""
    statement: dict[str, object] = {
        "Effect": "Allow",
        "Action": list(actions),
        "Resource": list(resources),
    }
    if condition:
        statement["Condition"] = condition
    return statement


def _iam_arn(args: GovernanceAutomationArgs, kind: str, name: str) -> str:
    """Resolve an account-local IAM ARN."""
    return f"arn:{args.partition}:iam::{args.account_id}:{kind}/{name}"


def _key_arn(args: GovernanceAutomationArgs) -> str:
    """Return account/region key scope; callers must add alias or tag conditions."""
    return f"arn:{args.partition}:kms:{args.region}:{args.account_id}:key/*"


def _boundary_name(args: GovernanceAutomationArgs, repo: ManagedRepository) -> str:
    """Match the service component's canonical project naming."""
    project = _ci_config_project(args.settings, repo.name)
    return f"GovernanceBoundary-{project}-{args.settings.environment}"


def _replication_boundary_name(
    args: GovernanceAutomationArgs, repo: ManagedRepository
) -> str:
    """Return the separately constrained S3 replication boundary name."""
    project = _ci_config_project(args.settings, repo.name)
    return f"GovernanceReplicationBoundary-{project}-{args.settings.environment}"


def _repo_buckets(args: GovernanceAutomationArgs, repo: ManagedRepository) -> list[str]:
    """Resolve the same primary/replica bucket names as PulumiStateBuckets."""
    primary = args.settings.state_bucket_name_for_repo(repo.name)
    replica = _replica_bucket_name(
        primary, args.settings.replication_region or DEFAULT_REPLICATION_REGION
    )
    return [f"arn:{args.partition}:s3:::{name}" for name in (primary, replica)]


def _repo_secrets(args: GovernanceAutomationArgs, repo: ManagedRepository) -> list[str]:
    """Scope secrets to exact configured suffixes and AWS's six-character suffix."""
    project = _ci_config_project(args.settings, repo.name)
    return [
        f"arn:{args.partition}:secretsmanager:{args.region}:{args.account_id}:"
        f"secret:/{project}/ci/{suffix}-??????"
        for suffix in _ci_secret_suffixes(args.settings)
    ]


def _validate_backend(args: GovernanceAutomationArgs) -> tuple[str, str]:
    """Require a dedicated governance prefix and the account's platform alias."""
    error = "governance backend must be s3://<bucket>/governance"
    if re.search(r"[%\\\x00-\x20]", args.backend_url):
        raise ValueError(error)
    try:
        backend = urlsplit(args.backend_url)
    except ValueError:
        raise ValueError(error) from None
    if (
        backend.scheme != "s3"
        or not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", backend.netloc)
        or backend.query
        or backend.fragment
        or backend.path != "/governance"
    ):
        raise ValueError(error)
    expected = (
        f"awskms://alias/pulumi-platform-bootstrap-{args.settings.environment}"
        f"?region={args.region}"
    )
    if args.secrets_provider != expected:
        raise ValueError("governance secrets provider must use the platform KMS alias")
    if args.settings.environment not in {"test", "prod"}:
        raise ValueError("governance automation supports test and prod only")
    return f"arn:{args.partition}:s3:::{backend.netloc}", "governance"


def governance_backend_policy(
    args: GovernanceAutomationArgs, *, purpose: str = "apply"
) -> str:
    """Allow state/lock I/O only inside the dedicated governance prefix."""
    bucket, prefix = _validate_backend(args)
    return _document(
        [
            _allow(["s3:GetBucketLocation"], [bucket]),
            _allow(
                ["s3:ListBucket"],
                [bucket],
                {"StringLike": {"s3:prefix": [prefix, f"{prefix}/*"]}},
            ),
            _allow(
                [
                    "s3:GetObject",
                    "s3:GetObjectVersion",
                ],
                [f"{bucket}/{prefix}/*"],
            ),
            *(
                [
                    {
                        "Effect": "Deny",
                        "Action": ["s3:PutObject", "s3:DeleteObject"],
                        "NotResource": [f"{bucket}/{prefix}/.pulumi/locks/*"],
                    },
                    {
                        "Effect": "Deny",
                        "Action": ["s3:DeleteObjectVersion"],
                        "Resource": "*",
                    },
                ]
                if purpose != "apply"
                else []
            ),
            _allow(
                ["s3:PutObject", "s3:DeleteObject"],
                [
                    f"{bucket}/{prefix}/*"
                    if purpose == "apply"
                    else f"{bucket}/{prefix}/.pulumi/locks/*"
                ],
            ),
            _allow(
                _KMS_USE,
                [_key_arn(args)],
                {
                    "ForAnyValue:StringEquals": {
                        "kms:ResourceAliases": [
                            f"alias/pulumi-platform-bootstrap-{args.settings.environment}"
                        ]
                    }
                },
            ),
        ]
    )


def governance_trust_policy(
    args: GovernanceAutomationArgs, purpose: str, provider_arn: str
) -> str:
    """Bind normal workflow OIDC to repository, main ref and protected environment."""
    if purpose not in {"preview", "drift", "apply"}:
        raise ValueError("unsupported governance role purpose")
    expected_provider = _iam_arn(
        args, "oidc-provider", "token.actions.githubusercontent.com"
    )
    if provider_arn != expected_provider:
        raise ValueError("governance OIDC provider must belong to the target account")
    repository = f"{args.settings.org}/{args.settings.repo}"
    environment = "governance" if purpose == "apply" else "governance-preview"
    document = _document(
        [
            {
                "Effect": "Allow",
                "Action": ["sts:AssumeRoleWithWebIdentity"],
                "Principal": {"Federated": provider_arn},
                "Condition": {
                    "StringEquals": {
                        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
                        "token.actions.githubusercontent.com:sub": expand_subjects(
                            [f"repo:{repository}:environment:{environment}"],
                            repository,
                            args.settings.github_repository_id,
                            args.settings.github_repository_owner_id,
                        ),
                        **identity_conditions(
                            args.settings.github_repository_id,
                            args.settings.github_repository_owner_id,
                        ),
                        "token.actions.githubusercontent.com:repository": repository,
                        "token.actions.githubusercontent.com:workflow": (
                            "Pulumi Governance Runner"
                        ),
                        "token.actions.githubusercontent.com:ref": (
                            f"refs/heads/{args.settings.github_branch or 'main'}"
                        ),
                    }
                },
            }
        ]
    )
    return validate_trust_policy_size(document)


def service_boundary_policy(
    args: GovernanceAutomationArgs, repo: ManagedRepository
) -> str:
    """Cap every service role at its own state, KMS alias and CI configuration."""
    primary = _repo_buckets(args, repo)[0]
    return _document(
        [
            _allow(["sts:GetCallerIdentity"], ["*"]),
            _allow(["s3:GetBucketLocation", "s3:ListBucket"], [primary]),
            _allow(
                [
                    "s3:GetObject",
                    "s3:GetObjectVersion",
                    "s3:PutObject",
                    "s3:DeleteObject",
                    "s3:DeleteObjectVersion",
                ],
                [f"{primary}/state/*", f"{primary}/.pulumi/*"],
            ),
            _allow(
                _KMS_USE,
                [_key_arn(args)],
                {
                    "ForAnyValue:StringEquals": {
                        "kms:ResourceAliases": [
                            args.settings.pulumi_secrets_alias_name_for_repo(repo.name)
                        ]
                    }
                },
            ),
            _allow(_SECRET_READ, _repo_secrets(args, repo)),
        ]
    )


def _role_resources(
    args: GovernanceAutomationArgs, repo: ManagedRepository
) -> tuple[list[str], str]:
    """Resolve exact deploy/config role ARNs and the replication role ARN."""
    project = _ci_config_project(args.settings, repo.name)
    names = [
        _ci_role_name(args.settings, purpose, project)
        for purpose in ("preview", "apply", "drift")
    ]
    names.extend(
        _ci_config_read_role_name(args.settings, suffix, project)
        for suffix in _ci_secret_suffixes(args.settings)
    )
    replication = _replication_role_name(
        _replication_role_suffix(repo.name, settings_obj=args.settings)
    )
    return (
        [_iam_arn(args, "role", name) for name in names],
        _iam_arn(args, "role", replication),
    )


def _managed_policy_resources(
    args: GovernanceAutomationArgs, repo: ManagedRepository
) -> list[str]:
    """Resolve only the two service-apply policy names; never boundary policies."""
    project = _ci_config_project(args.settings, repo.name)
    apply_name = _ci_role_name(args.settings, "apply", project)
    return [
        _iam_arn(args, "policy", f"{apply_name}-{suffix}")
        for suffix in ("pulumi-backend", "secret-read-deny")
    ]


def governance_repo_iam_policy(
    args: GovernanceAutomationArgs, repo: ManagedRepository, *, apply: bool
) -> str:
    """Manage exact service identities only with operator-owned boundaries."""
    service_roles, replica_role = _role_resources(args, repo)
    policy_arns = _managed_policy_resources(args, repo)
    boundaries = [
        _iam_arn(args, "policy", _boundary_name(args, repo)),
        _iam_arn(args, "policy", _replication_boundary_name(args, repo)),
    ]
    statements = [
        _allow(_IAM_READ, [*service_roles, replica_role]),
        _allow(_POLICY_READ, [*policy_arns, *boundaries]),
    ]
    if apply:
        for roles, boundary in (
            (service_roles, boundaries[0]),
            ([replica_role], boundaries[1]),
        ):
            statements.append(
                _allow(
                    _IAM_EDIT,
                    roles,
                    {"StringEquals": {"iam:PermissionsBoundary": boundary}},
                )
            )
        statements.extend(
            [
                _allow(
                    [
                        "iam:UpdateAssumeRolePolicy",
                        "iam:UpdateRole",
                        "iam:UpdateRoleDescription",
                        "iam:TagRole",
                        "iam:UntagRole",
                        "iam:DeleteRole",
                    ],
                    [*service_roles, replica_role],
                ),
                _allow(_POLICY_EDIT, policy_arns),
                _allow(
                    ["iam:PassRole"],
                    [replica_role],
                    {"StringEquals": {"iam:PassedToService": "s3.amazonaws.com"}},
                ),
                {
                    "Effect": "Deny",
                    "Action": ["iam:DeleteRolePermissionsBoundary"],
                    "Resource": [*service_roles, replica_role],
                },
            ]
        )
    return _document(statements)


def governance_repo_storage_policy(
    args: GovernanceAutomationArgs, repo: ManagedRepository, *, apply: bool
) -> str:
    """Manage repo bucket metadata, tagged keys and exact CI secrets."""
    keys = [_key_arn(args)]
    tags = {
        "StringEquals": {
            "aws:ResourceTag/Repository": repo.name,
            "aws:ResourceTag/Environment": args.settings.environment,
            "aws:ResourceTag/Purpose": "pulumi-secrets",
        }
    }
    alias = (
        f"arn:{args.partition}:kms:{args.region}:{args.account_id}:"
        f"{args.settings.pulumi_secrets_alias_name_for_repo(repo.name)}"
    )
    statements = [
        _allow(_S3_READ, _repo_buckets(args, repo)),
        _allow(_KMS_READ, keys, tags),
        _allow(_SECRET_READ, _repo_secrets(args, repo)),
    ]
    if apply:
        statements.extend(
            [
                _allow(_S3_EDIT, _repo_buckets(args, repo)),
                _allow(_KMS_EDIT, keys, tags),
                _allow(
                    ["kms:CreateKey"],
                    ["*"],
                    {
                        "StringEquals": {
                            "aws:RequestTag/Repository": repo.name,
                            "aws:RequestTag/Environment": args.settings.environment,
                            "aws:RequestTag/Purpose": "pulumi-secrets",
                        }
                    },
                ),
                _allow(
                    ["kms:TagResource"],
                    keys,
                    {
                        "StringEquals": {
                            **tags["StringEquals"],
                            "aws:RequestTag/Repository": repo.name,
                        },
                        "StringEqualsIfExists": {
                            "aws:RequestTag/Environment": args.settings.environment,
                            "aws:RequestTag/Purpose": "pulumi-secrets",
                        },
                    },
                ),
                _allow(
                    ["kms:CreateAlias", "kms:UpdateAlias", "kms:DeleteAlias"], [alias]
                ),
                _allow(
                    ["kms:CreateAlias", "kms:UpdateAlias", "kms:DeleteAlias"],
                    keys,
                    tags,
                ),
                _allow(_SECRET_EDIT, _repo_secrets(args, repo)),
            ]
        )
    return _document(statements)


def _validate_catalog(args: GovernanceAutomationArgs) -> None:
    """Reject overlapping resource namespaces before allocating any resources."""
    names = [repo.name for repo in args.repositories]
    canonical = [_ci_config_project(args.settings, name) for name in names]
    declared = [repo.project_name for repo in args.repositories]
    bootstrap_project = _ci_config_project(args.settings, args.settings.repo)
    if not names:
        raise ValueError("governance catalog must be nonempty")
    for namespace in (names, canonical, declared):
        if len(set(namespace)) != len(namespace):
            raise ValueError(
                "governance catalog must have unique names, "
                "canonical and declared projects"
            )
    if bootstrap_project in set(canonical) | set(declared):
        raise ValueError("governance catalog must exclude bootstrap projects")
    if 2 + 2 * len(names) > 10:
        raise ValueError("governance role exceeds the default 10 policy attachments")
    for repo in args.repositories:
        _role_resources(args, repo)


class GovernanceAutomation(pulumi.ComponentResource):
    """Create runner roles and immutable boundaries in the operator bootstrap stack."""

    def __init__(
        self,
        name: str,
        *,
        args: GovernanceAutomationArgs,
        opts: pulumi.ResourceOptions | None = None,
    ) -> None:
        _validate_backend(args)
        _validate_catalog(args)
        super().__init__("bootstrap:ci:GovernanceAutomation", name, None, opts)
        self.roles: dict[str, aws.iam.Role] = {}
        self.boundaries: dict[str, aws.iam.Policy] = {}
        for repo in args.repositories:
            self._create_boundaries(name, args, repo)
        for purpose in ("preview", "drift", "apply"):
            self._create_runner(name, args, purpose)
        prefix = f"AWS_GOVERNANCE_{args.settings.environment.upper()}"
        self.github_variables: dict[str, pulumi.Input[str]] = {
            f"{prefix}_ACCOUNT_ID": args.account_id,
            f"{prefix}_REGION": args.region,
            f"{prefix}_BACKEND_URL": args.backend_url,
            f"{prefix}_SECRETS_PROVIDER": args.secrets_provider,
            **{
                f"{prefix}_{purpose.upper()}_ROLE_ARN": role.arn
                for purpose, role in self.roles.items()
            },
        }
        self.register_outputs({"githubVariables": self.github_variables})

    def _create_boundaries(
        self, name: str, args: GovernanceAutomationArgs, repo: ManagedRepository
    ) -> None:
        """Create policies outside the delegated runner's mutation resource set."""
        documents = {
            _boundary_name(args, repo): service_boundary_policy(args, repo),
            _replication_boundary_name(args, repo): _replication_role_policy(
                _repo_buckets(args, repo)
            ),
        }
        for policy_name, document in documents.items():
            self.boundaries[policy_name] = aws.iam.Policy(
                f"{name}-{policy_name}",
                name=policy_name,
                policy=document,
                tags=base_tags(
                    {"Purpose": "governance-boundary"}, settings=args.settings
                ),
                opts=pulumi.ResourceOptions(
                    parent=self, protect=args.protect_resources
                ),
            )

    def _create_runner(
        self, name: str, args: GovernanceAutomationArgs, purpose: str
    ) -> None:
        """Create one protected runner role and separately sized policy attachments."""
        role_name = f"GitHubGovernance{purpose.title()}-{args.settings.environment}"
        role = aws.iam.Role(
            f"{name}-{purpose}",
            name=role_name,
            permissions_boundary=_role_permissions_boundary(
                role_name,
                account_id=args.account_id,
                partition=args.partition,
                external_role_boundaries=args.external_role_boundaries,
            ),
            assume_role_policy=apply_output(
                pulumi.Output.from_input(args.provider_arn),
                lambda arn: governance_trust_policy(args, purpose, arn),
            ),
            tags=base_tags(
                {"Purpose": f"governance-{purpose}"}, settings=args.settings
            ),
            opts=pulumi.ResourceOptions(parent=self, protect=args.protect_resources),
        )
        self.roles[purpose] = role
        documents = {
            "backend": governance_backend_policy(args, purpose=purpose),
            "metadata": _document(
                [
                    _allow(
                        [
                            "sts:GetCallerIdentity",
                            "kms:ListAliases",
                            "access-analyzer:ValidatePolicy",
                        ],
                        ["*"],
                    ),
                    _allow(
                        ["iam:GetOpenIDConnectProvider"],
                        [
                            _iam_arn(
                                args,
                                "oidc-provider",
                                "token.actions.githubusercontent.com",
                            )
                        ],
                    ),
                ]
            ),
        }
        for repo in args.repositories:
            documents[f"{repo.name}-iam"] = governance_repo_iam_policy(
                args, repo, apply=purpose == "apply"
            )
            documents[f"{repo.name}-storage"] = governance_repo_storage_policy(
                args, repo, apply=purpose == "apply"
            )
        for suffix, document in documents.items():
            policy = aws.iam.Policy(
                f"{name}-{purpose}-{suffix}",
                name=f"{role_name}-{suffix}",
                policy=document,
                tags=base_tags(
                    {"Purpose": f"governance-{purpose}"}, settings=args.settings
                ),
                opts=pulumi.ResourceOptions(
                    parent=self, protect=args.protect_resources
                ),
            )
            aws.iam.RolePolicyAttachment(
                f"{name}-{purpose}-{suffix}-attachment",
                role=role.name,
                policy_arn=policy.arn,
                opts=pulumi.ResourceOptions(
                    parent=self, protect=args.protect_resources
                ),
            )
