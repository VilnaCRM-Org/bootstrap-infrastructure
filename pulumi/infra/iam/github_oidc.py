"""GitHub OIDC provider and per-repository deploy roles."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import cast

import pulumi_aws as aws

import pulumi

from ..bootstrap_settings import BootstrapSettings
from ..config import managed_repositories, settings
from ..github_identity import expand_subjects, identity_conditions
from ..managed_repository import ManagedRepository
from ..repository_catalog import ManagedRepositoryCatalog
from ..utils.outputs import apply_output
from ..utils.tags import base_tags

_ROLE_NAME_PREFIX = "PulumiDeploy-"
_MAX_IAM_ROLE_NAME_LENGTH = 64
_GITHUB_OIDC_URL = "https://token.actions.githubusercontent.com"


@dataclass(frozen=True)
class _DeployRoleContext:
    """Static inputs needed to create or import one GitHub deploy role."""

    component_name: str
    repo_name: str
    repo_suffix: str
    branch_name: str
    repository_project: str
    repository_metadata: Mapping[str, str]
    repository_id: str | None = None
    repository_owner_id: str | None = None


def _role_exists(name: str) -> bool:
    """Return True when the IAM role already exists."""
    try:
        aws.iam.get_role(name=name)
    except Exception as exc:
        message = str(exc)
        if "NoSuchEntity" in message or "couldn't find resource" in message:
            return False
        raise
    else:
        return True


def _existing_github_oidc_provider_arn() -> str | None:
    """Return the account-level GitHub OIDC provider ARN when it already exists."""
    try:
        provider = aws.iam.get_open_id_connect_provider(url=_GITHUB_OIDC_URL)
    except Exception as exc:
        message = str(exc)
        if "NoSuchEntity" in message or "couldn't find resource" in message:
            return None
        raise
    return provider.arn


def _repo_suffix(repo_name: str, settings_obj: BootstrapSettings | None = None) -> str:
    """Return a readable role suffix that stays unique after normalization."""
    active_settings = settings_obj or settings
    base = active_settings.sanitize_bucket_component(repo_name, "repoSlug").replace(
        ".",
        "-",
    )
    normalized = repo_name.strip().lower()
    if normalized == base:
        return base
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:8]
    return f"{base}-{digest}"


def _truncate_role_suffix(repo_suffix: str) -> str:
    max_suffix_len = _MAX_IAM_ROLE_NAME_LENGTH - len(_ROLE_NAME_PREFIX)
    if len(repo_suffix) <= max_suffix_len:
        return repo_suffix
    digest = hashlib.sha256(repo_suffix.encode("utf-8")).hexdigest()[:8]
    truncated_len = max_suffix_len - len(digest) - 1
    truncated_len = max(truncated_len, 1)
    return f"{repo_suffix[:truncated_len]}-{digest}"


def _role_name_for_suffix(repo_suffix: str) -> str:
    return f"{_ROLE_NAME_PREFIX}{_truncate_role_suffix(repo_suffix)}"


def _assume_role_policy(
    arn: str,
    org: str,
    repo_name: str,
    branch_name: str,
    *,
    environment: str,
    repository_id: str | None = None,
    owner_id: str | None = None,
) -> str:
    """Bind the protected environment, immutable identity and protected branch."""
    repository = f"{org}/{repo_name}"
    branch_ref = f"refs/heads/{branch_name}"
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Federated": arn},
                    "Action": "sts:AssumeRoleWithWebIdentity",
                    "Condition": {
                        "StringEquals": {
                            "token.actions.githubusercontent.com:aud": (
                                "sts.amazonaws.com"
                            ),
                            "token.actions.githubusercontent.com:repository": (
                                repository
                            ),
                            "token.actions.githubusercontent.com:ref": branch_ref,
                            "token.actions.githubusercontent.com:sub": expand_subjects(
                                [f"repo:{repository}:environment:{environment}"],
                                repository,
                                repository_id,
                                owner_id,
                            ),
                            **identity_conditions(repository_id, owner_id),
                        }
                    },
                }
            ],
        },
        sort_keys=True,
    )


def _deploy_policy(
    bucket_arn: str, objects_arn: str, secrets_key_arn: str | None = None
) -> str:
    """Return the least-privilege policy for Pulumi state and secrets access."""
    statements = [
        {
            "Effect": "Allow",
            "Action": ["s3:ListBucket"],
            "Resource": bucket_arn,
            "Condition": {"StringLike": {"s3:prefix": "state/*"}},
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "s3:GetObjectVersion",
                "s3:PutObject",
                "s3:DeleteObject",
                "s3:DeleteObjectVersion",
            ],
            "Resource": objects_arn,
        },
    ]
    if secrets_key_arn:
        statements.append(
            {
                "Effect": "Allow",
                "Action": [
                    "kms:Decrypt",
                    "kms:Encrypt",
                    "kms:GenerateDataKey",
                    "kms:DescribeKey",
                    "kms:ReEncrypt*",
                ],
                "Resource": secrets_key_arn,
            }
        )
    return json.dumps({"Version": "2012-10-17", "Statement": statements})


def _assume_role_policy_for_repo(
    arn: str,
    org: str,
    repo_name: str,
    branch_name: str,
    *,
    environment: str,
    repository_id: str | None = None,
    owner_id: str | None = None,
) -> str:
    """Typed wrapper used by Pulumi Output.apply during OIDC trust policy creation."""
    return _assume_role_policy(
        arn,
        org,
        repo_name,
        branch_name,
        environment=environment,
        repository_id=repository_id,
        owner_id=owner_id,
    )


def _deploy_policy_from_values(values: Sequence[str | None]) -> str:
    """Build the deploy policy from Pulumi output values."""
    return _deploy_policy(
        cast(str, values[0]),
        cast(str, values[1]),
        values[2],
    )


def _provider_resource(
    name: str,
    parent: pulumi.ComponentResource,
    settings_obj: BootstrapSettings,
    *,
    manage_provider: bool | None = None,
    configured_provider_arn: pulumi.Input[str] | None = None,
) -> aws.iam.OpenIdConnectProvider:
    """Return the shared GitHub Actions OIDC provider resource."""
    provider_arn = configured_provider_arn or settings_obj.github_oidc_provider_arn
    if manage_provider is False and provider_arn is None:
        provider_arn = (
            f"arn:{aws.get_partition().partition}:iam::"
            f"{aws.get_caller_identity().account_id}:"
            "oidc-provider/token.actions.githubusercontent.com"
        )
    if provider_arn is None:
        provider_arn = _existing_github_oidc_provider_arn()
    if manage_provider is False or (manage_provider is None and provider_arn):
        return aws.iam.OpenIdConnectProvider.get(
            f"{name}-provider",
            provider_arn,
            opts=pulumi.ResourceOptions(parent=parent),
        )
    return aws.iam.OpenIdConnectProvider(
        f"{name}-provider",
        client_id_lists=["sts.amazonaws.com"],
        thumbprint_lists=[
            "6938fd4d98bab03faadb97b34396831e3780aea1",
            "1c58a3a8518e8759bf075b76b750d4f2df264fcd",
        ],
        tags=base_tags({"Purpose": "github-actions-oidc"}, settings=settings_obj),
        url=_GITHUB_OIDC_URL,
        opts=pulumi.ResourceOptions(parent=parent, import_=provider_arn),
    )


def _required_secret_key_arn(
    repo_name: str, secrets_key_arns: Mapping[str, pulumi.Input[str]] | None
) -> pulumi.Input[str] | None:
    """Return the secrets key ARN for one repository or raise when missing."""
    if secrets_key_arns is None:
        return None
    if repo_name not in secrets_key_arns:
        raise ValueError(
            f"Missing Pulumi secrets KMS key ARN for managed repository '{repo_name}'."
        )
    return secrets_key_arns[repo_name]


class GitHubOidcRoles(pulumi.ComponentResource):
    """Create the GitHub OIDC provider and per-repository deploy roles."""

    def __init__(
        self,
        name: str,
        *,
        repositories: Sequence[ManagedRepository] | None = None,
        secrets_key_arns: Mapping[str, pulumi.Input[str]] | None = None,
        settings: BootstrapSettings | None = None,
        manage_provider: bool | None = None,
        manage_roles: bool = True,
        provider_arn: pulumi.Input[str] | None = None,
        permissions_boundary: pulumi.Input[str] | None = None,
        adopt_existing_policies: bool = False,
        preferred_inline_policy_names: Mapping[str, str] | None = None,
        role_guard_factory: Callable[[str, aws.iam.Role], pulumi.Resource]
        | None = None,
        opts: pulumi.ResourceOptions | None = None,
    ) -> None:
        """Initialize OIDC provider and deploy roles for repositories."""
        super().__init__("bootstrap:iam:GitHubOidcRoles", name, None, opts)

        self._settings = settings or globals()["settings"]
        self.provider = _provider_resource(
            name,
            self,
            self._settings,
            manage_provider=manage_provider,
            configured_provider_arn=provider_arn,
        )
        self._manage_roles = manage_roles
        self._permissions_boundary = permissions_boundary
        self._adopt_existing_policies = adopt_existing_policies
        self._preferred_inline_policy_names = preferred_inline_policy_names or {}
        self._role_guard_factory = role_guard_factory
        self.deploy_role_arns: dict[str, pulumi.Output[str]] = {}

        if repositories is not None:
            repos = list(repositories)
        elif settings is not None:
            repos = ManagedRepositoryCatalog.from_settings(self._settings).repositories
        else:
            repos = managed_repositories()
        for repo in repos:
            self.deploy_role_arns[repo.name] = self._create_deploy_role(
                name,
                repo,
                secrets_key_arns=secrets_key_arns,
            )

        self.register_outputs({"deploy_role_arns": self.deploy_role_arns})

    def _create_deploy_role(
        self,
        component_name: str,
        repo: ManagedRepository,
        *,
        secrets_key_arns: Mapping[str, pulumi.Input[str]] | None,
    ) -> pulumi.Output[str]:
        """Create or import the deploy role and attach its least-privilege policy."""
        bucket_name = self._settings.state_bucket_name_for_repo(repo.name)
        repo_suffix = _repo_suffix(repo.name, self._settings)
        role = self._deploy_role_resource(
            _DeployRoleContext(
                component_name=component_name,
                repo_name=repo.name,
                repo_suffix=repo_suffix,
                branch_name=self._settings.github_branch
                or repo.default_branch
                or "main",
                repository_project=repo.project_name,
                repository_metadata=repo.tag_metadata(),
                repository_id=repo.repository_id,
                repository_owner_id=repo.repository_owner_id,
            )
        )
        if not self._manage_roles:
            return role.arn
        guard_dependencies = (
            [self._role_guard_factory(repo.name, role)]
            if self._role_guard_factory is not None
            else []
        )
        key_arn = _required_secret_key_arn(repo.name, secrets_key_arns)
        policy = apply_output(
            cast(
                pulumi.Output[Sequence[str | None]],
                pulumi.Output.all(
                    pulumi.Output.from_input(f"arn:aws:s3:::{bucket_name}"),
                    pulumi.Output.from_input(f"arn:aws:s3:::{bucket_name}/state/*"),
                    key_arn,
                ),
            ),
            _deploy_policy_from_values,
        )
        policy_name = f"{component_name}-policy-{repo_suffix}"
        existing_policy = None
        if self._adopt_existing_policies:
            from .adoption import inline_policy_name

            existing_policy = inline_policy_name(
                _role_name_for_suffix(repo_suffix),
                policy_name,
                **(
                    {"preferred_name": self._preferred_inline_policy_names[repo.name]}
                    if repo.name in self._preferred_inline_policy_names
                    else {}
                ),
            )
        aws.iam.RolePolicy(
            policy_name,
            name=existing_policy
            or (policy_name if self._adopt_existing_policies else None),
            role=role.id,
            policy=policy,
            opts=pulumi.ResourceOptions(
                parent=self,
                depends_on=guard_dependencies,
                import_=(
                    f"{_role_name_for_suffix(repo_suffix)}:{existing_policy}"
                    if existing_policy
                    else None
                ),
            ),
        )
        return role.arn

    def _deploy_role_resource(
        self,
        context: _DeployRoleContext,
    ) -> aws.iam.Role:
        """Create or import the IAM role used by GitHub Actions for one repo."""
        role_name = _role_name_for_suffix(context.repo_suffix)
        if not self._manage_roles:
            return aws.iam.Role.get(
                f"{context.component_name}-role-{context.repo_suffix}",
                role_name,
                opts=pulumi.ResourceOptions(parent=self),
            )
        existing_role = _role_exists(role_name)
        assume_role_policy = apply_output(
            self.provider.arn,
            lambda arn: _assume_role_policy_for_repo(
                arn,
                self._settings.org,
                context.repo_name,
                context.branch_name,
                environment=self._settings.environment,
                repository_id=context.repository_id,
                owner_id=context.repository_owner_id,
            ),
        )
        return aws.iam.Role(
            f"{context.component_name}-role-{context.repo_suffix}",
            name=role_name,
            permissions_boundary=self._permissions_boundary,
            assume_role_policy=assume_role_policy,
            tags=base_tags(
                {
                    "Purpose": "pulumi-deploy",
                    "Repository": context.repo_name,
                    "App": context.repo_name,
                    "RepositoryProject": context.repository_project,
                    **context.repository_metadata,
                },
                settings=self._settings,
            ),
            opts=pulumi.ResourceOptions(
                parent=self, import_=role_name if existing_role else None
            ),
        )
