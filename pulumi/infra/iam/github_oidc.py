"""GitHub OIDC provider and per-repository deploy roles."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import cast

import pulumi_aws as aws

import pulumi

from ..bootstrap_settings import BootstrapSettings
from ..config import managed_repositories, settings
from ..managed_repository import ManagedRepository
from ..utils.outputs import apply_output
from ..utils.tags import base_tags

_ROLE_NAME_PREFIX = "PulumiDeploy-"
_MAX_IAM_ROLE_NAME_LENGTH = 64


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


def _assume_role_policy(arn: str, org: str, repo_name: str, branch_name: str) -> str:
    """Build the OIDC trust policy for a specific GitHub repo and branch."""
    return f"""
{{
  "Version": "2012-10-17",
  "Statement": [
    {{
      "Effect": "Allow",
      "Principal": {{
        "Federated": "{arn}"
      }},
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {{
        "StringEquals": {{
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        }},
        "StringLike": {{
          "token.actions.githubusercontent.com:sub":
            "repo:{org}/{repo_name}:ref:refs/heads/{branch_name}"
        }}
      }}
    }}
  ]
}}
"""


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
    arn: str, org: str, repo_name: str, branch_name: str
) -> str:
    """Typed wrapper used by Pulumi Output.apply during OIDC trust policy creation."""
    return _assume_role_policy(arn, org, repo_name, branch_name)


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
) -> aws.iam.OpenIdConnectProvider:
    """Return the shared GitHub Actions OIDC provider resource."""
    if settings_obj.github_oidc_provider_arn:
        return aws.iam.OpenIdConnectProvider.get(
            f"{name}-provider",
            settings_obj.github_oidc_provider_arn,
            opts=pulumi.ResourceOptions(parent=parent),
        )
    return aws.iam.OpenIdConnectProvider(
        f"{name}-provider",
        client_id_lists=["sts.amazonaws.com"],
        thumbprint_lists=[
            "6938fd4d98bab03faadb97b34396831e3780aea1",
            "1c58a3a8518e8759bf075b76b750d4f2df264fcd",
        ],
        url="https://token.actions.githubusercontent.com",
        opts=pulumi.ResourceOptions(parent=parent),
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
        opts: pulumi.ResourceOptions | None = None,
    ) -> None:
        """Initialize OIDC provider and deploy roles for repositories."""
        super().__init__("bootstrap:iam:GitHubOidcRoles", name, None, opts)

        self._settings = settings or globals()["settings"]
        self.provider = _provider_resource(name, self, self._settings)
        self.deploy_role_arns: dict[str, pulumi.Output[str]] = {}

        repos = (
            list(repositories) if repositories is not None else managed_repositories()
        )
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
            component_name,
            repo_name=repo.name,
            repo_suffix=repo_suffix,
            branch_name=self._settings.github_branch or repo.default_branch or "main",
            repository_project=repo.project_name,
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
        aws.iam.RolePolicy(
            f"{component_name}-policy-{repo_suffix}",
            role=role.id,
            policy=policy,
            opts=pulumi.ResourceOptions(parent=self),
        )
        return role.arn

    def _deploy_role_resource(
        self,
        component_name: str,
        *,
        repo_name: str,
        repo_suffix: str,
        branch_name: str,
        repository_project: str,
    ) -> aws.iam.Role:
        """Create or import the IAM role used by GitHub Actions for one repo."""
        role_name = _role_name_for_suffix(repo_suffix)
        if _role_exists(role_name):
            return aws.iam.Role.get(
                f"{component_name}-role-{repo_suffix}",
                role_name,
                opts=pulumi.ResourceOptions(parent=self),
            )
        assume_role_policy = apply_output(
            self.provider.arn,
            lambda arn: _assume_role_policy_for_repo(
                arn,
                self._settings.org,
                repo_name,
                branch_name,
            ),
        )
        return aws.iam.Role(
            f"{component_name}-role-{repo_suffix}",
            name=role_name,
            assume_role_policy=assume_role_policy,
            tags=base_tags(
                {
                    "Purpose": "pulumi-deploy",
                    "Repository": repo_name,
                    "App": repo_name,
                    "RepositoryProject": repository_project,
                },
                settings=self._settings,
            ),
            opts=pulumi.ResourceOptions(parent=self),
        )
