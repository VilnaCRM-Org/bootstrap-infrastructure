"""GitHub OIDC provider and per-repository deploy roles."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import cast

import pulumi_aws as aws

import pulumi

from ..config import (
    ManagedRepository,
    managed_repositories,
    sanitize_bucket_component,
    settings,
    state_bucket_name_for_repo,
)
from ..utils.outputs import apply_output
from ..utils.tags import base_tags

_ROLE_NAME_PREFIX = "PulumiDeploy-"
_MAX_IAM_ROLE_NAME_LENGTH = 64


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
            "Action": ["s3:ListBucket", "s3:CreateBucket"],
            "Resource": bucket_arn,
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


class GitHubOidcRoles(pulumi.ComponentResource):
    """Create the GitHub OIDC provider and per-repository deploy roles."""

    def __init__(
        self,
        name: str,
        *,
        repositories: Sequence[ManagedRepository] | None = None,
        secrets_key_arns: Mapping[str, pulumi.Input[str]] | None = None,
        opts: pulumi.ResourceOptions | None = None,
    ) -> None:
        """Initialize OIDC provider and deploy roles for repositories."""
        super().__init__("bootstrap:iam:GitHubOidcRoles", name, None, opts)

        repos = (
            list(repositories) if repositories is not None else managed_repositories()
        )

        if settings.github_oidc_provider_arn:
            provider = aws.iam.OpenIdConnectProvider.get(
                f"{name}-provider",
                settings.github_oidc_provider_arn,
                opts=pulumi.ResourceOptions(parent=self),
            )
        else:
            provider = aws.iam.OpenIdConnectProvider(
                f"{name}-provider",
                client_id_lists=["sts.amazonaws.com"],
                thumbprint_lists=[
                    "6938fd4d98bab03faadb97b34396831e3780aea1",
                    "1c58a3a8518e8759bf075b76b750d4f2df264fcd",
                ],
                url="https://token.actions.githubusercontent.com",
                opts=pulumi.ResourceOptions(parent=self),
            )

        self.provider = provider
        self.deploy_role_arns: dict[str, pulumi.Output[str]] = {}

        for repo in repos:
            bucket_name = state_bucket_name_for_repo(repo.name)
            bucket_arn = pulumi.Output.from_input(f"arn:aws:s3:::{bucket_name}")
            objects_arn = pulumi.Output.from_input(
                f"arn:aws:s3:::{bucket_name}/state/*"
            )
            branch = settings.github_branch or repo.default_branch or "main"

            repo_suffix = sanitize_bucket_component(repo.name, "repoSlug").replace(
                ".", "-"
            )
            role_name = _role_name_for_suffix(repo_suffix)

            def build_assume_role_policy(
                arn: str, repo_name: str = repo.name, branch_name: str = branch
            ) -> str:
                return _assume_role_policy_for_repo(
                    arn,
                    settings.org,
                    repo_name,
                    branch_name,
                )

            assume_role_policy = apply_output(provider.arn, build_assume_role_policy)

            role = aws.iam.Role(
                f"{name}-role-{repo_suffix}",
                name=role_name,
                assume_role_policy=assume_role_policy,
                tags=base_tags(
                    {
                        "Purpose": "pulumi-deploy",
                        "Repository": repo.name,
                        "App": repo.name,
                    }
                ),
                opts=pulumi.ResourceOptions(parent=self),
            )

            if secrets_key_arns is not None and repo.name not in secrets_key_arns:
                raise ValueError(
                    "Missing Pulumi secrets KMS key ARN for managed "
                    f"repository '{repo.name}'."
                )

            key_arn = secrets_key_arns.get(repo.name) if secrets_key_arns else None
            policy = apply_output(
                cast(
                    pulumi.Output[Sequence[str | None]],
                    pulumi.Output.all(bucket_arn, objects_arn, key_arn),
                ),
                _deploy_policy_from_values,
            )

            aws.iam.RolePolicy(
                f"{name}-policy-{repo_suffix}",
                role=role.id,
                policy=policy,
                opts=pulumi.ResourceOptions(parent=self),
            )

            self.deploy_role_arns[repo.name] = role.arn

        self.register_outputs({"deploy_role_arns": self.deploy_role_arns})
