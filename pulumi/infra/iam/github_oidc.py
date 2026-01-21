"""GitHub OIDC provider and per-repository deploy roles."""

from __future__ import annotations

import hashlib
from typing import Dict, Sequence

import pulumi
import pulumi_aws as aws

from ..config import ManagedRepository, managed_repositories, settings, state_bucket_name_for_repo, sanitize_bucket_component
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
          "token.actions.githubusercontent.com:sub": "repo:{org}/{repo_name}:ref:refs/heads/{branch_name}"
        }}
      }}
    }}
  ]
}}
"""


def _deploy_policy(bucket_arn: str, objects_arn: str) -> str:
  """Return the least-privilege S3 policy for Pulumi state access."""
  return f"""
{{
  "Version": "2012-10-17",
  "Statement": [
    {{
      "Effect": "Allow",
      "Action": ["s3:ListBucket", "s3:CreateBucket"],
      "Resource": "{bucket_arn}"
    }},
    {{
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:GetObjectVersion",
        "s3:PutObject",
        "s3:DeleteObject",
        "s3:DeleteObjectVersion"
      ],
      "Resource": "{objects_arn}"
    }}
  ]
}}
"""


class GitHubOidcRoles(pulumi.ComponentResource):
  """Create the GitHub OIDC provider and per-repository deploy roles."""

  def __init__(
    self,
    name: str,
    *,
    repositories: Sequence[ManagedRepository] | None = None,
    opts: pulumi.ResourceOptions | None = None,
  ) -> None:
    """Initialize OIDC provider and deploy roles for repositories."""
    super().__init__("bootstrap:iam:GitHubOidcRoles", name, None, opts)

    repos = list(repositories) if repositories is not None else managed_repositories()

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
    self.deploy_role_arns: Dict[str, pulumi.Output[str]] = {}

    for repo in repos:
      bucket_name = state_bucket_name_for_repo(repo.name)
      bucket_arn = pulumi.Output.from_input(f"arn:aws:s3:::{bucket_name}")
      objects_arn = pulumi.Output.from_input(f"arn:aws:s3:::{bucket_name}/state/*")
      branch = settings.github_branch or repo.default_branch or "main"

      repo_suffix = sanitize_bucket_component(repo.name, "repoSlug").replace(".", "-")
      role_name = _role_name_for_suffix(repo_suffix)

      assume_role_policy = provider.arn.apply(
        lambda arn, repo_name=repo.name, branch_name=branch: _assume_role_policy(
          arn,
          settings.org,
          repo_name,
          branch_name,
        )
      )

      role = aws.iam.Role(
        f"{name}-role-{repo_suffix}",
        name=role_name,
        assume_role_policy=assume_role_policy,
        tags=base_tags({"Purpose": "pulumi-deploy", "Repository": repo.name, "App": repo.name}),
        opts=pulumi.ResourceOptions(parent=self),
      )

      policy = pulumi.Output.all(bucket_arn, objects_arn).apply(
        lambda values: _deploy_policy(values[0], values[1])
      )

      aws.iam.RolePolicy(
        f"{name}-policy-{repo_suffix}",
        role=role.id,
        policy=policy,
        opts=pulumi.ResourceOptions(parent=self),
      )

      self.deploy_role_arns[repo.name] = role.arn

    self.register_outputs({"deploy_role_arns": self.deploy_role_arns})
