from __future__ import annotations

from typing import Dict

import pulumi
import pulumi_aws as aws

from ..config import (
  managed_repositories,
  settings,
  state_bucket_name_for_repo,
  _sanitize_bucket_component,
)


provider = aws.iam.OpenIdConnectProvider(
  "githubOidcProvider",
  client_id_list=["sts.amazonaws.com"],
  thumbprint_list=[
    "6938fd4d98bab03faadb97b34396831e3780aea1",
    "1c58a3a8518e8759bf075b76b750d4f2df264fcd",
  ],
  url="https://token.actions.githubusercontent.com",
)

role_arns: Dict[str, pulumi.Output[str]] = {}

for repo in managed_repositories():
  bucket_name = state_bucket_name_for_repo(repo.name)
  bucket_arn = pulumi.Output.from_input(f"arn:aws:s3:::{bucket_name}")
  objects_arn = pulumi.Output.from_input(f"arn:aws:s3:::{bucket_name}/state/*")
  branch = settings.github_branch or repo.default_branch or "main"

  repo_suffix = _sanitize_bucket_component(repo.name, "repoSlug").replace(".", "-")

  assume_role_policy = provider.arn.apply(
    lambda arn, repo_name=repo.name: f"""
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
          "token.actions.githubusercontent.com:sub": "repo:{settings.org}/{repo_name}:ref:refs/heads/{branch}"
        }}
      }}
    }}
  ]
}}
"""
  )

  role = aws.iam.Role(
    f"pulumiDeployRole-{repo_suffix}",
    name=f"PulumiDeploy-{repo_suffix}",
    assume_role_policy=assume_role_policy,
  )

  policy = pulumi.Output.all(bucket_arn, objects_arn).apply(
    lambda values: f"""
{{
  "Version": "2012-10-17",
  "Statement": [
    {{
      "Effect": "Allow",
      "Action": ["s3:ListBucket"],
      "Resource": "{values[0]}"
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
      "Resource": "{values[1]}"
    }}
  ]
}}
"""
  )

  aws.iam.RolePolicy(
    f"pulumiDeployPolicy-{repo_suffix}",
    role=role.id,
    policy=policy,
  )

  role_arns[repo.name] = role.arn

pulumi.export("deployRoleArns", role_arns)
