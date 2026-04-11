"""GitHub automation role and ECR runner repository for bootstrap operations."""

from __future__ import annotations

import json

import pulumi_aws as aws

import pulumi

from .config import automation_role_name, runner_ecr_repository_name, settings
from .utils.outputs import apply_output
from .utils.tags import base_tags


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


def _automation_policy(account_id: str) -> str:
    """Return the policy used by GitHub automation for bootstrap operations."""
    role_arn = f"arn:aws:iam::{account_id}:role/*"
    oidc_provider_arn = (
        f"arn:aws:iam::{account_id}:oidc-provider/token.actions.githubusercontent.com"
    )
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
                    "Action": ["s3:*"],
                    "Resource": "*",
                },
                {
                    "Sid": "ManageBootstrapKms",
                    "Effect": "Allow",
                    "Action": ["kms:*"],
                    "Resource": "*",
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
                        "iam:ListOpenIDConnectProviders",
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
                    "Resource": [role_arn, oidc_provider_arn],
                },
                {
                    "Sid": "CreateBootstrapOidcProvider",
                    "Effect": "Allow",
                    "Action": ["iam:CreateOpenIDConnectProvider"],
                    "Resource": "*",
                },
                {
                    "Sid": "PassBootstrapRolesToBackup",
                    "Effect": "Allow",
                    "Action": ["iam:PassRole"],
                    "Resource": role_arn,
                    "Condition": {
                        "StringEquals": {"iam:PassedToService": "backup.amazonaws.com"}
                    },
                },
                {
                    "Sid": "ManageBootstrapBackup",
                    "Effect": "Allow",
                    "Action": ["backup:*"],
                    "Resource": "*",
                },
                {
                    "Sid": "ManageBootstrapEcr",
                    "Effect": "Allow",
                    "Action": ["ecr:*"],
                    "Resource": "*",
                },
            ],
        }
    )


class GitHubAutomation(pulumi.ComponentResource):
    """Provision the ECR runner repository and GitHub automation role."""

    def __init__(
        self,
        name: str,
        *,
        oidc_provider_arn: pulumi.Input[str] | None = None,
        opts: pulumi.ResourceOptions | None = None,
    ) -> None:
        """Initialize automation resources for this repository/environment."""
        super().__init__("bootstrap:github:Automation", name, None, opts)

        if not settings.repo:
            raise ValueError("repoSlug config is required for GitHub automation.")
        provider_arn = oidc_provider_arn or settings.github_oidc_provider_arn
        if provider_arn is None:
            raise ValueError(
                "githubOidcProviderArn config is required for GitHub automation."
            )

        repo_name = settings.repo
        environment = settings.environment
        ecr_repository_name = runner_ecr_repository_name(repo_name)
        role_name = automation_role_name(repo_name)
        base_opts = pulumi.ResourceOptions(parent=self)

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
                }
            ),
            opts=base_opts,
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
                    settings.org,
                    repo_name,
                    environment,
                ),
            ),
            tags=base_tags(
                {
                    "Purpose": "pulumi-automation",
                    "Repository": repo_name,
                    "App": repo_name,
                }
            ),
            opts=base_opts,
        )

        aws.iam.RolePolicy(
            f"{name}-policy",
            role=role.id,
            policy=_automation_policy(aws.get_caller_identity().account_id),
            opts=base_opts,
        )

        self.repository = repository
        self.role = role

        self.register_outputs(
            {
                "repository_name": repository.name,
                "repository_url": repository.repository_url,
                "role_arn": role.arn,
            }
        )
