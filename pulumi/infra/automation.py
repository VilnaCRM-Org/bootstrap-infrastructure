"""GitHub automation role and ECR runner repository for bootstrap operations."""

from __future__ import annotations

import json

import pulumi_aws as aws

import pulumi

from .config import automation_role_name, runner_ecr_repository_name, settings
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


def _automation_policy() -> str:
    """Return the policy used by GitHub automation for bootstrap operations."""
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
                    "Action": ["iam:*"],
                    "Resource": "*",
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
        opts: pulumi.ResourceOptions | None = None,
    ) -> None:
        """Initialize automation resources for this repository/environment."""
        super().__init__("bootstrap:github:Automation", name, None, opts)

        if not settings.repo:
            raise ValueError("repoSlug config is required for GitHub automation.")
        if not settings.github_oidc_provider_arn:
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
            assume_role_policy=_automation_assume_role_policy(
                settings.github_oidc_provider_arn,
                settings.org,
                repo_name,
                environment,
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
            policy=_automation_policy(),
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
