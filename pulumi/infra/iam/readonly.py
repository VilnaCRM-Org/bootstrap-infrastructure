"""Read-only IAM role for Claude Code / AI-assisted AWS investigation."""

from __future__ import annotations

import json
from collections.abc import Sequence

import pulumi_aws as aws

import pulumi

from ..config import claude_readonly_role_name, settings
from ..utils.tags import base_tags

READ_ONLY_MANAGED_POLICY_ARN = "arn:aws:iam::aws:policy/ReadOnlyAccess"
_READONLY_SESSION_DURATION_SECONDS = 3600

# AWS' ReadOnlyAccess grants these sensitive reads, which would let a read-only
# principal exfiltrate secrets/credentials in plaintext. They are denied
# explicitly so the role stays read-only WITHOUT being a secret-exfil primitive.
_DENIED_SENSITIVE_ACTIONS = [
    "secretsmanager:GetSecretValue",
    "secretsmanager:BatchGetSecretValue",
    "kms:Decrypt",
    "kms:GenerateDataKey",
    "kms:GenerateDataKeyWithoutPlaintext",
    "ssm:GetParameter",
    "ssm:GetParameters",
    "ssm:GetParametersByPath",
    "lambda:GetFunction",
    "lambda:GetFunctionConfiguration",
    "ec2:GetPasswordData",
    "ec2:GetConsoleOutput",
    "ec2:GetConsoleScreenshot",
    "ecr:GetAuthorizationToken",
    "ecr-public:GetAuthorizationToken",
    "codeartifact:GetAuthorizationToken",
    "sts:GetSessionToken",
    "cognito-identity:GetCredentialsForIdentity",
    "cognito-identity:GetOpenIdToken",
]


def _readonly_assume_role_policy(principal_arns: Sequence[str]) -> str:
    """Build a trust policy letting the given principals assume the role with MFA."""
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": list(principal_arns)},
                    "Action": "sts:AssumeRole",
                    "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}},
                }
            ],
        }
    )


def _readonly_deny_policy() -> str:
    """Return the explicit-deny policy that blocks secret and credential reads."""
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "DenySecretAndCredentialReads",
                    "Effect": "Deny",
                    "Action": _DENIED_SENSITIVE_ACTIONS,
                    "Resource": "*",
                }
            ],
        }
    )


class ClaudeReadOnlyRole(pulumi.ComponentResource):
    """Provision a read-only IAM role for AI-assisted AWS investigation."""

    def __init__(
        self,
        name: str,
        *,
        principal_arns: Sequence[str],
        opts: pulumi.ResourceOptions | None = None,
    ) -> None:
        """Initialize the read-only role assumable by the given principals."""
        super().__init__("bootstrap:iam:ClaudeReadOnlyRole", name, None, opts)

        principals = list(principal_arns)
        if not principals:
            raise ValueError(
                "ClaudeReadOnlyRole requires at least one principal ARN to trust."
            )

        repo_name = settings.repo or settings.environment
        role_name = claude_readonly_role_name(repo_name)
        base_opts = pulumi.ResourceOptions(parent=self)

        role = aws.iam.Role(
            f"{name}-role",
            name=role_name,
            assume_role_policy=_readonly_assume_role_policy(principals),
            max_session_duration=_READONLY_SESSION_DURATION_SECONDS,
            tags=base_tags(
                {
                    "Purpose": "claude-readonly",
                    "App": repo_name,
                }
            ),
            opts=base_opts,
        )

        readonly_attachment = aws.iam.RolePolicyAttachment(
            f"{name}-readonly-attachment",
            role=role.name,
            policy_arn=READ_ONLY_MANAGED_POLICY_ARN,
            opts=base_opts,
        )

        secret_deny_policy = aws.iam.RolePolicy(
            f"{name}-deny-secrets",
            role=role.id,
            policy=_readonly_deny_policy(),
            opts=base_opts,
        )

        self.role = role
        self.readonly_attachment = readonly_attachment
        self.secret_deny_policy = secret_deny_policy
        self.register_outputs({"role_arn": role.arn})
