"""AWS-side resources that back Pulumi ESC CI configuration."""

from __future__ import annotations

import json
from collections.abc import Sequence

import pulumi_aws as aws

import pulumi

from .bootstrap_settings import BootstrapSettings
from .config import settings as default_settings
from .utils.outputs import apply_output
from .utils.tags import base_tags

PULUMI_ESC_OIDC_URL = "https://api.pulumi.com/oidc"
ESC_SECRET_SUFFIXES_BY_STACK = {
    "test": ("test-pr", "test"),
    "prod": ("prod-preview", "prod"),
}


def _pulumi_esc_org(settings: BootstrapSettings) -> str:
    """Return the Pulumi ESC organization slug expected by this repository."""
    return settings.sanitize_bucket_component(settings.org, "githubOrg").replace(
        ".",
        "-",
    )


def _pulumi_esc_project(settings: BootstrapSettings) -> str:
    """Return the Pulumi ESC project name expected by this repository."""
    if not settings.repo:
        raise ValueError("repoSlug config is required for Pulumi ESC CI resources.")
    return settings.sanitize_bucket_component(settings.repo, "repoSlug").replace(
        ".",
        "-",
    )


def _ci_secret_suffixes(environment: str) -> tuple[str, ...]:
    """Return ESC secret suffixes owned by one bootstrap stack."""
    return ESC_SECRET_SUFFIXES_BY_STACK.get(environment, (environment,))


def _ci_secret_id(settings: BootstrapSettings, suffix: str) -> str:
    """Return the AWS Secrets Manager secret ID used by one ESC environment."""
    project = _pulumi_esc_project(settings)
    return f"/{project}/ci/{suffix}"


def _ci_secret_arn_patterns(
    *,
    account_id: str,
    partition: str,
    settings: BootstrapSettings,
    suffixes: Sequence[str],
) -> list[str]:
    """Return ARN patterns for Secrets Manager secrets with random suffixes."""
    return [
        f"arn:{partition}:secretsmanager:*:{account_id}:secret:"
        f"{_ci_secret_id(settings, suffix)}-*"
        for suffix in suffixes
    ]


def _esc_read_role_name(settings: BootstrapSettings) -> str:
    """Return the IAM role name Pulumi ESC assumes to read CI secrets."""
    project = _pulumi_esc_project(settings)
    environment = settings.sanitize_bucket_component(
        settings.environment,
        "environment",
    ).replace(".", "-")
    name = f"PulumiEscCiSecretsRead-{project}-{environment}"
    if len(name) > 64:
        raise ValueError(
            "Combined repo/environment produce Pulumi ESC read role name "
            f"'{name}' longer than 64 characters."
        )
    return name


def _pulumi_esc_audience(settings: BootstrapSettings) -> str:
    """Return the AWS OIDC audience for Pulumi ESC."""
    return f"aws:{_pulumi_esc_org(settings)}"


def _pulumi_esc_subjects(
    settings: BootstrapSettings,
    suffixes: Sequence[str],
) -> list[str]:
    """Return allowed Pulumi ESC OIDC subject claims for CI environments."""
    org = _pulumi_esc_org(settings)
    project = _pulumi_esc_project(settings)
    return [
        "pulumi:environments:pulumi.organization.login:"
        f"{org}:currentEnvironment.name:{project}/{suffix}"
        for suffix in suffixes
    ]


def _esc_read_assume_role_policy(
    provider_arn: str,
    settings: BootstrapSettings,
    suffixes: Sequence[str],
) -> str:
    """Return trust policy for the Pulumi ESC AWS secrets read role."""
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Federated": provider_arn},
                    "Action": "sts:AssumeRoleWithWebIdentity",
                    "Condition": {
                        "StringEquals": {
                            "api.pulumi.com/oidc:aud": _pulumi_esc_audience(settings),
                            "api.pulumi.com/oidc:sub": _pulumi_esc_subjects(
                                settings,
                                suffixes,
                            ),
                        }
                    },
                }
            ],
        },
        sort_keys=True,
    )


def _esc_read_policy(
    *,
    account_id: str,
    partition: str,
    settings: BootstrapSettings,
    suffixes: Sequence[str],
) -> str:
    """Return least-privilege policy for ESC to read CI secret payloads."""
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "ReadCiConfigurationSecrets",
                    "Effect": "Allow",
                    "Action": [
                        "secretsmanager:DescribeSecret",
                        "secretsmanager:GetSecretValue",
                    ],
                    "Resource": _ci_secret_arn_patterns(
                        account_id=account_id,
                        partition=partition,
                        settings=settings,
                        suffixes=suffixes,
                    ),
                }
            ],
        },
        sort_keys=True,
    )


def _is_missing_lookup_error(message: str, markers: tuple[str, ...]) -> bool:
    """Return True when an AWS lookup error means the resource is absent."""
    return (
        any(marker in message for marker in markers)
        or "not found" in message.lower()
        or "couldn't find resource" in message
        or "empty result" in message
    )


def _secret_exists(name: str) -> bool:
    """Return True when a Secrets Manager secret already exists."""
    try:
        secret = aws.secretsmanager.get_secret(name=name)
    except Exception as exc:
        if _is_missing_lookup_error(
            str(exc),
            ("ResourceNotFoundException", "ResourceNotFound"),
        ):
            return False
        raise
    return bool(getattr(secret, "arn", None))


def _iam_role_exists(name: str) -> bool:
    """Return True when the IAM role already exists."""
    try:
        role = aws.iam.get_role(name=name)
    except Exception as exc:
        if _is_missing_lookup_error(
            str(exc), ("NoSuchEntity", "NoSuchEntityException")
        ):
            return False
        raise
    return bool(getattr(role, "arn", None))


def _existing_pulumi_esc_oidc_provider_arn() -> str | None:
    """Return the account-level Pulumi ESC OIDC provider ARN if present."""
    try:
        provider = aws.iam.get_open_id_connect_provider(url=PULUMI_ESC_OIDC_URL)
    except Exception as exc:
        if _is_missing_lookup_error(
            str(exc), ("NoSuchEntity", "NoSuchEntityException")
        ):
            return None
        raise
    arn = getattr(provider, "arn", None)
    return arn if isinstance(arn, str) and arn else None


class CiConfiguration(pulumi.ComponentResource):
    """Provision AWS resources that Pulumi ESC uses for CI configuration."""

    def __init__(
        self,
        name: str,
        *,
        settings: BootstrapSettings | None = None,
        opts: pulumi.ResourceOptions | None = None,
    ) -> None:
        super().__init__("bootstrap:ci:CiConfiguration", name, None, opts)

        self._settings = settings or default_settings
        suffixes = _ci_secret_suffixes(self._settings.environment)
        account_id = aws.get_caller_identity().account_id
        partition = aws.get_partition().partition

        self.secret_ids: dict[str, str] = {}
        self.secret_arns: dict[str, pulumi.Output[str]] = {}
        for suffix in suffixes:
            secret_id = _ci_secret_id(self._settings, suffix)
            secret = aws.secretsmanager.Secret(
                f"{name}-secret-{suffix}",
                name=secret_id,
                description=(
                    "Pulumi ESC source-of-truth JSON for "
                    f"{_pulumi_esc_project(self._settings)}/{suffix} CI."
                ),
                recovery_window_in_days=30,
                tags=base_tags(
                    {
                        "Purpose": "ci-configuration",
                        "EscEnvironment": suffix,
                        "Repository": _pulumi_esc_project(self._settings),
                    },
                    settings=self._settings,
                ),
                opts=pulumi.ResourceOptions(
                    parent=self,
                    import_=secret_id if _secret_exists(secret_id) else None,
                ),
            )
            self.secret_ids[suffix] = secret_id
            self.secret_arns[suffix] = secret.arn

        provider_arn = _existing_pulumi_esc_oidc_provider_arn()
        if provider_arn is not None:
            self.oidc_provider = aws.iam.OpenIdConnectProvider.get(
                f"{name}-pulumi-esc-oidc-provider",
                provider_arn,
                opts=pulumi.ResourceOptions(parent=self),
            )
        else:
            self.oidc_provider = aws.iam.OpenIdConnectProvider(
                f"{name}-pulumi-esc-oidc-provider",
                client_id_lists=[_pulumi_esc_audience(self._settings)],
                tags=base_tags(
                    {"Purpose": "pulumi-esc-oidc"},
                    settings=self._settings,
                ),
                url=PULUMI_ESC_OIDC_URL,
                opts=pulumi.ResourceOptions(parent=self),
            )

        role_name = _esc_read_role_name(self._settings)
        self.read_role = aws.iam.Role(
            f"{name}-pulumi-esc-secrets-read-role",
            name=role_name,
            assume_role_policy=apply_output(
                pulumi.Output.from_input(self.oidc_provider.arn),
                lambda arn: _esc_read_assume_role_policy(
                    arn,
                    self._settings,
                    suffixes,
                ),
            ),
            tags=base_tags(
                {"Purpose": "pulumi-esc-ci-secrets-read"},
                settings=self._settings,
            ),
            opts=pulumi.ResourceOptions(
                parent=self,
                import_=role_name if _iam_role_exists(role_name) else None,
            ),
        )
        self.read_policy = aws.iam.RolePolicy(
            f"{name}-pulumi-esc-secrets-read-policy",
            name=f"{role_name}-policy",
            role=self.read_role.id,
            policy=_esc_read_policy(
                account_id=account_id,
                partition=partition,
                settings=self._settings,
                suffixes=suffixes,
            ),
            opts=pulumi.ResourceOptions(parent=self),
        )

        self.register_outputs(
            {
                "secret_ids": self.secret_ids,
                "secret_arns": self.secret_arns,
                "read_role_arn": self.read_role.arn,
            }
        )
