"""AWS-side resources that back GitHub Actions CI configuration."""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass

import pulumi_aws as aws

import pulumi

from .bootstrap_settings import BootstrapSettings
from .config import settings as default_settings
from .utils.outputs import apply_output
from .utils.tags import base_tags

CI_CONFIG_SECRET_SUFFIXES_BY_STACK = {
    "test": ("test-pr", "test"),
    "prod": ("prod-preview", "prod"),
}
NIGHTLY_GUARDRAILS_WORKFLOW = "Nightly Guardrails"
OPERATIONS_ALERT_TRIAGE_WORKFLOW = "Operations Alert Issue Triage"
PULUMI_PR_COMMAND_RUNNER_WORKFLOW = "Pulumi PR Command Runner"
PULUMI_PR_GUARDRAILS_WORKFLOW = "Pulumi PR Guardrails"
PULUMI_PROD_WORKFLOW = "Pulumi Production"
PULUMI_TEST_DEPLOY_WORKFLOW = "Pulumi Test Deploy"
WELL_ARCHITECTED_EVIDENCE_WORKFLOW = "Well-Architected Evidence"
_WORKFLOW_FILE_BY_NAME = {
    NIGHTLY_GUARDRAILS_WORKFLOW: "nightly-guardrails.yml",
    OPERATIONS_ALERT_TRIAGE_WORKFLOW: "operations-alert-triage.yml",
    PULUMI_PR_COMMAND_RUNNER_WORKFLOW: "pulumi-pr-command-runner.yml",
    PULUMI_PR_GUARDRAILS_WORKFLOW: "pulumi-pr-guardrails.yml",
    PULUMI_PROD_WORKFLOW: "pulumi-prod.yml",
    PULUMI_TEST_DEPLOY_WORKFLOW: "pulumi-test-deploy.yml",
    WELL_ARCHITECTED_EVIDENCE_WORKFLOW: "well-architected-evidence.yml",
}


@dataclass(frozen=True)
class CiConfigurationArgs:
    """Configuration for AWS-side GitHub CI config resources."""

    settings: BootstrapSettings | None = None
    oidc_provider_arn: pulumi.Input[str] | None = None
    protect_resources: bool = False


def _ci_config_project(settings: BootstrapSettings) -> str:
    """Return the repository project name used in CI secret IDs."""
    if not settings.repo:
        raise ValueError("repoSlug config is required for AWS CI configuration.")
    return settings.sanitize_bucket_component(settings.repo, "repoSlug").replace(
        ".",
        "-",
    )


def _ci_secret_suffixes(environment: str) -> tuple[str, ...]:
    """Return CI secret suffixes owned by one bootstrap stack."""
    return CI_CONFIG_SECRET_SUFFIXES_BY_STACK.get(environment, (environment,))


def _ci_secret_id(settings: BootstrapSettings, suffix: str) -> str:
    """Return the AWS Secrets Manager secret ID used by one CI configuration."""
    project = _ci_config_project(settings)
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


def _ci_config_read_role_name(settings: BootstrapSettings, suffix: str) -> str:
    """Return the GitHub OIDC role name allowed to read one CI secret."""
    project = _ci_config_project(settings)
    safe_suffix = settings.sanitize_bucket_component(suffix, "ciConfigSuffix").replace(
        ".",
        "-",
    )
    name = f"GitHubCiConfigRead-{project}-{safe_suffix}"
    if len(name) > 64:
        raise ValueError(
            "Combined repo/CI suffix produce GitHub CI config read role name "
            f"'{name}' longer than 64 characters."
        )
    return name


def _github_actions_subjects(settings: BootstrapSettings, suffix: str) -> list[str]:
    """Return allowed GitHub OIDC subject claims for one CI config suffix."""
    if not settings.repo:
        raise ValueError("repoSlug config is required for GitHub OIDC subjects.")
    branch = settings.github_branch or "main"
    repo = f"{settings.org}/{settings.repo}"
    if suffix == "test-pr":
        return [f"repo:{repo}:pull_request"]
    if suffix == "test":
        return [
            f"repo:{repo}:ref:refs/heads/{branch}",
            f"repo:{repo}:environment:test",
        ]
    if suffix == "prod":
        return [f"repo:{repo}:environment:prod"]
    return [f"repo:{repo}:ref:refs/heads/{branch}"]


def _github_actions_workflows(
    settings: BootstrapSettings,
    suffix: str,
) -> list[str]:
    """Return allowed workflow names for one CI config suffix."""
    if not settings.repo:
        raise ValueError("repoSlug config is required for GitHub workflow names.")
    workflows_by_suffix = {
        "test-pr": [
            PULUMI_PR_GUARDRAILS_WORKFLOW,
            WELL_ARCHITECTED_EVIDENCE_WORKFLOW,
        ],
        "test": [
            PULUMI_PR_GUARDRAILS_WORKFLOW,
            PULUMI_TEST_DEPLOY_WORKFLOW,
            NIGHTLY_GUARDRAILS_WORKFLOW,
            PULUMI_PR_COMMAND_RUNNER_WORKFLOW,
            OPERATIONS_ALERT_TRIAGE_WORKFLOW,
            WELL_ARCHITECTED_EVIDENCE_WORKFLOW,
        ],
        "prod-preview": [
            PULUMI_PROD_WORKFLOW,
            NIGHTLY_GUARDRAILS_WORKFLOW,
            PULUMI_PR_COMMAND_RUNNER_WORKFLOW,
        ],
        "prod": [
            PULUMI_PROD_WORKFLOW,
            PULUMI_PR_COMMAND_RUNNER_WORKFLOW,
        ],
    }
    return workflows_by_suffix.get(
        suffix,
        [settings.environment],
    )


def _github_actions_workflow_file_refs_for_repo(
    org: str,
    repo: str,
    workflows: Sequence[str],
) -> list[str]:
    """Return allowed GitHub OIDC workflow_ref claims for trusted workflows."""
    refs: list[str] = []
    for workflow in workflows:
        workflow_file = _WORKFLOW_FILE_BY_NAME.get(workflow, "*")
        refs.append(f"{org}/{repo}/.github/workflows/{workflow_file}@*")
    return refs


def _github_actions_workflow_file_refs(
    settings: BootstrapSettings,
    workflows: Sequence[str],
) -> list[str]:
    """Return allowed GitHub OIDC workflow_ref claims for this repository."""
    if not settings.repo:
        raise ValueError("repoSlug config is required for GitHub workflow refs.")
    return _github_actions_workflow_file_refs_for_repo(
        settings.org,
        settings.repo,
        workflows,
    )


def _ci_config_read_assume_role_policy(
    provider_arn: str,
    settings: BootstrapSettings,
    suffix: str,
) -> str:
    """Return trust policy for the GitHub AWS CI config read role."""
    workflows = _github_actions_workflows(settings, suffix)
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
                            "token.actions.githubusercontent.com:aud": (
                                "sts.amazonaws.com"
                            ),
                            "token.actions.githubusercontent.com:sub": (
                                _github_actions_subjects(settings, suffix)
                            ),
                        },
                        "StringLike": {
                            "token.actions.githubusercontent.com:workflow": (workflows),
                            "token.actions.githubusercontent.com:workflow_ref": (
                                _github_actions_workflow_file_refs(
                                    settings,
                                    workflows,
                                )
                            ),
                        },
                    },
                }
            ],
        },
        sort_keys=True,
    )


def _ci_config_read_policy(
    *,
    account_id: str,
    partition: str,
    settings: BootstrapSettings,
    suffixes: Sequence[str],
) -> str:
    """Return least-privilege policy for GitHub to read CI secret payloads."""
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


def _secret_import_id(name: str) -> str | None:
    """Return the Secrets Manager secret import ID when the secret exists."""
    try:
        secret = aws.secretsmanager.get_secret(name=name)
    except Exception as exc:
        if _is_missing_lookup_error(
            str(exc),
            ("ResourceNotFoundException", "ResourceNotFound"),
        ):
            return None
        raise
    arn = getattr(secret, "arn", None)
    return str(arn) if arn else None


def _iam_role_exists(name: str) -> bool:
    """Return True when the IAM role already exists."""
    try:
        role = aws.iam.get_role(name=name)
    except Exception as exc:
        if _is_missing_lookup_error(
            str(exc),
            ("NoSuchEntity", "NoSuchEntityException"),
        ):
            return False
        raise
    return bool(getattr(role, "arn", None))


class CiConfiguration(pulumi.ComponentResource):
    """Provision AWS resources GitHub Actions uses for CI configuration."""

    def __init__(
        self,
        name: str,
        *,
        args: CiConfigurationArgs | None = None,
        opts: pulumi.ResourceOptions | None = None,
    ) -> None:
        super().__init__("bootstrap:ci:CiConfiguration", name, None, opts)

        config = args or CiConfigurationArgs()
        self._settings = config.settings or default_settings
        provider_arn = (
            config.oidc_provider_arn or self._settings.github_oidc_provider_arn
        )
        if provider_arn is None:
            raise ValueError(
                "githubOidcProviderArn config is required for AWS CI configuration."
            )

        suffixes = _ci_secret_suffixes(self._settings.environment)
        account_id = aws.get_caller_identity().account_id
        partition = aws.get_partition().partition

        self.secret_ids: dict[str, str] = {}
        self.secrets: dict[str, aws.secretsmanager.Secret] = {}
        self.secret_arns: dict[str, pulumi.Output[str]] = {}
        self.read_roles: dict[str, aws.iam.Role] = {}
        self.read_role_arns: dict[str, pulumi.Output[str]] = {}
        self.read_policies: dict[str, aws.iam.RolePolicy] = {}

        for suffix in suffixes:
            secret_id = _ci_secret_id(self._settings, suffix)
            secret = aws.secretsmanager.Secret(
                f"{name}-secret-{suffix}",
                name=secret_id,
                description=(
                    "AWS Secrets Manager source-of-truth JSON for "
                    f"{_ci_config_project(self._settings)}/{suffix} CI."
                ),
                recovery_window_in_days=30,
                tags=base_tags(
                    {
                        "Purpose": "ci-configuration",
                        "CiConfigSuffix": suffix,
                        "Repository": _ci_config_project(self._settings),
                    },
                    settings=self._settings,
                ),
                opts=pulumi.ResourceOptions(
                    parent=self,
                    import_=_secret_import_id(secret_id),
                    protect=config.protect_resources,
                ),
            )
            self.secret_ids[suffix] = secret_id
            self.secrets[suffix] = secret
            self.secret_arns[suffix] = secret.arn

            role_name = _ci_config_read_role_name(self._settings, suffix)
            role = aws.iam.Role(
                f"{name}-github-ci-config-read-role-{suffix}",
                name=role_name,
                assume_role_policy=apply_output(
                    pulumi.Output.from_input(provider_arn),
                    lambda arn, ci_suffix=suffix: _ci_config_read_assume_role_policy(
                        arn,
                        self._settings,
                        ci_suffix,
                    ),
                ),
                tags=base_tags(
                    {
                        "Purpose": "github-ci-configuration-read",
                        "CiConfigSuffix": suffix,
                    },
                    settings=self._settings,
                ),
                opts=pulumi.ResourceOptions(
                    parent=self,
                    import_=role_name if _iam_role_exists(role_name) else None,
                    protect=config.protect_resources,
                ),
            )
            self.read_roles[suffix] = role
            self.read_role_arns[suffix] = role.arn
            policy = aws.iam.RolePolicy(
                f"{name}-github-ci-config-read-policy-{suffix}",
                name=f"{role_name}-policy",
                role=role.id,
                policy=_ci_config_read_policy(
                    account_id=account_id,
                    partition=partition,
                    settings=self._settings,
                    suffixes=(suffix,),
                ),
                opts=pulumi.ResourceOptions(
                    parent=self,
                    protect=config.protect_resources,
                ),
            )
            self.read_policies[suffix] = policy

        self.register_outputs(
            {
                "secret_ids": self.secret_ids,
                "secret_arns": self.secret_arns,
                "read_role_arns": self.read_role_arns,
            }
        )
