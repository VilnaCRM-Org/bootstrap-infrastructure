"""One-time AWS resources that let GitHub Actions run AWS-only Pulumi CI."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

import pulumi_aws as aws

import pulumi

from .automation import (
    _automation_policy_documents,
    _operations_alert_triage_policy,
    _operations_alert_triage_role_name,
)
from .bootstrap_settings import BootstrapSettings
from .ci_config import CiConfiguration, CiConfigurationArgs, _ci_config_project
from .config import settings as default_settings
from .iam import GitHubOidcRoles
from .operations_monitoring import _queue_name, _topic_name, _trail_name
from .utils.outputs import apply_output
from .utils.tags import base_tags

_MAX_IAM_ROLE_NAME_LENGTH = 64
_CREATE_POLICY_ACTION = "iam:CreatePolicy"
_NIGHTLY_GUARDRAILS_WORKFLOW = "nightly-guardrails.yml"
_OPERATIONS_ALERT_TRIAGE_WORKFLOW = "operations-alert-triage.yml"
_PULUMI_PR_COMMAND_RUNNER_WORKFLOW = "pulumi-pr-command-runner.yml"
_PULUMI_PR_GUARDRAILS_WORKFLOW = "pulumi-pr-guardrails.yml"
_PULUMI_PROD_WORKFLOW = "pulumi-prod.yml"
_PULUMI_TEST_DEPLOY_WORKFLOW = "pulumi-test-deploy.yml"
_WELL_ARCHITECTED_EVIDENCE_WORKFLOW = "well-architected-evidence.yml"
_CI_ROLE_PREFIX_BY_PURPOSE = {
    "preview": "GitHubCiPreview",
    "apply": "GitHubCiApply",
    "drift": "GitHubCiDrift",
}
_CI_SECRET_SUFFIXES_BY_ENVIRONMENT = {
    "test": ("test-pr", "test"),
    "prod": ("prod-preview", "prod"),
}
_PULUMI_BACKEND_S3_ACTIONS = (
    "s3:ListBucket",
    "s3:GetObject",
    "s3:GetObjectVersion",
    "s3:PutObject",
    "s3:DeleteObject",
    "s3:DeleteObjectVersion",
)
_PULUMI_KMS_ACTIONS = (
    "kms:Decrypt",
    "kms:Encrypt",
    "kms:GenerateDataKey",
    "kms:DescribeKey",
    "kms:ReEncrypt*",
)
_READ_ONLY_ACTIONS = (
    "access-analyzer:ValidatePolicy",
    "backup:Describe*",
    "backup:Get*",
    "backup:List*",
    "budgets:Describe*",
    "budgets:ListTagsForResource",
    "budgets:ViewBudget",
    "ce:GetAnomalies",
    "ce:GetAnomalyMonitors",
    "ce:GetAnomalySubscriptions",
    "ce:GetCostAndUsage",
    "ce:GetCostForecast",
    "ce:ListTagsForResource",
    "cloudtrail:DescribeTrails",
    "cloudtrail:Get*",
    "cloudtrail:ListTags",
    "config:Describe*",
    "config:Get*",
    "config:List*",
    "ecr:Describe*",
    "ecr:Get*",
    "ecr:ListTagsForResource",
    "events:DescribeRule",
    "events:List*",
    "guardduty:Get*",
    "guardduty:List*",
    "iam:Get*",
    "iam:List*",
    "kms:Describe*",
    "kms:Get*",
    "kms:List*",
    "s3:GetAccelerateConfiguration",
    "s3:GetBucket*",
    "s3:GetEncryptionConfiguration",
    "s3:GetLifecycleConfiguration",
    "s3:GetReplicationConfiguration",
    "s3:ListAllMyBuckets",
    "s3:ListBucket",
    "secretsmanager:DescribeSecret",
    "secretsmanager:GetResourcePolicy",
    "secretsmanager:ListSecretVersionIds",
    "secretsmanager:ListSecrets",
    "securityhub:Describe*",
    "securityhub:Get*",
    "securityhub:List*",
    "sns:Get*",
    "sns:List*",
    "sqs:Get*",
    "sqs:List*",
    "sts:GetCallerIdentity",
)
_IAM_POLICY_MANAGEMENT_ACTIONS = (
    _CREATE_POLICY_ACTION,
    "iam:CreatePolicyVersion",
    "iam:DeletePolicy",
    "iam:DeletePolicyVersion",
    "iam:GetPolicy",
    "iam:GetPolicyVersion",
    "iam:ListPolicies",
    "iam:ListPolicyTags",
    "iam:ListPolicyVersions",
    "iam:SetDefaultPolicyVersion",
    "iam:TagPolicy",
    "iam:UntagPolicy",
)


@dataclass(frozen=True)
class _CiRoleSpec:
    """Static inputs for one GitHub CI role."""

    purpose: str
    role_name: str
    subjects: Sequence[str]
    workflow_refs: Sequence[str]
    policy_documents: Sequence[tuple[str, str]]


@dataclass(frozen=True)
class _BootstrapBuildContext:
    """Shared resource inputs for the CI bootstrap component."""

    parent: pulumi.Resource
    name: str
    account_id: str
    partition: str
    region: str
    settings: BootstrapSettings
    provider_arn: pulumi.Input[str]
    protect_resources: bool


@dataclass(frozen=True)
class _PayloadOverrides:
    """Optional values and role outputs used to build CI secret payloads."""

    role_arns: Mapping[str, pulumi.Input[str]]
    operations_alert_triage_role_arn: pulumi.Input[str] | None
    pulumi_backend_url: str | None
    pulumi_secrets_provider: str | None


@dataclass(frozen=True)
class _BootstrapOutputInputs:
    """Inputs exported by the GitHub CI bootstrap component."""

    oidc_provider_arn: pulumi.Input[str]
    ci_configuration: CiConfiguration
    role_arns: Mapping[str, pulumi.Input[str]]
    operations_alert_triage_role_arn: pulumi.Input[str] | None
    github_variables: Mapping[str, pulumi.Input[str]]
    secret_payload_keys: Mapping[str, Sequence[str]]
    secret_versions: Mapping[str, aws.secretsmanager.SecretVersion]


@dataclass(frozen=True)
class GitHubCiBootstrapArgs:
    """Configuration for the one-time GitHub CI AWS bootstrap component."""

    settings: BootstrapSettings | None = None
    pulumi_backend_url: str | None = None
    pulumi_secrets_provider: str | None = None
    write_secret_values: bool = True
    protect_resources: bool = True


@dataclass(frozen=True)
class _OperationsAlertTriageResources:
    """Resources and output value for optional operations alert triage."""

    role: aws.iam.Role | None
    policy: aws.iam.RolePolicy | None
    role_arn: pulumi.Input[str] | None


def _environment_part(settings: BootstrapSettings) -> str:
    """Return the normalized environment segment used in role names."""
    environment = settings.sanitize_bucket_component(
        settings.environment,
        "environment",
    )
    return environment.replace(".", "-")


def _ci_secret_suffixes(settings: BootstrapSettings) -> tuple[str, ...]:
    """Return fixed CI config suffixes owned by this account stack."""
    return _CI_SECRET_SUFFIXES_BY_ENVIRONMENT.get(
        settings.environment,
        (settings.environment,),
    )


def _ci_role_name(settings: BootstrapSettings, purpose: str) -> str:
    """Return a deterministic GitHub CI role name for one purpose."""
    prefix = _CI_ROLE_PREFIX_BY_PURPOSE[purpose]
    name = f"{prefix}-{_ci_config_project(settings)}-{_environment_part(settings)}"
    if len(name) > _MAX_IAM_ROLE_NAME_LENGTH:
        raise ValueError(
            "Combined repo/environment produce GitHub CI role name "
            f"'{name}' longer than 64 characters."
        )
    return name


def _iam_role_exists(name: str) -> bool:
    """Return True when an IAM role already exists."""
    try:
        aws.iam.get_role(name=name)
    except Exception as exc:
        message = str(exc)
        if "NoSuchEntity" in message or "couldn't find resource" in message:
            return False
        raise
    return True


def _workflow_ref(settings: BootstrapSettings, workflow: str, ref: str) -> str:
    """Return a GitHub OIDC job_workflow_ref condition value."""
    if not settings.repo:
        raise ValueError("repoSlug config is required for GitHub workflow refs.")
    return f"{settings.org}/{settings.repo}/.github/workflows/{workflow}@{ref}"


def _branch_ref(settings: BootstrapSettings) -> str:
    """Return the configured GitHub branch ref."""
    return f"refs/heads/{settings.github_branch or 'main'}"


def _repo_subject(settings: BootstrapSettings, suffix: str) -> str:
    """Return a GitHub OIDC subject for this repository."""
    if not settings.repo:
        raise ValueError("repoSlug config is required for GitHub OIDC subjects.")
    return f"repo:{settings.org}/{settings.repo}:{suffix}"


def _deployment_role_subjects(settings: BootstrapSettings, purpose: str) -> list[str]:
    """Return trusted GitHub OIDC subjects for a CI deployment role."""
    branch_subject = _repo_subject(settings, f"ref:{_branch_ref(settings)}")
    if purpose == "preview" and settings.environment == "test":
        return [branch_subject, _repo_subject(settings, "pull_request")]
    if purpose == "apply" and settings.environment == "prod":
        return [_repo_subject(settings, "environment:prod")]
    return [branch_subject]


def _deployment_role_workflow_refs(
    settings: BootstrapSettings,
    purpose: str,
) -> list[str]:
    """Return trusted workflow refs for one CI role purpose."""
    branch_ref = _branch_ref(settings)
    if settings.environment == "test" and purpose == "preview":
        workflow_specs = (
            (_PULUMI_PR_GUARDRAILS_WORKFLOW, "refs/*"),
            (_WELL_ARCHITECTED_EVIDENCE_WORKFLOW, "refs/*"),
            (_PULUMI_TEST_DEPLOY_WORKFLOW, branch_ref),
            (_PULUMI_PR_COMMAND_RUNNER_WORKFLOW, branch_ref),
        )
    elif settings.environment == "test" and purpose == "apply":
        workflow_specs = (
            (_PULUMI_TEST_DEPLOY_WORKFLOW, branch_ref),
            (_PULUMI_PR_COMMAND_RUNNER_WORKFLOW, branch_ref),
        )
    elif settings.environment == "test":
        workflow_specs = (
            (_PULUMI_TEST_DEPLOY_WORKFLOW, branch_ref),
            (_NIGHTLY_GUARDRAILS_WORKFLOW, branch_ref),
            (_PULUMI_PR_COMMAND_RUNNER_WORKFLOW, branch_ref),
        )
    elif purpose == "drift":
        workflow_specs = (
            (_PULUMI_PROD_WORKFLOW, branch_ref),
            (_NIGHTLY_GUARDRAILS_WORKFLOW, branch_ref),
            (_PULUMI_PR_COMMAND_RUNNER_WORKFLOW, branch_ref),
        )
    else:
        workflow_specs = (
            (_PULUMI_PROD_WORKFLOW, branch_ref),
            (_PULUMI_PR_COMMAND_RUNNER_WORKFLOW, branch_ref),
        )
    return [_workflow_ref(settings, workflow, ref) for workflow, ref in workflow_specs]


def _deployment_assume_role_policy(
    oidc_provider_arn: str,
    subjects: Sequence[str],
    workflow_refs: Sequence[str],
) -> str:
    """Build the trust policy for one GitHub OIDC CI role."""
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
                            "token.actions.githubusercontent.com:sub": list(subjects),
                        },
                        "StringLike": {
                            "token.actions.githubusercontent.com:job_workflow_ref": (
                                list(workflow_refs)
                            )
                        },
                    },
                }
            ],
        },
        sort_keys=True,
    )


def _state_bucket_resources(settings: BootstrapSettings) -> tuple[str, str]:
    """Return the Pulumi backend bucket and state-object ARN patterns."""
    bucket_name = settings.state_bucket_name()
    return f"arn:aws:s3:::{bucket_name}", f"arn:aws:s3:::{bucket_name}/state/*"


def _pulumi_secrets_alias_conditions(settings: BootstrapSettings) -> list[str]:
    """Return accepted Pulumi KMS secrets-provider aliases."""
    environment = _environment_part(settings)
    return [
        f"alias/pulumi-*-{environment}-secrets",
        f"alias/pulumi-platform-bootstrap-{environment}",
    ]


def _pulumi_backend_policy_document(
    account_id: str,
    partition: str,
    settings: BootstrapSettings,
) -> str:
    """Return S3 backend and KMS secrets-provider access for Pulumi CLI."""
    bucket_arn, objects_arn = _state_bucket_resources(settings)
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "ReadCallerIdentity",
                    "Effect": "Allow",
                    "Action": ["sts:GetCallerIdentity"],
                    "Resource": "*",
                },
                {
                    "Sid": "UsePulumiStateBucket",
                    "Effect": "Allow",
                    "Action": list(_PULUMI_BACKEND_S3_ACTIONS),
                    "Resource": [bucket_arn, objects_arn],
                },
                {
                    "Sid": "UsePulumiSecretsProviderKey",
                    "Effect": "Allow",
                    "Action": list(_PULUMI_KMS_ACTIONS),
                    "Resource": f"arn:{partition}:kms:*:{account_id}:key/*",
                    "Condition": {
                        "ForAnyValue:StringLike": {
                            "kms:ResourceAliases": _pulumi_secrets_alias_conditions(
                                settings
                            )
                        }
                    },
                },
            ],
        },
        sort_keys=True,
    )


def _read_only_policy_document(
    _account_id: str,
    _partition: str,
    _settings: BootstrapSettings,
) -> str:
    """Return read-only AWS metadata access used by preview, drift, and evidence."""
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "ReadStackMetadata",
                    "Effect": "Allow",
                    "Action": list(_READ_ONLY_ACTIONS),
                    "Resource": "*",
                },
                {
                    "Sid": "DenySecretValueReads",
                    "Effect": "Deny",
                    "Action": ["secretsmanager:GetSecretValue"],
                    "Resource": "*",
                },
            ],
        },
        sort_keys=True,
    )


def _apply_extra_policy_document(account_id: str, partition: str) -> str:
    """Return extra permissions needed to manage automation managed policies."""
    automation_policy_arn = (
        f"arn:{partition}:iam::{account_id}:policy/github-automation-*"
    )
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "CreateBootstrapAutomationManagedPolicies",
                    "Effect": "Allow",
                    "Action": [_CREATE_POLICY_ACTION],
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {
                            "aws:RequestTag/Purpose": "pulumi-automation-policy"
                        }
                    },
                },
                {
                    "Sid": "ManageBootstrapAutomationManagedPolicies",
                    "Effect": "Allow",
                    "Action": [
                        action
                        for action in _IAM_POLICY_MANAGEMENT_ACTIONS
                        if action != _CREATE_POLICY_ACTION
                    ],
                    "Resource": automation_policy_arn,
                },
                {
                    "Sid": "ListBootstrapAutomationManagedPolicies",
                    "Effect": "Allow",
                    "Action": ["iam:ListPolicies"],
                    "Resource": "*",
                },
            ],
        },
        sort_keys=True,
    )


def _role_policy_documents(
    account_id: str,
    partition: str,
    settings: BootstrapSettings,
    purpose: str,
) -> list[tuple[str, str]]:
    """Return policy documents for one GitHub CI role purpose."""
    backend_policy = _pulumi_backend_policy_document(account_id, partition, settings)
    if purpose in {"preview", "drift"}:
        return [
            ("pulumi-backend", backend_policy),
            ("read-only", _read_only_policy_document(account_id, partition, settings)),
        ]
    if not settings.repo:
        raise ValueError("repoSlug config is required for GitHub CI apply policy.")
    return [
        ("pulumi-backend", backend_policy),
        *_automation_policy_documents(account_id, settings, settings.repo),
        ("iam-managed-policies", _apply_extra_policy_document(account_id, partition)),
    ]


def _role_specs(
    *,
    account_id: str,
    partition: str,
    settings: BootstrapSettings,
) -> list[_CiRoleSpec]:
    """Return deterministic role specs for the three deployment role purposes."""
    return [
        _CiRoleSpec(
            purpose=purpose,
            role_name=_ci_role_name(settings, purpose),
            subjects=_deployment_role_subjects(settings, purpose),
            workflow_refs=_deployment_role_workflow_refs(settings, purpose),
            policy_documents=_role_policy_documents(
                account_id,
                partition,
                settings,
                purpose,
            ),
        )
        for purpose in ("preview", "apply", "drift")
    ]


def _create_role(
    context: _BootstrapBuildContext,
    spec: _CiRoleSpec,
) -> aws.iam.Role:
    """Create or import one GitHub OIDC CI role and its inline policies."""
    role = aws.iam.Role(
        f"{context.name}-{spec.purpose}-role",
        name=spec.role_name,
        assume_role_policy=apply_output(
            pulumi.Output.from_input(context.provider_arn),
            lambda arn: _deployment_assume_role_policy(
                arn,
                spec.subjects,
                spec.workflow_refs,
            ),
        ),
        tags=base_tags(
            {
                "Purpose": f"github-ci-{spec.purpose}",
                "Repository": _ci_config_project(context.settings),
            },
            settings=context.settings,
        ),
        opts=pulumi.ResourceOptions(
            parent=context.parent,
            import_=spec.role_name if _iam_role_exists(spec.role_name) else None,
            protect=context.protect_resources,
        ),
    )
    for policy_suffix, policy_document in spec.policy_documents:
        aws.iam.RolePolicy(
            f"{context.name}-{spec.purpose}-{policy_suffix}",
            name=f"{spec.role_name}-{policy_suffix}",
            role=role.id,
            policy=policy_document,
            opts=pulumi.ResourceOptions(
                parent=context.parent,
                protect=context.protect_resources,
            ),
        )
    return role


def _create_roles(
    context: _BootstrapBuildContext,
    specs: Sequence[_CiRoleSpec],
) -> dict[str, aws.iam.Role]:
    """Create or import all GitHub OIDC CI deployment roles."""
    return {
        spec.purpose: _create_role(
            context,
            spec=spec,
        )
        for spec in specs
    }


def _secret_string(payload: Mapping[str, pulumi.Input[str]]) -> pulumi.Output[str]:
    """Serialize a secret payload after all Pulumi inputs resolve."""
    keys = list(payload)
    values = [pulumi.Output.from_input(payload[key]) for key in keys]
    return pulumi.Output.all(*values).apply(
        lambda resolved: json.dumps(
            dict(zip(keys, resolved, strict=True)),
            sort_keys=True,
        )
    )


def _default_backend_url(settings: BootstrapSettings) -> str:
    """Return the default S3 backend URL used by the main Pulumi stack."""
    return f"s3://{settings.state_bucket_name()}"


def _default_secrets_provider(settings: BootstrapSettings, region: str) -> str:
    """Return the default AWS KMS secrets provider for the main stack."""
    return (
        f"awskms://alias/pulumi-platform-bootstrap-{_environment_part(settings)}"
        f"?region={region}"
    )


def _operations_topic_arn(
    account_id: str,
    partition: str,
    region: str,
    settings: BootstrapSettings,
) -> str:
    """Return the deterministic operations SNS topic ARN."""
    return f"arn:{partition}:sns:{region}:{account_id}:{_topic_name(settings)}"


def _create_operations_alert_triage(
    context: _BootstrapBuildContext,
) -> _OperationsAlertTriageResources:
    """Create the test-account operations alert triage role when required."""
    if context.settings.environment != "test":
        return _OperationsAlertTriageResources(None, None, None)

    triage_role_name = _operations_alert_triage_role_name(
        context.settings,
        context.settings.repo or "",
    )
    role = aws.iam.Role(
        f"{context.name}-operations-alert-triage-role",
        name=triage_role_name,
        assume_role_policy=apply_output(
            pulumi.Output.from_input(context.provider_arn),
            lambda arn: _deployment_assume_role_policy(
                arn,
                [
                    _repo_subject(
                        context.settings,
                        f"ref:{_branch_ref(context.settings)}",
                    )
                ],
                [
                    _workflow_ref(
                        context.settings,
                        _OPERATIONS_ALERT_TRIAGE_WORKFLOW,
                        _branch_ref(context.settings),
                    )
                ],
            ),
        ),
        tags=base_tags(
            {
                "Purpose": "operations-alert-triage",
                "Repository": _ci_config_project(context.settings),
            },
            settings=context.settings,
        ),
        opts=pulumi.ResourceOptions(
            parent=context.parent,
            import_=triage_role_name if _iam_role_exists(triage_role_name) else None,
            protect=context.protect_resources,
        ),
    )
    policy = aws.iam.RolePolicy(
        f"{context.name}-operations-alert-triage-policy",
        name=f"{triage_role_name}-policy",
        role=role.id,
        policy=_operations_alert_triage_policy(context.account_id, context.settings),
        opts=pulumi.ResourceOptions(
            parent=context.parent,
            protect=context.protect_resources,
        ),
    )
    return _OperationsAlertTriageResources(role, policy, role.arn)


def _payloads(
    context: _BootstrapBuildContext,
    overrides: _PayloadOverrides,
) -> dict[str, dict[str, pulumi.Input[str]]]:
    """Return CI config JSON payloads keyed by fixed secret suffix."""
    backend_url = overrides.pulumi_backend_url or _default_backend_url(
        context.settings,
    )
    secrets_provider = overrides.pulumi_secrets_provider or _default_secrets_provider(
        context.settings,
        context.region,
    )
    common = {
        "AWS_ACCOUNT_ID": context.account_id,
        "AWS_REGION": context.region,
        "PULUMI_BACKEND_URL": backend_url,
        "PULUMI_SECRETS_PROVIDER": secrets_provider,
    }
    preview_common = {
        **common,
        "AWS_PREVIEW_ROLE_ARN": overrides.role_arns["preview"],
        "PULUMI_PREVIEW_STACKS": context.settings.environment,
    }
    drift_common = {
        "AWS_DRIFT_ROLE_ARN": overrides.role_arns["drift"],
        "PULUMI_DRIFT_STACKS": context.settings.environment,
    }
    if context.settings.environment == "test":
        triage_role_arn = overrides.operations_alert_triage_role_arn
        if triage_role_arn is None:
            raise ValueError(
                "test bootstrap requires operations alert triage role ARN."
            )
        return {
            "test-pr": {
                **preview_common,
                "OPERATIONS_TOPIC_ARN": _operations_topic_arn(
                    context.account_id,
                    context.partition,
                    context.region,
                    context.settings,
                ),
                "OPERATIONS_CLOUDTRAIL_NAME": (
                    context.settings.operations_cloudtrail_name
                    or _trail_name(context.settings)
                ),
            },
            "test": {
                **preview_common,
                **drift_common,
                "AWS_APPLY_ROLE_ARN": overrides.role_arns["apply"],
                "AWS_OPERATIONS_ALERT_TRIAGE_ROLE_ARN": triage_role_arn,
                "OPERATIONS_ALERT_QUEUE_NAME": _queue_name(context.settings),
                "OPERATIONS_TOPIC_ARN": _operations_topic_arn(
                    context.account_id,
                    context.partition,
                    context.region,
                    context.settings,
                ),
                "OPERATIONS_CLOUDTRAIL_NAME": (
                    context.settings.operations_cloudtrail_name
                    or _trail_name(context.settings)
                ),
            },
        }
    if context.settings.environment == "prod":
        return {
            "prod-preview": {
                **preview_common,
                **drift_common,
            },
            "prod": {
                **common,
                "AWS_APPLY_ROLE_ARN": overrides.role_arns["apply"],
                "PULUMI_PREVIEW_STACKS": context.settings.environment,
            },
        }
    return {
        context.settings.environment: {
            **preview_common,
            **drift_common,
            "AWS_APPLY_ROLE_ARN": overrides.role_arns["apply"],
        }
    }


def _create_secret_versions(
    context: _BootstrapBuildContext,
    ci_configuration: CiConfiguration,
    secret_payloads: Mapping[str, Mapping[str, pulumi.Input[str]]],
    write_secret_values: bool,
) -> dict[str, aws.secretsmanager.SecretVersion]:
    """Write AWS Secrets Manager values when the bootstrap stack manages them."""
    if not write_secret_values:
        return {}
    return {
        suffix: aws.secretsmanager.SecretVersion(
            f"{context.name}-secret-value-{suffix}",
            secret_id=ci_configuration.secret_ids[suffix],
            secret_string=pulumi.Output.secret(_secret_string(secret_payloads[suffix])),
            opts=pulumi.ResourceOptions(
                parent=context.parent,
                depends_on=[
                    ci_configuration.secrets[suffix],
                    *ci_configuration.read_roles.values(),
                ],
                protect=context.protect_resources,
            ),
        )
        for suffix in _ci_secret_suffixes(context.settings)
    }


def _github_variables(
    settings: BootstrapSettings,
    *,
    region: str,
    ci_configuration: CiConfiguration,
) -> dict[str, pulumi.Input[str]]:
    """Return GitHub repository variables that point workflows at AWS config."""
    if settings.environment == "test":
        return {
            "AWS_TEST_REGION": region,
            "AWS_TEST_PR_CI_CONFIG_ROLE_ARN": (
                ci_configuration.read_role_arns["test-pr"]
            ),
            "AWS_TEST_CI_CONFIG_ROLE_ARN": ci_configuration.read_role_arns["test"],
        }
    if settings.environment == "prod":
        return {
            "AWS_PROD_REGION": region,
            "AWS_PROD_PREVIEW_CI_CONFIG_ROLE_ARN": (
                ci_configuration.read_role_arns["prod-preview"]
            ),
            "AWS_PROD_CI_CONFIG_ROLE_ARN": ci_configuration.read_role_arns["prod"],
        }
    return {f"AWS_{settings.environment.upper()}_REGION": region}


def _secret_payload_keys(
    secret_payloads: Mapping[str, Mapping[str, pulumi.Input[str]]],
) -> dict[str, list[str]]:
    """Return sorted secret payload keys for safe stack outputs and tests."""
    return {suffix: sorted(payload) for suffix, payload in secret_payloads.items()}


def _github_ci_bootstrap_outputs(inputs: _BootstrapOutputInputs) -> dict[str, object]:
    """Return component outputs in one stable shape."""
    return {
        "oidc_provider_arn": inputs.oidc_provider_arn,
        "ci_configuration_secret_ids": inputs.ci_configuration.secret_ids,
        "ci_configuration_read_role_arns": inputs.ci_configuration.read_role_arns,
        "deployment_role_arns": inputs.role_arns,
        "operations_alert_triage_role_arn": inputs.operations_alert_triage_role_arn,
        "github_variables": inputs.github_variables,
        "secret_payload_keys": inputs.secret_payload_keys,
        "secret_versions": {
            suffix: version.version_id
            for suffix, version in inputs.secret_versions.items()
        },
    }


def _require_repo(settings: BootstrapSettings) -> BootstrapSettings:
    """Return settings only after confirming repository-scoped config exists."""
    if not settings.repo:
        raise ValueError("repoSlug config is required for GitHub CI bootstrap.")
    return settings


class GitHubCiBootstrap(pulumi.ComponentResource):
    """Provision one-time GitHub OIDC roles and AWS CI config payloads."""

    def __init__(
        self,
        name: str,
        *,
        args: GitHubCiBootstrapArgs | None = None,
        opts: pulumi.ResourceOptions | None = None,
    ) -> None:
        super().__init__("bootstrap:ci:GitHubCiBootstrap", name, None, opts)

        config = args or GitHubCiBootstrapArgs()
        configured_settings = _require_repo(config.settings or default_settings)
        account_id = aws.get_caller_identity().account_id
        partition = aws.get_partition().partition
        region = aws.get_region().region

        oidc = GitHubOidcRoles(
            f"{name}-oidc",
            settings=configured_settings,
            repositories=[],
            opts=pulumi.ResourceOptions(parent=self),
        )
        ci_configuration = CiConfiguration(
            f"{name}-configuration",
            args=CiConfigurationArgs(
                settings=configured_settings,
                oidc_provider_arn=oidc.provider.arn,
                protect_resources=config.protect_resources,
            ),
            opts=pulumi.ResourceOptions(parent=self),
        )
        context = _BootstrapBuildContext(
            parent=self,
            name=name,
            account_id=account_id,
            partition=partition,
            region=region,
            settings=configured_settings,
            provider_arn=oidc.provider.arn,
            protect_resources=config.protect_resources,
        )

        self.roles = _create_roles(
            context,
            specs=_role_specs(
                account_id=account_id,
                partition=partition,
                settings=configured_settings,
            ),
        )
        self.role_arns = {purpose: role.arn for purpose, role in self.roles.items()}

        triage_resources = _create_operations_alert_triage(context)
        self.operations_alert_triage_role = triage_resources.role
        self.operations_alert_triage_policy = triage_resources.policy

        self.secret_payloads = _payloads(
            context,
            _PayloadOverrides(
                role_arns=self.role_arns,
                operations_alert_triage_role_arn=triage_resources.role_arn,
                pulumi_backend_url=config.pulumi_backend_url,
                pulumi_secrets_provider=config.pulumi_secrets_provider,
            ),
        )
        self.secret_versions = _create_secret_versions(
            context,
            ci_configuration=ci_configuration,
            secret_payloads=self.secret_payloads,
            write_secret_values=config.write_secret_values,
        )

        self.oidc_provider_arn = oidc.provider.arn
        self.ci_configuration = ci_configuration
        self.github_variables = _github_variables(
            configured_settings,
            region=region,
            ci_configuration=ci_configuration,
        )
        self.secret_payload_keys = _secret_payload_keys(self.secret_payloads)

        self.register_outputs(
            _github_ci_bootstrap_outputs(
                _BootstrapOutputInputs(
                    oidc_provider_arn=self.oidc_provider_arn,
                    ci_configuration=ci_configuration,
                    role_arns=self.role_arns,
                    operations_alert_triage_role_arn=triage_resources.role_arn,
                    github_variables=self.github_variables,
                    secret_payload_keys=self.secret_payload_keys,
                    secret_versions=self.secret_versions,
                )
            )
        )
