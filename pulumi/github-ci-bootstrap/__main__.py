"""Entrypoint for the one-time GitHub CI AWS bootstrap Pulumi project."""

from __future__ import annotations

import sys
from importlib import import_module
from pathlib import Path

PULUMI_ROOT = Path(__file__).resolve().parents[1]
if str(PULUMI_ROOT) not in sys.path:
    sys.path.insert(0, str(PULUMI_ROOT))

pulumi = import_module("pulumi")
infra = import_module("infra")
BootstrapSettings = infra.BootstrapSettings
GitHubCiBootstrap = infra.GitHubCiBootstrap
GitHubCiBootstrapArgs = infra.GitHubCiBootstrapArgs

cfg = pulumi.Config()
cfg.require("githubRepositoryId")
cfg.require("githubRepositoryOwnerId")
expected_account_id = cfg.require("awsAccountId")
aws = import_module("pulumi_aws")
governance_module = import_module("infra.governance_automation")
account_id = aws.get_caller_identity().account_id
governance_module.assert_bootstrap_account(expected_account_id, account_id)
settings = BootstrapSettings.from_pulumi_config(cfg)
write_secret_values = cfg.get_bool("writeSecretValues")
protect_resources = cfg.get_bool("protectResources")
managed_secret_values = True if write_secret_values is None else write_secret_values
if protect_resources is False:
    raise ValueError("Operator-owned resources require protectResources=true.")
protected_resources = True

governance_catalog = infra.ManagedRepositoryCatalog.load_from_json_file(
    cfg.get("governanceRepositoryCatalogPath")
    or str(PULUMI_ROOT / "repositories.governance.json")
)
for repository in governance_catalog:
    if repository.repository_id is None or repository.repository_owner_id is None:
        raise ValueError("Governance catalog repositories require pinned GitHub IDs.")

platform_catalog = infra.ManagedRepositoryCatalog.load_from_json_file(
    cfg.get("repositoryCatalogPath") or str(PULUMI_ROOT / "repositories.bootstrap.json")
)
for repository in platform_catalog:
    if repository.repository_id is None or repository.repository_owner_id is None:
        raise ValueError("Platform catalog repositories require pinned GitHub IDs.")
    if repository.name != settings.repo:
        raise ValueError("Platform catalog must contain only the bootstrap repository.")
    if repository.default_branch != settings.github_branch:
        raise ValueError(
            "Bootstrap config and platform catalog default branches differ."
        )
    if (
        repository.repository_id,
        repository.repository_owner_id,
    ) != (settings.github_repository_id, settings.github_repository_owner_id):
        raise ValueError("Bootstrap config and platform catalog GitHub IDs differ.")
governance_region = aws.get_region().region
partition = aws.get_partition().partition
platform_iam = import_module("infra.platform_iam")
platform_controls = import_module("infra.platform_control_iam")
boundaries = platform_iam.PlatformIamBoundaries(
    "platform-iam-boundaries",
    settings=settings,
    account_id=account_id,
    region=governance_region,
    repositories=platform_catalog,
)
boundary_arns = {purpose: policy.arn for purpose, policy in boundaries.policies.items()}
control_boundary_arn = boundary_arns["control"]

bootstrap = GitHubCiBootstrap(
    "github-ci-bootstrap",
    args=GitHubCiBootstrapArgs(
        settings=settings,
        pulumi_backend_url=cfg.get("pulumiBackendUrl"),
        pulumi_dir=cfg.get("pulumiDir") or "pulumi",
        pulumi_secrets_provider=cfg.get("pulumiSecretsProvider"),
        write_secret_values=managed_secret_values,
        protect_resources=protected_resources,
        control_permissions_boundary=control_boundary_arn,
        manage_oidc_provider=True,
    ),
    opts=pulumi.ResourceOptions(depends_on=[boundaries]),
)

platform_control_iam = platform_controls.PlatformControlIam(
    "platform-control-iam",
    settings=settings,
    repositories=platform_catalog,
    account_id=account_id,
    partition=partition,
    region=governance_region,
    provider_arn=bootstrap.oidc_provider_arn,
    boundary_arns=boundary_arns,
    inline_policy_names=cfg.get_object("platformInlinePolicyNames"),
    opts=pulumi.ResourceOptions(depends_on=[boundaries, bootstrap]),
)

# The operator bootstrap owns its own runner roles and immutable service
# boundaries. The delegated governance stack cannot change these resources.
governance_automation = governance_module.GovernanceAutomation(
    "governance-automation",
    args=governance_module.GovernanceAutomationArgs(
        settings=settings,
        repositories=governance_catalog,
        account_id=account_id,
        partition=aws.get_partition().partition,
        region=governance_region,
        provider_arn=bootstrap.oidc_provider_arn,
        backend_url=cfg.get("governanceBackendUrl")
        or f"s3://{settings.state_bucket_name()}/governance",
        secrets_provider=cfg.get("governanceSecretsProvider")
        or (
            f"awskms://alias/pulumi-platform-bootstrap-{settings.environment}"
            f"?region={governance_region}"
        ),
        protect_resources=protected_resources,
    ),
)
pulumi.export("governanceGithubVariables", governance_automation.github_variables)

pulumi.export("environment", settings.environment)
pulumi.export("oidcProviderArn", bootstrap.oidc_provider_arn)
pulumi.export("ciConfigurationSecretIds", bootstrap.ci_configuration.secret_ids)
pulumi.export("githubCiConfigReadRoleArns", bootstrap.ci_configuration.read_role_arns)
pulumi.export("githubCiDeploymentRoleArns", bootstrap.role_arns)
pulumi.export(
    "operationsAlertTriageRoleArn",
    (
        bootstrap.operations_alert_triage_role.arn
        if bootstrap.operations_alert_triage_role is not None
        else None
    ),
)
pulumi.export("githubVariables", bootstrap.github_variables)
pulumi.export("ciSecretPayloadKeys", bootstrap.secret_payload_keys)
pulumi.export(
    "ciSecretVersionIds",
    {
        suffix: version.version_id
        for suffix, version in bootstrap.secret_versions.items()
    },
)
