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
settings = BootstrapSettings.from_pulumi_config(cfg)
write_secret_values = cfg.get_bool("writeSecretValues")
protect_resources = cfg.get_bool("protectResources")
managed_secret_values = True if write_secret_values is None else write_secret_values
protected_resources = True if protect_resources is None else protect_resources

bootstrap = GitHubCiBootstrap(
    "github-ci-bootstrap",
    args=GitHubCiBootstrapArgs(
        settings=settings,
        pulumi_backend_url=cfg.get("pulumiBackendUrl"),
        pulumi_secrets_provider=cfg.get("pulumiSecretsProvider"),
        write_secret_values=managed_secret_values,
        protect_resources=protected_resources,
    ),
)

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
