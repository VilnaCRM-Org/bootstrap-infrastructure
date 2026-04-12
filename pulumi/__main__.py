"""Pulumi entrypoint with a single orchestration point for bootstrap resources."""

from __future__ import annotations

from app import EnvironmentSettings
from infra import (
    BootstrapInfrastructure,
    BootstrapInfrastructureDependencies,
    ManagedRepositoryCatalog,
)
from infra import (
    config as bootstrap_config,
)

import pulumi

settings = EnvironmentSettings("environment-settings")
environment_settings = settings

pulumi.export("environment", settings.environment)
pulumi.export("serviceName", settings.service_name)
pulumi.export("stackTag", settings.stack_tag)
pulumi.export("defaultTags", settings.default_tags)

bootstrap_settings = bootstrap_config.settings
cfg = bootstrap_config.cfg
bootstrap_requested = bootstrap_settings.bootstrap_requested(cfg)

if bootstrap_requested:
    repository_catalog = ManagedRepositoryCatalog.from_settings(bootstrap_settings, cfg)
    dependencies = BootstrapInfrastructureDependencies()
    bootstrap = BootstrapInfrastructure(
        "bootstrap",
        settings=bootstrap_settings,
        repository_catalog=repository_catalog,
        dependencies=dependencies,
    )

    logging = bootstrap.logging
    state = bootstrap.state
    secrets = bootstrap.secrets
    oidc = bootstrap.oidc
    backup = bootstrap.backup
    if bootstrap.automation is not None:
        automation = bootstrap.automation

    pulumi.export("centralLogBucket", bootstrap.outputs["centralLogBucket"])
    pulumi.export("centralLogBucketArn", bootstrap.outputs["centralLogBucketArn"])
    pulumi.export("pulumiStateBuckets", bootstrap.outputs["pulumiStateBuckets"])
    pulumi.export("pulumiBackendUrls", bootstrap.outputs["pulumiBackendUrls"])
    pulumi.export("pulumiSecretsKeyArns", bootstrap.outputs["pulumiSecretsKeyArns"])
    pulumi.export("pulumiSecretsAliases", bootstrap.outputs["pulumiSecretsAliases"])
    pulumi_secrets_provider_urls = bootstrap.outputs["pulumiSecretsProviderUrls"]
    pulumi.export("pulumiSecretsProviderUrls", pulumi_secrets_provider_urls)
    pulumi.export("deployRoleArns", bootstrap.outputs["deployRoleArns"])
    managed_repository_projects = bootstrap.outputs["managedRepositoryProjects"]
    pulumi.export("managedRepositoryProjects", managed_repository_projects)

    if bootstrap.automation is not None:
        pulumi.export("automationRoleArn", bootstrap.outputs["automationRoleArn"])
        pulumi.export("runnerRepositoryName", bootstrap.outputs["runnerRepositoryName"])
        pulumi.export("runnerRepositoryUrl", bootstrap.outputs["runnerRepositoryUrl"])
