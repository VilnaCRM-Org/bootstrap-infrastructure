"""Pulumi entrypoint with a single orchestration point for bootstrap resources."""

from __future__ import annotations

from app import EnvironmentSettings

import pulumi

settings = EnvironmentSettings("environment-settings")
environment_settings = settings

pulumi.export("environment", settings.environment)
pulumi.export("serviceName", settings.service_name)
pulumi.export("stackTag", settings.stack_tag)
pulumi.export("defaultTags", settings.default_tags)

cfg = pulumi.Config()
bootstrap_requested = bool(
    cfg.get("repoSlug")
    or cfg.get("repositoryCatalogPath")
    or cfg.get_object("managedRepositories")
)

if bootstrap_requested:
    from infra import (
        BootstrapInfrastructure,
        BootstrapInfrastructureDependencies,
        ManagedRepositoryCatalog,
    )
    from infra import (
        config as bootstrap_config,
    )

    bootstrap_settings = bootstrap_config.settings
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
    monitoring = bootstrap.monitoring
    cost_controls = bootstrap.cost_controls
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
    managed_repository_metadata = bootstrap.outputs["managedRepositoryMetadata"]
    pulumi.export("managedRepositoryMetadata", managed_repository_metadata)
    pulumi.export("backupVaultName", bootstrap.outputs["backupVaultName"])
    pulumi.export("backupVaultArn", bootstrap.outputs["backupVaultArn"])
    operations_alert_topic_arn = bootstrap.outputs["operationsAlertTopicArn"]
    pulumi.export("operationsAlertTopicArn", operations_alert_topic_arn)
    operations_alert_rule_names = bootstrap.outputs["operationsAlertRuleNames"]
    pulumi.export("operationsAlertRuleNames", operations_alert_rule_names)
    operations_alert_key_alias_name = bootstrap.outputs[
        "operationsAlertTopicKeyAliasName"
    ]
    pulumi.export("operationsAlertTopicKeyAliasName", operations_alert_key_alias_name)
    pulumi.export("monthlyBudgetName", bootstrap.outputs["monthlyBudgetName"])
    pulumi.export("costAnomalyMonitorArn", bootstrap.outputs["costAnomalyMonitorArn"])
    cost_anomaly_subscription_arn = bootstrap.outputs["costAnomalySubscriptionArn"]
    pulumi.export("costAnomalySubscriptionArn", cost_anomaly_subscription_arn)

    if bootstrap.automation is not None:
        pulumi.export("automationRoleArn", bootstrap.outputs["automationRoleArn"])
        pulumi.export("runnerRepositoryName", bootstrap.outputs["runnerRepositoryName"])
        pulumi.export("runnerRepositoryUrl", bootstrap.outputs["runnerRepositoryUrl"])
