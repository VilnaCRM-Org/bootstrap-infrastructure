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
    security_account_controls = bootstrap.security_account_controls
    if bootstrap.automation is not None:
        automation = bootstrap.automation
    if bootstrap.ci_config is not None:
        ci_config = bootstrap.ci_config

    pulumi.export("centralLogBucket", bootstrap.outputs["centralLogBucket"])
    pulumi.export("centralLogBucketArn", bootstrap.outputs["centralLogBucketArn"])
    pulumi.export("pulumiStateBuckets", bootstrap.outputs["pulumiStateBuckets"])
    pulumi.export("pulumiBackendUrls", bootstrap.outputs["pulumiBackendUrls"])
    pulumi.export("pulumiSecretsKeyArns", bootstrap.outputs["pulumiSecretsKeyArns"])
    pulumi.export("pulumiSecretsAliases", bootstrap.outputs["pulumiSecretsAliases"])
    pulumi_secrets_provider_urls = bootstrap.outputs["pulumiSecretsProviderUrls"]
    pulumi.export("pulumiSecretsProviderUrls", pulumi_secrets_provider_urls)
    pulumi.export("deployRoleArns", bootstrap.outputs["deployRoleArns"])
    if bootstrap.ci_config is not None:
        pulumi.export(
            "ciConfigurationSecretIds",
            bootstrap.outputs["ciConfigurationSecretIds"],
        )
        pulumi.export(
            "ciConfigurationSecretArns",
            bootstrap.outputs["ciConfigurationSecretArns"],
        )
        pulumi.export(
            "githubCiConfigReadRoleArns",
            bootstrap.outputs["githubCiConfigReadRoleArns"],
        )
    managed_repository_projects = bootstrap.outputs["managedRepositoryProjects"]
    pulumi.export("managedRepositoryProjects", managed_repository_projects)
    managed_repository_metadata = bootstrap.outputs["managedRepositoryMetadata"]
    pulumi.export("managedRepositoryMetadata", managed_repository_metadata)
    pulumi.export("backupVaultName", bootstrap.outputs["backupVaultName"])
    pulumi.export("backupVaultArn", bootstrap.outputs["backupVaultArn"])
    pulumi.export("backupRoleArn", bootstrap.outputs["backupRoleArn"])
    operations_alert_topic_arn = bootstrap.outputs["operationsAlertTopicArn"]
    pulumi.export("operationsAlertTopicArn", operations_alert_topic_arn)
    pulumi.export(
        "operationsCloudTrailBucketName",
        bootstrap.outputs["operationsCloudTrailBucketName"],
    )
    pulumi.export(
        "operationsCloudTrailName",
        bootstrap.outputs["operationsCloudTrailName"],
    )
    operations_alert_rule_names = bootstrap.outputs["operationsAlertRuleNames"]
    pulumi.export("operationsAlertRuleNames", operations_alert_rule_names)
    operations_alert_key_alias_name = bootstrap.outputs[
        "operationsAlertTopicKeyAliasName"
    ]
    pulumi.export("operationsAlertTopicKeyAliasName", operations_alert_key_alias_name)
    operations_alert_queue_arn = bootstrap.outputs["operationsAlertQueueArn"]
    pulumi.export("operationsAlertQueueArn", operations_alert_queue_arn)
    operations_alert_queue_name = bootstrap.outputs["operationsAlertQueueName"]
    pulumi.export("operationsAlertQueueName", operations_alert_queue_name)
    operations_alert_queue_url = bootstrap.outputs["operationsAlertQueueUrl"]
    pulumi.export("operationsAlertQueueUrl", operations_alert_queue_url)
    operations_alert_queue_subscription_arn = bootstrap.outputs[
        "operationsAlertQueueSubscriptionArn"
    ]
    pulumi.export(
        "operationsAlertQueueSubscriptionArn", operations_alert_queue_subscription_arn
    )
    pulumi.export("monthlyBudgetName", bootstrap.outputs["monthlyBudgetName"])
    pulumi.export("costAnomalyMonitorArn", bootstrap.outputs["costAnomalyMonitorArn"])
    cost_anomaly_subscription_arn = bootstrap.outputs["costAnomalySubscriptionArn"]
    pulumi.export("costAnomalySubscriptionArn", cost_anomaly_subscription_arn)
    pulumi.export("guardDutyDetectorId", bootstrap.outputs["guardDutyDetectorId"])
    pulumi.export("securityHubAccountArn", bootstrap.outputs["securityHubAccountArn"])
    pulumi.export(
        "awsConfigRecorderName",
        bootstrap.outputs["awsConfigRecorderName"],
    )
    pulumi.export(
        "awsConfigDeliveryChannelName",
        bootstrap.outputs["awsConfigDeliveryChannelName"],
    )
    pulumi.export(
        "awsConfigDeliveryBucketName",
        bootstrap.outputs["awsConfigDeliveryBucketName"],
    )

    if bootstrap.automation is not None:
        pulumi.export("automationRoleArn", bootstrap.outputs["automationRoleArn"])
        pulumi.export(
            "operationsAlertTriageRoleArn",
            bootstrap.outputs["operationsAlertTriageRoleArn"],
        )
        pulumi.export("runnerRepositoryName", bootstrap.outputs["runnerRepositoryName"])
        pulumi.export("runnerRepositoryUrl", bootstrap.outputs["runnerRepositoryUrl"])
