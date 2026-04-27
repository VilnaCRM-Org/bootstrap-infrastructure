"""Single orchestration point for the bootstrap infrastructure stack."""

from __future__ import annotations

import pulumi

from .bootstrap_dependencies import BootstrapInfrastructureDependencies
from .bootstrap_settings import BootstrapSettings
from .repository_catalog import ManagedRepositoryCatalog


class BootstrapInfrastructure(pulumi.ComponentResource):
    """Compose the full bootstrap infrastructure from injected dependencies."""

    def __init__(
        self,
        name: str,
        *,
        settings: BootstrapSettings,
        repository_catalog: ManagedRepositoryCatalog,
        dependencies: BootstrapInfrastructureDependencies | None = None,
        opts: pulumi.ResourceOptions | None = None,
    ) -> None:
        super().__init__("bootstrap:infra:BootstrapInfrastructure", name, None, opts)

        self.settings = settings
        self.repository_catalog = repository_catalog
        self.dependencies = dependencies or BootstrapInfrastructureDependencies()

        child_opts = pulumi.ResourceOptions(parent=self)
        repositories = repository_catalog.repositories

        self.logging = self.dependencies.logging_buckets_cls(
            "central-logging",
            settings=settings,
            opts=child_opts,
        )
        self.state = self.dependencies.state_buckets_cls(
            "pulumi-state",
            settings=settings,
            repositories=repositories,
            log_delivery_dependencies=[
                self.logging.bucket,
                self.logging.replica_bucket,
            ],
            opts=child_opts,
        )
        self.secrets = self.dependencies.secrets_keys_cls(
            "pulumi-secrets",
            settings=settings,
            repositories=repositories,
            opts=child_opts,
        )
        self.oidc = self.dependencies.oidc_roles_cls(
            "github-oidc",
            settings=settings,
            repositories=repositories,
            secrets_key_arns=self.secrets.key_arns,
            opts=child_opts,
        )
        self.automation = None
        if settings.repo:
            automation_repository = next(
                (
                    repository
                    for repository in repositories
                    if repository.name == settings.repo
                ),
                None,
            )
            self.automation = self.dependencies.automation_cls(
                "github-automation",
                settings=settings,
                repository_project=(
                    automation_repository.project_name
                    if automation_repository is not None
                    else settings.repo
                ),
                oidc_provider_arn=self.oidc.provider.arn,
                opts=child_opts,
            )

        backup_targets = [self.logging.bucket.arn, *self.state.bucket_arns.values()]
        self.backup = self.dependencies.backup_plan_cls(
            "s3-backup",
            settings=settings,
            backup_target_arns=backup_targets,
            opts=child_opts,
        )
        self.monitoring = self.dependencies.monitoring_cls(
            "operations-monitoring",
            settings=settings,
            opts=child_opts,
        )
        self.cost_controls = self.dependencies.cost_controls_cls(
            "cost-controls",
            operations_topic_arn=self.monitoring.topic.arn,
            notification_dependencies=[self.monitoring.topic_policy],
            settings=settings,
            opts=child_opts,
        )

        self.outputs: dict[str, pulumi.Input[object]] = {
            "centralLogBucket": self.logging.bucket.bucket,
            "centralLogBucketArn": self.logging.bucket.arn,
            "pulumiStateBuckets": self.state.state_buckets,
            "pulumiBackendUrls": self.state.backend_urls,
            "pulumiSecretsKeyArns": self.secrets.key_arns,
            "pulumiSecretsAliases": self.secrets.alias_names,
            "pulumiSecretsProviderUrls": self.secrets.provider_urls,
            "deployRoleArns": self.oidc.deploy_role_arns,
            "managedRepositoryProjects": repository_catalog.project_mapping(),
            "managedRepositoryMetadata": repository_catalog.metadata_mapping(),
            "backupVaultName": self.backup.vault.name,
            "backupVaultArn": self.backup.vault.arn,
            "operationsAlertTopicArn": self.monitoring.topic.arn,
            "operationsAlertRuleNames": {
                suffix: rule.name for suffix, rule in self.monitoring.rules.items()
            },
            "operationsAlertTopicKeyAliasName": self.monitoring.topic_key_alias.name,
            "monthlyBudgetName": self.cost_controls.monthly_budget.name,
            "costAnomalyMonitorArn": self.cost_controls.anomaly_monitor_arn,
            "costAnomalySubscriptionArn": (self.cost_controls.anomaly_subscription.arn),
        }
        if self.automation is not None:
            self.outputs.update(
                {
                    "automationRoleArn": self.automation.role.arn,
                    "runnerRepositoryName": self.automation.repository.name,
                    "runnerRepositoryUrl": self.automation.repository.repository_url,
                }
            )

        self.register_outputs(self.outputs)
