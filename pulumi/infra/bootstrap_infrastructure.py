"""Single orchestration point for the bootstrap infrastructure stack."""

from __future__ import annotations

from collections.abc import Sequence

import pulumi

from .bootstrap_dependencies import BootstrapInfrastructureDependencies
from .bootstrap_settings import BootstrapSettings
from .cost_controls import CostControlInputs
from .managed_repository import ManagedRepository
from .repository_catalog import ManagedRepositoryCatalog


def _repository_project(
    repositories: Sequence[ManagedRepository],
    repository_name: str,
) -> str:
    """Return the catalog project for a repository, falling back to its name."""
    for repository in repositories:
        if repository.name == repository_name:
            return repository.project_name
    return repository_name


def _create_ci_config(
    *,
    dependencies: BootstrapInfrastructureDependencies,
    settings: BootstrapSettings,
    opts: pulumi.ResourceOptions,
):
    """Create Pulumi ESC AWS backing resources when a runner repo is configured."""
    if not settings.repo:
        return None
    return dependencies.ci_config_cls(
        "ci-configuration",
        settings=settings,
        opts=opts,
    )


def _create_automation(
    *,
    bootstrap,
    repositories: Sequence[ManagedRepository],
    opts: pulumi.ResourceOptions,
):
    """Create the bootstrap automation role for repo-scoped stacks."""
    settings = bootstrap.settings
    if not settings.repo:
        return None
    return bootstrap.dependencies.automation_cls(
        "github-automation",
        settings=settings,
        repository_project=_repository_project(repositories, settings.repo),
        oidc_provider_arn=bootstrap.oidc.provider.arn,
        opts=opts,
    )


def _automation_policy_dependencies(automation) -> list[pulumi.Resource]:
    """Return resources that policy-driven controls must wait for."""
    if automation is None:
        return []
    return list(automation.policy_dependencies)


def _base_outputs(
    bootstrap,
    repository_catalog: ManagedRepositoryCatalog,
) -> dict[str, pulumi.Input[object]]:
    """Return outputs emitted by every bootstrap stack."""
    return {
        "centralLogBucket": bootstrap.logging.bucket.bucket,
        "centralLogBucketArn": bootstrap.logging.bucket.arn,
        "pulumiStateBuckets": bootstrap.state.state_buckets,
        "pulumiBackendUrls": bootstrap.state.backend_urls,
        "pulumiSecretsKeyArns": bootstrap.secrets.key_arns,
        "pulumiSecretsAliases": bootstrap.secrets.alias_names,
        "pulumiSecretsProviderUrls": bootstrap.secrets.provider_urls,
        "deployRoleArns": bootstrap.oidc.deploy_role_arns,
        "managedRepositoryProjects": repository_catalog.project_mapping(),
        "managedRepositoryMetadata": repository_catalog.metadata_mapping(),
        "backupVaultName": bootstrap.backup.vault.name,
        "backupVaultArn": bootstrap.backup.vault.arn,
        "backupRoleArn": bootstrap.backup.role.arn,
        "operationsAlertTopicArn": bootstrap.monitoring.topic.arn,
        "operationsCloudTrailBucketName": bootstrap.monitoring.cloudtrail_bucket_name,
        "operationsCloudTrailName": bootstrap.monitoring.cloudtrail_name,
        "operationsAlertRuleNames": {
            suffix: rule.name for suffix, rule in bootstrap.monitoring.rules.items()
        },
        "operationsAlertTopicKeyAliasName": (bootstrap.monitoring.topic_key_alias.name),
        "operationsAlertQueueArn": bootstrap.monitoring.alert_queue.arn,
        "operationsAlertQueueName": bootstrap.monitoring.alert_queue.name,
        "operationsAlertQueueUrl": bootstrap.monitoring.alert_queue.url,
        "operationsAlertQueueSubscriptionArn": (
            bootstrap.monitoring.alert_queue_subscription.arn
        ),
        "monthlyBudgetName": bootstrap.cost_controls.monthly_budget.name,
        "costAnomalyMonitorArn": bootstrap.cost_controls.anomaly_monitor_arn,
        "costAnomalySubscriptionArn": (
            bootstrap.cost_controls.anomaly_subscription.arn
        ),
        "guardDutyDetectorId": (
            bootstrap.security_account_controls.guardduty_detector.id
        ),
        "securityHubAccountArn": (
            bootstrap.security_account_controls.security_hub_account.arn
        ),
        "awsConfigRecorderName": (
            bootstrap.security_account_controls.config_recorder.name
        ),
        "awsConfigDeliveryChannelName": (
            bootstrap.security_account_controls.config_delivery_channel.name
        ),
        "awsConfigDeliveryBucketName": (
            bootstrap.security_account_controls.config_bucket.bucket
        ),
    }


def _automation_outputs(automation) -> dict[str, pulumi.Input[object]]:
    """Return outputs for repo-scoped GitHub automation resources."""
    if automation is None:
        return {}
    return {
        "automationRoleArn": automation.role.arn,
        "operationsAlertTriageRoleArn": (automation.operations_alert_triage_role.arn),
        "runnerRepositoryName": automation.repository.name,
        "runnerRepositoryUrl": automation.repository.repository_url,
    }


def _ci_config_outputs(ci_config) -> dict[str, pulumi.Input[object]]:
    """Return outputs for AWS Secrets Manager backed Pulumi ESC resources."""
    if ci_config is None:
        return {}
    return {
        "ciConfigurationSecretIds": ci_config.secret_ids,
        "ciConfigurationSecretArns": ci_config.secret_arns,
        "pulumiEscSecretsReadRoleArn": ci_config.read_role.arn,
    }


def _bootstrap_outputs(
    bootstrap,
    repository_catalog: ManagedRepositoryCatalog,
) -> dict[str, pulumi.Input[object]]:
    """Return the complete stack output map."""
    outputs = _base_outputs(bootstrap, repository_catalog)
    outputs.update(_automation_outputs(bootstrap.automation))
    outputs.update(_ci_config_outputs(bootstrap.ci_config))
    return outputs


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
        self.ci_config = _create_ci_config(
            dependencies=self.dependencies,
            settings=settings,
            opts=child_opts,
        )
        self.automation = _create_automation(
            bootstrap=self,
            repositories=repositories,
            opts=child_opts,
        )
        automation_policy_dependencies = _automation_policy_dependencies(
            self.automation
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
            resource_dependencies=automation_policy_dependencies,
            opts=child_opts,
        )
        self.cost_controls = self.dependencies.cost_controls_cls(
            "cost-controls",
            CostControlInputs(
                operations_topic_arn=self.monitoring.topic.arn,
                notification_dependencies=[self.monitoring.topic_policy],
                resource_dependencies=automation_policy_dependencies,
                settings=settings,
            ),
            opts=child_opts,
        )
        self.security_account_controls = (
            self.dependencies.security_account_controls_cls(
                "security-account-controls",
                resource_dependencies=automation_policy_dependencies,
                settings=settings,
                opts=child_opts,
            )
        )

        self.outputs = _bootstrap_outputs(self, repository_catalog)
        self.register_outputs(self.outputs)
