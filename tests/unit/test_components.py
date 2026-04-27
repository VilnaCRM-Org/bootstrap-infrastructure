import asyncio
import json
import runpy
from pathlib import Path

import pytest
from infra import (
    BootstrapInfrastructure,
    BootstrapInfrastructureDependencies,
    CentralLoggingBuckets,
    CostControls,
    GitHubAutomation,
    ManagedRepositoryCatalog,
    OperationsMonitoring,
    PulumiSecretsKeys,
    PulumiStateBuckets,
    S3BackupPlan,
    config,
    logging_bucket,
    operations_monitoring,
    pulumi_secrets,
    pulumi_state,
)
from infra.cost_controls import (
    COST_ALLOCATION_TAG_KEYS,
    managed_cost_allocation_tag_keys,
)
from infra.iam import GitHubOidcRoles, github_oidc
from infra.utils.outputs import future_output

# Pulumi does not expose a public sync helper for Output values in tests, so keep
# this internal import isolated here in case the SDK changes it later.
from pulumi.runtime.sync_await import _sync_await

import pulumi


def _resource_state_by_name(pulumi_mocks, name: str) -> dict:
    """Wait briefly for an asynchronously registered mock resource to appear."""
    for _ in range(50):
        for _typ, resource_name, state in pulumi_mocks.resources:
            if resource_name == name:
                return state
        asyncio.get_event_loop().run_until_complete(asyncio.sleep(0.01))
    pytest.fail(f"Expected mock resource {name!r} to be registered.")


def test_managed_cost_allocation_tag_keys_returns_stable_copy():
    """Cost allocation tag helper should return a mutable copy of stable keys."""
    tag_keys = managed_cost_allocation_tag_keys(("Owner", "CostCenter"))

    assert tag_keys == ["Owner", "CostCenter"]  # nosec B101


def test_central_logging_buckets_rejects_long_replica(  # noqa: ARG001
    pulumi_mocks, monkeypatch
):
    monkeypatch.setattr(
        logging_bucket, "central_logging_bucket_name", lambda _region: "a" * 60
    )
    monkeypatch.setattr(config.settings, "replication_region", "us-west-2")
    with pytest.raises(ValueError):
        CentralLoggingBuckets("central-logs")


def test_central_logging_buckets_reject_same_replication_region(  # noqa: ARG001
    pulumi_mocks,
):
    with pytest.raises(ValueError, match="must differ from primary region"):
        CentralLoggingBuckets("central-logs", replication_region="us-east-1")


def test_components_build(pulumi_mocks, monkeypatch):  # noqa: ARG001
    monkeypatch.setattr(config.settings, "logging_prefix", "company")
    monkeypatch.setattr(config.settings, "repo", "bootstrap-infrastructure")
    monkeypatch.setattr(config.settings, "environment", "test")
    monkeypatch.setattr(config.settings, "replication_region", "us-west-2")
    monkeypatch.setattr(
        config.settings,
        "github_oidc_provider_arn",
        "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com",
    )
    monkeypatch.setattr(
        pulumi_state, "_bucket_exists", lambda _name, provider=None: False
    )
    monkeypatch.setattr(
        logging_bucket, "_bucket_exists", lambda _name, provider=None: False
    )
    monkeypatch.setattr(github_oidc, "_role_exists", lambda _name: False)

    repos = [config.ManagedRepository(name="repo", default_branch="main")]

    logging = CentralLoggingBuckets("central-logging")
    state = PulumiStateBuckets(
        "pulumi-state", repositories=repos, replication_region=""
    )
    secrets = PulumiSecretsKeys("pulumi-secrets", repositories=repos)
    oidc = GitHubOidcRoles(
        "github-oidc", repositories=repos, secrets_key_arns=secrets.key_arns
    )
    automation = GitHubAutomation("github-automation")
    S3BackupPlan(
        "backup", backup_target_arns=[logging.bucket.arn, *state.bucket_arns.values()]
    )
    monitoring = OperationsMonitoring("operations-monitoring")

    assert logging.bucket is not None  # nosec B101
    assert state.backend_urls  # nosec B101
    assert secrets.provider_urls  # nosec B101
    assert oidc.deploy_role_arns  # nosec B101
    assert automation.repository.repository_url is not None  # nosec B101
    assert monitoring.rules  # nosec B101

    _sync_await(future_output(logging.bucket.bucket))
    _sync_await(future_output(state.backend_urls["repo"]))
    _sync_await(future_output(monitoring.topic.arn))
    _sync_await(future_output(monitoring.alert_queue.arn))
    _sync_await(future_output(monitoring.alert_queue.url))
    _sync_await(future_output(monitoring.alert_queue_subscription.arn))

    resource_states = [state for _typ, _name, state in pulumi_mocks.resources]
    central_logging_state = next(
        state
        for state in resource_states
        if state.get("bucket") == "company-central-logs-us-east-1-test"
    )
    central_logging_encryption_state = _resource_state_by_name(
        pulumi_mocks, "central-logging-primary-encryption"
    )
    state_bucket_logging_state = _resource_state_by_name(
        pulumi_mocks, "pulumi-state-repo-logging"
    )
    replica_state_bucket_logging_state = _resource_state_by_name(
        pulumi_mocks, "pulumi-state-replica-repo-logging"
    )
    alert_topic_state = _resource_state_by_name(
        pulumi_mocks, "operations-monitoring-topic"
    )
    alert_topic_key_state = _resource_state_by_name(
        pulumi_mocks, "operations-monitoring-topic-key"
    )
    alert_topic_key_alias_state = _resource_state_by_name(
        pulumi_mocks, "operations-monitoring-topic-key-alias"
    )
    alert_topic_policy_state = _resource_state_by_name(
        pulumi_mocks, "operations-monitoring-topic-policy"
    )
    alert_queue_state = _resource_state_by_name(
        pulumi_mocks, "operations-monitoring-alert-queue"
    )
    alert_queue_policy_state = _resource_state_by_name(
        pulumi_mocks, "operations-monitoring-alert-queue-policy"
    )
    alert_queue_subscription_state = _resource_state_by_name(
        pulumi_mocks, "operations-monitoring-alert-queue-subscription"
    )
    backup_rule_state = _resource_state_by_name(
        pulumi_mocks, "operations-monitoring-backup-failed-rule"
    )
    kms_rule_state = _resource_state_by_name(
        pulumi_mocks, "operations-monitoring-kms-risk-rule"
    )

    assert central_logging_encryption_state["rules"] is not None  # nosec B101
    assert central_logging_state["tags"]["LoggingExempt"] == "true"  # nosec B101
    assert (
        central_logging_state["tags"]["LoggingExemptReason"]
        == "Centralized S3 access log sink"
    )  # nosec B101
    assert (
        state_bucket_logging_state["targetBucket"]
        == "company-central-logs-us-east-1-test"
    )  # nosec B101
    assert (
        replica_state_bucket_logging_state["targetBucket"]
        == "company-central-logs-us-east-1-test-replication"
    )  # nosec B101
    assert alert_topic_state["name"] == "bootstrap-test-operations"  # nosec B101
    assert (  # nosec B101
        alert_topic_state["kmsMasterKeyId"]
        == "arn:aws:kms:us-east-1:123456789012:key/operations-monitoring-topic-key"
    )
    alert_topic_key_policy = json.loads(alert_topic_key_state["policy"])
    eventbridge_key_statement = next(
        statement
        for statement in alert_topic_key_policy["Statement"]
        if statement["Sid"] == "AllowEventBridgeForEncryptedSns"
    )
    assert alert_topic_key_state["enableKeyRotation"] is True  # nosec B101
    assert alert_topic_key_state["tags"]["Purpose"] == "operations-alerting"  # nosec B101
    assert eventbridge_key_statement["Principal"]["Service"] == (  # nosec B101
        "events.amazonaws.com"
    )
    assert "Condition" not in eventbridge_key_statement  # nosec B101
    alert_topic_policy = json.loads(alert_topic_policy_state["policy"])
    topic_statements = {
        statement["Sid"]: statement for statement in alert_topic_policy["Statement"]
    }
    assert topic_statements["AllowAccountTopicAdministration"][  # nosec B101
        "Principal"
    ] == {"AWS": "arn:aws:iam::123456789012:root"}
    topic_owner_actions = topic_statements["AllowAccountTopicAdministration"]["Action"]
    expected_topic_owner_actions = list(operations_monitoring.SNS_TOPIC_OWNER_ACTIONS)
    if topic_owner_actions != expected_topic_owner_actions:
        raise AssertionError(
            "SNS topic owner actions should stay explicit and service-scoped."
        )
    assert topic_statements["AllowEventBridgePublish"]["Condition"] == {  # nosec B101
        "StringEquals": {"aws:SourceAccount": "123456789012"}
    }
    assert topic_statements["AllowBudgetsPublish"]["Condition"] == {  # nosec B101
        "ArnLike": {
            "aws:SourceArn": "arn:aws:budgets::123456789012:*",
        },
        "StringEquals": {"aws:SourceAccount": "123456789012"},
    }
    assert topic_statements["AllowCostAnomalyPublish"]["Condition"] == {  # nosec B101
        "StringEquals": {"aws:SourceAccount": "123456789012"},
    }
    assert alert_queue_state["name"] == "bootstrap-test-operations-alerts"  # nosec B101
    assert alert_queue_state["sqsManagedSseEnabled"] is True  # nosec B101
    assert alert_queue_state["tags"]["Purpose"] == "operations-alerting"  # nosec B101
    assert alert_queue_policy_state["queueUrl"] == (  # nosec B101
        "https://sqs.us-east-1.amazonaws.com/123456789012/"
        "bootstrap-test-operations-alerts"
    )
    alert_queue_policy = json.loads(alert_queue_policy_state["policy"])
    queue_statements = {
        statement["Sid"]: statement for statement in alert_queue_policy["Statement"]
    }
    assert queue_statements["AllowOperationsTopicSendMessage"] == {  # nosec B101
        "Sid": "AllowOperationsTopicSendMessage",
        "Effect": "Allow",
        "Principal": {"Service": "sns.amazonaws.com"},
        "Action": "sqs:SendMessage",
        "Resource": (
            "arn:aws:sqs:us-east-1:123456789012:bootstrap-test-operations-alerts"
        ),
        "Condition": {
            "ArnEquals": {
                "aws:SourceArn": (
                    "arn:aws:sns:us-east-1:123456789012:bootstrap-test-operations"
                )
            },
            "StringEquals": {"aws:SourceAccount": "123456789012"},
        },
    }
    assert alert_queue_subscription_state["topic"] == (  # nosec B101
        "arn:aws:sns:us-east-1:123456789012:bootstrap-test-operations"
    )
    assert alert_queue_subscription_state["protocol"] == "sqs"  # nosec B101
    assert alert_queue_subscription_state["endpoint"] == (  # nosec B101
        "arn:aws:sqs:us-east-1:123456789012:bootstrap-test-operations-alerts"
    )
    assert (  # nosec B101
        alert_topic_key_alias_state["name"]
        == "alias/bootstrap-test-operations-alerting"
    )
    assert backup_rule_state["name"] == "bootstrap-test-backup-failed"  # nosec B101
    assert "Backup Job State Change" in backup_rule_state["eventPattern"]  # nosec B101
    assert kms_rule_state["name"] == "bootstrap-test-kms-risk"  # nosec B101
    assert "ScheduleKeyDeletion" in kms_rule_state["eventPattern"]  # nosec B101


def test_operations_monitoring_rule_name_guard(monkeypatch):
    """Rule names must stay inside the EventBridge length limit."""
    monkeypatch.setattr(config.settings, "environment", "e" * 60)

    with pytest.raises(ValueError, match="EventBridge rule name"):
        operations_monitoring._rule_name(config.settings, "backup-failed")  # noqa: SLF001


def test_operations_monitoring_policies_are_partition_aware():
    """Operations policies should support non-commercial AWS partitions."""
    topic_policy = json.loads(
        operations_monitoring._topic_policy(  # noqa: SLF001
            "arn:aws-us-gov:sns:us-gov-west-1:123456789012:bootstrap-test-operations",
            "123456789012",
            "aws-us-gov",
        )
    )
    queue_policy = json.loads(
        operations_monitoring._queue_policy(  # noqa: SLF001
            (
                "arn:aws-us-gov:sqs:us-gov-west-1:123456789012:"
                "bootstrap-test-operations-alerts"
            ),
            ("arn:aws-us-gov:sns:us-gov-west-1:123456789012:bootstrap-test-operations"),
            "123456789012",
        )
    )
    topic_key_policy = json.loads(
        operations_monitoring._topic_key_policy("123456789012", "aws-us-gov")  # noqa: SLF001
    )

    topic_statements = {
        statement["Sid"]: statement for statement in topic_policy["Statement"]
    }
    key_statements = {
        statement["Sid"]: statement for statement in topic_key_policy["Statement"]
    }
    queue_statements = {
        statement["Sid"]: statement for statement in queue_policy["Statement"]
    }

    assert topic_statements["AllowAccountTopicAdministration"]["Principal"] == {  # nosec B101
        "AWS": "arn:aws-us-gov:iam::123456789012:root"
    }
    assert key_statements["EnableAccountPermissions"]["Principal"] == {  # nosec B101
        "AWS": "arn:aws-us-gov:iam::123456789012:root"
    }
    assert topic_statements["AllowBudgetsPublish"]["Condition"]["ArnLike"] == {  # nosec B101
        "aws:SourceArn": "arn:aws-us-gov:budgets::123456789012:*"
    }
    assert queue_statements["AllowOperationsTopicSendMessage"]["Resource"] == (  # nosec B101
        "arn:aws-us-gov:sqs:us-gov-west-1:123456789012:bootstrap-test-operations-alerts"
    )
    assert queue_statements["AllowOperationsTopicSendMessage"]["Condition"] == {  # nosec B101
        "ArnEquals": {
            "aws:SourceArn": (
                "arn:aws-us-gov:sns:us-gov-west-1:123456789012:"
                "bootstrap-test-operations"
            )
        },
        "StringEquals": {"aws:SourceAccount": "123456789012"},
    }


def test_cost_controls_emit_budget_and_anomaly_resources(pulumi_mocks, monkeypatch):  # noqa: ARG001
    monkeypatch.setattr(config.settings, "environment", "test")
    monkeypatch.setattr(config.settings, "monthly_budget_limit_usd", "75")
    monkeypatch.setattr(config.settings, "cost_anomaly_threshold_usd", "15")
    monkeypatch.setattr(config.settings, "cost_anomaly_monitor_arn", None)
    monkeypatch.setattr(config.settings, "manage_cost_allocation_tags", True)

    start = len(pulumi_mocks.resources)
    controls = CostControls(
        "cost-controls",
        operations_topic_arn=(
            "arn:aws:sns:us-east-1:123456789012:bootstrap-test-operations"
        ),
    )

    budget_name = _sync_await(future_output(controls.monthly_budget.name))
    monitor_arn = _sync_await(future_output(controls.anomaly_monitor.arn))
    subscription_arn = _sync_await(future_output(controls.anomaly_subscription.arn))

    assert budget_name == "bootstrap-test-monthly-cost"  # nosec B101
    assert monitor_arn is not None  # nosec B101
    assert subscription_arn is not None  # nosec B101

    new_resources = pulumi_mocks.resources[start:]
    budget_state = next(
        state
        for resource_type, _name, state in new_resources
        if resource_type == "aws:budgets/budget:Budget"
    )
    monitor_state = next(
        state
        for resource_type, _name, state in new_resources
        if resource_type == "aws:costexplorer/anomalyMonitor:AnomalyMonitor"
    )
    subscription_state = next(
        state
        for resource_type, _name, state in new_resources
        if resource_type == "aws:costexplorer/anomalySubscription:AnomalySubscription"
    )
    allocation_tags = [
        state
        for resource_type, _name, state in new_resources
        if resource_type == "aws:costexplorer/costAllocationTag:CostAllocationTag"
    ]

    assert budget_state["limitAmount"] == "75"  # nosec B101
    assert budget_state["limitUnit"] == "USD"  # nosec B101
    assert budget_state["notifications"][0]["subscriberSnsTopicArns"] == [  # nosec B101
        "arn:aws:sns:us-east-1:123456789012:bootstrap-test-operations"
    ]
    assert monitor_state["monitorDimension"] == "SERVICE"  # nosec B101
    assert subscription_state["frequency"] == "IMMEDIATE"  # nosec B101
    assert subscription_state["subscribers"][0]["type"] == "SNS"  # nosec B101
    assert len(allocation_tags) == len(COST_ALLOCATION_TAG_KEYS)  # nosec B101


def test_cost_controls_can_reuse_existing_anomaly_monitor(pulumi_mocks, monkeypatch):  # noqa: ARG001
    existing_monitor_arn = "arn:aws:ce::123456789012:anomalymonitor/existing-service"
    monkeypatch.setattr(config.settings, "environment", "test")
    monkeypatch.setattr(
        config.settings, "cost_anomaly_monitor_arn", existing_monitor_arn
    )
    monkeypatch.setattr(config.settings, "manage_cost_allocation_tags", False)

    start = len(pulumi_mocks.resources)
    controls = CostControls(
        "cost-controls-existing-monitor",
        operations_topic_arn=(
            "arn:aws:sns:us-east-1:123456789012:bootstrap-test-operations"
        ),
    )

    monitor_arn = _sync_await(future_output(controls.anomaly_monitor_arn))
    _sync_await(future_output(controls.anomaly_subscription.arn))
    assert monitor_arn == existing_monitor_arn  # nosec B101
    assert controls.anomaly_monitor is None  # nosec B101

    new_resources = pulumi_mocks.resources[start:]
    assert not any(  # nosec B101
        resource_type == "aws:costexplorer/anomalyMonitor:AnomalyMonitor"
        for resource_type, _name, _state in new_resources
    )
    subscription_state = next(
        state
        for resource_type, _name, state in new_resources
        if resource_type == "aws:costexplorer/anomalySubscription:AnomalySubscription"
    )
    assert subscription_state["monitorArnLists"] == [existing_monitor_arn]  # nosec B101


def test_bootstrap_infrastructure_composes_catalog_and_di(pulumi_mocks, monkeypatch):  # noqa: ARG001
    monkeypatch.setattr(config.settings, "logging_prefix", "company")
    monkeypatch.setattr(config.settings, "repo", "core-service-infrastructure")
    monkeypatch.setattr(config.settings, "org", "VilnaCRM-Org")
    monkeypatch.setattr(config.settings, "environment", "test")
    monkeypatch.setattr(config.settings, "replication_region", "us-west-2")
    monkeypatch.setattr(
        config.settings,
        "github_oidc_provider_arn",
        "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com",
    )
    monkeypatch.setattr(
        pulumi_state, "_bucket_exists", lambda _name, provider=None: False
    )
    monkeypatch.setattr(
        logging_bucket, "_bucket_exists", lambda _name, provider=None: False
    )
    monkeypatch.setattr(github_oidc, "_role_exists", lambda _name: False)

    repository_catalog = ManagedRepositoryCatalog(
        [
            config.ManagedRepository(
                name="core-service-infrastructure",
                default_branch="main",
                project="core-service",
            )
        ]
    )
    bootstrap = BootstrapInfrastructure(
        "bootstrap",
        settings=config.settings,
        repository_catalog=repository_catalog,
        dependencies=BootstrapInfrastructureDependencies(),
    )

    assert bootstrap.outputs["managedRepositoryProjects"] == {
        "core-service-infrastructure": "core-service"
    }  # nosec B101
    assert bootstrap.outputs["managedRepositoryMetadata"][  # nosec B101
        "core-service-infrastructure"
    ] == {
        "defaultBranch": "main",
        "project": "core-service",
        "lifecycleState": "active",
        "expectedEnvironments": 2,
    }  # nosec B101
    assert "operationsAlertTopicArn" in bootstrap.outputs  # nosec B101
    assert "operationsAlertQueueArn" in bootstrap.outputs  # nosec B101
    assert "operationsAlertQueueSubscriptionArn" in bootstrap.outputs  # nosec B101
    assert "backupVaultArn" in bootstrap.outputs  # nosec B101
    log_delivery_dependencies = bootstrap.state._log_delivery_dependencies  # noqa: SLF001
    expected_log_delivery_dependencies = [
        bootstrap.logging.bucket,
        bootstrap.logging.replica_bucket,
    ]
    if log_delivery_dependencies != expected_log_delivery_dependencies:
        raise AssertionError("state buckets must depend on central logging buckets")

    assert bootstrap.automation is not None  # nosec B101
    _sync_await(future_output(bootstrap.automation.repository.repository_url))
    _sync_await(future_output(bootstrap.automation.role.arn))

    repository_state = next(
        state
        for resource_type, _name, state in pulumi_mocks.resources
        if resource_type == "aws:ecr/repository:Repository"
    )
    role_state = next(
        state
        for resource_type, _name, state in pulumi_mocks.resources
        if resource_type == "aws:iam/role:Role"
        and state.get("name") == "PulumiAutomation-core-service-infrastructure-test"
    )

    assert repository_state["tags"]["RepositoryProject"] == "core-service"  # nosec B101
    assert role_state["tags"]["RepositoryProject"] == "core-service"  # nosec B101

    topic_state = _resource_state_by_name(pulumi_mocks, "operations-monitoring-topic")
    assert topic_state["tags"]["Purpose"] == "operations-alerting"  # nosec B101


def test_state_buckets_reject_same_replication_region(  # noqa: ARG001
    monkeypatch, pulumi_mocks
):
    monkeypatch.setattr(config.settings, "replication_region", "us-east-1")

    repos = [config.ManagedRepository(name="repo", default_branch="main")]

    with pytest.raises(ValueError, match="must differ from primary region"):
        PulumiStateBuckets("pulumi-state-invalid", repositories=repos)


def test_github_oidc_roles_with_existing_provider(  # noqa: ARG001
    monkeypatch, pulumi_mocks
):
    class FakeProvider:
        arn = pulumi.Output.from_input(
            "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
        )

    monkeypatch.setattr(
        github_oidc.settings, "github_oidc_provider_arn", "arn:existing"
    )
    monkeypatch.setattr(
        github_oidc.aws.iam.OpenIdConnectProvider,
        "get",
        lambda *_args, **_kwargs: FakeProvider(),
    )

    repos = [config.ManagedRepository(name="repo2", default_branch="main")]
    roles = GitHubOidcRoles("github-oidc-existing", repositories=repos)
    assert roles.deploy_role_arns  # nosec B101


def test_pulumi_secrets_keys_emit_expected_resources_and_outputs(
    pulumi_mocks, monkeypatch
):  # noqa: ARG001
    monkeypatch.setattr(config.settings, "environment", "test")
    repos = [config.ManagedRepository(name="repo", default_branch="main")]
    captured = {}

    def fake_provider(repo_name, region):
        captured["repo_name"] = repo_name
        captured["region"] = region
        return "awskms://alias/pulumi-repo-test-secrets?region=us-east-1"

    monkeypatch.setattr(
        pulumi_secrets, "pulumi_secrets_provider_for_repo", fake_provider
    )

    start = len(pulumi_mocks.resources)
    secrets = PulumiSecretsKeys("pulumi-secrets", repositories=repos)

    component_urn = _sync_await(future_output(secrets.urn))
    provider_url = _sync_await(future_output(secrets.provider_urls["repo"]))
    alias_name_output = _sync_await(future_output(secrets.alias_names["repo"]))
    key_arn_output = _sync_await(future_output(secrets.key_arns["repo"]))

    assert component_urn is not None  # nosec B101
    assert provider_url is not None  # nosec B101
    assert alias_name_output is not None  # nosec B101
    assert key_arn_output is not None  # nosec B101
    assert "bootstrap:kms:PulumiSecretsKeys" in component_urn  # nosec B101
    assert provider_url == "awskms://alias/pulumi-repo-test-secrets?region=us-east-1"  # nosec B101
    assert alias_name_output == "alias/pulumi-repo-test-secrets"  # nosec B101
    assert (
        key_arn_output
        == "arn:aws:kms:us-east-1:123456789012:key/pulumi-secrets-key-repo"
    )  # nosec B101
    assert captured["repo_name"] == "repo"  # nosec B101
    assert captured["region"] == "us-east-1"  # nosec B101

    new_resources = pulumi_mocks.resources[start:]
    key_type, key_name, key_state = next(
        (type_, name, state)
        for type_, name, state in new_resources
        if type_ == "aws:kms/key:Key"
    )
    alias_type, alias_name, alias_state = next(
        (type_, name, state)
        for type_, name, state in new_resources
        if type_ == "aws:kms/alias:Alias"
    )

    assert key_type == "aws:kms/key:Key"  # nosec B101
    assert key_name == "pulumi-secrets-key-repo"  # nosec B101
    assert key_state["description"] == "Pulumi secrets KMS key for repo (main)"  # nosec B101
    assert key_state["deletionWindowInDays"] == 30  # nosec B101
    assert key_state["enableKeyRotation"] is True  # nosec B101
    assert '"AWS": "arn:aws:iam::123456789012:root"' in key_state["policy"]  # nosec B101
    assert key_state["tags"]["Purpose"] == "pulumi-secrets"  # nosec B101
    assert key_state["tags"]["Repository"] == "repo"  # nosec B101
    assert key_state["tags"]["App"] == "repo"  # nosec B101
    assert alias_type == "aws:kms/alias:Alias"  # nosec B101
    assert alias_name == "pulumi-secrets-alias-repo"  # nosec B101
    assert alias_state["name"] == "alias/pulumi-repo-test-secrets"  # nosec B101


def test_pulumi_secrets_keys_derives_repositories_without_explicit_list(
    pulumi_mocks, monkeypatch
):  # noqa: ARG001
    injected_settings = config.BootstrapSettings(
        org="VilnaCRM-Org",
        repo="settings-repo",
        environment="review",
        owner="platform",
        cost_center="core",
        data_classification="internal",
        criticality="high",
        retention_class="standard",
        github_branch="release",
        logging_prefix="company",
        replication_region="us-west-2",
        github_token=None,
        github_oidc_provider_arn=None,
    )
    monkeypatch.setattr(config.settings, "environment", "test")
    monkeypatch.setattr(
        pulumi_secrets,
        "managed_repositories",
        lambda: [config.ManagedRepository(name="global-repo", default_branch="main")],
    )

    settings_secrets = PulumiSecretsKeys(
        "pulumi-secrets-settings", settings=injected_settings
    )
    global_secrets = PulumiSecretsKeys("pulumi-secrets-global")

    settings_provider_url = _sync_await(
        future_output(settings_secrets.provider_urls["settings-repo"])
    )
    global_provider_url = _sync_await(
        future_output(global_secrets.provider_urls["global-repo"])
    )

    assert (  # nosec B101
        settings_provider_url
        == "awskms://alias/pulumi-settings-repo-review-secrets?region=us-east-1"
    )
    assert (  # nosec B101
        global_provider_url
        == "awskms://alias/pulumi-global-repo-test-secrets?region=us-east-1"
    )


def test_github_automation_emits_runner_repository_and_role(pulumi_mocks, monkeypatch):  # noqa: ARG001
    monkeypatch.setattr(config.settings, "repo", "bootstrap-infrastructure")
    monkeypatch.setattr(config.settings, "environment", "test")
    monkeypatch.setattr(config.settings, "org", "VilnaCRM-Org")
    monkeypatch.setattr(
        config.settings,
        "github_oidc_provider_arn",
        "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com",
    )

    start = len(pulumi_mocks.resources)
    automation = GitHubAutomation("github-automation")

    repository_url = _sync_await(future_output(automation.repository.repository_url))
    role_arn = _sync_await(future_output(automation.role.arn))
    assert repository_url is not None  # nosec B101
    assert role_arn is not None  # nosec B101
    assert repository_url.endswith("/pulumi-runner/bootstrap-infrastructure-test")  # nosec B101
    assert role_arn.endswith(":role/PulumiAutomation-bootstrap-infrastructure-test")  # nosec B101

    new_resources = pulumi_mocks.resources[start:]
    repository_type, _, repository_state = next(
        (type_, name, state)
        for type_, name, state in new_resources
        if type_ == "aws:ecr/repository:Repository"
    )
    role_type, _, role_state = next(
        (type_, name, state)
        for type_, name, state in new_resources
        if type_ == "aws:iam/role:Role"
        and state.get("name") == "PulumiAutomation-bootstrap-infrastructure-test"
    )
    policy_state = _resource_state_by_name(pulumi_mocks, "github-automation-policy")

    assert repository_type == "aws:ecr/repository:Repository"  # nosec B101
    assert repository_state["name"] == "pulumi-runner/bootstrap-infrastructure-test"  # nosec B101
    assert repository_state["imageTagMutability"] == "IMMUTABLE"  # nosec B101
    assert repository_state["imageScanningConfiguration"]["scanOnPush"] is True  # nosec B101
    assert role_type == "aws:iam/role:Role"  # nosec B101
    assert (
        "repo:VilnaCRM-Org/bootstrap-infrastructure:environment:test"
        in role_state["assumeRolePolicy"]
    )  # nosec B101
    automation_policy = json.loads(policy_state["policy"])
    statements = {
        statement["Sid"]: statement for statement in automation_policy["Statement"]
    }
    assert statements["ManageBootstrapEcr"]["Resource"] == [  # nosec B101
        "arn:aws:ecr:*:123456789012:repository/pulumi-runner/"
        "bootstrap-infrastructure-test"
    ]
    assert (  # nosec B101
        "arn:aws:iam::123456789012:role/PulumiAutomation-"
        "bootstrap-infrastructure-test" in statements["ManageBootstrapIam"]["Resource"]
    )
    assert statements["ManageBootstrapS3"]["Resource"] == [  # nosec B101
        "arn:aws:s3:::pulumi-*-test-state",
        "arn:aws:s3:::pulumi-*-test-state-replication",
        "arn:aws:s3:::company-central-logs-*-test",
        "arn:aws:s3:::company-central-logs-*-test-replication",
    ]
    all_actions = {
        action
        for statement in automation_policy["Statement"]
        for action in statement["Action"]
    }
    assert "kms:Decrypt" not in all_actions  # nosec B101
    assert "kms:Encrypt" not in all_actions  # nosec B101
    assert "kms:GenerateDataKey" not in all_actions  # nosec B101
    assert "kms:ReEncryptFrom" not in all_actions  # nosec B101
    assert statements["ManageBootstrapEventBridge"]["Resource"] == [  # nosec B101
        "arn:aws:events:*:123456789012:rule/bootstrap-test-*"
    ]
    assert statements["ManageBootstrapSns"]["Resource"] == [  # nosec B101
        "arn:aws:sns:*:123456789012:bootstrap-test-operations"
    ]
    assert "sns:Subscribe" in statements["ManageBootstrapSns"]["Action"]  # nosec B101
    assert statements["ManageBootstrapSnsSubscriptions"]["Resource"] == [  # nosec B101
        "arn:aws:sns:*:123456789012:bootstrap-test-operations:*"
    ]
    assert statements["ManageBootstrapSnsSubscriptions"]["Action"] == [  # nosec B101
        "sns:GetSubscriptionAttributes",
        "sns:Unsubscribe",
    ]
    assert statements["ManageBootstrapBudgets"]["Resource"] == [  # nosec B101
        "arn:aws:budgets::123456789012:budget/bootstrap-test-*"
    ]
    assert statements["CreateBudgetServiceLinkedRole"]["Resource"] == (  # nosec B101
        "arn:aws:iam::123456789012:role/aws-service-role/"
        "budgets.amazonaws.com/AWSServiceRoleForBudgets"
    )
    assert statements["CreateBudgetServiceLinkedRole"]["Condition"] == {  # nosec B101
        "StringEquals": {"iam:AWSServiceName": "budgets.amazonaws.com"}
    }
    assert statements["ReadBillingViewDataForBudgets"] == {  # nosec B101
        "Sid": "ReadBillingViewDataForBudgets",
        "Effect": "Allow",
        "Action": ["billing:GetBillingViewData"],
        "Resource": "*",
    }
    assert statements["CreateBootstrapCostExplorer"]["Resource"] == "*"  # nosec B101
    assert statements["CreateBootstrapCostExplorer"]["Condition"] == {  # nosec B101
        "StringEquals": {
            "aws:RequestTag/Environment": "test",
            "aws:RequestTag/Purpose": [
                "cost-anomaly-monitor",
                "cost-anomaly-subscription",
            ],
        }
    }
    assert statements["ManageBootstrapCostExplorer"]["Resource"] == [  # nosec B101
        "arn:aws:ce::123456789012:anomalymonitor/*",
        "arn:aws:ce::123456789012:anomalysubscription/*",
    ]
    assert (  # nosec B101
        "ManageBootstrapCostAllocationTags" not in statements
    )
    assert "budgets:ModifyBudget" in statements["ManageBootstrapBudgets"]["Action"]  # nosec B101
    assert (  # nosec B101
        "ce:CreateAnomalySubscription"
        in statements["CreateBootstrapCostExplorer"]["Action"]
    )


def test_github_automation_requires_repo(monkeypatch):
    monkeypatch.setattr(config.settings, "repo", None)
    monkeypatch.setattr(
        config.settings,
        "github_oidc_provider_arn",
        "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com",
    )

    with pytest.raises(ValueError, match="repoSlug config is required"):
        GitHubAutomation("github-automation-missing-repo")


def test_github_automation_requires_provider(monkeypatch):
    monkeypatch.setattr(config.settings, "repo", "bootstrap-infrastructure")
    monkeypatch.setattr(config.settings, "github_oidc_provider_arn", None)

    with pytest.raises(ValueError, match="githubOidcProviderArn config is required"):
        GitHubAutomation("github-automation-missing-provider")


def test_github_oidc_roles_require_matching_kms_key(  # noqa: ARG001
    monkeypatch, pulumi_mocks
):
    class FakeProvider:
        arn = pulumi.Output.from_input(
            "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
        )

    monkeypatch.setattr(
        github_oidc.settings, "github_oidc_provider_arn", "arn:existing"
    )
    monkeypatch.setattr(
        github_oidc.aws.iam.OpenIdConnectProvider,
        "get",
        lambda *_args, **_kwargs: FakeProvider(),
    )

    repos = [config.ManagedRepository(name="repo3", default_branch="main")]
    with pytest.raises(ValueError, match="Missing Pulumi secrets KMS key ARN"):
        GitHubOidcRoles(
            "github-oidc-kms-missing", repositories=repos, secrets_key_arns={}
        )


def test_github_oidc_roles_create_provider_when_missing(monkeypatch, pulumi_mocks):  # noqa: ARG001
    monkeypatch.setattr(github_oidc.settings, "github_oidc_provider_arn", None)
    monkeypatch.setattr(github_oidc.settings, "org", "VilnaCRM-Org")
    monkeypatch.setattr(github_oidc.settings, "environment", "test")

    repos = [config.ManagedRepository(name="repo3", default_branch="main")]
    roles = GitHubOidcRoles("github-oidc-created", repositories=repos)

    assert roles.deploy_role_arns  # nosec B101

    provider_state = _resource_state_by_name(
        pulumi_mocks, "github-oidc-created-provider"
    )
    assert provider_state["tags"]["Project"] == "bootstrap"  # nosec B101
    assert provider_state["tags"]["Environment"] == "test"  # nosec B101
    assert provider_state["tags"]["Owner"] == "platform"  # nosec B101
    assert provider_state["tags"]["CostCenter"] == "core"  # nosec B101
    assert provider_state["tags"]["Purpose"] == "github-actions-oidc"  # nosec B101


def test_github_oidc_roles_use_injected_settings_repositories(
    monkeypatch, pulumi_mocks
):  # noqa: ARG001
    class FakeProvider:
        arn = pulumi.Output.from_input(
            "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
        )

    injected_settings = config.BootstrapSettings(
        org="VilnaCRM-Org",
        repo=None,
        environment="test",
        owner="platform",
        cost_center="engineering",
        data_classification="internal",
        criticality="high",
        retention_class="standard",
        github_branch=None,
        logging_prefix="company",
        replication_region="us-west-2",
        github_token=None,
        github_oidc_provider_arn="arn:existing",
        managed_repo_overrides=[
            config.ManagedRepository(name="repo-managed", default_branch="main")
        ],
    )

    monkeypatch.setattr(
        github_oidc.aws.iam.OpenIdConnectProvider,
        "get",
        lambda *_args, **_kwargs: FakeProvider(),
    )
    monkeypatch.setattr(
        github_oidc,
        "managed_repositories",
        lambda: (_ for _ in ()).throw(
            AssertionError("should not use global managed repositories")
        ),
    )

    roles = GitHubOidcRoles("github-oidc-injected", settings=injected_settings)

    assert "repo-managed" in roles.deploy_role_arns  # nosec B101


def test_github_oidc_roles_use_global_repositories_without_injected_settings(
    monkeypatch, pulumi_mocks
):  # noqa: ARG001
    class FakeProvider:
        arn = pulumi.Output.from_input(
            "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
        )

    monkeypatch.setattr(
        github_oidc.settings, "github_oidc_provider_arn", "arn:existing"
    )
    monkeypatch.setattr(
        github_oidc.aws.iam.OpenIdConnectProvider,
        "get",
        lambda *_args, **_kwargs: FakeProvider(),
    )
    monkeypatch.setattr(
        github_oidc,
        "managed_repositories",
        lambda: [config.ManagedRepository(name="repo-global", default_branch="main")],
    )

    roles = GitHubOidcRoles("github-oidc-global")

    assert "repo-global" in roles.deploy_role_arns  # nosec B101


def test_github_oidc_role_name_limits_length():
    long_suffix = "a" * 70
    role_name = github_oidc._role_name_for_suffix(long_suffix)
    assert role_name.startswith(github_oidc._ROLE_NAME_PREFIX)  # nosec B101
    assert len(role_name) <= github_oidc._MAX_IAM_ROLE_NAME_LENGTH  # nosec B101


def test_github_oidc_role_exists_true(monkeypatch):
    monkeypatch.setattr(github_oidc.aws.iam, "get_role", lambda **_kwargs: object())

    assert github_oidc._role_exists("PulumiDeploy-repo") is True  # nosec B101


def test_github_oidc_role_exists_false(monkeypatch):
    def raise_missing(**_kwargs):
        raise RuntimeError("NoSuchEntity")

    monkeypatch.setattr(github_oidc.aws.iam, "get_role", raise_missing)

    assert github_oidc._role_exists("PulumiDeploy-repo") is False  # nosec B101


def test_github_oidc_role_exists_false_for_missing_resource(monkeypatch):
    def raise_missing(**_kwargs):
        raise RuntimeError("couldn't find resource")

    monkeypatch.setattr(github_oidc.aws.iam, "get_role", raise_missing)

    assert github_oidc._role_exists("PulumiDeploy-repo") is False  # nosec B101


def test_github_oidc_role_exists_raises_unexpected(monkeypatch):
    def raise_other(**_kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(github_oidc.aws.iam, "get_role", raise_other)

    with pytest.raises(RuntimeError, match="boom"):
        github_oidc._role_exists("PulumiDeploy-repo")


def test_github_oidc_repo_suffix_disambiguates_normalized_collisions():
    dotted = github_oidc._repo_suffix("team.app")
    dashed = github_oidc._repo_suffix("team-app")
    underscored = github_oidc._repo_suffix("team_app")
    assert dotted.startswith("team-app-")  # nosec B101
    assert dotted != dashed  # nosec B101
    assert underscored.startswith("team-app-")  # nosec B101
    assert underscored != dashed  # nosec B101


def test_truncate_role_suffix_keeps_short():
    short_suffix = "repo-short"
    assert github_oidc._truncate_role_suffix(short_suffix) == short_suffix  # nosec B101


def test_truncate_role_suffix_truncates_long():
    long_suffix = "a" * 70
    truncated = github_oidc._truncate_role_suffix(long_suffix)
    assert truncated != long_suffix  # nosec B101
    max_suffix_len = github_oidc._MAX_IAM_ROLE_NAME_LENGTH - len(
        github_oidc._ROLE_NAME_PREFIX
    )
    assert len(truncated) <= max_suffix_len  # nosec B101


def test_task_roles_module_has_no_exports():
    from infra.iam import task_roles

    assert task_roles.__all__ == []  # nosec B101


def test_stack_main_executes(pulumi_mocks, monkeypatch):  # noqa: ARG001
    config.managed_repositories.cache_clear()
    try:
        monkeypatch.setattr(config.settings, "repo", "repo")
        monkeypatch.setattr(config.settings, "environment", "test")
        monkeypatch.setattr(config.settings, "replication_region", "us-west-2")
        monkeypatch.setattr(
            config.settings,
            "github_oidc_provider_arn",
            "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com",
        )
        monkeypatch.setattr(config.settings, "managed_repo_overrides", None)
        stack_path = Path(__file__).resolve().parents[2] / "pulumi" / "__main__.py"
        # Keep a fast stack smoke test alongside the integration suite.
        runpy.run_path(str(stack_path))
    finally:
        config.managed_repositories.cache_clear()


def test_stack_main_executes_bootstrap_repo_mode(  # noqa: ARG001
    pulumi_mocks, monkeypatch
):
    config.managed_repositories.cache_clear()
    try:
        monkeypatch.setattr(config.settings, "repo", "repo")
        monkeypatch.setattr(config.settings, "org", "VilnaCRM-Org")
        monkeypatch.setattr(config.settings, "environment", "test")
        monkeypatch.setattr(config.settings, "replication_region", "us-west-2")
        monkeypatch.setattr(config.settings, "managed_repo_overrides", None)
        monkeypatch.setattr(
            config.settings,
            "github_oidc_provider_arn",
            "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com",
        )

        class FakeConfig:
            def get(self, key, default=None):
                values = {
                    "environment": "test",
                    "serviceName": "bootstrap-infrastructure",
                    "repoSlug": "repo",
                    "githubOrg": "VilnaCRM-Org",
                    "githubBranch": "main",
                    "githubOidcProviderArn": (
                        "arn:aws:iam::123456789012:oidc-provider/"
                        "token.actions.githubusercontent.com"
                    ),
                }
                return values.get(key, default)

            def get_object(self, key, default=None):
                return {"managedRepositories": None}.get(key, default)

        monkeypatch.setattr(pulumi, "Config", lambda: FakeConfig())
        stack_path = Path(__file__).resolve().parents[2] / "pulumi" / "__main__.py"

        module_globals = runpy.run_path(str(stack_path))

        assert module_globals["state"].backend_urls  # nosec B101
        assert module_globals["secrets"].provider_urls  # nosec B101
        assert module_globals["oidc"].deploy_role_arns  # nosec B101
        assert module_globals["automation"].repository.repository_url is not None  # nosec B101
    finally:
        config.managed_repositories.cache_clear()


def test_stack_main_executes_managed_repository_mode_without_automation(  # noqa: ARG001
    pulumi_mocks, monkeypatch
):
    config.managed_repositories.cache_clear()
    try:
        repo = config.ManagedRepository(name="repo-managed", default_branch="main")
        monkeypatch.setattr(config.settings, "repo", None)
        monkeypatch.setattr(config.settings, "org", "VilnaCRM-Org")
        monkeypatch.setattr(config.settings, "environment", "test")
        monkeypatch.setattr(config.settings, "replication_region", "us-west-2")
        monkeypatch.setattr(config.settings, "managed_repo_overrides", [repo])
        monkeypatch.setattr(
            config.settings,
            "github_oidc_provider_arn",
            "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com",
        )

        class FakeConfig:
            def get(self, key, default=None):
                values = {
                    "environment": "test",
                    "serviceName": "bootstrap-infrastructure",
                    "githubOrg": "VilnaCRM-Org",
                    "githubBranch": "main",
                    "githubOidcProviderArn": (
                        "arn:aws:iam::123456789012:oidc-provider/"
                        "token.actions.githubusercontent.com"
                    ),
                }
                return values.get(key, default)

            def get_object(self, key, default=None):
                values = {
                    "managedRepositories": [
                        {"name": "repo-managed", "defaultBranch": "main"}
                    ]
                }
                return values.get(key, default)

        monkeypatch.setattr(pulumi, "Config", lambda: FakeConfig())
        stack_path = Path(__file__).resolve().parents[2] / "pulumi" / "__main__.py"

        module_globals = runpy.run_path(str(stack_path))

        assert module_globals["state"].backend_urls  # nosec B101
        assert module_globals["secrets"].provider_urls  # nosec B101
        assert module_globals["oidc"].deploy_role_arns  # nosec B101
        assert "automation" not in module_globals  # nosec B101
    finally:
        config.managed_repositories.cache_clear()
