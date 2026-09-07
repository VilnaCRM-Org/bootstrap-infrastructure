import hashlib
import json
from types import SimpleNamespace

import infra.automation as automation
import infra.bootstrap_infrastructure as bootstrap_infrastructure
import pytest
from infra import ci_config, config, pulumi_secrets
from infra.iam import github_oidc

import pulumi


def test_mutation_target_pulumi_secrets_key_policy():
    policy = json.loads(pulumi_secrets._key_policy("123456789012"))
    statement = policy["Statement"][0]
    assert policy["Version"] == "2012-10-17"  # nosec B101
    assert statement["Sid"] == "EnableAccountPermissions"  # nosec B101
    assert statement["Effect"] == "Allow"  # nosec B101
    assert statement["Principal"]["AWS"] == "arn:aws:iam::123456789012:root"  # nosec B101
    assert statement["Action"] == "kms:*"  # nosec B101
    assert statement["Resource"] == "*"  # nosec B101


def test_mutation_target_adoption_helpers_detect_existing_resources(monkeypatch):
    monkeypatch.setattr(
        automation.aws.ecr,
        "get_repository",
        lambda name: SimpleNamespace(name=name),
    )
    monkeypatch.setattr(
        automation.aws.iam,
        "get_role",
        lambda name: SimpleNamespace(name=name),
    )
    monkeypatch.setattr(
        pulumi_secrets.aws.kms,
        "get_alias",
        lambda name: SimpleNamespace(name=name),
    )

    assert automation._ecr_repository_exists("repo") is True  # nosec B101
    assert automation._iam_role_exists("role") is True  # nosec B101
    assert pulumi_secrets._kms_alias_exists("alias/repo") is True  # nosec B101


def test_mutation_target_bootstrap_repository_project_fallback():
    repositories = [
        config.ManagedRepository(
            name="core-service-infrastructure",
            default_branch="main",
            project="core-service",
        )
    ]

    assert (  # nosec B101
        bootstrap_infrastructure._repository_project(
            repositories,
            "core-service-infrastructure",
        )
        == "core-service"
    )
    assert (  # nosec B101
        bootstrap_infrastructure._repository_project(repositories, "missing-repo")
        == "missing-repo"
    )


def test_mutation_target_ci_config_secret_contract():
    settings = config.BootstrapSettings(
        org="VilnaCRM-Org",
        repo="bootstrap-infrastructure",
        environment="test",
        owner="platform",
        cost_center="core",
        data_classification="internal",
        criticality="high",
        retention_class="standard",
        github_branch="main",
        logging_prefix="company",
        replication_region=None,
        github_token=None,
        github_oidc_provider_arn=None,
    )

    assert ci_config._ci_secret_suffixes("test") == ("test-pr", "test")  # nosec B101
    assert ci_config._ci_secret_suffixes("prod") == (  # nosec B101
        "prod-preview",
        "prod",
    )
    assert ci_config._ci_secret_id(settings, "test") == (  # nosec B101
        "/bootstrap-infrastructure/ci/test"
    )
    assert ci_config._github_actions_subjects(settings, "test-pr") == [  # nosec B101
        "repo:VilnaCRM-Org/bootstrap-infrastructure:pull_request"
    ]
    assert ci_config._github_actions_subjects(settings, "test") == [  # nosec B101
        "repo:VilnaCRM-Org/bootstrap-infrastructure:ref:refs/heads/main",
        "repo:VilnaCRM-Org/bootstrap-infrastructure:environment:test",
        "repo:VilnaCRM-Org/bootstrap-infrastructure:environment:test-preview",
    ]

    policy = json.loads(
        ci_config._ci_config_read_policy(
            region="eu-central-1",
            secret_arns=(
                "arn:aws:secretsmanager:eu-central-1:123456789012:secret:/bootstrap-infrastructure/ci/test-aBc123",
            ),
            account_id="123456789012",
            partition="aws",
            settings=settings,
            suffixes=("test-pr", "test"),
        )
    )
    statement = policy["Statement"][0]
    assert statement["Action"] == [  # nosec B101
        "secretsmanager:DescribeSecret",
        "secretsmanager:GetSecretValue",
    ]
    assert statement["Resource"] == [  # nosec B101
        (
            "arn:aws:secretsmanager:*:123456789012:secret:"
            "/bootstrap-infrastructure/ci/test-pr-*"
        ),
        (
            "arn:aws:secretsmanager:*:123456789012:secret:"
            "/bootstrap-infrastructure/ci/test-*"
        ),
    ]


def test_mutation_target_ci_config_validation_and_lookup_helpers(monkeypatch):
    settings = config.BootstrapSettings(
        org="VilnaCRM-Org",
        repo="bootstrap-infrastructure",
        environment="test",
        owner="platform",
        cost_center="core",
        data_classification="internal",
        criticality="high",
        retention_class="standard",
        github_branch="main",
        logging_prefix="company",
        replication_region=None,
        github_token=None,
        github_oidc_provider_arn=None,
    )
    no_repo_settings = config.BootstrapSettings(
        org="VilnaCRM-Org",
        repo=None,
        environment="test",
        owner="platform",
        cost_center="core",
        data_classification="internal",
        criticality="high",
        retention_class="standard",
        github_branch="main",
        logging_prefix="company",
        replication_region=None,
        github_token=None,
        github_oidc_provider_arn=None,
    )
    long_role_settings = config.BootstrapSettings(
        org="VilnaCRM-Org",
        repo="a" * 50,
        environment="test",
        owner="platform",
        cost_center="core",
        data_classification="internal",
        criticality="high",
        retention_class="standard",
        github_branch="main",
        logging_prefix="company",
        replication_region=None,
        github_token=None,
        github_oidc_provider_arn=None,
    )

    with pytest.raises(ValueError, match="repoSlug config is required"):
        ci_config._ci_config_project(no_repo_settings)
    with pytest.raises(ValueError, match="repoSlug config is required"):
        ci_config._github_actions_subjects(no_repo_settings, "test")
    with pytest.raises(ValueError, match="repoSlug config is required"):
        ci_config._github_actions_workflows(no_repo_settings, "test")
    with pytest.raises(ValueError, match="longer than 64 characters"):
        ci_config._ci_config_read_role_name(long_role_settings, "test")
    assert ci_config._ci_config_read_role_name(settings, "test") == (  # nosec B101
        "GitHubCiConfigRead-bootstrap-infrastructure-test"
    )
    assert ci_config._github_actions_subjects(settings, "test-pr") == [  # nosec B101
        "repo:VilnaCRM-Org/bootstrap-infrastructure:pull_request"
    ]
    assert ci_config._github_actions_workflows(settings, "test-pr") == [  # nosec B101
        "Pulumi PR Guardrails",
        "Well-Architected Evidence",
    ]
    assert ci_config._github_actions_subjects(settings, "prod") == [  # nosec B101
        "repo:VilnaCRM-Org/bootstrap-infrastructure:environment:prod"
    ]
    trust_policy = json.loads(
        ci_config._ci_config_read_assume_role_policy(
            "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com",
            settings,
            "prod-preview",
        )
    )
    assert trust_policy["Statement"][0]["Condition"]["StringEquals"][  # nosec B101
        "token.actions.githubusercontent.com:sub"
    ] == [
        "repo:VilnaCRM-Org/bootstrap-infrastructure:ref:refs/heads/main",
        "repo:VilnaCRM-Org/bootstrap-infrastructure:environment:prod-preview",
    ]
    assert ci_config._is_missing_lookup_error(  # nosec B101
        "reading KMS Alias: empty result",
        (),
    )
    assert not ci_config._is_missing_lookup_error("iam throttled", ())  # nosec B101

    monkeypatch.setattr(
        ci_config.aws.secretsmanager,
        "get_secret",
        lambda *, name: SimpleNamespace(arn=f"arn:aws:secretsmanager:::secret:{name}"),
    )
    assert ci_config._secret_import_id("present") == (  # nosec B101
        "arn:aws:secretsmanager:::secret:present"
    )
    monkeypatch.setattr(
        ci_config.aws.secretsmanager,
        "get_secret",
        lambda *, name: SimpleNamespace(name=name),
    )
    assert ci_config._secret_import_id("without-arn") is None  # nosec B101

    def missing_secret(*, name):  # noqa: ARG001
        raise RuntimeError("ResourceNotFoundException")

    def failing_secret(*, name):  # noqa: ARG001
        raise RuntimeError("secretsmanager throttled")

    monkeypatch.setattr(ci_config.aws.secretsmanager, "get_secret", missing_secret)
    assert ci_config._secret_import_id("missing") is None  # nosec B101
    monkeypatch.setattr(ci_config.aws.secretsmanager, "get_secret", failing_secret)
    with pytest.raises(RuntimeError, match="secretsmanager throttled"):
        ci_config._secret_import_id("failing")

    monkeypatch.setattr(
        ci_config.aws.iam,
        "get_role",
        lambda *, name: SimpleNamespace(arn=f"arn:aws:iam:::role/{name}"),
    )
    assert ci_config._iam_role_exists("present") is True  # nosec B101

    def missing_role(*, name):  # noqa: ARG001
        raise RuntimeError("NoSuchEntity")

    def failing_role(*, name):  # noqa: ARG001
        raise RuntimeError("iam throttled")

    monkeypatch.setattr(ci_config.aws.iam, "get_role", missing_role)
    assert ci_config._iam_role_exists("missing") is False  # nosec B101
    monkeypatch.setattr(ci_config.aws.iam, "get_role", failing_role)
    with pytest.raises(RuntimeError, match="iam throttled"):
        ci_config._iam_role_exists("failing")


def test_mutation_target_adoption_helpers_treat_not_found_as_absent(monkeypatch):
    def missing_ecr_repository(*, name):
        raise RuntimeError(f"RepositoryNotFoundException: {name}")

    def missing_iam_role(*, name):
        raise RuntimeError(f"NoSuchEntity: {name}")

    def missing_kms_alias(*, name):
        raise RuntimeError(f"NotFoundException: {name}")

    monkeypatch.setattr(automation.aws.ecr, "get_repository", missing_ecr_repository)
    monkeypatch.setattr(automation.aws.iam, "get_role", missing_iam_role)
    monkeypatch.setattr(pulumi_secrets.aws.kms, "get_alias", missing_kms_alias)

    assert automation._ecr_repository_exists("repo") is False  # nosec B101
    assert automation._iam_role_exists("role") is False  # nosec B101
    assert pulumi_secrets._kms_alias_exists("alias/repo") is False  # nosec B101


def test_mutation_target_kms_alias_empty_result_is_absent(monkeypatch):
    def missing_kms_alias(*, name):
        raise RuntimeError(f"reading KMS Alias ({name}): empty result")

    monkeypatch.setattr(pulumi_secrets.aws.kms, "get_alias", missing_kms_alias)

    assert pulumi_secrets._kms_alias_exists("alias/repo") is False  # nosec B101


def test_mutation_target_adoption_helpers_reraise_unexpected_errors(monkeypatch):
    def failing_ecr_repository(*, name):  # noqa: ARG001
        raise RuntimeError("ecr throttled")

    def failing_iam_role(*, name):  # noqa: ARG001
        raise RuntimeError("iam throttled")

    def failing_kms_alias(*, name):  # noqa: ARG001
        raise RuntimeError("kms throttled")

    monkeypatch.setattr(automation.aws.ecr, "get_repository", failing_ecr_repository)
    monkeypatch.setattr(automation.aws.iam, "get_role", failing_iam_role)
    monkeypatch.setattr(pulumi_secrets.aws.kms, "get_alias", failing_kms_alias)

    with pytest.raises(RuntimeError, match="ecr throttled"):
        automation._ecr_repository_exists("repo")
    with pytest.raises(RuntimeError, match="iam throttled"):
        automation._iam_role_exists("role")
    with pytest.raises(RuntimeError, match="kms throttled"):
        pulumi_secrets._kms_alias_exists("alias/repo")


def test_mutation_target_pulumi_secrets_component(monkeypatch):
    monkeypatch.setattr(config.settings, "environment", "test")
    repos = [config.ManagedRepository(name="repo", default_branch="main")]
    component_init = {}
    registered_outputs = {}
    key_calls = {}
    alias_calls = {}

    class FakeKey:
        def __init__(
            self,
            resource_name,
            *,
            description,
            deletion_window_in_days,
            enable_key_rotation,
            policy,
            tags,
            opts,
        ):
            key_calls.update(
                {
                    "resource_name": resource_name,
                    "description": description,
                    "deletion_window_in_days": deletion_window_in_days,
                    "enable_key_rotation": enable_key_rotation,
                    "policy": policy,
                    "tags": tags,
                    "opts": opts,
                }
            )
            self.arn = "arn:aws:kms:us-east-1:123456789012:key/pulumi-secrets-key-repo"
            self.key_id = "pulumi-secrets-key-repo-key-id"

    class FakeAlias:
        def __init__(self, resource_name, *, name, target_key_id, opts):
            alias_calls.update(
                {
                    "resource_name": resource_name,
                    "name": name,
                    "target_key_id": target_key_id,
                    "opts": opts,
                }
            )
            self.name = name

    def fake_component_init(self, resource_type, name, props, opts):
        component_init.update(
            {
                "resource_type": resource_type,
                "name": name,
                "props": props,
                "opts": opts,
            }
        )

    def fake_register_outputs(self, outputs):
        registered_outputs.update(outputs)

    monkeypatch.setattr(pulumi.ComponentResource, "__init__", fake_component_init)
    monkeypatch.setattr(
        pulumi.ComponentResource, "register_outputs", fake_register_outputs
    )
    monkeypatch.setattr(pulumi.Output, "from_input", staticmethod(lambda value: value))
    monkeypatch.setattr(
        pulumi_secrets.aws,
        "get_caller_identity",
        lambda: SimpleNamespace(account_id="123456789012"),
    )
    monkeypatch.setattr(
        pulumi_secrets.aws,
        "get_region",
        lambda: SimpleNamespace(name="us-east-1", region="us-east-1"),
    )
    monkeypatch.setattr(pulumi_secrets.aws.kms, "Key", FakeKey)
    monkeypatch.setattr(pulumi_secrets.aws.kms, "Alias", FakeAlias)
    monkeypatch.setattr(pulumi_secrets, "_kms_alias_exists", lambda _name: False)
    monkeypatch.setattr(
        pulumi_secrets,
        "pulumi_secrets_provider_for_repo",
        lambda repo_name, region: (
            f"awskms://alias/pulumi-{repo_name}-test-secrets?region={region}"
        ),
    )

    secrets = pulumi_secrets.PulumiSecretsKeys("pulumi-secrets", repositories=repos)

    assert component_init["resource_type"] == "bootstrap:kms:PulumiSecretsKeys"  # nosec B101
    assert component_init["name"] == "pulumi-secrets"  # nosec B101
    assert key_calls["resource_name"] == "pulumi-secrets-key-repo"  # nosec B101
    assert key_calls["description"] == "Pulumi secrets KMS key for repo (main)"  # nosec B101
    assert key_calls["deletion_window_in_days"] == 30  # nosec B101
    assert key_calls["enable_key_rotation"] is True  # nosec B101
    assert '"Effect": "Allow"' in key_calls["policy"]  # nosec B101
    assert '"AWS": "arn:aws:iam::123456789012:root"' in key_calls["policy"]  # nosec B101
    assert key_calls["tags"]["Purpose"] == "pulumi-secrets"  # nosec B101
    assert key_calls["tags"]["Repository"] == "repo"  # nosec B101
    assert key_calls["tags"]["App"] == "repo"  # nosec B101
    assert alias_calls["resource_name"] == "pulumi-secrets-alias-repo"  # nosec B101
    assert alias_calls["name"] == "alias/pulumi-repo-test-secrets"  # nosec B101
    assert alias_calls["target_key_id"] == "pulumi-secrets-key-repo-key-id"  # nosec B101
    assert (
        secrets.key_arns["repo"]
        == "arn:aws:kms:us-east-1:123456789012:key/pulumi-secrets-key-repo"
    )  # nosec B101
    assert secrets.alias_names["repo"] == "alias/pulumi-repo-test-secrets"  # nosec B101
    assert (
        secrets.provider_urls["repo"]
        == "awskms://alias/pulumi-repo-test-secrets?region=us-east-1"
    )  # nosec B101
    assert registered_outputs["key_arns"] == secrets.key_arns  # nosec B101
    assert registered_outputs["alias_names"] == secrets.alias_names  # nosec B101
    assert registered_outputs["provider_urls"] == secrets.provider_urls  # nosec B101


def test_mutation_target_github_automation_policy_uses_explicit_actions(monkeypatch):
    monkeypatch.setattr(config.settings, "environment", "test")
    monkeypatch.setattr(config.settings, "logging_prefix", "company")
    policy = json.loads(
        automation._automation_policy(
            "123456789012",
            config.settings,
            "bootstrap-infrastructure",
        )
    )
    actions = {
        action for statement in policy["Statement"] for action in statement["Action"]
    }
    allow_actions = {
        action
        for statement in policy["Statement"]
        if statement["Effect"] == "Allow"
        for action in statement["Action"]
    }
    statements = {statement["Sid"]: statement for statement in policy["Statement"]}
    split_documents = automation._automation_policy_documents(
        "123456789012",
        config.settings,
        "bootstrap-infrastructure",
    )
    split_statements = {
        statement["Sid"]: statement
        for _name, document in split_documents
        for statement in json.loads(document)["Statement"]
    }

    assert split_statements == statements  # nosec B101
    assert all(  # nosec B101
        len(document.encode("utf-8"))
        <= automation.IAM_CUSTOMER_MANAGED_POLICY_MAX_BYTES
        for _name, document in split_documents
    )

    assert "s3:*" not in actions  # nosec B101
    assert "kms:*" not in allow_actions  # nosec B101
    assert "backup:*" not in actions  # nosec B101
    assert "ecr:*" not in actions  # nosec B101
    assert "events:*" not in actions  # nosec B101
    assert "cloudtrail:*" not in actions  # nosec B101
    assert "sns:*" not in actions  # nosec B101
    assert "secretsmanager:*" not in actions  # nosec B101
    assert "guardduty:*" not in actions  # nosec B101
    assert "securityhub:*" not in actions  # nosec B101
    assert "config:*" not in actions  # nosec B101
    assert "s3:CreateBucket" in actions  # nosec B101
    assert "s3:GetAccelerateConfiguration" in actions  # nosec B101
    assert "kms:CreateKey" in actions  # nosec B101
    assert "kms:Decrypt" not in allow_actions  # nosec B101
    assert "kms:Encrypt" not in allow_actions  # nosec B101
    assert "kms:GenerateDataKey" not in allow_actions  # nosec B101
    assert "backup:CreateBackupPlan" in actions  # nosec B101
    assert "ecr:CreateRepository" in actions  # nosec B101
    assert "ecr:DescribeImages" in actions  # nosec B101
    assert "events:PutRule" in actions  # nosec B101
    assert "cloudtrail:CreateTrail" in actions  # nosec B101
    assert "sns:CreateTopic" in actions  # nosec B101
    assert "sqs:CreateQueue" in actions  # nosec B101
    assert "secretsmanager:CreateSecret" not in allow_actions  # nosec B101
    assert "secretsmanager:GetSecretValue" not in allow_actions  # nosec B101
    assert "secretsmanager:PutSecretValue" not in allow_actions  # nosec B101
    assert "secretsmanager:UpdateSecret" not in allow_actions  # nosec B101
    assert "sqs:ReceiveMessage" not in allow_actions  # nosec B101
    assert "sqs:DeleteMessage" not in allow_actions  # nosec B101
    assert "budgets:ModifyBudget" in actions  # nosec B101
    assert "budgets:ViewBudget" in actions  # nosec B101
    assert "ce:CreateAnomalyMonitor" in actions  # nosec B101
    assert "billing:GetBillingViewData" in actions  # nosec B101
    assert "guardduty:CreateDetector" in actions  # nosec B101
    assert "securityhub:EnableSecurityHub" in actions  # nosec B101
    assert "config:PutConfigurationRecorder" in actions  # nosec B101
    assert statements["ManageBootstrapS3"]["Resource"] == [  # nosec B101
        "arn:aws:s3:::pulumi-bootstrap-infrastructure-test-state",
        "arn:aws:s3:::pulumi-bootstrap-infrastructure--c1194dce-eu-west-1-replication",
        "arn:aws:s3:::company-central-logs-*-test",
        "arn:aws:s3:::company-central-logs-*-test-*-replication",
        "arn:aws:s3:::bootstrap-*-test-cloudtrail",
        "arn:aws:s3:::bootstrap-*-test-aws-config",
    ]
    assert statements["PassBootstrapRolesToS3Replication"] == {  # nosec B101
        "Sid": "PassBootstrapRolesToS3Replication",
        "Effect": "Allow",
        "Action": ["iam:PassRole"],
        "Resource": [
            "arn:aws:iam::123456789012:role/PulumiStateRepl-bootstrap-infrastructure-test",
            "arn:aws:iam::123456789012:role/central-logging-replication-role-test",
        ],
        "Condition": {"StringEquals": {"iam:PassedToService": "s3.amazonaws.com"}},
    }
    pass_role_statements = [
        statement
        for statement in statements.values()
        if statement["Action"] == ["iam:PassRole"] and statement["Effect"] == "Allow"
    ]
    assert {statement["Sid"] for statement in pass_role_statements} == {  # nosec B101
        "PassBootstrapRolesToBackup",
        "PassBootstrapRolesToConfig",
        "PassBootstrapRolesToS3Replication",
    }
    assert all(  # nosec B101
        statement["Resource"] != "*" for statement in pass_role_statements
    )
    assert statements["ManageBootstrapEcr"]["Resource"] == [  # nosec B101
        "arn:aws:ecr:*:123456789012:repository/pulumi-runner/"
        "bootstrap-infrastructure-test"
    ]
    assert statements["ManageBootstrapEventBridge"]["Resource"] == [  # nosec B101
        "arn:aws:events:*:123456789012:rule/bootstrap-test-*"
    ]
    assert statements["ManageBootstrapCloudTrail"]["Resource"] == [  # nosec B101
        "arn:aws:cloudtrail:*:123456789012:trail/bootstrap-test-management-events"
    ]
    assert statements["ReadCloudTrailTrailsForRefresh"] == {  # nosec B101
        "Sid": "ReadCloudTrailTrailsForRefresh",
        "Effect": "Allow",
        "Action": ["cloudtrail:DescribeTrails"],
        "Resource": "*",
    }
    assert statements["ManageBootstrapSns"]["Resource"] == [  # nosec B101
        "arn:aws:sns:*:123456789012:bootstrap-test-operations"
    ]
    assert statements["ManageBootstrapSnsSubscriptions"]["Resource"] == [  # nosec B101
        "arn:aws:sns:*:123456789012:bootstrap-test-operations"
    ]
    assert statements["ManageBootstrapSqs"]["Resource"] == [  # nosec B101
        "arn:aws:sqs:*:123456789012:bootstrap-test-operations-alerts"
    ]
    assert "CreateBootstrapCiSecrets" not in statements
    assert "ManageBootstrapCiSecrets" not in statements
    assert statements["ReadPlatformCiSecrets"]["Action"] == [
        "secretsmanager:DescribeSecret",
        "secretsmanager:GetResourcePolicy",
    ]
    assert statements["DenyBootstrapSqsConsumption"] == {  # nosec B101
        "Sid": "DenyBootstrapSqsConsumption",
        "Effect": "Deny",
        "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage"],
        "Resource": ["arn:aws:sqs:*:123456789012:bootstrap-test-operations-alerts"],
    }
    alert_triage_policy = json.loads(
        automation._operations_alert_triage_policy("123456789012", config.settings)
    )
    assert alert_triage_policy["Statement"] == [  # nosec B101
        {
            "Sid": "ConsumeOperationsAlertQueue",
            "Effect": "Allow",
            "Action": [
                "sqs:GetQueueUrl",
                "sqs:ReceiveMessage",
                "sqs:DeleteMessage",
            ],
            "Resource": ["arn:aws:sqs:*:123456789012:bootstrap-test-operations-alerts"],
        }
    ]
    assert statements["ManageBootstrapBudgets"]["Resource"] == [  # nosec B101
        "arn:aws:budgets::123456789012:budget/bootstrap-test-*"
    ]
    assert statements["ReadAccountBudgetsForEvidence"] == {  # nosec B101
        "Sid": "ReadAccountBudgetsForEvidence",
        "Effect": "Allow",
        "Action": ["budgets:ViewBudget"],
        "Resource": ["arn:aws:budgets::123456789012:budget/*"],
    }
    assert statements["ManageBootstrapCostAnomalyMonitors"]["Resource"] == [  # nosec B101
        "arn:aws:ce::123456789012:anomalymonitor/*",
    ]
    assert statements["ReadCostAnomalyMonitorsForEvidence"] == {  # nosec B101
        "Sid": "ReadCostAnomalyMonitorsForEvidence",
        "Effect": "Allow",
        "Action": ["ce:GetAnomalyMonitors"],
        "Resource": ["arn:aws:ce::123456789012:anomalymonitor/*"],
    }
    assert statements["ManageBootstrapCostAnomalyMonitors"]["Condition"] == {  # nosec B101
        "StringEquals": {
            "aws:ResourceTag/Environment": "test",
            "aws:ResourceTag/Purpose": "cost-anomaly-monitor",
        }
    }
    assert statements["ManageBootstrapCostAnomalySubscriptions"]["Resource"] == [  # nosec B101
        "arn:aws:ce::123456789012:anomalysubscription/*",
    ]
    assert statements["ManageBootstrapCostAnomalySubscriptions"]["Condition"] == {  # nosec B101
        "StringEquals": {
            "aws:ResourceTag/Environment": "test",
            "aws:ResourceTag/Purpose": "cost-anomaly-subscription",
        }
    }
    assert "ManageBootstrapIam" not in statements
    assert statements["ManageBoundedBackup"]["Condition"] == {
        "StringEquals": {
            "iam:PermissionsBoundary": (
                "arn:aws:iam::123456789012:policy/PlatformBoundary-backup-test"
            )
        }
    }
    assert (  # nosec B101
        statements["ManageBootstrapKmsKeys"]["Condition"]["StringEquals"]
        == {
            "aws:ResourceTag/Environment": "test",
            "aws:ResourceTag/Purpose": [
                "pulumi-secrets",
                "operations-alerting",
                "operations-cloudtrail",
            ],
        }
    )
    assert statements["CreateBootstrapKmsKeys"]["Condition"]["StringEquals"] == {  # nosec B101
        "aws:RequestTag/Environment": "test",
        "aws:RequestTag/Repository": "bootstrap-infrastructure",
        "aws:RequestTag/Purpose": [
            "pulumi-secrets",
            "operations-alerting",
            "operations-cloudtrail",
        ],
    }
    assert (  # nosec B101
        "arn:aws:kms:*:123456789012:alias/bootstrap-test-operations-alerting"
        in statements["ManageBootstrapKmsAliases"]["Resource"]
    )
    assert (  # nosec B101
        "arn:aws:kms:*:123456789012:alias/bootstrap-test-operations-cloudtrail"
        in statements["ManageBootstrapKmsAliases"]["Resource"]
    )
    assert (  # nosec B101
        statements["ManageBootstrapKmsAliases"]["Condition"]["StringEqualsIfExists"]
        == {
            "aws:ResourceTag/Environment": "test",
            "aws:ResourceTag/Purpose": [
                "pulumi-secrets",
                "operations-alerting",
                "operations-cloudtrail",
            ],
        }
    )
    assert statements["ManageSecurityHubAccount"]["Resource"] == [  # nosec B101
        "arn:aws:securityhub:*:123456789012:hub/default"
    ]
    assert statements["ManageAwsConfigRecorder"]["Resource"] == [  # nosec B101
        "arn:aws:config:*:123456789012:configuration-recorder/"
        "bootstrap-test-configuration-recorder/*"
    ]
    assert {
        statement["Sid"]
        for statement in policy["Statement"]
        if statement.get("Resource") == "*" and statement["Effect"] == "Allow"
    } == {
        "CreateBootstrapKmsKeys",
        "CreateBootstrapCostAnomalyMonitor",
        "CreateBootstrapCostAnomalySubscription",
        "CreateBootstrapGuardDutyDetector",
        "ListBootstrapKmsAliases",
        "ManageAwsConfigDeliveryChannel",
        "ReadBillingViewDataForBudgets",
        "ReadCloudTrailTrailsForRefresh",
        "ReadGuardDutyDetectors",
        "ReadIdentity",
        "ReadPlatformIam",
    }  # nosec B101


def _split_automation_policy_documents() -> list[tuple[str, str]]:
    return automation._automation_policy_documents(
        "123456789012",
        config.settings,
        "bootstrap-infrastructure",
    )


def test_mutation_target_automation_policy_documents_skip_empty_groups(monkeypatch):
    monkeypatch.setattr(config.settings, "environment", "test")
    monkeypatch.setattr(config.settings, "logging_prefix", "company")
    empty_group = ("empty-policy", frozenset({"StatementThatDoesNotExist"}))
    monkeypatch.setattr(
        automation,
        "_AUTOMATION_MANAGED_POLICY_GROUPS",
        (empty_group, *automation._AUTOMATION_MANAGED_POLICY_GROUPS),
    )

    documents = _split_automation_policy_documents()

    assert documents[0][0] == "policy"  # nosec B101
    assert empty_group[0] not in {name for name, _document in documents}  # nosec B101


def test_mutation_target_automation_policy_documents_require_complete_groups(
    monkeypatch,
):
    monkeypatch.setattr(config.settings, "environment", "test")
    monkeypatch.setattr(config.settings, "logging_prefix", "company")
    monkeypatch.setattr(
        automation,
        "_AUTOMATION_MANAGED_POLICY_GROUPS",
        tuple(
            (
                name,
                frozenset(sid for sid in policy_sids if sid != "ReadIdentity"),
            )
            for name, policy_sids in automation._AUTOMATION_MANAGED_POLICY_GROUPS
        ),
    )

    with pytest.raises(ValueError, match="ReadIdentity"):
        _split_automation_policy_documents()


def test_mutation_target_automation_policy_documents_require_inline_policy_first(
    monkeypatch,
):
    monkeypatch.setattr(config.settings, "environment", "test")
    monkeypatch.setattr(config.settings, "logging_prefix", "company")
    groups = automation._AUTOMATION_MANAGED_POLICY_GROUPS
    monkeypatch.setattr(
        automation,
        "_AUTOMATION_MANAGED_POLICY_GROUPS",
        (("not-policy", groups[0][1]), *groups[1:]),
    )

    with pytest.raises(ValueError, match="first automation policy document"):
        _split_automation_policy_documents()


def test_mutation_target_automation_policy_documents_enforce_inline_size(
    monkeypatch,
):
    monkeypatch.setattr(config.settings, "environment", "test")
    monkeypatch.setattr(config.settings, "logging_prefix", "company")
    monkeypatch.setattr(automation, "IAM_ROLE_INLINE_POLICY_MAX_BYTES", 1)

    with pytest.raises(ValueError, match="inline policy document exceeds"):
        _split_automation_policy_documents()


def test_mutation_target_automation_policy_documents_enforce_managed_size(
    monkeypatch,
):
    monkeypatch.setattr(config.settings, "environment", "test")
    monkeypatch.setattr(config.settings, "logging_prefix", "company")
    monkeypatch.setattr(automation, "IAM_ROLE_INLINE_POLICY_MAX_BYTES", 100_000)
    monkeypatch.setattr(automation, "IAM_CUSTOMER_MANAGED_POLICY_MAX_BYTES", 1)

    with pytest.raises(ValueError, match="managed policy document exceeds"):
        _split_automation_policy_documents()


def test_mutation_target_github_oidc_role_name_limits_length():
    repo_suffix = "a" * 70
    digest = hashlib.sha256(repo_suffix.encode("utf-8")).hexdigest()[:8]
    expected = f"PulumiDeploy-{'a' * 42}-{digest}"
    assert github_oidc._truncate_role_suffix(repo_suffix) == f"{'a' * 42}-{digest}"  # nosec B101
    assert github_oidc._role_name_for_suffix(repo_suffix) == expected  # nosec B101
    assert len(expected) == github_oidc._MAX_IAM_ROLE_NAME_LENGTH == 64  # nosec B101


def test_mutation_target_github_oidc_truncation_keeps_digest():
    assert github_oidc._role_name_for_suffix("repo-short") == "PulumiDeploy-repo-short"  # nosec B101


def test_mutation_target_operations_alert_triage_role_name_limits_length(monkeypatch):
    monkeypatch.setattr(config.settings, "environment", "test")

    assert (  # nosec B101
        automation._operations_alert_triage_role_name(
            config.settings,
            "bootstrap-infrastructure",
        )
        == "OperationsAlertTriage-bootstrap-infrastructure-test"
    )
    with pytest.raises(ValueError, match="operations alert triage role name"):
        automation._operations_alert_triage_role_name(config.settings, "a" * 40)
