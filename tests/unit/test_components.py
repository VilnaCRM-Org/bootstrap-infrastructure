import asyncio
import json
import runpy
from pathlib import Path
from typing import cast

import pytest
from infra import (
    BootstrapInfrastructure,
    BootstrapInfrastructureDependencies,
    CentralLoggingBuckets,
    CiConfiguration,
    CiConfigurationArgs,
    CostControlInputs,
    CostControls,
    GitHubAutomation,
    GitHubCiBootstrap,
    GitHubCiBootstrapArgs,
    ManagedRepositoryCatalog,
    OperationsMonitoring,
    PulumiSecretsKeys,
    PulumiStateBuckets,
    S3BackupPlan,
    SecurityAccountControls,
    automation,
    ci_bootstrap,
    ci_config,
    config,
    logging_bucket,
    operations_monitoring,
    pulumi_secrets,
    pulumi_state,
    security_account_controls,
)
from infra.cost_controls import (
    COST_ALLOCATION_TAG_KEYS,
    managed_cost_allocation_tag_keys,
)
from infra.iam import GitHubOidcRoles, github_oidc
from infra.utils.outputs import future_output

# Pulumi does not expose a public sync helper for Output values in tests, so keep
# this internal import isolated here in case the SDK changes it later.
from pulumi.runtime.stack import wait_for_rpcs
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


def _ci_bootstrap_settings(environment: str) -> config.BootstrapSettings:
    """Return settings for GitHub CI bootstrap component tests."""
    return config.BootstrapSettings(
        org="VilnaCRM-Org",
        repo="bootstrap-infrastructure",
        environment=environment,
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
        manage_cost_allocation_tags=environment == "test",
    )


def test_managed_cost_allocation_tag_keys_returns_stable_copy():
    """Cost allocation tag helper should return a mutable copy of stable keys."""
    tag_keys = managed_cost_allocation_tag_keys(("Owner", "CostCenter"))

    assert tag_keys == ["Owner", "CostCenter"]  # nosec B101


def test_central_logging_buckets_truncates_long_replica_name():
    replica_name = logging_bucket._replica_bucket_name("a" * 60, "us-west-2")

    assert len(replica_name) <= 63  # nosec B101
    assert replica_name.endswith("-us-west-2-replication")  # nosec B101


def test_central_logging_buckets_reject_same_replication_region(  # noqa: ARG001
    pulumi_mocks,
):
    with pytest.raises(ValueError, match="must differ from primary region"):
        CentralLoggingBuckets("central-logs", replication_region="us-east-1")


def test_operations_monitoring_rejects_long_cloudtrail_bucket_name(monkeypatch):
    monkeypatch.setattr(config.settings, "environment", "x" * 40)

    with pytest.raises(ValueError, match="CloudTrail bucket name exceeds"):
        operations_monitoring._cloudtrail_bucket_name(
            config.settings,
            "123456789012",
            "eu-central-1",
        )


def test_operations_monitoring_topic_name_normalizes_dot_environment():
    settings = config.BootstrapSettings(
        org="VilnaCRM-Org",
        repo="bootstrap-infrastructure",
        environment="prod.eu",
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

    assert (  # nosec B101
        operations_monitoring._topic_name(settings) == "bootstrap-prod-eu-operations"
    )


def test_security_account_controls_normalizes_dot_environment():
    settings = config.BootstrapSettings(
        org="VilnaCRM-Org",
        repo="bootstrap-infrastructure",
        environment="prod.eu",
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

    assert (  # nosec B101
        security_account_controls._config_bucket_name(
            settings, "123456789012", "eu-central-1"
        )
        == "bootstrap-123456789012-eu-central-1-prod-eu-aws-config"
    )
    assert (  # nosec B101
        security_account_controls._config_recorder_name(settings)
        == "bootstrap-prod.eu-configuration-recorder"
    )


def test_security_account_controls_reject_long_resource_names():
    settings = config.BootstrapSettings(
        org="VilnaCRM-Org",
        repo="bootstrap-infrastructure",
        environment="x" * 40,
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

    with pytest.raises(ValueError, match="AWS Config bucket name exceeds"):
        security_account_controls._config_bucket_name(
            settings,
            "123456789012",
            "eu-central-1",
        )
    with pytest.raises(ValueError, match="AWS Config recorder role name exceeds"):
        security_account_controls._config_role_name(settings)


def test_github_automation_policy_normalizes_sns_environment_and_allocation_tags():
    settings = config.BootstrapSettings(
        org="VilnaCRM-Org",
        repo="bootstrap-infrastructure",
        environment="prod.eu",
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
        manage_cost_allocation_tags=True,
    )

    policy = json.loads(
        automation._automation_policy(
            "123456789012",
            settings,
            "bootstrap-infrastructure",
        )
    )
    statements = {statement["Sid"]: statement for statement in policy["Statement"]}

    assert statements["ManageBootstrapSns"]["Resource"] == [  # nosec B101
        "arn:aws:sns:*:123456789012:bootstrap-prod-eu-operations"
    ]
    assert statements["ManageBootstrapSnsSubscriptions"]["Resource"] == "*"  # nosec B101
    assert statements["ManageBootstrapCostAllocationTags"] == {  # nosec B101
        "Sid": "ManageBootstrapCostAllocationTags",
        "Effect": "Allow",
        "Action": [
            "ce:ListCostAllocationTags",
            "ce:UpdateCostAllocationTagsStatus",
        ],
        "Resource": "*",
    }
    assert (  # nosec B101
        "PassBootstrapRolesToConfig" in statements
    )
    assert (  # nosec B101
        "CreateBootstrapGuardDutyDetector" in statements
    )
    assert (  # nosec B101
        statements["CreateSecurityServiceLinkedRoles"]["Condition"]
        == {
            "StringEquals": {
                "iam:AWSServiceName": [
                    "guardduty.amazonaws.com",
                    "securityhub.amazonaws.com",
                ]
            }
        }
    )


def test_github_automation_trust_requires_environment_for_every_apply():
    provider_arn = (
        "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
    )

    test_policy = json.loads(
        automation._automation_assume_role_policy(
            provider_arn,
            "VilnaCRM-Org",
            "bootstrap-infrastructure",
            "test",
            "main",
        )
    )
    prod_policy = json.loads(
        automation._automation_assume_role_policy(
            provider_arn,
            "VilnaCRM-Org",
            "bootstrap-infrastructure",
            "prod",
            "main",
        )
    )

    test_condition = test_policy["Statement"][0]["Condition"]
    prod_condition = prod_policy["Statement"][0]["Condition"]
    test_subjects = test_condition["StringEquals"][
        "token.actions.githubusercontent.com:sub"
    ]
    prod_subjects = prod_condition["StringEquals"][
        "token.actions.githubusercontent.com:sub"
    ]

    assert test_subjects == [  # nosec B101
        "repo:VilnaCRM-Org/bootstrap-infrastructure:environment:test",
    ]
    assert prod_subjects == [  # nosec B101
        "repo:VilnaCRM-Org/bootstrap-infrastructure:environment:prod"
    ]
    assert (
        test_condition["StringEquals"][  # nosec B101
            "token.actions.githubusercontent.com:repository"
        ]
        == "VilnaCRM-Org/bootstrap-infrastructure"
    )
    assert (
        prod_condition["StringEquals"][  # nosec B101
            "token.actions.githubusercontent.com:repository"
        ]
        == "VilnaCRM-Org/bootstrap-infrastructure"
    )
    assert "StringLike" not in test_condition  # nosec B101
    assert "StringLike" not in prod_condition  # nosec B101


def test_ci_configuration_manages_aws_secret_containers_and_github_read_roles(
    pulumi_mocks,
    monkeypatch,
):  # noqa: ARG001
    monkeypatch.setattr(ci_config, "_secret_import_id", lambda _name: None)
    monkeypatch.setattr(ci_config, "_iam_role_exists", lambda _name: False)
    provider_arn = (
        "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
    )
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

    start = len(pulumi_mocks.resources)
    component = CiConfiguration(
        "ci-configuration",
        args=CiConfigurationArgs(
            settings=settings,
            oidc_provider_arn=provider_arn,
        ),
    )

    _sync_await(future_output(component.secret_arns["test-pr"]))
    _sync_await(future_output(component.secret_arns["test"]))
    test_pr_role_arn = _sync_await(future_output(component.read_role_arns["test-pr"]))
    test_role_arn = _sync_await(future_output(component.read_role_arns["test"]))
    assert test_pr_role_arn.endswith(  # nosec B101
        ":role/GitHubCiConfigRead-bootstrap-infrastructure-test-pr"
    )
    assert test_role_arn.endswith(  # nosec B101
        ":role/GitHubCiConfigRead-bootstrap-infrastructure-test"
    )
    assert component.secret_ids == {  # nosec B101
        "test-pr": "/bootstrap-infrastructure/ci/test-pr",
        "test": "/bootstrap-infrastructure/ci/test",
    }

    new_resources = pulumi_mocks.resources[start:]
    secret_states = {
        state["name"]: state
        for resource_type, _name, state in new_resources
        if resource_type == "aws:secretsmanager/secret:Secret"
    }
    assert not any(  # nosec B101
        resource_type == "aws:secretsmanager/secretVersion:SecretVersion"
        for resource_type, _name, _state in new_resources
    )
    assert set(secret_states) == {  # nosec B101
        "/bootstrap-infrastructure/ci/test-pr",
        "/bootstrap-infrastructure/ci/test",
    }
    assert all(  # nosec B101
        state["tags"]["Purpose"] == "ci-configuration"
        for state in secret_states.values()
    )
    assert (
        secret_states["/bootstrap-infrastructure/ci/test-pr"]["tags"][  # nosec B101
            "CiConfigSuffix"
        ]
        == "test-pr"
    )

    test_pr_role_state = _resource_state_by_name(
        pulumi_mocks,
        "ci-configuration-github-ci-config-read-role-test-pr",
    )
    test_role_state = _resource_state_by_name(
        pulumi_mocks,
        "ci-configuration-github-ci-config-read-role-test",
    )
    test_pr_policy = json.loads(test_pr_role_state["assumeRolePolicy"])
    test_policy = json.loads(test_role_state["assumeRolePolicy"])
    test_pr_condition = test_pr_policy["Statement"][0]["Condition"]
    test_condition = test_policy["Statement"][0]["Condition"]
    assert test_pr_condition["StringEquals"] == {  # nosec B101
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
        "token.actions.githubusercontent.com:repository": (
            "VilnaCRM-Org/bootstrap-infrastructure"
        ),
        "token.actions.githubusercontent.com:sub": [
            "repo:VilnaCRM-Org/bootstrap-infrastructure:pull_request"
        ],
        "token.actions.githubusercontent.com:workflow": [
            "Pulumi PR Guardrails",
            "Well-Architected Evidence",
        ],
    }
    assert "StringLike" not in test_pr_condition  # nosec B101
    assert test_condition["StringEquals"] == {  # nosec B101
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
        "token.actions.githubusercontent.com:ref": "refs/heads/main",
        "token.actions.githubusercontent.com:repository": (
            "VilnaCRM-Org/bootstrap-infrastructure"
        ),
        "token.actions.githubusercontent.com:sub": [
            "repo:VilnaCRM-Org/bootstrap-infrastructure:ref:refs/heads/main",
            "repo:VilnaCRM-Org/bootstrap-infrastructure:environment:test",
            "repo:VilnaCRM-Org/bootstrap-infrastructure:environment:test-preview",
        ],
        "token.actions.githubusercontent.com:workflow": [
            "Pulumi PR Guardrails",
            "Pulumi Test Deploy",
            "Nightly Guardrails",
            "Pulumi PR Command Runner",
            "Operations Alert Issue Triage",
            "Well-Architected Evidence",
        ],
    }
    assert "StringLike" not in test_condition  # nosec B101

    test_pr_policy_state = _resource_state_by_name(
        pulumi_mocks,
        "ci-configuration-github-ci-config-read-policy-test-pr",
    )
    test_policy_state = _resource_state_by_name(
        pulumi_mocks,
        "ci-configuration-github-ci-config-read-policy-test",
    )
    for suffix, state in (
        ("test-pr", test_pr_policy_state),
        ("test", test_policy_state),
    ):
        resolved = json.loads(state["policy"])
        clauses = {item["Sid"]: item for item in resolved["Statement"]}
        assert clauses["DenyDecryptOutsideOwnedCiSecrets"]["Condition"] == {
            "StringNotEquals": {
                "kms:EncryptionContext:SecretARN": [
                    _sync_await(future_output(component.secret_arns[suffix]))
                ]
            }
        }
        assert clauses["DenyDecryptOutsideSecretsManager"]["Condition"] == {
            "StringNotEquals": {
                "kms:ViaService": "secretsmanager.us-east-1.amazonaws.com"
            }
        }
    policy = json.loads(test_pr_policy_state["policy"])
    statement = policy["Statement"][0]
    assert statement["Action"] == [  # nosec B101
        "secretsmanager:DescribeSecret",
        "secretsmanager:GetSecretValue",
    ]
    assert statement["Resource"] == [  # nosec B101
        "arn:aws:secretsmanager:*:123456789012:secret:"
        "/bootstrap-infrastructure/ci/test-pr-*"
    ]
    test_policy_document = json.loads(test_policy_state["policy"])
    assert (  # nosec B101
        "/bootstrap-infrastructure/ci/test" in json.dumps(test_policy_document)
    )


def test_ci_configuration_uses_github_oidc_provider_for_prod_suffixes(
    pulumi_mocks,
    monkeypatch,
):  # noqa: ARG001
    provider_arn = (
        "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
    )
    monkeypatch.setattr(ci_config, "_secret_import_id", lambda _name: None)
    monkeypatch.setattr(ci_config, "_iam_role_exists", lambda _name: False)
    settings = config.BootstrapSettings(
        org="VilnaCRM-Org",
        repo="bootstrap-infrastructure",
        environment="prod",
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

    start = len(pulumi_mocks.resources)
    component = CiConfiguration(
        "ci-configuration-prod",
        args=CiConfigurationArgs(
            settings=settings,
            oidc_provider_arn=provider_arn,
        ),
    )

    _sync_await(future_output(component.read_role_arns["prod-preview"]))
    _sync_await(future_output(component.read_role_arns["prod"]))
    provider_resources = {
        name
        for resource_type, name, _state in pulumi_mocks.resources[start:]
        if resource_type == "aws:iam/openIdConnectProvider:OpenIdConnectProvider"
    }
    assert provider_resources == set()  # nosec B101
    assert component.secret_ids == {  # nosec B101
        "prod-preview": "/bootstrap-infrastructure/ci/prod-preview",
        "prod": "/bootstrap-infrastructure/ci/prod",
    }
    preview_role_state = _resource_state_by_name(
        pulumi_mocks,
        "ci-configuration-prod-github-ci-config-read-role-prod-preview",
    )
    prod_role_state = _resource_state_by_name(
        pulumi_mocks,
        "ci-configuration-prod-github-ci-config-read-role-prod",
    )
    preview_policy = json.loads(preview_role_state["assumeRolePolicy"])
    prod_policy = json.loads(prod_role_state["assumeRolePolicy"])
    assert preview_policy["Statement"][0]["Condition"]["StringEquals"][  # nosec B101
        "token.actions.githubusercontent.com:sub"
    ] == [
        "repo:VilnaCRM-Org/bootstrap-infrastructure:ref:refs/heads/main",
        "repo:VilnaCRM-Org/bootstrap-infrastructure:environment:prod-preview",
    ]
    assert prod_policy["Statement"][0]["Condition"]["StringEquals"][  # nosec B101
        "token.actions.githubusercontent.com:sub"
    ] == ["repo:VilnaCRM-Org/bootstrap-infrastructure:environment:prod"]
    assert (
        prod_policy["Statement"][0]["Condition"]["StringEquals"][  # nosec B101
            "token.actions.githubusercontent.com:repository"
        ]
        == "VilnaCRM-Org/bootstrap-infrastructure"
    )
    assert "StringLike" not in prod_policy["Statement"][0]["Condition"]  # nosec B101


def test_ci_configuration_requires_github_oidc_provider(
    pulumi_mocks,
    monkeypatch,
):  # noqa: ARG001
    monkeypatch.setattr(ci_config, "_secret_import_id", lambda _name: None)
    monkeypatch.setattr(ci_config, "_iam_role_exists", lambda _name: False)
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

    with pytest.raises(ValueError, match="githubOidcProviderArn config is required"):
        CiConfiguration(
            "ci-configuration-no-provider",
            args=CiConfigurationArgs(settings=settings),
        )


def test_github_ci_bootstrap_test_stack_creates_scoped_ci_roles_and_payloads(
    pulumi_mocks,
    monkeypatch,
):  # noqa: ARG001
    monkeypatch.setattr(ci_config, "_secret_import_id", lambda _name: None)
    monkeypatch.setattr(ci_config, "_iam_role_exists", lambda _name: False)
    monkeypatch.setattr(ci_bootstrap, "_iam_role_exists", lambda _name: False)
    monkeypatch.setattr(
        github_oidc,
        "_existing_github_oidc_provider_arn",
        lambda: None,
    )
    settings = _ci_bootstrap_settings("test")

    start = len(pulumi_mocks.resources)
    component = GitHubCiBootstrap(
        "github-ci-bootstrap-test",
        args=GitHubCiBootstrapArgs(
            settings=settings,
            protect_resources=True,
        ),
    )

    _sync_await(future_output(component.role_arns["preview"]))
    _sync_await(future_output(component.role_arns["apply"]))
    _sync_await(future_output(component.role_arns["drift"]))
    _sync_await(future_output(component.ci_configuration.read_role_arns["test-pr"]))
    _sync_await(future_output(component.ci_configuration.read_role_arns["test"]))
    assert component.operations_alert_triage_role is not None  # nosec B101
    _sync_await(future_output(component.operations_alert_triage_role.arn))
    _sync_await(wait_for_rpcs())

    assert _resource_state_by_name(  # nosec B101
        pulumi_mocks,
        "github-ci-bootstrap-test-secret-value-test",
    )
    assert _resource_state_by_name(  # nosec B101
        pulumi_mocks,
        "github-ci-bootstrap-test-secret-value-test-pr",
    )
    new_resources = pulumi_mocks.resources[start:]
    assert component.ci_configuration.secret_ids == {  # nosec B101
        "test-pr": "/bootstrap-infrastructure/ci/test-pr",
        "test": "/bootstrap-infrastructure/ci/test",
    }
    assert set(component.role_arns) == {"preview", "apply", "drift"}  # nosec B101
    assert component.secret_payload_keys["test-pr"] == [  # nosec B101
        "AWS_ACCOUNT_ID",
        "AWS_PREVIEW_ROLE_ARN",
        "AWS_REGION",
        "OPERATIONS_CLOUDTRAIL_NAME",
        "OPERATIONS_TOPIC_ARN",
        "PULUMI_BACKEND_URL",
        "PULUMI_DIR",
        "PULUMI_PREVIEW_STACKS",
        "PULUMI_SECRETS_PROVIDER",
    ]
    assert "AWS_APPLY_ROLE_ARN" not in component.secret_payload_keys["test-pr"]  # nosec B101
    assert "AWS_DRIFT_ROLE_ARN" not in component.secret_payload_keys["test-pr"]  # nosec B101
    assert component.secret_payload_keys["test"] == [  # nosec B101
        "AWS_ACCOUNT_ID",
        "AWS_APPLY_ROLE_ARN",
        "AWS_DRIFT_ROLE_ARN",
        "AWS_OPERATIONS_ALERT_TRIAGE_ROLE_ARN",
        "AWS_PREVIEW_ROLE_ARN",
        "AWS_REGION",
        "OPERATIONS_ALERT_QUEUE_NAME",
        "OPERATIONS_CLOUDTRAIL_NAME",
        "OPERATIONS_TOPIC_ARN",
        "PULUMI_BACKEND_URL",
        "PULUMI_DIR",
        "PULUMI_DRIFT_STACKS",
        "PULUMI_PREVIEW_STACKS",
        "PULUMI_SECRETS_PROVIDER",
    ]

    preview_state = _resource_state_by_name(
        pulumi_mocks,
        "github-ci-bootstrap-test-preview-role",
    )
    apply_state = _resource_state_by_name(
        pulumi_mocks,
        "github-ci-bootstrap-test-apply-role",
    )
    triage_state = _resource_state_by_name(
        pulumi_mocks,
        "github-ci-bootstrap-test-operations-alert-triage-role",
    )
    preview_trust = json.loads(preview_state["assumeRolePolicy"])
    apply_trust = json.loads(apply_state["assumeRolePolicy"])
    triage_trust = json.loads(triage_state["assumeRolePolicy"])

    preview_condition = preview_trust["Statement"][0]["Condition"]
    apply_condition = apply_trust["Statement"][0]["Condition"]
    triage_condition = triage_trust["Statement"][0]["Condition"]
    assert preview_condition["StringEquals"][  # nosec B101
        "token.actions.githubusercontent.com:sub"
    ] == [
        "repo:VilnaCRM-Org/bootstrap-infrastructure:ref:refs/heads/main",
        "repo:VilnaCRM-Org/bootstrap-infrastructure:pull_request",
        "repo:VilnaCRM-Org/bootstrap-infrastructure:environment:test",
        "repo:VilnaCRM-Org/bootstrap-infrastructure:environment:test-preview",
    ]
    assert apply_condition["StringEquals"][  # nosec B101
        "token.actions.githubusercontent.com:sub"
    ] == [
        "repo:VilnaCRM-Org/bootstrap-infrastructure:environment:test",
    ]
    assert "pull_request" not in json.dumps(apply_condition)  # nosec B101
    assert "pulumi-pr-guardrails.yml" not in json.dumps(apply_condition)  # nosec B101
    assert (
        preview_condition["StringEquals"][  # nosec B101
            "token.actions.githubusercontent.com:repository"
        ]
        == "VilnaCRM-Org/bootstrap-infrastructure"
    )
    assert (
        apply_condition["StringEquals"][  # nosec B101
            "token.actions.githubusercontent.com:repository"
        ]
        == "VilnaCRM-Org/bootstrap-infrastructure"
    )
    assert (
        triage_condition["StringEquals"][  # nosec B101
            "token.actions.githubusercontent.com:repository"
        ]
        == "VilnaCRM-Org/bootstrap-infrastructure"
    )
    assert "StringLike" not in preview_condition  # nosec B101
    assert "StringLike" not in apply_condition  # nosec B101
    assert (
        triage_condition["StringEquals"][  # nosec B101
            "token.actions.githubusercontent.com:workflow"
        ]
        == "Operations Alert Issue Triage"
    )
    assert "StringLike" not in triage_condition  # nosec B101

    backend_policy = json.loads(
        ci_bootstrap._pulumi_backend_policy_document(
            "123456789012",
            "aws",
            settings,
        )
    )
    backend_statements = {
        statement["Sid"]: statement for statement in backend_policy["Statement"]
    }
    assert backend_statements["UsePulumiStateBucket"]["Resource"] == [  # nosec B101
        "arn:aws:s3:::pulumi-bootstrap-infrastructure-test-state",
        "arn:aws:s3:::pulumi-bootstrap-infrastructure-test-state/state/test/*",
    ]

    policy_documents = [
        json.loads(state["policy"])
        for resource_type, _name, state in new_resources
        if resource_type in {"aws:iam/policy:Policy", "aws:iam/rolePolicy:RolePolicy"}
    ]
    assert policy_documents  # nosec B101
    read_stack_metadata = next(
        statement
        for policy_document in policy_documents
        for statement in policy_document["Statement"]
        if statement["Sid"] == "ReadStackMetadata"
    )
    assert "ce:ListCostAllocationTags" in read_stack_metadata["Action"]  # nosec B101
    assert any(  # nosec B101
        resource_type == "aws:iam/policy:Policy"
        and name.startswith("github-ci-bootstrap-test-apply-")
        for resource_type, name, _state in new_resources
    )
    for policy_document in policy_documents:
        serialized = json.dumps(policy_document)
        assert "AdministratorAccess" not in serialized  # nosec B101
        for statement in policy_document["Statement"]:
            actions = statement["Action"]
            if isinstance(actions, str):
                actions = [actions]
            assert "*" not in actions  # nosec B101


def test_github_ci_bootstrap_prod_stack_uses_protected_apply_subject(
    pulumi_mocks,
    monkeypatch,
):  # noqa: ARG001
    monkeypatch.setattr(ci_config, "_secret_import_id", lambda _name: None)
    monkeypatch.setattr(ci_config, "_iam_role_exists", lambda _name: False)
    monkeypatch.setattr(ci_bootstrap, "_iam_role_exists", lambda _name: False)
    monkeypatch.setattr(
        github_oidc,
        "_existing_github_oidc_provider_arn",
        lambda: None,
    )
    settings = _ci_bootstrap_settings("prod")

    start = len(pulumi_mocks.resources)
    component = GitHubCiBootstrap(
        "github-ci-bootstrap-prod",
        args=GitHubCiBootstrapArgs(
            settings=settings,
            protect_resources=True,
        ),
    )

    _sync_await(future_output(component.role_arns["preview"]))
    _sync_await(future_output(component.role_arns["apply"]))
    _sync_await(future_output(component.role_arns["drift"]))
    _sync_await(
        future_output(component.ci_configuration.read_role_arns["prod-preview"])
    )
    _sync_await(future_output(component.ci_configuration.read_role_arns["prod"]))

    assert component.operations_alert_triage_role is None  # nosec B101
    assert component.ci_configuration.secret_ids == {  # nosec B101
        "prod-preview": "/bootstrap-infrastructure/ci/prod-preview",
        "prod": "/bootstrap-infrastructure/ci/prod",
    }
    assert sorted(component.secret_payload_keys) == [  # nosec B101
        "prod",
        "prod-preview",
    ]
    assert "AWS_APPLY_ROLE_ARN" not in component.secret_payload_keys["prod-preview"]  # nosec B101
    assert component.secret_payload_keys["prod"] == [  # nosec B101
        "AWS_ACCOUNT_ID",
        "AWS_APPLY_ROLE_ARN",
        "AWS_REGION",
        "PULUMI_BACKEND_URL",
        "PULUMI_DIR",
        "PULUMI_PREVIEW_STACKS",
        "PULUMI_SECRETS_PROVIDER",
    ]
    assert _resource_state_by_name(  # nosec B101
        pulumi_mocks,
        "github-ci-bootstrap-prod-secret-value-prod",
    )
    assert _resource_state_by_name(  # nosec B101
        pulumi_mocks,
        "github-ci-bootstrap-prod-secret-value-prod-preview",
    )
    new_resources = pulumi_mocks.resources[start:]
    assert not any(  # nosec B101
        name == "github-ci-bootstrap-prod-operations-alert-triage-role"
        for _resource_type, name, _state in new_resources
    )

    apply_state = _resource_state_by_name(
        pulumi_mocks,
        "github-ci-bootstrap-prod-apply-role",
    )
    preview_state = _resource_state_by_name(
        pulumi_mocks,
        "github-ci-bootstrap-prod-preview-role",
    )
    drift_state = _resource_state_by_name(
        pulumi_mocks,
        "github-ci-bootstrap-prod-drift-role",
    )
    apply_trust = json.loads(apply_state["assumeRolePolicy"])
    preview_trust = json.loads(preview_state["assumeRolePolicy"])
    drift_trust = json.loads(drift_state["assumeRolePolicy"])

    assert apply_trust["Statement"][0]["Condition"]["StringEquals"][  # nosec B101
        "token.actions.githubusercontent.com:sub"
    ] == ["repo:VilnaCRM-Org/bootstrap-infrastructure:environment:prod"]
    assert "pull_request" not in json.dumps(apply_trust)  # nosec B101
    assert (
        "repo:VilnaCRM-Org/bootstrap-infrastructure:environment:prod"
        not in (
            preview_trust["Statement"][0]["Condition"]["StringEquals"][
                "token.actions.githubusercontent.com:sub"
            ]
        )
    )
    assert (
        preview_trust["Statement"][0]["Condition"]["StringEquals"][  # nosec B101
            "token.actions.githubusercontent.com:repository"
        ]
        == "VilnaCRM-Org/bootstrap-infrastructure"
    )
    assert (
        apply_trust["Statement"][0]["Condition"]["StringEquals"][  # nosec B101
            "token.actions.githubusercontent.com:repository"
        ]
        == "VilnaCRM-Org/bootstrap-infrastructure"
    )
    assert (
        drift_trust["Statement"][0]["Condition"]["StringEquals"][  # nosec B101
            "token.actions.githubusercontent.com:repository"
        ]
        == "VilnaCRM-Org/bootstrap-infrastructure"
    )
    assert "StringLike" not in preview_trust["Statement"][0]["Condition"]  # nosec B101
    assert "StringLike" not in apply_trust["Statement"][0]["Condition"]  # nosec B101
    assert "StringLike" not in drift_trust["Statement"][0]["Condition"]  # nosec B101


def test_github_ci_bootstrap_helpers_cover_error_paths(monkeypatch):
    settings = _ci_bootstrap_settings("test")
    long_settings = _ci_bootstrap_settings("stage")
    long_settings.repo = "x" * 50
    missing_repo_settings = _ci_bootstrap_settings("test")
    missing_repo_settings.repo = None

    assert ci_bootstrap._ci_secret_suffixes(settings) == ("test-pr", "test")  # nosec B101
    assert ci_bootstrap._ci_secret_suffixes(long_settings) == ("stage",)  # nosec B101
    with pytest.raises(ValueError, match="longer than 64 characters"):
        ci_bootstrap._ci_role_name(long_settings, "preview")
    with pytest.raises(ValueError, match="OIDC subjects"):
        ci_bootstrap._repo_subject(missing_repo_settings, "pull_request")
    monkeypatch.setattr(
        ci_bootstrap,
        "_pulumi_backend_policy_document",
        lambda _account_id, _partition, _settings, _repo=None, **_kwargs: "{}",
    )
    with pytest.raises(ValueError, match="apply policy"):
        ci_bootstrap._role_policy_documents(
            "123456789012",
            "aws",
            missing_repo_settings,
            "apply",
        )
    with pytest.raises(ValueError, match="GitHub CI bootstrap"):
        ci_bootstrap._require_repo(missing_repo_settings)

    monkeypatch.setattr(ci_bootstrap.aws.iam, "get_role", lambda name: object())
    assert ci_bootstrap._iam_role_exists("present") is True  # nosec B101

    def missing_role(*, name: str):
        raise RuntimeError(f"NoSuchEntity: {name}")

    monkeypatch.setattr(ci_bootstrap.aws.iam, "get_role", missing_role)
    assert ci_bootstrap._iam_role_exists("missing") is False  # nosec B101

    def unknown_error(*, name: str):
        raise RuntimeError(f"unexpected lookup failure for {name}")

    monkeypatch.setattr(ci_bootstrap.aws.iam, "get_role", unknown_error)
    with pytest.raises(RuntimeError, match="unexpected lookup failure"):
        ci_bootstrap._iam_role_exists("broken")


def test_secrets_alias_for_repo_is_repo_and_env_scoped():
    """The convenience alias helper is repo/env scoped without the wildcard."""
    settings = _ci_bootstrap_settings("test")

    assert (  # nosec B101
        settings.pulumi_secrets_alias_name_for_repo("user-service-infrastructure")
        == "alias/pulumi-user-service-infrastructure-test-secrets"
    )
    assert (  # nosec B101
        settings.secrets_alias_for_repo("user-service-infrastructure", "test")
        == "alias/pulumi-user-service-infrastructure-test-secrets"
    )
    # secrets_alias_for_repo honours an explicit env distinct from settings.environment.
    assert (  # nosec B101
        settings.secrets_alias_for_repo("user-service-infrastructure", "prod")
        == "alias/pulumi-user-service-infrastructure-prod-secrets"
    )
    # Dotted repo/env segments collapse to hyphens (KMS alias rules).
    assert (  # nosec B101
        settings.secrets_alias_for_repo("repo.with.dots", "stage.1")
        == "alias/pulumi-repo-with-dots-stage-1-secrets"
    )


def test_secrets_alias_for_repo_rejects_blank_repo():
    """Blank repo names cannot be sanitized into an alias and must raise."""
    settings = _ci_bootstrap_settings("test")

    with pytest.raises(ValueError, match="cannot be fully sanitized"):
        settings.secrets_alias_for_repo("   ", "test")


def test_pulumi_secrets_alias_conditions_service_repo_excludes_platform_bootstrap():
    """Governance service-repo path (AWS-SRE-1, FR3) drops platform-bootstrap."""
    settings = _ci_bootstrap_settings("test")

    conditions = ci_bootstrap._pulumi_secrets_alias_conditions(
        settings,
        "user-service-infrastructure",
        "test",
        include_platform_bootstrap=False,
    )

    assert conditions == [  # nosec B101
        "alias/pulumi-user-service-infrastructure-test-secrets",
    ]
    # No platform-bootstrap master-key alias for a managed service repo.
    assert "pulumi-platform-bootstrap" not in json.dumps(conditions)  # nosec B101
    # No wildcard alias survives the refactor.
    assert "pulumi-*" not in json.dumps(conditions)  # nosec B101


def test_pulumi_secrets_alias_conditions_single_repo_keeps_platform_bootstrap():
    """Single-repo bootstrap back-compat keeps the two-alias repo-scoped list."""
    settings = _ci_bootstrap_settings("test")

    conditions = ci_bootstrap._pulumi_secrets_alias_conditions(
        settings,
        "bootstrap-infrastructure",
        "test",
        include_platform_bootstrap=True,
    )

    assert conditions == [  # nosec B101
        "alias/pulumi-bootstrap-infrastructure-test-secrets",
        "alias/pulumi-platform-bootstrap-test",
    ]
    # The wildcard alias is replaced by the repo-scoped alias either way.
    assert "pulumi-*" not in json.dumps(conditions)  # nosec B101


def test_pulumi_secrets_alias_conditions_isolate_repos():
    """Repo A's alias-condition list never references repo B's alias (FR3)."""
    settings = _ci_bootstrap_settings("test")

    repo_a = ci_bootstrap._pulumi_secrets_alias_conditions(
        settings,
        "repo-a-infrastructure",
        "test",
        include_platform_bootstrap=False,
    )

    assert "repo-b-infrastructure" not in json.dumps(repo_a)  # nosec B101


def test_pulumi_secrets_alias_conditions_rejects_blank_repo():
    """Blank repo names raise, matching the _require_repo guard intent (edge)."""
    settings = _ci_bootstrap_settings("test")

    with pytest.raises(ValueError, match="cannot be fully sanitized"):
        ci_bootstrap._pulumi_secrets_alias_conditions(
            settings,
            "   ",
            "test",
            include_platform_bootstrap=False,
        )


def test_pulumi_backend_policy_document_uses_repo_scoped_alias_condition():
    """The single-repo backend policy renders the repo-scoped two-alias list."""
    settings = _ci_bootstrap_settings("test")

    backend_policy = json.loads(
        ci_bootstrap._pulumi_backend_policy_document(
            "123456789012",
            "aws",
            settings,
        )
    )
    secrets_statement = next(
        statement
        for statement in backend_policy["Statement"]
        if statement["Sid"] == "UsePulumiSecretsProviderKey"
    )
    aliases = secrets_statement["Condition"]["ForAnyValue:StringLike"][
        "kms:ResourceAliases"
    ]
    assert aliases == [  # nosec B101
        "alias/pulumi-bootstrap-infrastructure-test-secrets",
        "alias/pulumi-platform-bootstrap-test",
    ]
    assert "pulumi-*" not in json.dumps(aliases)  # nosec B101


def test_github_ci_bootstrap_payload_helpers_cover_custom_env_and_secret_string():
    settings = _ci_bootstrap_settings("stage")
    role_arns = {
        "preview": "arn:aws:iam::123456789012:role/preview",
        "apply": "arn:aws:iam::123456789012:role/apply",
        "drift": "arn:aws:iam::123456789012:role/drift",
    }

    payload_context = ci_bootstrap._BootstrapBuildContext(
        parent=cast(pulumi.Resource, object()),
        name="github-ci-bootstrap-stage",
        account_id="123456789012",
        partition="aws",
        region="eu-central-1",
        settings=settings,
        provider_arn="arn:aws:iam::123456789012:oidc-provider/token",
        pulumi_dir="pulumi",
        protect_resources=True,
    )
    payloads = ci_bootstrap._payloads(
        payload_context,
        ci_bootstrap._PayloadOverrides(
            role_arns=role_arns,
            operations_alert_triage_role_arn=None,
            pulumi_backend_url="s3://custom-state",
            pulumi_dir="pulumi",
            pulumi_secrets_provider="awskms://alias/custom?region=eu-central-1",
        ),
    )
    secret_json = _sync_await(
        future_output(
            ci_bootstrap._secret_string(
                {"B": "2", "A": pulumi.Output.from_input("1")},
            )
        )
    )

    assert list(payloads) == ["stage"]  # nosec B101
    assert payloads["stage"] == {  # nosec B101
        "AWS_ACCOUNT_ID": "123456789012",
        "AWS_APPLY_ROLE_ARN": role_arns["apply"],
        "AWS_DRIFT_ROLE_ARN": role_arns["drift"],
        "AWS_PREVIEW_ROLE_ARN": role_arns["preview"],
        "AWS_REGION": "eu-central-1",
        "PULUMI_BACKEND_URL": "s3://custom-state",
        "PULUMI_DIR": "pulumi",
        "PULUMI_DRIFT_STACKS": "stage",
        "PULUMI_PREVIEW_STACKS": "stage",
        "PULUMI_SECRETS_PROVIDER": "awskms://alias/custom?region=eu-central-1",
    }
    assert json.loads(secret_json) == {"A": "1", "B": "2"}  # nosec B101

    with pytest.raises(ValueError, match="triage role ARN"):
        ci_bootstrap._payloads(
            ci_bootstrap._BootstrapBuildContext(
                parent=cast(pulumi.Resource, object()),
                name="github-ci-bootstrap-test",
                account_id="123456789012",
                partition="aws",
                region="eu-central-1",
                settings=_ci_bootstrap_settings("test"),
                provider_arn="arn:aws:iam::123456789012:oidc-provider/token",
                pulumi_dir="pulumi",
                protect_resources=True,
            ),
            ci_bootstrap._PayloadOverrides(
                role_arns=role_arns,
                operations_alert_triage_role_arn=None,
                pulumi_backend_url=None,
                pulumi_dir="pulumi",
                pulumi_secrets_provider=None,
            ),
        )


def test_github_ci_bootstrap_custom_stack_can_skip_secret_values(
    pulumi_mocks,
    monkeypatch,
):  # noqa: ARG001
    monkeypatch.setattr(ci_config, "_secret_import_id", lambda _name: None)
    monkeypatch.setattr(ci_config, "_iam_role_exists", lambda _name: False)
    monkeypatch.setattr(ci_bootstrap, "_iam_role_exists", lambda _name: False)
    monkeypatch.setattr(
        github_oidc,
        "_existing_github_oidc_provider_arn",
        lambda: None,
    )
    settings = _ci_bootstrap_settings("stage")

    start = len(pulumi_mocks.resources)
    component = GitHubCiBootstrap(
        "github-ci-bootstrap-stage",
        args=GitHubCiBootstrapArgs(
            settings=settings,
            write_secret_values=False,
            protect_resources=True,
        ),
    )

    _sync_await(future_output(component.role_arns["preview"]))
    _sync_await(future_output(component.role_arns["apply"]))
    _sync_await(future_output(component.role_arns["drift"]))
    _sync_await(future_output(component.ci_configuration.read_role_arns["stage"]))

    assert component.operations_alert_triage_role is None  # nosec B101
    assert component.operations_alert_triage_policy is None  # nosec B101
    assert component.secret_versions == {}  # nosec B101
    assert component.github_variables == {  # nosec B101
        "AWS_STAGE_REGION": "us-east-1",
        "AWS_STAGE_ACCOUNT_ID": "123456789012",
    }
    assert component.secret_payload_keys["stage"] == [  # nosec B101
        "AWS_ACCOUNT_ID",
        "AWS_APPLY_ROLE_ARN",
        "AWS_DRIFT_ROLE_ARN",
        "AWS_PREVIEW_ROLE_ARN",
        "AWS_REGION",
        "PULUMI_BACKEND_URL",
        "PULUMI_DIR",
        "PULUMI_DRIFT_STACKS",
        "PULUMI_PREVIEW_STACKS",
        "PULUMI_SECRETS_PROVIDER",
    ]
    assert not any(  # nosec B101
        resource_type == "aws:secretsmanager/secretVersion:SecretVersion"
        for resource_type, _name, _state in pulumi_mocks.resources[start:]
    )


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
    central_logging_replica_encryption_state = _resource_state_by_name(
        pulumi_mocks, "central-logging-replica-encryption"
    )
    state_bucket_logging_state = _resource_state_by_name(
        pulumi_mocks, "pulumi-state-repo-logging"
    )
    state_bucket_encryption_state = _resource_state_by_name(
        pulumi_mocks, "pulumi-state-repo-encryption"
    )
    replica_state_bucket_logging_state = _resource_state_by_name(
        pulumi_mocks, "pulumi-state-replica-repo-logging"
    )
    replica_state_bucket_encryption_state = _resource_state_by_name(
        pulumi_mocks, "pulumi-state-replica-repo-encryption"
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
    cloudtrail_key_state = _resource_state_by_name(
        pulumi_mocks, "operations-monitoring-cloudtrail-key"
    )
    cloudtrail_key_alias_state = _resource_state_by_name(
        pulumi_mocks, "operations-monitoring-cloudtrail-key-alias"
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
    cloudtrail_bucket_state = _resource_state_by_name(
        pulumi_mocks, "operations-monitoring-cloudtrail-bucket"
    )
    cloudtrail_bucket_encryption_state = _resource_state_by_name(
        pulumi_mocks, "operations-monitoring-cloudtrail-bucket-encryption"
    )
    cloudtrail_bucket_policy_state = _resource_state_by_name(
        pulumi_mocks, "operations-monitoring-cloudtrail-bucket-policy"
    )
    cloudtrail_state = _resource_state_by_name(
        pulumi_mocks, "operations-monitoring-cloudtrail"
    )
    backup_restore_policy_state = _resource_state_by_name(
        pulumi_mocks, "backup-restore-drill-policy"
    )
    backup_rule_state = _resource_state_by_name(
        pulumi_mocks, "operations-monitoring-backup-failed-rule"
    )
    kms_rule_state = _resource_state_by_name(
        pulumi_mocks, "operations-monitoring-kms-risk-rule"
    )

    managed_bucket_encryption_rules = [
        central_logging_encryption_state["rules"][0],
        central_logging_replica_encryption_state["rules"][0],
        state_bucket_encryption_state["rules"][0],
        replica_state_bucket_encryption_state["rules"][0],
    ]
    for encryption_rule in managed_bucket_encryption_rules:
        assert encryption_rule["blockedEncryptionTypes"] == ["SSE-C"]  # nosec B101
        assert encryption_rule["bucketKeyEnabled"] is False  # nosec B101
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
        == "company-central-logs-us-east-1-test-us-west-2-replication"
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
    assert cloudtrail_bucket_state["bucket"] == (  # nosec B101
        "bootstrap-123456789012-us-east-1-test-cloudtrail"
    )
    cloudtrail_key_policy = json.loads(cloudtrail_key_state["policy"])
    cloudtrail_key_statements = {
        statement["Sid"]: statement for statement in cloudtrail_key_policy["Statement"]
    }
    assert cloudtrail_key_state["enableKeyRotation"] is True  # nosec B101
    assert cloudtrail_key_state["tags"]["Purpose"] == (  # nosec B101
        "operations-cloudtrail"
    )
    assert cloudtrail_key_alias_state["name"] == (  # nosec B101
        "alias/bootstrap-test-operations-cloudtrail"
    )
    assert cloudtrail_key_statements["AllowCloudTrailEncryptLogs"][  # nosec B101
        "Condition"
    ] == {
        "StringEquals": {
            "aws:SourceArn": (
                "arn:aws:cloudtrail:us-east-1:123456789012:trail/"
                "bootstrap-test-management-events"
            )
        },
        "StringLike": {
            "kms:EncryptionContext:aws:cloudtrail:arn": (
                "arn:aws:cloudtrail:*:123456789012:trail/"
                "bootstrap-test-management-events"
            )
        },
    }
    cloudtrail_bucket_encryption = json.dumps(
        cloudtrail_bucket_encryption_state["rules"],
        sort_keys=True,
    )
    assert (  # nosec B101
        cloudtrail_bucket_encryption_state["rules"][0]["bucketKeyEnabled"] is False
    )
    assert cloudtrail_bucket_encryption_state["rules"][0][  # nosec B101
        "blockedEncryptionTypes"
    ] == ["SSE-C"]
    assert "aws:kms" in cloudtrail_bucket_encryption  # nosec B101
    assert (  # nosec B101
        "arn:aws:kms:us-east-1:123456789012:key/"
        "operations-monitoring-cloudtrail-key" in cloudtrail_bucket_encryption
    )
    cloudtrail_bucket_policy = json.loads(cloudtrail_bucket_policy_state["policy"])
    cloudtrail_put_statement = next(
        statement
        for statement in cloudtrail_bucket_policy["Statement"]
        if statement["Sid"] == "AllowCloudTrailPutObject"
    )
    assert cloudtrail_put_statement["Condition"] == {  # nosec B101
        "ArnLike": {
            "aws:SourceArn": (
                "arn:aws:cloudtrail:us-east-1:123456789012:trail/"
                "bootstrap-test-management-events"
            )
        },
        "StringEquals": {
            "aws:SourceAccount": "123456789012",
            "s3:x-amz-acl": "bucket-owner-full-control",
        },
    }
    assert cloudtrail_state["name"] == (  # nosec B101
        "bootstrap-test-management-events"
    )
    assert cloudtrail_state["enableLogFileValidation"] is True  # nosec B101
    assert cloudtrail_state["includeGlobalServiceEvents"] is True  # nosec B101
    assert cloudtrail_state["isMultiRegionTrail"] is True  # nosec B101
    assert cloudtrail_state["kmsKeyId"] == (  # nosec B101
        "arn:aws:kms:us-east-1:123456789012:key/operations-monitoring-cloudtrail-key"
    )
    backup_restore_policy = json.loads(backup_restore_policy_state["policy"])
    restore_policy_resources = {
        resource
        for statement in backup_restore_policy["Statement"]
        for resource in (
            statement["Resource"]
            if isinstance(statement["Resource"], list)
            else [statement["Resource"]]
        )
    }
    assert (  # nosec B101
        "arn:aws:s3:::awsbackup-restore-test-bootstrap-123456789012-*"
        in restore_policy_resources
    )
    assert (  # nosec B101
        "arn:aws:s3:::awsbackup-restore-test-bootstrap-123456789012-*/*"
        in restore_policy_resources
    )
    assert (  # nosec B101
        "arn:aws:kms:*:123456789012:key/*" in restore_policy_resources
    )
    kms_restore_statement = next(
        statement
        for statement in backup_restore_policy["Statement"]
        if statement["Sid"] == "UseS3KmsKeysForIsolatedRestoreDrills"
    )
    assert kms_restore_statement["Condition"] == {  # nosec B101
        "ForAnyValue:StringLike": {
            "kms:ResourceAliases": [
                "alias/pulumi-*-secrets",
                "alias/bootstrap-*-operations-cloudtrail",
            ]
        },
        "StringLike": {"kms:ViaService": ["s3.*.amazonaws.com"]},
    }
    restore_policy_attachments = [
        state
        for resource_type, _name, state in pulumi_mocks.resources
        if resource_type == "aws:iam/rolePolicyAttachment:RolePolicyAttachment"
        and state.get("policyArn")
        == "arn:aws:iam::aws:policy/AWSBackupServiceRolePolicyForS3Restore"
    ]
    assert restore_policy_attachments == []  # nosec B101
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


def test_operations_monitoring_can_reuse_existing_cloudtrail(pulumi_mocks, monkeypatch):  # noqa: ARG001
    """Existing management trails should avoid duplicate CloudTrail resources."""
    monkeypatch.setattr(config.settings, "environment", "test")
    monkeypatch.setattr(
        config.settings,
        "operations_cloudtrail_name",
        "existing-management-events",
    )

    monitoring = OperationsMonitoring("operations-monitoring-reuse")

    assert monitoring.cloudtrail is None  # nosec B101
    assert monitoring.cloudtrail_bucket is None  # nosec B101
    assert _sync_await(future_output(monitoring.cloudtrail_name)) == (  # nosec B101
        "existing-management-events"
    )
    assert _sync_await(future_output(monitoring.cloudtrail_bucket_name)) is None  # nosec B101
    cloudtrail_resource_names = {
        name
        for resource_type, name, _state in pulumi_mocks.resources
        if resource_type == "aws:cloudtrail/trail:Trail"
    }
    assert cloudtrail_resource_names == set()  # nosec B101


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
        CostControlInputs(
            operations_topic_arn=(
                "arn:aws:sns:us-east-1:123456789012:bootstrap-test-operations"
            )
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
        CostControlInputs(
            operations_topic_arn=(
                "arn:aws:sns:us-east-1:123456789012:bootstrap-test-operations"
            )
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


def test_security_account_controls_emit_detection_and_config_resources(
    pulumi_mocks, monkeypatch
):  # noqa: ARG001
    monkeypatch.setattr(config.settings, "environment", "test")

    start = len(pulumi_mocks.resources)
    controls = SecurityAccountControls("security-account-controls")

    detector_id = _sync_await(future_output(controls.guardduty_detector.id))
    hub_arn = _sync_await(future_output(controls.security_hub_account.arn))
    recorder_name = _sync_await(future_output(controls.config_recorder.name))
    delivery_channel_name = _sync_await(
        future_output(controls.config_delivery_channel.name)
    )
    bucket_name = _sync_await(future_output(controls.config_bucket.bucket))

    assert detector_id is not None  # nosec B101
    assert hub_arn == "arn:aws:securityhub:us-east-1:123456789012:hub/default"  # nosec B101
    assert recorder_name == "bootstrap-test-configuration-recorder"  # nosec B101
    assert (  # nosec B101
        delivery_channel_name == "bootstrap-test-configuration-delivery"
    )
    assert bucket_name == "bootstrap-123456789012-us-east-1-test-aws-config"  # nosec B101

    new_resources = pulumi_mocks.resources[start:]
    detector_state = next(
        state
        for resource_type, _name, state in new_resources
        if resource_type == "aws:guardduty/detector:Detector"
    )
    security_hub_state = next(
        state
        for resource_type, _name, state in new_resources
        if resource_type == "aws:securityhub/account:Account"
    )
    recorder_state = next(
        state
        for resource_type, _name, state in new_resources
        if resource_type == "aws:cfg/recorder:Recorder"
    )
    delivery_state = next(
        state
        for resource_type, _name, state in new_resources
        if resource_type == "aws:cfg/deliveryChannel:DeliveryChannel"
    )
    role_state = next(
        state
        for resource_type, _name, state in new_resources
        if resource_type == "aws:iam/role:Role"
        and state.get("name") == "aws-config-recorder-role-test"
    )
    bucket_policy_state = next(
        state
        for resource_type, _name, state in new_resources
        if resource_type == "aws:s3/bucketPolicy:BucketPolicy"
    )

    assert detector_state["enable"] is True  # nosec B101
    assert detector_state["findingPublishingFrequency"] == "FIFTEEN_MINUTES"  # nosec B101
    assert security_hub_state["autoEnableControls"] is True  # nosec B101
    assert recorder_state["recordingGroup"]["allSupported"] is True  # nosec B101
    assert recorder_state["recordingMode"]["recordingFrequency"] == "DAILY"  # nosec B101
    assert delivery_state["snapshotDeliveryProperties"]["deliveryFrequency"] == (  # nosec B101
        "TwentyFour_Hours"
    )
    assume_role_policy = json.loads(role_state["assumeRolePolicy"])
    assume_role_statements = assume_role_policy["Statement"]
    assert any(  # nosec B101
        statement.get("Principal", {}).get("Service")
        == security_account_controls.AWS_CONFIG_SERVICE_PRINCIPAL
        and statement.get("Action") == "sts:AssumeRole"
        for statement in assume_role_statements
    )
    assert "AWSConfigBucketDelivery" in bucket_policy_state["policy"]  # nosec B101


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
    assert "backupRoleArn" in bootstrap.outputs  # nosec B101
    assert "ciConfigurationSecretIds" in bootstrap.outputs  # nosec B101
    assert "ciConfigurationSecretArns" in bootstrap.outputs  # nosec B101
    assert "githubCiConfigReadRoleArns" in bootstrap.outputs  # nosec B101
    assert "guardDutyDetectorId" in bootstrap.outputs  # nosec B101
    assert "securityHubAccountArn" in bootstrap.outputs  # nosec B101
    assert "awsConfigRecorderName" in bootstrap.outputs  # nosec B101
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
    _sync_await(future_output(bootstrap.automation.policy.name))

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
    policy_state = _resource_state_by_name(pulumi_mocks, "github-automation-policy")

    assert repository_state["tags"]["RepositoryProject"] == "core-service"  # nosec B101
    assert role_state["tags"]["RepositoryProject"] == "core-service"  # nosec B101
    assert policy_state["name"] == "github-automation-policy"  # nosec B101

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


def test_github_oidc_roles_reuse_discovered_provider(  # noqa: ARG001
    monkeypatch, pulumi_mocks
):
    class FakeLookup:
        arn = (
            "arn:aws:iam::123456789012:oidc-provider/"
            "token.actions.githubusercontent.com"
        )

    class FakeProvider:
        arn = pulumi.Output.from_input(FakeLookup.arn)

    captured = {}

    def fake_get_provider(url):
        captured["url"] = url
        return FakeLookup()

    def fake_get_resource(_name, provider_arn, **_kwargs):
        captured["provider_arn"] = provider_arn
        return FakeProvider()

    monkeypatch.setattr(github_oidc.settings, "github_oidc_provider_arn", None)
    monkeypatch.setattr(github_oidc, "_role_exists", lambda _name: False)
    monkeypatch.setattr(
        github_oidc.aws.iam,
        "get_open_id_connect_provider",
        fake_get_provider,
    )
    monkeypatch.setattr(
        github_oidc.aws.iam.OpenIdConnectProvider,
        "get",
        fake_get_resource,
    )

    repos = [config.ManagedRepository(name="repo-discovered", default_branch="main")]
    roles = GitHubOidcRoles("github-oidc-discovered", repositories=repos)

    assert roles.deploy_role_arns  # nosec B101
    assert captured == {  # nosec B101
        "url": "https://token.actions.githubusercontent.com",
        "provider_arn": FakeLookup.arn,
    }
    provider_resource_names = {
        name
        for resource_type, name, _state in pulumi_mocks.resources
        if resource_type == "aws:iam/openIdConnectProvider:OpenIdConnectProvider"
    }
    assert "github-oidc-discovered-provider" not in provider_resource_names  # nosec B101


def test_github_oidc_roles_scope_state_and_kms_per_repository():
    secret_key_arns = {
        "repo-one": "arn:aws:kms:us-east-1:123456789012:key/repo-one",
        "repo-two": "arn:aws:kms:us-east-1:123456789012:key/repo-two",
    }

    repo_one_policy = json.loads(
        github_oidc._deploy_policy(
            "arn:aws:s3:::pulumi-repo-one-test-state",
            "arn:aws:s3:::pulumi-repo-one-test-state/state/*",
            secret_key_arns["repo-one"],
        )
    )
    repo_two_policy = json.loads(
        github_oidc._deploy_policy(
            "arn:aws:s3:::pulumi-repo-two-test-state",
            "arn:aws:s3:::pulumi-repo-two-test-state/state/*",
            secret_key_arns["repo-two"],
        )
    )
    repo_one_statements = repo_one_policy["Statement"]
    repo_two_statements = repo_two_policy["Statement"]

    assert repo_one_statements[0]["Resource"] == (  # nosec B101
        "arn:aws:s3:::pulumi-repo-one-test-state"
    )
    assert repo_one_statements[1]["Resource"] == (  # nosec B101
        "arn:aws:s3:::pulumi-repo-one-test-state/state/*"
    )
    assert repo_one_statements[2]["Resource"] == secret_key_arns["repo-one"]  # nosec B101
    assert "repo-two" not in json.dumps(repo_one_statements)  # nosec B101

    assert repo_two_statements[0]["Resource"] == (  # nosec B101
        "arn:aws:s3:::pulumi-repo-two-test-state"
    )
    assert repo_two_statements[1]["Resource"] == (  # nosec B101
        "arn:aws:s3:::pulumi-repo-two-test-state/state/*"
    )
    assert repo_two_statements[2]["Resource"] == secret_key_arns["repo-two"]  # nosec B101
    assert "repo-one" not in json.dumps(repo_two_statements)  # nosec B101

    provider_arn = (
        "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
    )
    repo_one_trust = json.loads(
        github_oidc._assume_role_policy(
            provider_arn,
            "VilnaCRM-Org",
            "repo-one",
            "main",
            environment="test",
        )
    )
    repo_two_trust = json.loads(
        github_oidc._assume_role_policy(
            provider_arn,
            "VilnaCRM-Org",
            "repo-two",
            "release",
            environment="test",
        )
    )
    for trust, repo, branch in [
        (repo_one_trust, "repo-one", "main"),
        (repo_two_trust, "repo-two", "release"),
    ]:
        assert trust["Statement"][0]["Condition"] == {
            "StringEquals": {
                "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
                "token.actions.githubusercontent.com:repository": (
                    f"VilnaCRM-Org/{repo}"
                ),
                "token.actions.githubusercontent.com:ref": f"refs/heads/{branch}",
                "token.actions.githubusercontent.com:sub": [
                    f"repo:VilnaCRM-Org/{repo}:environment:test"
                ],
            }
        }


def test_github_oidc_existing_provider_lookup_handles_missing(monkeypatch):
    def raise_missing(**_kwargs):
        raise RuntimeError("couldn't find resource")

    monkeypatch.setattr(
        github_oidc.aws.iam,
        "get_open_id_connect_provider",
        raise_missing,
    )

    assert github_oidc._existing_github_oidc_provider_arn() is None  # nosec B101


def test_github_oidc_existing_provider_lookup_raises_unexpected(monkeypatch):
    def raise_unexpected(**_kwargs):
        raise RuntimeError("throttled")

    monkeypatch.setattr(
        github_oidc.aws.iam,
        "get_open_id_connect_provider",
        raise_unexpected,
    )

    with pytest.raises(RuntimeError, match="throttled"):
        github_oidc._existing_github_oidc_provider_arn()


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
    automation_resource = GitHubAutomation("github-automation")

    repository_url = _sync_await(
        future_output(automation_resource.repository.repository_url)
    )
    role_arn = _sync_await(future_output(automation_resource.role.arn))
    triage_role_arn = _sync_await(
        future_output(automation_resource.operations_alert_triage_role.arn)
    )
    assert repository_url is not None  # nosec B101
    assert role_arn is not None  # nosec B101
    assert triage_role_arn is not None  # nosec B101
    assert repository_url.endswith("/pulumi-runner/bootstrap-infrastructure-test")  # nosec B101
    assert role_arn.endswith(":role/PulumiAutomation-bootstrap-infrastructure-test")  # nosec B101
    assert triage_role_arn.endswith(  # nosec B101
        ":role/OperationsAlertTriage-bootstrap-infrastructure-test"
    )

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
    triage_role_type, _, triage_role_state = next(
        (type_, name, state)
        for type_, name, state in new_resources
        if type_ == "aws:iam/role:Role"
        and state.get("name") == "OperationsAlertTriage-bootstrap-infrastructure-test"
    )
    policy_names = [
        "github-automation-policy",
        "github-automation-iam-policy",
        "github-automation-iam-boundary-policy",
        "github-automation-operations-policy",
        "github-automation-cost-policy",
        "github-automation-security-policy",
    ]
    managed_policy_names = policy_names[1:]
    policy_states = [
        _resource_state_by_name(pulumi_mocks, policy_name)
        for policy_name in policy_names
    ]
    attachment_states = [
        _resource_state_by_name(pulumi_mocks, f"{policy_name}-attachment")
        for policy_name in managed_policy_names
    ]
    exclusive_attachment_state = next(
        state
        for type_, name, state in new_resources
        if type_
        == "aws:iam/rolePolicyAttachmentsExclusive:RolePolicyAttachmentsExclusive"
        and name == "github-automation-managed-policy-attachments-exclusive"
    )

    assert repository_type == "aws:ecr/repository:Repository"  # nosec B101
    assert repository_state["name"] == "pulumi-runner/bootstrap-infrastructure-test"  # nosec B101
    assert repository_state["imageTagMutability"] == "IMMUTABLE"  # nosec B101
    assert repository_state["imageScanningConfiguration"]["scanOnPush"] is True  # nosec B101
    assert role_type == "aws:iam/role:Role"  # nosec B101
    assert triage_role_type == "aws:iam/role:Role"  # nosec B101
    role_subjects = json.loads(role_state["assumeRolePolicy"])["Statement"][0][
        "Condition"
    ]["StringEquals"]["token.actions.githubusercontent.com:sub"]
    assert role_subjects == [
        "repo:VilnaCRM-Org/bootstrap-infrastructure:environment:test"
    ]
    assert (  # nosec B101
        "repo:VilnaCRM-Org/bootstrap-infrastructure:ref:refs/heads/main"
        in triage_role_state["assumeRolePolicy"]
    )
    assert (  # nosec B101
        "repo:VilnaCRM-Org/bootstrap-infrastructure:environment:test"
        not in triage_role_state["assumeRolePolicy"]
    )
    assert (  # nosec B101
        '"token.actions.githubusercontent.com:repository"'
        in role_state["assumeRolePolicy"]
    )
    assert (  # nosec B101
        '"token.actions.githubusercontent.com:repository"'
        in triage_role_state["assumeRolePolicy"]
    )
    assert "Pulumi PR Guardrails" not in role_state["assumeRolePolicy"]  # nosec B101
    assert (  # nosec B101
        "Operations Alert Issue Triage" in triage_role_state["assumeRolePolicy"]
    )
    assert (  # nosec B101
        len(policy_states[0]["policy"].encode("utf-8"))
        <= automation.IAM_ROLE_INLINE_POLICY_MAX_BYTES
    )
    for managed_policy_state in policy_states[1:]:
        assert (  # nosec B101
            len(managed_policy_state["policy"].encode("utf-8"))
            <= automation.IAM_CUSTOMER_MANAGED_POLICY_MAX_BYTES
        )
    for attachment_state in attachment_states:
        assert (  # nosec B101
            attachment_state["role"] == "PulumiAutomation-bootstrap-infrastructure-test"
        )
    assert (  # nosec B101
        exclusive_attachment_state["roleName"]
        == "PulumiAutomation-bootstrap-infrastructure-test"
    )
    assert (
        set(exclusive_attachment_state["policyArns"])
        == {  # nosec B101
            state["arn"] for state in policy_states[1:]
        }
    )
    assert (  # nosec B101
        "arn:aws:iam::aws:policy/AdministratorAccess"
        not in exclusive_attachment_state["policyArns"]
    )
    automation_policies = [
        json.loads(policy_state["policy"]) for policy_state in policy_states
    ]
    statements = {
        statement["Sid"]: statement
        for document in automation_policies
        for statement in document["Statement"]
    }
    account_control_sids = {
        statement["Sid"] for statement in automation_policies[-1]["Statement"]
    }
    assert "ManageSecurityHubAccount" in account_control_sids  # nosec B101
    assert "ManageAwsConfigRecorder" in account_control_sids  # nosec B101
    assert "CreateBootstrapGuardDutyDetector" in account_control_sids  # nosec B101
    assert statements["ManageBootstrapEcr"]["Resource"] == [  # nosec B101
        "arn:aws:ecr:*:123456789012:repository/pulumi-runner/"
        "bootstrap-infrastructure-test"
    ]
    assert "ecr:DescribeImages" in statements["ManageBootstrapEcr"]["Action"]  # nosec B101
    assert "ManageBootstrapIam" not in statements
    bounded = statements["ManageBoundedBackup"]
    assert bounded["Resource"] == "arn:aws:iam::123456789012:role/s3-backup-role-test"
    assert bounded["Condition"]["StringEquals"]["iam:PermissionsBoundary"] == (
        "arn:aws:iam::123456789012:policy/PlatformBoundary-backup-test"
    )
    assert statements["DenyControllerIamChanges"]["NotResource"] == [
        bounded["Resource"]
    ]
    assert statements["ManageBootstrapS3"]["Resource"] == [  # nosec B101
        "arn:aws:s3:::pulumi-bootstrap-infrastructure-test-state",
        "arn:aws:s3:::pulumi-bootstrap-infrastructure--c1194dce-eu-west-1-replication",
        "arn:aws:s3:::company-central-logs-*-test",
        "arn:aws:s3:::company-central-logs-*-test-*-replication",
        "arn:aws:s3:::bootstrap-*-test-cloudtrail",
        "arn:aws:s3:::bootstrap-*-test-aws-config",
    ]
    all_actions = {
        action
        for document in automation_policies
        for statement in document["Statement"]
        for action in statement["Action"]
    }
    all_allow_actions = {
        action
        for document in automation_policies
        for statement in document["Statement"]
        if statement["Effect"] == "Allow"
        for action in statement["Action"]
    }
    assert "kms:Decrypt" not in all_allow_actions  # nosec B101
    assert "kms:Encrypt" not in all_allow_actions  # nosec B101
    assert "kms:GenerateDataKey" not in all_allow_actions  # nosec B101
    assert "kms:ReEncryptFrom" not in all_allow_actions  # nosec B101
    assert "cloudtrail:*" not in all_actions  # nosec B101
    assert "cloudtrail:CreateTrail" in all_actions  # nosec B101
    assert "cloudtrail:DescribeTrails" in all_actions  # nosec B101
    assert "sqs:ReceiveMessage" not in all_allow_actions  # nosec B101
    assert "sqs:DeleteMessage" not in all_allow_actions  # nosec B101
    assert "secretsmanager:GetSecretValue" not in all_allow_actions  # nosec B101
    assert "secretsmanager:PutSecretValue" not in all_allow_actions  # nosec B101
    assert "secretsmanager:UpdateSecret" not in all_allow_actions  # nosec B101
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
    assert "sns:Subscribe" in statements["ManageBootstrapSns"]["Action"]  # nosec B101
    assert statements["ManageBootstrapSnsSubscriptions"]["Resource"] == "*"  # nosec B101
    assert statements["ManageBootstrapSnsSubscriptions"]["Action"] == [  # nosec B101
        "sns:GetSubscriptionAttributes",
        "sns:Unsubscribe",
    ]
    assert "CreateBootstrapCiSecrets" not in statements
    assert "ManageBootstrapCiSecrets" not in statements
    assert statements["ReadPlatformCiSecrets"]["Action"] == [
        "secretsmanager:DescribeSecret"
    ]
    assert statements["ReadPlatformCiSecrets"]["Resource"] == [
        "arn:aws:secretsmanager:*:123456789012:secret:/bootstrap-infrastructure/ci/test-pr-*",
        "arn:aws:secretsmanager:*:123456789012:secret:/bootstrap-infrastructure/ci/test-*",
    ]
    assert statements["DenyBootstrapSqsConsumption"] == {  # nosec B101
        "Sid": "DenyBootstrapSqsConsumption",
        "Effect": "Deny",
        "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage"],
        "Resource": ["arn:aws:sqs:*:123456789012:bootstrap-test-operations-alerts"],
    }
    triage_policy_state = _resource_state_by_name(
        pulumi_mocks,
        "github-automation-operations-alert-triage-policy",
    )
    triage_policy = json.loads(triage_policy_state["policy"])
    assert triage_policy["Statement"] == [  # nosec B101
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
    assert statements["CreateBootstrapCostAnomalyMonitor"]["Resource"] == "*"  # nosec B101
    assert statements["CreateBootstrapCostAnomalyMonitor"]["Action"] == [  # nosec B101
        "ce:CreateAnomalyMonitor"
    ]
    assert statements["CreateBootstrapCostAnomalyMonitor"]["Condition"] == {  # nosec B101
        "StringEquals": {
            "aws:RequestTag/Environment": "test",
            "aws:RequestTag/Purpose": "cost-anomaly-monitor",
        }
    }
    assert statements["CreateBootstrapCostAnomalySubscription"]["Resource"] == "*"  # nosec B101
    assert statements["CreateBootstrapCostAnomalySubscription"]["Action"] == [  # nosec B101
        "ce:CreateAnomalySubscription"
    ]
    assert statements["CreateBootstrapCostAnomalySubscription"]["Condition"] == {  # nosec B101
        "StringEquals": {
            "aws:RequestTag/Environment": "test",
            "aws:RequestTag/Purpose": "cost-anomaly-subscription",
        }
    }
    assert statements["ReadCostAnomalyMonitorsForEvidence"] == {  # nosec B101
        "Sid": "ReadCostAnomalyMonitorsForEvidence",
        "Effect": "Allow",
        "Action": ["ce:GetAnomalyMonitors"],
        "Resource": ["arn:aws:ce::123456789012:anomalymonitor/*"],
    }
    assert statements["ManageBootstrapCostAnomalyMonitors"]["Resource"] == [  # nosec B101
        "arn:aws:ce::123456789012:anomalymonitor/*",
    ]
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
    assert (  # nosec B101
        "ManageBootstrapCostAllocationTags" not in statements
    )
    assert "budgets:ModifyBudget" in statements["ManageBootstrapBudgets"]["Action"]  # nosec B101
    assert "budgets:ViewBudget" in statements["ManageBootstrapBudgets"]["Action"]  # nosec B101


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
    monkeypatch.setattr(github_oidc, "_existing_github_oidc_provider_arn", lambda: None)

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
            def require(self, key):
                return {
                    "awsAccountId": "123456789012",
                    "githubRepositoryId": "1098568429",
                    "githubRepositoryOwnerId": "114362548",
                }[key]

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
            def require(self, key):
                return {
                    "awsAccountId": "123456789012",
                    "githubRepositoryId": "1098568429",
                    "githubRepositoryOwnerId": "114362548",
                }[key]

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
