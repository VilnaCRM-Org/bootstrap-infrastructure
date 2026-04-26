import hashlib
import json
from types import SimpleNamespace

import infra.automation as automation
from infra import config, pulumi_secrets
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
    statements = {statement["Sid"]: statement for statement in policy["Statement"]}

    assert "s3:*" not in actions  # nosec B101
    assert "kms:*" not in actions  # nosec B101
    assert "backup:*" not in actions  # nosec B101
    assert "ecr:*" not in actions  # nosec B101
    assert "events:*" not in actions  # nosec B101
    assert "sns:*" not in actions  # nosec B101
    assert "s3:CreateBucket" in actions  # nosec B101
    assert "kms:CreateKey" in actions  # nosec B101
    assert "kms:Decrypt" not in actions  # nosec B101
    assert "kms:Encrypt" not in actions  # nosec B101
    assert "kms:GenerateDataKey" not in actions  # nosec B101
    assert "backup:CreateBackupPlan" in actions  # nosec B101
    assert "ecr:CreateRepository" in actions  # nosec B101
    assert "events:PutRule" in actions  # nosec B101
    assert "sns:CreateTopic" in actions  # nosec B101
    assert statements["ManageBootstrapS3"]["Resource"] == [  # nosec B101
        "arn:aws:s3:::pulumi-*-test-state",
        "arn:aws:s3:::pulumi-*-test-state-replication",
        "arn:aws:s3:::company-central-logs-*-test",
        "arn:aws:s3:::company-central-logs-*-test-replication",
    ]
    assert statements["ManageBootstrapEcr"]["Resource"] == [  # nosec B101
        "arn:aws:ecr:*:123456789012:repository/pulumi-runner/"
        "bootstrap-infrastructure-test"
    ]
    assert statements["ManageBootstrapEventBridge"]["Resource"] == [  # nosec B101
        "arn:aws:events:*:123456789012:rule/bootstrap-test-*"
    ]
    assert statements["ManageBootstrapSns"]["Resource"] == [  # nosec B101
        "arn:aws:sns:*:123456789012:bootstrap-test-operations"
    ]
    assert (  # nosec B101
        "arn:aws:iam::123456789012:role/PulumiAutomation-"
        "bootstrap-infrastructure-test" in statements["ManageBootstrapIam"]["Resource"]
    )
    assert (  # nosec B101
        statements["ManageBootstrapKmsKeys"]["Condition"]["StringEquals"]
        == {
            "aws:ResourceTag/Environment": "test",
            "aws:ResourceTag/Purpose": ["pulumi-secrets", "operations-alerting"],
        }
    )
    assert statements["CreateBootstrapKmsKeys"]["Condition"]["StringEquals"] == {  # nosec B101
        "aws:RequestTag/Environment": "test",
        "aws:RequestTag/Purpose": ["pulumi-secrets", "operations-alerting"],
    }
    assert (  # nosec B101
        "arn:aws:kms:*:123456789012:alias/bootstrap-test-operations-alerting"
        in statements["ManageBootstrapKmsAliases"]["Resource"]
    )
    assert {
        statement["Sid"]
        for statement in policy["Statement"]
        if statement["Resource"] == "*"
    } == {
        "CreateBootstrapKmsKeys",
        "CreateBootstrapOidcProvider",
        "ListBootstrapOidcProviders",
        "ListBootstrapKmsAliases",
        "ReadIdentity",
    }  # nosec B101


def test_mutation_target_github_oidc_role_name_limits_length():
    repo_suffix = "a" * 70
    digest = hashlib.sha256(repo_suffix.encode("utf-8")).hexdigest()[:8]
    expected = f"PulumiDeploy-{'a' * 42}-{digest}"
    assert github_oidc._truncate_role_suffix(repo_suffix) == f"{'a' * 42}-{digest}"  # nosec B101
    assert github_oidc._role_name_for_suffix(repo_suffix) == expected  # nosec B101
    assert len(expected) == github_oidc._MAX_IAM_ROLE_NAME_LENGTH == 64  # nosec B101


def test_mutation_target_github_oidc_truncation_keeps_digest():
    assert github_oidc._role_name_for_suffix("repo-short") == "PulumiDeploy-repo-short"  # nosec B101
