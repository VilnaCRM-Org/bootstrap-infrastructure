"""Platform IAM cannot rewrite its controls or remove service ceilings."""

import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from iam_statement_matcher import iam_statement_matches
from infra import automation, config, platform_iam, security_account_controls
from infra.bootstrap_settings import BootstrapSettings
from infra.ci_bootstrap import _role_specs
from infra.iam import adoption
from infra.managed_repository import ManagedRepository
from pulumi.runtime.stack import wait_for_rpcs
from pulumi.runtime.sync_await import _sync_await

ACCOUNT = "123456789012"
REPO = ManagedRepository(name="bootstrap-infrastructure", default_branch="main")


def settings(environment="test"):
    return replace(
        config.settings,
        repo=REPO.name,
        environment=environment,
        logging_prefix="company",
        replication_region="eu-west-1",
    )


def values(value):
    return value if isinstance(value, list) else [value]


@pytest.mark.parametrize("environment", ["test", "prod"])
def test_live_config_control_ceiling_fits_iam_quota(environment):
    path = Path(__file__).parents[2] / "pulumi" / f"Pulumi.{environment}.yaml"
    raw = yaml.safe_load(path.read_text())["config"]
    public = {
        key.split(":", 1)[1]: value
        for key, value in raw.items()
        if key.startswith("bootstrap-infrastructure:") and not isinstance(value, dict)
    }
    cfg = SimpleNamespace(
        get=public.get,
        get_bool=public.get,
        get_object=public.get,
        get_secret=lambda key: None,
    )
    configured = BootstrapSettings.from_pulumi_config(cfg)
    policy = platform_iam.platform_control_boundary(ACCOUNT, configured, REPO.name)
    assert len(policy) <= 6144
    statements = json.loads(policy)["Statement"]
    assert all(
        "*" not in values(statement["Action"])
        for statement in statements
        if statement["Effect"] == "Allow"
    )
    guard = json.loads(platform_iam.platform_control_state_guard(ACCOUNT, configured))[
        "Statement"
    ]
    assert any(
        statement["Effect"] == "Deny"
        and "iam:DeleteRolePermissionsBoundary" in values(statement["Action"])
        for statement in guard
    )


def test_only_backup_role_has_boundary_conditioned_iam_mutation_grants():
    cfg = settings()
    document = json.loads(automation._automation_policy(ACCOUNT, cfg, REPO.name))
    statements = {item["Sid"]: item for item in document["Statement"]}
    grant = statements["ManageBoundedBackup"]
    assert grant["Resource"] == f"arn:aws:iam::{ACCOUNT}:role/s3-backup-role-test"
    assert grant["Condition"] == {
        "StringEquals": {
            "iam:PermissionsBoundary": (
                f"arn:aws:iam::{ACCOUNT}:policy/PlatformBoundary-backup-test"
            )
        }
    }
    assert statements["DenyControllerIamChanges"]["NotResource"] == [grant["Resource"]]
    assert "ManageBoundedStateReplication" not in statements
    assert "ManageBoundedLogReplication" not in statements
    assert "ManageBootstrapIam" not in statements
    for sid in (
        "PassBootstrapRolesToBackup",
        "PassBootstrapRolesToConfig",
        "PassBootstrapRolesToS3Replication",
    ):
        assert all("*" not in arn for arn in statements[sid]["Resource"])
        assert "iam:PassedToService" in statements[sid]["Condition"]["StringEquals"]


def test_replication_and_backup_caps_are_separate_and_exclude_iam():
    documents = platform_iam.platform_workload_boundaries(
        ACCOUNT, settings(), "eu-central-1", [REPO]
    )
    assert set(documents) == {"state-replication", "log-replication", "backup"}
    for document in documents.values():
        assert len(document) <= 6144
        assert all(
            not action.startswith(("iam:", "sts:"))
            for statement in json.loads(document)["Statement"]
            for action in values(statement["Action"])
        )
    assert "company-central-logs" not in documents["state-replication"]
    assert "pulumi-bootstrap-infrastructure" not in documents["log-replication"]
    backup = json.loads(documents["backup"])["Statement"]
    kms = next(item for item in backup if "kms:Decrypt" in values(item["Action"]))
    aliases = kms["Condition"]["ForAnyValue:StringLike"]["kms:ResourceAliases"]
    assert all("*" not in alias for alias in aliases)
    assert "alias/pulumi-platform-bootstrap-test" in aliases


def test_invalid_names_purposes_and_oversized_boundary_fail_closed():
    with pytest.raises(ValueError, match="Unknown platform"):
        platform_iam.platform_boundary_arn(ACCOUNT, settings(), "admin")
    with pytest.raises(ValueError, match="Invalid platform"):
        platform_iam.platform_role_name(
            replace(settings(), platform_backup_role_name="*"), "backup"
        )
    with pytest.raises(ValueError, match="6144"):
        platform_iam._compact_policy(
            [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "x" * 6144}]
        )


def test_control_boundary_attaches_to_apply_only():
    arn = platform_iam.platform_boundary_arn(ACCOUNT, settings(), "control")
    specs = _role_specs(
        account_id=ACCOUNT,
        partition="aws",
        settings=settings(),
        control_permissions_boundary=arn,
    )
    assert {item.purpose: item.permissions_boundary for item in specs} == {
        "preview": None,
        "apply": arn,
        "drift": None,
    }


@pytest.mark.parametrize("environment", ["test", "prod"])
def test_control_boundary_allows_platform_provider_metadata_with_exact_alias(
    environment,
):
    """Saved-plan preparation describes the existing platform provider key."""
    document = platform_iam.platform_control_boundary(
        ACCOUNT, settings(environment), REPO.name
    )
    grants = [
        item
        for item in json.loads(document)["Statement"]
        if "kms:Decrypt" in values(item["Action"])
    ]
    assert grants == [
        {
            "Effect": "Allow",
            "Action": [
                "kms:Decrypt",
                "kms:Encrypt",
                "kms:GenerateDataKey",
                "kms:DescribeKey",
            ],
            "Resource": f"arn:aws:kms:*:{ACCOUNT}:key/*",
            "Condition": {
                "ForAnyValue:StringEquals": {
                    "kms:ResourceAliases": (
                        f"alias/pulumi-platform-bootstrap-{environment}"
                    )
                }
            },
        }
    ]
    assert len(document) <= 6144


@pytest.mark.parametrize("environment", ["test", "prod"])
@pytest.mark.parametrize("boundary", [False, True])
def test_ci_secret_metadata_scope_and_value_denials(environment, boundary):
    cfg = settings(environment)
    build = (
        platform_iam.platform_control_boundary
        if boundary
        else automation._automation_policy
    )
    statements = json.loads(build(ACCOUNT, cfg, REPO.name))["Statement"]
    allows = [item for item in statements if item["Effect"] == "Allow"]
    denies = [item for item in statements if item["Effect"] == "Deny"]
    prefix = f"arn:aws:secretsmanager:eu-central-1:{ACCOUNT}:secret:/"
    suffixes = (
        ("test", "test-pr") if environment == "test" else ("prod", "prod-preview")
    )
    for suffix in suffixes:
        resource = f"{prefix}{REPO.name}/ci/{suffix}-Ab12Cd"
        for action in ("DescribeSecret", "GetResourcePolicy"):
            qualified = f"secretsmanager:{action}"
            assert any(
                iam_statement_matches(item, qualified, resource) for item in allows
            )
            for foreign in (
                resource.replace(ACCOUNT, "111111111111"),
                resource.replace(REPO.name, "other-infrastructure"),
                resource.replace(f"/ci/{suffix}-", "/runtime/config-"),
                resource.replace(f"/ci/{suffix}-", "/ci/other-"),
            ):
                assert not any(
                    iam_statement_matches(item, qualified, foreign) for item in allows
                )
        for action in ("GetSecretValue", "BatchGetSecretValue"):
            assert any(
                iam_statement_matches(item, f"secretsmanager:{action}", resource)
                for item in denies
            )
        for action in (
            "GetSecretValue",
            "BatchGetSecretValue",
            "PutResourcePolicy",
            "DeleteSecret",
        ):
            assert not any(
                iam_statement_matches(item, f"secretsmanager:{action}", resource)
                for item in allows
            )


def test_ci_secret_resource_compaction_preserves_uncovered_patterns():
    resources = ["prefix-*", "prefix-child-*", "other-*", "exact", "else"]
    assert platform_iam._compact_ci_secret_resources(resources) == [
        "prefix-*",
        "other-*",
        "exact",
        "else",
    ]


@pytest.mark.parametrize("adopt", [False, True])
@pytest.mark.parametrize("manage", [False, True])
def test_operator_components_own_replication_config_and_immutable_policies(
    pulumi_mocks, monkeypatch, adopt, manage
):
    monkeypatch.setattr(automation, "_iam_role_exists", lambda name: True)
    monkeypatch.setattr(
        adoption, "inline_policy_name", lambda role, prefix: prefix + "-abc1234"
    )
    monkeypatch.setattr(adoption, "attachment_exists", lambda role, policy: True)
    start = len(pulumi_mocks.resources)
    cfg = settings()
    boundaries = platform_iam.PlatformIamBoundaries(
        "caps",
        settings=cfg,
        account_id=ACCOUNT,
        region="eu-central-1",
        repositories=[REPO],
        manage_policies=manage,
    )
    platform_iam.PlatformReplicationIam(
        "replica",
        boundary_arns=boundaries.boundary_arns,
        settings=cfg,
        account_id=ACCOUNT,
        region="eu-central-1",
        repositories=[REPO],
        adopt_existing=adopt,
    )
    security_account_controls.ConfigRecorderIam(
        "config-iam",
        settings=cfg,
        account_id=ACCOUNT,
        partition="aws",
        region="eu-central-1",
        adopt_existing=adopt,
    )
    _sync_await(wait_for_rpcs())
    resources = pulumi_mocks.resources[start:]
    policies = [state for typ, _, state in resources if typ == "aws:iam/policy:Policy"]
    assert len(policies) == (4 if manage else 0)
    assert all(len(policy["policy"]) <= 6144 for policy in policies)
    roles = {
        state["name"]: state
        for typ, _, state in resources
        if typ == "aws:iam/role:Role"
    }
    assert set(roles) == {
        "central-logging-replication-role-test",
        "PulumiStateRepl-bootstrap-infrastructure-test",
        "aws-config-recorder-role-test",
    }
    assert roles["central-logging-replication-role-test"][
        "permissionsBoundary"
    ].endswith("log-replication-test")
    assert roles["PulumiStateRepl-bootstrap-infrastructure-test"][
        "permissionsBoundary"
    ].endswith("state-replication-test")
    config_trust = json.loads(
        roles["aws-config-recorder-role-test"]["assumeRolePolicy"]
    )
    assert config_trust["Statement"][0]["Principal"] == {
        "Service": "config.amazonaws.com"
    }


@pytest.mark.parametrize("environment", ["test", "prod"])
@pytest.mark.parametrize("purpose", ["preview", "apply", "drift"])
def test_controller_guard_denies_other_backends_and_foreign_keys(environment, purpose):
    document = json.loads(
        platform_iam.platform_control_state_guard(
            ACCOUNT, settings(environment), purpose=purpose
        )
    )
    statements = {statement["Sid"]: statement for statement in document["Statement"]}
    canonical = (
        f"arn:aws:s3:::pulumi-bootstrap-infrastructure-{environment}-state"
        f"/state/{environment}"
    )
    assert (
        statements["DenyNoncanonicalPlatformState"]["NotResource"] == canonical + "/*"
    )
    foreign = statements["DenyForeignRepositoryKms"]
    assert foreign["Effect"] == "Deny"
    assert foreign["Condition"]["StringNotEquals"] == {
        "aws:ResourceTag/Repository": REPO.name
    }
    assert "kms:TagResource" in foreign["Action"]
    assert "kms:UntagResource" in foreign["Action"]
    assert "kms:PutKeyPolicy" in foreign["Action"]
    if purpose == "apply":
        assert "DenyPreviewCheckpointMutation" not in statements
    else:
        assert (
            statements["DenyPreviewCheckpointMutation"]["NotResource"]
            == canonical + "/.pulumi/locks/*"
        )
        assert statements["DenyPreviewObjectVersionDeletion"]["Resource"] == "*"


def test_unknown_controller_guard_purpose_fails_closed():
    with pytest.raises(ValueError, match="Unknown platform guard purpose"):
        platform_iam.platform_control_state_guard(ACCOUNT, settings(), purpose="admin")


def test_all_ci_controller_roles_receive_immutable_guard(pulumi_mocks, monkeypatch):
    from infra import ci_bootstrap

    monkeypatch.setattr(ci_bootstrap, "_iam_role_exists", lambda name: False)
    start = len(pulumi_mocks.resources)
    component = ci_bootstrap.GitHubCiBootstrap(
        "guarded-ci", args=ci_bootstrap.GitHubCiBootstrapArgs(settings=settings())
    )
    _sync_await(wait_for_rpcs())
    guards = {
        name: state
        for typ, name, state in pulumi_mocks.resources[start:]
        if typ == "aws:iam/rolePolicy:RolePolicy" and name.endswith("-state-guard")
    }
    assert len(guards) == 3
    assert set(component.state_guards) == {"preview", "apply", "drift"}
    for purpose in component.state_guards:
        guard = guards[f"guarded-ci-{purpose}-state-guard"]
        assert (
            guard["role"] == f"GitHubCi{purpose.title()}-bootstrap-infrastructure-test"
        )
        document = json.loads(guard["policy"])
        assert all(item["Effect"] == "Deny" for item in document["Statement"])
        assert {"DenyForeignRepositoryKms", "DenyNoncanonicalPlatformState"} <= {
            item["Sid"] for item in document["Statement"]
        }


def test_boundary_retains_scoped_budget_without_account_wide_budget_grant(monkeypatch):
    cfg = settings()
    source = json.loads(automation._automation_policy(ACCOUNT, cfg, REPO.name))
    source["Statement"] = [
        item
        for item in source["Statement"]
        if item["Sid"] != "ReadAccountBudgetsForEvidence"
    ]
    monkeypatch.setattr(
        automation, "_automation_policy", lambda *args: json.dumps(source)
    )
    document = json.loads(
        platform_iam.platform_control_boundary(ACCOUNT, cfg, REPO.name)
    )
    resources = {
        resource
        for item in document["Statement"]
        for resource in values(item.get("Resource", []))
    }
    assert f"arn:aws:budgets::{ACCOUNT}:budget/*" not in resources
    assert f"arn:aws:budgets::{ACCOUNT}:budget/bootstrap-test-*" in resources


@pytest.mark.parametrize("environment", ["test", "prod"])
def test_backup_v5_bucket_tag_read_is_exact_and_account_bound(environment):
    """AWS managed policy v5 needs tag reads only on this platform's selection."""
    cfg = replace(settings(), environment=environment)
    document = platform_iam.platform_workload_boundaries(
        ACCOUNT, cfg, "eu-central-1", [REPO]
    )["backup"]
    grants = [
        item
        for item in json.loads(document)["Statement"]
        if "s3:ListTagsForResource" in values(item["Action"])
    ]
    assert grants == [
        {
            "Effect": "Allow",
            "Action": "s3:ListTagsForResource",
            "Resource": [
                f"arn:aws:s3:::{cfg.central_logging_bucket_name('eu-central-1')}",
                f"arn:aws:s3:::{cfg.state_bucket_name_for_repo(REPO.name)}",
            ],
            "Condition": {"StringEquals": {"aws:ResourceAccount": ACCOUNT}},
        }
    ]
    assert all("*" not in arn for arn in grants[0]["Resource"])
    assert len(document) <= 6144
