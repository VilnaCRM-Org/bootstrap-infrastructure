"""Cubic findings retain repository boundaries, conditions and physical names."""

import json
from dataclasses import replace
from types import SimpleNamespace

import pytest
from controller_fixtures import ACCOUNT, PROVIDER, REPO, inputs
from infra import automation, ci_bootstrap, governance_automation, platform_iam
from infra.ci_config import (
    _ci_config_project,
    _ci_config_read_role_name,
    _ci_secret_suffixes,
)
from infra.platform_control_iam import PlatformControlIam
from pulumi.runtime.stack import wait_for_rpcs
from pulumi.runtime.sync_await import _sync_await
from test_governance_automation import inputs as governor_inputs


def test_platform_rejects_service_repository_before_any_allocation(monkeypatch):
    monkeypatch.setattr(
        platform_iam.pulumi.ComponentResource,
        "__init__",
        lambda *a, **kw: pytest.fail("must validate before allocation"),
    )
    with pytest.raises(ValueError, match="primary bootstrap"):
        PlatformControlIam(
            "invalid",
            settings=inputs().settings,
            repositories=[REPO],
            account_id=ACCOUNT,
            region="eu-central-1",
            provider_arn=PROVIDER,
            partition="aws",
            boundary_arns={},
        )


@pytest.mark.parametrize(
    "repo_name,logical_suffix",
    [("logs", "state:logs"), ("bootstrap-infrastructure", "bootstrap-infrastructure")],
)
def test_replication_namespaces_preserve_existing_urns_without_logs_collision(
    pulumi_mocks, monkeypatch, repo_name, logical_suffix
):
    records = []
    original = pulumi_mocks.new_resource

    def record(args):
        records.append(args)
        return original(args)

    monkeypatch.setattr(pulumi_mocks, "new_resource", record)
    component = platform_iam.PlatformReplicationIam(
        "replication",
        settings=inputs().settings,
        repositories=[replace(REPO, name=repo_name)],
        account_id=ACCOUNT,
        region="eu-central-1",
        boundary_arns={
            "state-replication": "state-boundary",
            "log-replication": "log-boundary",
        },
    )
    _sync_await(wait_for_rpcs())
    assert set(component.namespaced_roles) == {("logs", ""), ("state", repo_name)}
    roles = [r for r in records if r.typ == "aws:iam/role:Role"]
    assert {r.name for r in roles} == {
        "replication-logs-role",
        f"replication-{logical_suffix}-role",
    }
    assert len({r.inputs["name"] for r in roles}) == 2


def test_boundary_group_does_not_discard_service_conditions():
    statement = {
        "Effect": "Allow",
        "Resource": ["arn:aws:ce::123456789012:anomalymonitor/*"],
        "Action": ["ce:DeleteAnomalyMonitor"],
        "Condition": {"StringEquals": {"aws:ResourceTag/Environment": "test"}},
    }
    assert (
        platform_iam._boundary_statement_group(statement, statement["Action"])
        == "sensitive"
    )


def test_backup_mutation_compaction_retains_trust_update_and_boundary_condition():
    condition = {"StringEquals": {"iam:PermissionsBoundary": "exact-backup-boundary"}}
    statement = {
        "Effect": "Allow",
        "Action": platform_iam.ROLE_MUTATIONS,
        "Resource": "backup-role",
        "Condition": condition,
    }
    platform_iam._compress_sensitive_statements([statement])
    assert "iam:UpdateAssumeRolePolicy" in statement["Action"]
    assert statement["Condition"] == condition


def test_triage_is_bound_to_ordinary_workflow_name():
    document = json.loads(
        automation._operations_alert_triage_assume_role_policy(
            PROVIDER, "test-org", "bootstrap-infrastructure", "main"
        )
    )
    equals = document["Statement"][0]["Condition"]["StringEquals"]
    assert (
        equals["token.actions.githubusercontent.com:workflow"]
        == "Operations Alert Issue Triage"
    )
    assert "token.actions.githubusercontent.com:job_workflow_ref" not in equals


def test_state_replication_invokes_inherit_the_component_provider(monkeypatch):
    from infra import pulumi_state

    import pulumi

    component = pulumi.ComponentResource("test:iam:Parent", "provider-parent")
    component._manage_replication_role = True
    component._replication_permissions_boundary = None
    component._settings = inputs().settings
    calls = []
    role_args = {}
    policy_args = {}

    def identity(*, opts):
        calls.append(opts)
        return SimpleNamespace(account_id="999999999999")

    def partition(*, opts):
        calls.append(opts)
        return SimpleNamespace(partition="aws-cn")

    def role(logical_name, **kwargs):
        role_args.update(kwargs)
        return SimpleNamespace(id=pulumi.Output.from_input(logical_name))

    monkeypatch.setattr(pulumi_state.aws, "get_caller_identity", identity)
    monkeypatch.setattr(pulumi_state.aws, "get_partition", partition)
    monkeypatch.setattr(pulumi_state.aws.iam, "Role", role)
    monkeypatch.setattr(
        pulumi_state.aws.iam, "RolePolicy", lambda *a, **kw: policy_args.update(kw)
    )
    pulumi_state.PulumiStateBuckets._create_replication_role(
        component,
        "state",
        repo=REPO,
        suffix="service",
        role_suffix="service",
        bucket=SimpleNamespace(arn=pulumi.Output.from_input("arn:aws-cn:s3:::state")),
        replica_bucket=SimpleNamespace(
            arn=pulumi.Output.from_input("arn:aws-cn:s3:::replica")
        ),
    )
    _sync_await(wait_for_rpcs())
    _sync_await(role_args["assume_role_policy"].future())
    _sync_await(policy_args["policy"].future())
    _sync_await(policy_args["role"].future())
    assert len(calls) == 2
    assert all(options.parent is component for options in calls)
    assert role_args["permissions_boundary"].startswith("arn:aws-cn:iam::999999999999:")
    assert role_args["opts"].parent is component


def test_backup_boundary_uses_shared_alias_sanitization():
    configured = inputs().settings
    repository = replace(REPO, name="Mixed.Case")
    document = json.loads(
        platform_iam.platform_workload_boundaries(
            ACCOUNT, configured, "eu-central-1", [repository]
        )["backup"]
    )
    aliases = [
        statement["Condition"]["ForAnyValue:StringLike"]["kms:ResourceAliases"]
        for statement in document["Statement"]
        if "ForAnyValue:StringLike" in statement.get("Condition", {})
    ]
    assert len(aliases) == 1
    assert configured.pulumi_secrets_alias_name_for_repo(repository.name) in aliases[0]
    assert not any("Mixed.Case" in alias for alias in aliases[0])


def test_managed_platform_ci_controls_are_protected():
    from infra.bootstrap_infrastructure import _create_ci_config

    captured = {}

    def build(name, *, args, opts):
        captured.update(name=name, args=args, opts=opts)

    _create_ci_config(
        bootstrap=SimpleNamespace(
            oidc=SimpleNamespace(provider=SimpleNamespace(arn=PROVIDER)),
            manage_control_resources=True,
        ),
        dependencies=SimpleNamespace(ci_config_cls=build),
        settings=inputs().settings,
        opts=None,
    )
    assert captured["args"].protect_resources is True
    assert captured["args"].manage_resources is True


def test_unconditioned_ce_read_cannot_override_tagged_mutation_ceiling():
    statements, service_actions, _, global_actions = (
        platform_iam._boundary_source_groups(
            {
                "Statement": [
                    {
                        "Sid": "ReadCostMonitor",
                        "Effect": "Allow",
                        "Action": ["ce:GetAnomalyMonitors"],
                        "Resource": [f"arn:aws:ce::{ACCOUNT}:anomalymonitor/*"],
                    }
                ]
            }
        )
    )
    assert "ce:*" not in service_actions | global_actions
    assert statements[0]["Action"] == ["ce:GetAnomalyMonitors"]


@pytest.mark.parametrize("environment", ["test", "prod"])
def test_governor_config_role_names_match_creator_for_long_projects(environment):
    args = governor_inputs(environment)
    longest_suffix = max(_ci_secret_suffixes(environment), key=len)
    project_length = 64 - len(f"GitHubCiConfigRead--{longest_suffix}")
    repo = replace(REPO, name="a" * project_length)
    roles, _ = governance_automation._role_resources(args, repo)
    project = _ci_config_project(args.settings, repo.name)
    creator_suffixes = _ci_secret_suffixes(args.settings.environment)
    assert creator_suffixes == ci_bootstrap._ci_secret_suffixes(args.settings)
    expected = set()
    for suffix in creator_suffixes:
        name = _ci_config_read_role_name(args.settings, suffix, project)
        assert len(name) <= 64
        expected.add(f"arn:aws:iam::{ACCOUNT}:role/{name}")
    assert {arn for arn in roles if ":role/GitHubCiConfigRead-" in arn} == expected


def test_governor_alias_operations_keep_target_key_conditions():
    document = json.loads(
        governance_automation.governance_repo_storage_policy(
            governor_inputs(), REPO, apply=True
        )
    )
    for action in ("kms:CreateAlias", "kms:UpdateAlias", "kms:DeleteAlias"):
        statements = [s for s in document["Statement"] if action in s["Action"]]
        alias = next(s for s in statements if ":alias/" in str(s["Resource"]))
        key = next(s for s in statements if ":key/" in str(s["Resource"]))
        assert "Condition" not in alias
        assert key["Condition"]["StringEquals"] == {
            "aws:ResourceTag/Repository": REPO.name,
            "aws:ResourceTag/Environment": "test",
            "aws:ResourceTag/Purpose": "pulumi-secrets",
        }


def test_governor_rejects_config_role_names_that_cannot_be_created():
    with pytest.raises(ValueError, match="config read role name"):
        governance_automation._role_resources(
            governor_inputs(), replace(REPO, name="a" * 42)
        )


def test_governor_cannot_retag_key_into_another_ownership_scope():
    document = json.loads(
        governance_automation.governance_repo_storage_policy(
            governor_inputs(), REPO, apply=True
        )
    )
    tag = next(s for s in document["Statement"] if s["Action"] == ["kms:TagResource"])
    assert tag["Condition"]["StringEquals"] == {
        "aws:ResourceTag/Repository": REPO.name,
        "aws:ResourceTag/Environment": "test",
        "aws:ResourceTag/Purpose": "pulumi-secrets",
        "aws:RequestTag/Repository": REPO.name,
    }
    assert tag["Condition"]["StringEqualsIfExists"] == {
        "aws:RequestTag/Environment": "test",
        "aws:RequestTag/Purpose": "pulumi-secrets",
    }
    assert not any("kms:UntagResource" in s["Action"] for s in document["Statement"])
