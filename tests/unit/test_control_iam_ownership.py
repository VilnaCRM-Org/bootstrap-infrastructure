"""Single-owner platform control IAM and metadata-only adoption regressions."""

import json
from dataclasses import replace
from types import SimpleNamespace

import pytest
from infra import automation
from infra.ci_config import CiConfiguration, CiConfigurationArgs
from infra.iam import adoption
from infra.iam.github_oidc import GitHubOidcRoles
from infra.platform_control_iam import PlatformControlIam
from infra.repository_catalog import ManagedRepositoryCatalog
from pulumi.runtime.stack import wait_for_rpcs
from pulumi.runtime.sync_await import _sync_await
from test_governance_automation import ACCOUNT, PROVIDER, REPO, inputs

from pulumi import Output


@pytest.fixture
def allocations(pulumi_mocks, monkeypatch):
    """Separate managed custom resources from read-only get() references."""
    records = []
    original = pulumi_mocks.new_resource

    def record(args):
        records.append(args)
        return original(args)

    monkeypatch.setattr(pulumi_mocks, "new_resource", record)
    return records


def managed(records, prefix):
    return [r for r in records if r.typ.startswith(prefix) and bool(r.inputs)]


def test_ci_config_reference_mode_never_registers_secret_or_iam_writes(allocations):
    component = CiConfiguration(
        "read-ci",
        args=CiConfigurationArgs(
            settings=inputs().settings,
            oidc_provider_arn=PROVIDER,
            manage_resources=False,
        ),
    )
    _sync_await(wait_for_rpcs())
    assert set(component.read_roles) == {"test-pr", "test"}
    assert component.read_policies == {}
    assert not managed(allocations, "aws:")
    assert {
        r.resource_id for r in allocations if r.typ.startswith("aws:secretsmanager/")
    } == {
        "arn:aws:secretsmanager:us-east-1:123456789012:secret:"
        "/bootstrap-infrastructure/ci/test-pr-example",
        "arn:aws:secretsmanager:us-east-1:123456789012:secret:"
        "/bootstrap-infrastructure/ci/test-example",
    }


@pytest.mark.parametrize("configured_provider", [True, False])
def test_platform_oidc_references_exact_roles_without_policy_mutation(
    allocations, configured_provider
):
    settings = replace(
        inputs().settings,
        github_oidc_provider_arn=PROVIDER if configured_provider else None,
    )
    component = GitHubOidcRoles(
        "read-oidc",
        settings=settings,
        repositories=[REPO],
        manage_provider=False,
        manage_roles=False,
        secrets_key_arns={},
    )
    _sync_await(wait_for_rpcs())
    assert set(component.deploy_role_arns) == {REPO.name}
    assert not managed(allocations, "aws:iam/")
    assert any(r.resource_id == PROVIDER for r in allocations)


def test_operator_oidc_imports_provider_and_caps_legacy_deploy_role(
    allocations, monkeypatch
):
    monkeypatch.setattr(
        adoption, "inline_policy_name", lambda role, prefix: prefix + "-old"
    )
    GitHubOidcRoles(
        "github-oidc",
        settings=inputs().settings,
        repositories=[REPO],
        secrets_key_arns={REPO.name: f"arn:aws:kms:eu-central-1:{ACCOUNT}:key/current"},
        manage_provider=True,
        permissions_boundary="control-boundary",
        adopt_existing_policies=True,
    )
    _sync_await(wait_for_rpcs())
    providers = managed(allocations, "aws:iam/openIdConnectProvider:")
    assert len(providers) == 1
    roles = managed(allocations, "aws:iam/role:")
    assert roles[0].inputs["permissionsBoundary"] == "control-boundary"
    policies = managed(allocations, "aws:iam/rolePolicy:")
    assert policies[0].inputs["name"].endswith("-old")


def test_platform_automation_keeps_ecr_but_only_reads_control_roles(allocations):
    component = automation.GitHubAutomation(
        "github-automation",
        settings=inputs().settings,
        oidc_provider_arn=PROVIDER,
        manage_roles=False,
    )
    _sync_await(wait_for_rpcs())
    assert not managed(allocations, "aws:iam/")
    assert len(managed(allocations, "aws:ecr/repository:")) == 1
    assert len(managed(allocations, "aws:ecr/lifecyclePolicy:")) == 1
    assert component.policy_dependencies == []
    assert component.policies == []
    assert component.policy is None


@pytest.mark.parametrize("existing", [False, True])
def test_operator_automation_adopts_control_policies_without_creating_ecr(
    allocations, monkeypatch, existing
):
    monkeypatch.setattr(
        adoption,
        "inline_policy_name",
        lambda role, prefix: prefix if existing else None,
    )
    monkeypatch.setattr(adoption, "attachment_exists", lambda role, arn: existing)
    monkeypatch.setattr(automation, "_aws_lookup_exists", lambda *a, **kw: existing)
    component = automation.GitHubAutomation(
        "github-automation",
        settings=inputs("prod").settings,
        oidc_provider_arn=PROVIDER,
        manage_repository=False,
        permissions_boundary="control-boundary",
        adopt_existing_policies=True,
    )
    _sync_await(wait_for_rpcs())
    assert not managed(allocations, "aws:ecr/")
    assert component.repository is None
    roles = managed(allocations, "aws:iam/role:")
    assert len(roles) == 2
    assert any(r.inputs.get("permissionsBoundary") == "control-boundary" for r in roles)
    assert component.policy_dependencies


@pytest.mark.parametrize("environment", ["test", "prod"])
@pytest.mark.parametrize("repo_name", [REPO.name, "automation"])
def test_operator_composition_uses_existing_kms_and_separates_test_triage(
    allocations, monkeypatch, environment, repo_name
):
    import infra.platform_control_iam as module

    repo = replace(REPO, name=repo_name)
    monkeypatch.setattr(
        module.platform_iam,
        "platform_control_state_guard",
        lambda account, settings, **kw: json.dumps({"Statement": []}),
    )
    calls = {}
    key_arn = f"arn:aws:kms:eu-central-1:{ACCOUNT}:key/current"
    monkeypatch.setattr(
        module.aws.kms,
        "get_alias",
        lambda **kw: SimpleNamespace(target_key_arn=key_arn),
    )

    def oidc(name, **kwargs):
        calls["oidc"] = (name, kwargs)
        kwargs["role_guard_factory"](repo.name, SimpleNamespace(name="deploy"))
        return SimpleNamespace(
            deploy_role_arns={
                repo.name: Output.from_input("arn:aws:iam::123456789012:role/deploy")
            }
        )

    def automate(name, **kwargs):
        calls["automation"] = (name, kwargs)
        kwargs["role_guard_factory"](SimpleNamespace(name="automation"))
        return SimpleNamespace(
            role=SimpleNamespace(arn="automation-arn", name="automation"),
            operations_alert_triage_role=SimpleNamespace(arn="triage-arn"),
        )

    def config(name, **kwargs):
        calls["config"] = (name, kwargs)
        return SimpleNamespace(role=SimpleNamespace(arn="config-arn"))

    monkeypatch.setattr(module, "GitHubOidcRoles", oidc)
    monkeypatch.setattr(module, "GitHubAutomation", automate)
    monkeypatch.setattr(module, "ConfigRecorderIam", config)
    monkeypatch.setattr(
        module,
        "PlatformReplicationIam",
        lambda name, **kw: (
            calls.setdefault("replication", (name, kw))
            and SimpleNamespace(roles={"logs": SimpleNamespace(arn="replication-arn")})
        ),
    )
    component = PlatformControlIam(
        "operator",
        settings=replace(inputs(environment).settings, repo=repo.name),
        repositories=ManagedRepositoryCatalog([repo]).repositories,
        account_id=ACCOUNT,
        partition="aws",
        region="eu-central-1",
        provider_arn=PROVIDER,
        boundary_arns={
            "control": "control-boundary",
            "state-replication": "state-boundary",
            "log-replication": "log-boundary",
        },
    )
    _sync_await(wait_for_rpcs())
    assert set(component.state_guards) == {("automation", ""), ("deploy", repo.name)}
    guard_names = {
        r.name
        for r in managed(allocations, "aws:iam/rolePolicy:")
        if r.inputs.get("name") == "PlatformControlStateGuard"
    }
    suffix = "deploy:automation" if repo.name == "automation" else repo.name
    assert guard_names == {
        "operator-automation-state-guard",
        f"operator-{suffix}-state-guard",
    }
    assert calls["oidc"][1]["secrets_key_arns"] == {repo.name: key_arn}
    assert calls["oidc"][1]["manage_provider"] is False
    assert calls["automation"][0] == "github-automation"
    assert calls["automation"][1]["manage_repository"] is False
    assert calls["automation"][1]["manage_triage"] is (environment == "prod")
    assert calls["config"][1]["adopt_existing"] is True
    assert calls["replication"][1]["adopt_existing"] is True


@pytest.mark.parametrize(
    "names,expected",
    [([], None), (["policy"], "policy"), (["unrelated", "policy-abc"], "policy-abc")],
)
def test_inline_adoption_uses_exact_names_or_legacy_generated_suffix(
    monkeypatch, names, expected
):
    monkeypatch.setattr(adoption, "_role_metadata", lambda *a: names)
    assert adoption.inline_policy_name("role", "policy") == expected


def test_inline_adoption_rejects_ambiguous_existing_names(monkeypatch):
    monkeypatch.setattr(adoption, "_role_metadata", lambda *a: ["policy", "policy-old"])
    with pytest.raises(ValueError, match="Ambiguous"):
        adoption.inline_policy_name("role", "policy")


@pytest.mark.parametrize("arn,expected", [("own", True), ("other", False)])
def test_attachment_adoption_never_matches_another_policy(monkeypatch, arn, expected):
    monkeypatch.setattr(adoption, "_role_metadata", lambda *a: [{"PolicyArn": "own"}])
    assert adoption.attachment_exists("role", arn) is expected


@pytest.mark.parametrize(
    "code,stderr",
    [(0, ""), (1, "An error occurred (NoSuchEntity)"), (1, "AccessDenied")],
)
def test_metadata_adoption_fails_closed_for_unexpected_errors(
    monkeypatch, code, stderr
):
    commands = []
    monkeypatch.setattr(adoption, "_assert_cli_account", lambda: None)

    def command(args, **kwargs):
        commands.append(args)
        return SimpleNamespace(
            returncode=code,
            stderr=stderr,
            stdout=json.dumps({"PolicyNames": ["policy"]}),
        )

    monkeypatch.setattr(adoption.subprocess, "run", command)
    if stderr == "AccessDenied":
        with pytest.raises(RuntimeError, match="metadata failed"):
            adoption._role_metadata("list-role-policies", "role", "PolicyNames")
    else:
        assert adoption._role_metadata("list-role-policies", "role", "PolicyNames") == (
            [] if code else ["policy"]
        )
    assert commands == [
        ["aws", "iam", "list-role-policies", "--role-name", "role", "--output", "json"]
    ]


@pytest.mark.parametrize("code,actual", [(0, ACCOUNT), (0, "999999999999"), (1, "")])
def test_cli_adoption_cannot_cross_the_provider_account(monkeypatch, code, actual):
    monkeypatch.setattr(
        adoption.aws, "get_caller_identity", lambda: SimpleNamespace(account_id=ACCOUNT)
    )
    calls = []

    def command(args, **kwargs):
        calls.append(args)
        return SimpleNamespace(returncode=code, stdout=actual)

    monkeypatch.setattr(adoption.subprocess, "run", command)
    if code or actual != ACCOUNT:
        with pytest.raises(RuntimeError, match="account does not match"):
            adoption._assert_cli_account()
    else:
        adoption._assert_cli_account()
    assert calls == [
        ["aws", "sts", "get-caller-identity", "--query", "Account", "--output", "text"]
    ]


@pytest.mark.parametrize("environment", ["test", "prod"])
def test_complete_operator_control_graph_has_only_iam_ownership(
    allocations, monkeypatch, tmp_path, environment
):
    """The composed operator must not acquire buckets, keys, or workload ownership."""
    import infra.platform_control_iam as module
    from pulumi.runtime import settings as runtime_settings

    monitor = runtime_settings.get_monitor()
    registrations = {}
    register = monitor.RegisterResource

    def record_parent(request):
        registrations[request.name] = (request.type, request.parent)
        return register(request)

    monkeypatch.setattr(monitor, "RegisterResource", record_parent)

    def canonical_urn(name):
        resource_type, parent = registrations[name]
        if parent:
            parent_name = parent.split("::")[-1]
            parent_type = canonical_urn(parent_name).split("::")[2]
            if parent_type != "pulumi:pulumi:Stack":
                resource_type = parent_type + "$" + resource_type
        return f"urn:pulumi:{{stack}}::{{project}}::{resource_type}::{name}"

    settings = replace(inputs(environment).settings, org="VilnaCRM-Org")
    repository = replace(REPO, name="bootstrap-infrastructure", project="bootstrap")
    monkeypatch.setattr(
        module.aws.kms,
        "get_alias",
        lambda **kw: SimpleNamespace(
            target_key_arn=f"arn:aws:kms:eu-central-1:{ACCOUNT}:key/current"
        ),
    )
    monkeypatch.setattr(adoption, "inline_policy_name", lambda role, prefix: prefix)
    monkeypatch.setattr(adoption, "attachment_exists", lambda role, arn: True)
    monkeypatch.setattr(automation, "_aws_lookup_exists", lambda *a, **kw: True)
    preferred = {
        settings.automation_role_name(settings.repo): {
            "github-automation-policy": "github-automation-policy"
        },
        "PulumiDeploy-bootstrap-infrastructure": {
            "github-oidc-policy-bootstrap-infrastructure": (
                "github-oidc-policy-bootstrap-infrastructure-selected"
            )
        },
    }
    monkeypatch.setattr(
        adoption,
        "inline_policy_name",
        lambda role, prefix, **kw: kw.get("preferred_name", prefix),
    )
    PlatformControlIam(
        "platform-control-iam",
        settings=settings,
        repositories=[repository],
        account_id=ACCOUNT,
        partition="aws",
        region="eu-central-1",
        provider_arn=PROVIDER,
        boundary_arns={
            "control": "control-boundary",
            "state-replication": "state-boundary",
            "log-replication": "log-boundary",
        },
        inline_policy_names=preferred,
    )
    _sync_await(wait_for_rpcs())
    customs = managed(allocations, "aws:")
    assert customs
    assert all(record.typ.startswith("aws:iam/") for record in customs)
    assert not managed(allocations, "aws:iam/openIdConnectProvider:")
    guards = [
        record
        for record in managed(allocations, "aws:iam/rolePolicy:")
        if record.inputs.get("name") == "PlatformControlStateGuard"
    ]
    assert len(guards) == 2
    for guard in guards:
        statements = {
            item["Sid"]: item
            for item in json.loads(guard.inputs["policy"])["Statement"]
        }
        assert statements["DenyNoncanonicalPlatformState"]["Effect"] == "Deny"
        assert statements["DenyForeignRepositoryKms"]["Effect"] == "Deny"
        assert f"/state/{environment}/*" in str(
            statements["DenyNoncanonicalPlatformState"]["NotResource"]
        )
    assert any("PulumiAutomation" in record.inputs["role"] for record in guards)
    assert any("PulumiDeploy" in record.inputs["role"] for record in guards)
    role_names = {
        record.inputs["name"] for record in managed(allocations, "aws:iam/role:")
    }
    assert any("PulumiAutomation" in name for name in role_names)
    assert any("PulumiDeploy" in name for name in role_names)
    assert any("config-recorder" in name for name in role_names)
    assert len(managed(allocations, "aws:iam/role:")) == (
        6 if environment == "prod" else 5
    )
    # Resource names/URNs are safe migration-review metadata; never persist policies.
    records_by_name = {record.name: record for record in customs}
    metadata = []
    for name, record in records_by_name.items():
        parent = registrations[name][1]
        metadata.append(
            {
                "target_urn_template": canonical_urn(name),
                "parent_urn_template": canonical_urn(parent.split("::")[-1]),
                "type": record.typ,
                "logical_name": record.name,
                "physical_name": record.inputs.get("name"),
                "role": record.inputs.get("role"),
                "policy_arn": record.inputs.get("policyArn"),
            }
        )
    assert all(
        "bootstrap:iam:PlatformControlIam$" in item["target_urn_template"]
        for item in metadata
    )
    (tmp_path / f"operator-control-{environment}.json").write_text(
        json.dumps(
            {
                "environment": environment,
                "provenance": ("mock graph; inline policy names omit live suffixes"),
                "resources": sorted(
                    metadata, key=lambda item: item["target_urn_template"]
                ),
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


@pytest.mark.parametrize(
    "preferred,valid",
    [
        ("policy", True),
        ("policy-old", True),
        ("other", False),
        ("policy-absent", False),
    ],
)
def test_explicit_policy_pin_must_match_prefix_and_exist(monkeypatch, preferred, valid):
    monkeypatch.setattr(adoption, "_role_metadata", lambda *a: ["policy", "policy-old"])
    if valid:
        assert (
            adoption.inline_policy_name("role", "policy", preferred_name=preferred)
            == preferred
        )
    else:
        with pytest.raises(ValueError, match="Preferred inline policy"):
            adoption.inline_policy_name("role", "policy", preferred_name=preferred)


@pytest.mark.parametrize(
    "configured",
    [
        [],
        {"foreign-role": {}},
        {"PulumiAutomation-bootstrap-infrastructure-test": []},
        {
            "PulumiAutomation-bootstrap-infrastructure-test": {
                "foreign-prefix": "policy"
            }
        },
        {
            "PulumiAutomation-bootstrap-infrastructure-test": {
                "github-automation-policy": None
            }
        },
        {
            "PulumiAutomation-bootstrap-infrastructure-test": {
                "github-automation-policy": ""
            }
        },
    ],
)
def test_policy_override_rejects_unreviewed_inventory(configured):
    from infra.platform_control_iam import _inline_policy_overrides

    with pytest.raises(ValueError, match="Inline policy"):
        _inline_policy_overrides(inputs().settings, [REPO], configured)


def test_platform_ci_secret_missing_metadata_never_creates_resource(
    allocations, monkeypatch
):
    import infra.ci_config as module

    monkeypatch.setattr(module, "_secret_import_id", lambda name: None)
    with pytest.raises(ValueError, match="Required operator-managed CI secret"):
        CiConfiguration(
            "missing-ci",
            args=CiConfigurationArgs(
                settings=inputs().settings,
                oidc_provider_arn=PROVIDER,
                manage_resources=False,
            ),
        )
    _sync_await(wait_for_rpcs())
    assert not managed(allocations, "aws:")
