"""The operator references pinned enrollment without changing resource ownership."""

import importlib
import runpy
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from infra import ManagedRepositoryCatalog, governance_automation, platform_iam
from pulumi.runtime.stack import wait_for_rpcs
from pulumi.runtime.sync_await import _sync_await
from seed import policy_registry
from test_governance_automation import inputs


@pytest.mark.parametrize("environment", ["test", "prod"])
def test_platform_seed_mode_registers_only_existing_component(
    pulumi_mocks, environment
):
    account = policy_registry.ACCOUNTS[environment]
    start = len(pulumi_mocks.resources)
    component = platform_iam.PlatformIamBoundaries(
        "platform-iam-boundaries",
        settings=inputs(environment).settings,
        account_id=account,
        region="eu-central-1",
        repositories=[],
        manage_policies=False,
    )
    _sync_await(wait_for_rpcs())
    assert [(kind, name) for kind, name, _ in pulumi_mocks.resources[start:]] == [
        ("bootstrap:iam:PlatformIamBoundaries", "platform-iam-boundaries")
    ]
    assert component.policies == {}
    assert component.boundary_arns == {
        purpose: (
            f"arn:aws:iam::{account}:policy/PlatformBoundary-{purpose}-{environment}"
        )
        for purpose in ("control", "backup", "state-replication", "log-replication")
    }
    catalog = policy_registry.load_catalog(environment)
    assert all(
        catalog["policies"][arn]["ownership"]
        == "existing_operator_policy_transfer_to_seed"
        for arn in component.boundary_arns.values()
    )


@pytest.mark.parametrize("environment", ["test", "prod"])
@pytest.mark.parametrize("mismatch", [None, "account", "region", "partition"])
def test_entrypoint_uses_actual_pinned_seed_bindings(
    monkeypatch, environment, mismatch
):
    catalog = policy_registry.load_catalog(environment)
    account = "111122223333" if mismatch == "account" else catalog["account_id"]
    settings = replace(
        inputs(environment).settings,
        github_repository_id="1098568429",
        github_repository_owner_id="114362548",
    )
    values = {
        "awsAccountId": account,
        "githubRepositoryId": settings.github_repository_id,
        "githubRepositoryOwnerId": settings.github_repository_owner_id,
    }
    config = SimpleNamespace(
        require=values.__getitem__,
        get=values.get,
        get_bool=values.get,
        get_object=values.get,
    )
    allocations = {}
    bootstrap = SimpleNamespace(
        oidc_provider_arn=catalog["operator_bindings"]["oidc"],
        ci_configuration=SimpleNamespace(secret_ids={}, read_role_arns={}),
        role_arns={},
        operations_alert_triage_role=None,
        github_variables={},
        secret_payload_keys={},
        secret_versions={},
    )

    def allocate(name, **kwargs):
        allocations[name] = kwargs
        if name == "github-ci-bootstrap":
            return bootstrap
        return SimpleNamespace(
            github_variables={},
            boundary_arns={
                purpose: platform_iam.platform_boundary_arn(account, settings, purpose)
                for purpose in platform_iam.PURPOSES
            },
        )

    modules = {
        "pulumi": SimpleNamespace(
            Config=lambda: config,
            ResourceOptions=lambda **kw: kw,
            export=lambda *args: None,
        ),
        "pulumi_aws": SimpleNamespace(
            get_caller_identity=lambda: SimpleNamespace(account_id=account),
            get_region=lambda: SimpleNamespace(
                region="us-east-1" if mismatch == "region" else "eu-central-1"
            ),
            get_partition=lambda: SimpleNamespace(
                partition="aws-cn" if mismatch == "partition" else "aws"
            ),
        ),
        "infra": SimpleNamespace(
            BootstrapSettings=SimpleNamespace(from_pulumi_config=lambda _: settings),
            GitHubCiBootstrap=allocate,
            GitHubCiBootstrapArgs=lambda **kw: kw,
            ManagedRepositoryCatalog=ManagedRepositoryCatalog,
        ),
        "infra.governance_automation": SimpleNamespace(
            assert_bootstrap_account=governance_automation.assert_bootstrap_account,
            GovernanceAutomation=allocate,
            GovernanceAutomationArgs=lambda **kw: kw,
        ),
        "infra.platform_iam": SimpleNamespace(PlatformIamBoundaries=allocate),
        "infra.platform_control_iam": SimpleNamespace(PlatformControlIam=allocate),
        "seed.policy_registry": policy_registry,
    }
    monkeypatch.setattr(importlib, "import_module", modules.__getitem__)
    entrypoint = (
        Path(__file__).resolve().parents[2] / "pulumi/github-ci-bootstrap/__main__.py"
    )
    if mismatch:
        with pytest.raises(
            ValueError, match="account mismatch|region/partition mismatch"
        ):
            runpy.run_path(str(entrypoint))
        assert allocations == {}
        return
    runpy.run_path(str(entrypoint))
    expected = {
        row["arn"].rsplit("/", 1)[-1]: row["boundary_arn"]
        for row in catalog["principals"]
        if row["owner_project"] == "github-ci-bootstrap"
        and row["boundary_arn"] is not None
    }
    assert expected
    bootstrap_args = allocations["github-ci-bootstrap"]["args"]
    governor_args = allocations["governance-automation"]["args"]
    assert bootstrap_args["external_role_boundaries"] == expected
    assert governor_args["external_role_boundaries"] == expected
    assert bootstrap_args["manage_oidc_provider"] is False
    assert allocations["platform-iam-boundaries"]["manage_policies"] is False
    assert governor_args["manage_service_boundaries"] is False
    assert (
        bootstrap_args["control_permissions_boundary"]
        == expected[f"GitHubCiApply-bootstrap-infrastructure-{environment}"]
    )
    assert all("aws-config-recorder" not in name for name in expected)
    assert all("user-service" not in name for name in expected)
    assert len(allocations["github-ci-bootstrap"]["opts"]["depends_on"]) == 1
    assert len(allocations["platform-control-iam"]["opts"]["depends_on"]) == 2
