"""Role constructors retain explicit independent boundaries without owning them."""

from dataclasses import replace

import pytest
from infra import ci_bootstrap, ci_config, governance_automation
from infra.iam import github_oidc
from infra.utils.outputs import future_output
from pulumi.runtime.stack import wait_for_rpcs
from pulumi.runtime.sync_await import _sync_await
from test_components import _ci_bootstrap_settings
from test_governance_automation import inputs

import pulumi

ACCOUNT = "123456789012"
BOUNDARY = f"arn:aws:iam::{ACCOUNT}:policy/issue215-seed/test/ceiling/example"


def resolve(mapping, *, existing=None, partition="aws"):
    """Exercise the common explicit-boundary agreement check."""
    return ci_config._role_permissions_boundary(
        "Role",
        account_id=ACCOUNT,
        partition=partition,
        external_role_boundaries=mapping,
        existing_boundary=existing,
    )


@pytest.mark.parametrize("existing", [None, BOUNDARY, "legacy-unchecked-boundary"])
def test_absent_map_preserves_existing_library_behavior(existing):
    assert resolve(None, existing=existing) is existing


@pytest.mark.parametrize("existing", [None, BOUNDARY])
def test_complete_map_accepts_same_boundary_and_unrelated_role_entries(existing):
    assert (
        resolve({"Role": BOUNDARY, "OtherConstructorRole": "unused"}, existing=existing)
        == BOUNDARY
    )


@pytest.mark.parametrize(
    "mapping",
    [
        {},
        {"role": BOUNDARY},
        {"Role": None},
        {"Role": 42},
        {"Role": ""},
        {"Role": BOUNDARY.replace(ACCOUNT, "999999999999")},
        {"Role": BOUNDARY.replace(ACCOUNT, "aws")},
        {"Role": BOUNDARY.replace(":policy/", ":role/")},
        {"Role": BOUNDARY.replace("arn:aws:", "arn:aws-us-gov:")},
        {"Role": BOUNDARY + "/*"},
        {"Role": BOUNDARY + "?"},
        {"Role": BOUNDARY + "/"},
        {"Role": BOUNDARY + "\n"},
    ],
)
def test_incomplete_or_invalid_map_fails_closed(mapping):
    with pytest.raises(ValueError, match="Missing or invalid external boundary"):
        resolve(mapping)


def test_exact_other_partition_is_allowed_only_when_explicitly_selected():
    boundary = BOUNDARY.replace("arn:aws:", "arn:aws-us-gov:")
    assert resolve({"Role": boundary}, partition="aws-us-gov") == boundary


def test_conflicting_explicit_boundary_rejected():
    with pytest.raises(ValueError, match="Conflicting external boundary"):
        resolve({"Role": BOUNDARY}, existing=BOUNDARY + "-conflict")


@pytest.mark.parametrize("matches", [True, False])
def test_output_boundary_must_agree_when_resolved(pulumi_mocks, matches):
    current = pulumi.Output.from_input(BOUNDARY if matches else BOUNDARY + "-conflict")
    assert resolve(None, existing=current) is current
    output = resolve({"Role": BOUNDARY}, existing=current)
    if matches:
        assert _sync_await(future_output(output)) == BOUNDARY
    else:
        with pytest.raises(ValueError, match="Conflicting external boundary"):
            _sync_await(future_output(output))


def bootstrap_names(environment):
    """List the physical role inventory each existing bootstrap constructor creates."""
    settings = _ci_bootstrap_settings(environment)
    names = [
        ci_bootstrap._ci_role_name(settings, purpose)
        for purpose in ("preview", "apply", "drift")
    ]
    names.extend(
        ci_config._ci_config_read_role_name(settings, suffix)
        for suffix in ci_config._ci_secret_suffixes(environment)
    )
    if environment == "test":
        names.append(
            ci_bootstrap._operations_alert_triage_role_name(settings, settings.repo)
        )
    return names


def boundary_map(names, environment):
    """Give each role a distinct policy ARN so accidental common assignment fails."""
    return {
        name: (
            f"arn:aws:iam::{ACCOUNT}:policy/issue215-seed/{environment}/ceiling/{name}"
        )
        for name in names
    }


@pytest.fixture
def bootstrap_lookups(monkeypatch):
    """Keep legacy metadata-import lookups deterministic and local."""
    monkeypatch.setattr(ci_config, "_secret_import_id", lambda _: None)
    monkeypatch.setattr(ci_config, "_iam_role_exists", lambda _: False)
    monkeypatch.setattr(ci_bootstrap, "_iam_role_exists", lambda _: False)
    monkeypatch.setattr(github_oidc, "_existing_github_oidc_provider_arn", lambda: None)


def role_states(pulumi_mocks):
    """Wait for registration and read the exact role inputs sent to Pulumi mocks."""
    _sync_await(wait_for_rpcs())
    return {
        state["name"]: state
        for kind, _, state in pulumi_mocks.resources
        if kind == "aws:iam/role:Role"
    }


def create_bootstrap(environment, mapping, *, current=None):
    """Create the normal component with only the boundary inputs changed."""
    return ci_bootstrap.GitHubCiBootstrap(
        f"external-bootstrap-{environment}",
        args=ci_bootstrap.GitHubCiBootstrapArgs(
            settings=_ci_bootstrap_settings(environment),
            write_secret_values=False,
            control_permissions_boundary=current,
            external_role_boundaries=mapping,
        ),
    )


@pytest.mark.parametrize("environment", ["test", "prod"])
def test_bootstrap_propagates_every_boundary_without_exclusive_attachments(
    pulumi_mocks, bootstrap_lookups, environment
):
    names = bootstrap_names(environment)
    mapping = boundary_map(names, environment)
    settings = _ci_bootstrap_settings(environment)
    apply = mapping[ci_bootstrap._ci_role_name(settings, "apply")]
    component = create_bootstrap(environment, mapping, current=apply)
    states = role_states(pulumi_mocks)
    assert set(states) == set(names)
    assert len(states) == (6 if environment == "test" else 5)
    for name, state in states.items():
        assert state["permissionsBoundary"] == mapping[name]
        assert "managedPolicyArns" not in state
        assert "inlinePolicies" not in state
        assert "forceDetachPolicies" not in state
    assert set(component.state_guards) == {"preview", "apply", "drift"}
    assert component.ci_configuration.read_roles
    assert not any("Exclusive" in kind for kind, _, _ in pulumi_mocks.resources)


@pytest.mark.parametrize("environment", ["test", "prod"])
def test_no_map_keeps_only_existing_apply_control_boundary(
    pulumi_mocks, bootstrap_lookups, environment
):
    create_bootstrap(environment, None, current=BOUNDARY)
    states = role_states(pulumi_mocks)
    apply_name = ci_bootstrap._ci_role_name(
        _ci_bootstrap_settings(environment), "apply"
    )
    for name, state in states.items():
        assert state.get("permissionsBoundary") == (
            BOUNDARY if name == apply_name else None
        )


@pytest.mark.parametrize(
    "environment,missing",
    [
        (environment, name)
        for environment in ("test", "prod")
        for name in bootstrap_names(environment)
    ],
)
def test_bootstrap_rejects_each_missing_role_mapping(
    pulumi_mocks, bootstrap_lookups, environment, missing
):
    mapping = boundary_map(bootstrap_names(environment), environment)
    del mapping[missing]
    with pytest.raises(ValueError, match="Missing or invalid external boundary"):
        create_bootstrap(environment, mapping)
    _sync_await(wait_for_rpcs())


def test_bootstrap_rejects_conflicting_control_boundary(
    pulumi_mocks, bootstrap_lookups
):
    mapping = boundary_map(bootstrap_names("test"), "test")
    with pytest.raises(ValueError, match="Conflicting external boundary"):
        create_bootstrap("test", mapping, current=BOUNDARY)
    _sync_await(wait_for_rpcs())


@pytest.mark.parametrize("environment", ["test", "prod"])
@pytest.mark.parametrize("external", [True, False])
def test_config_readers_retain_explicit_service_boundary(
    pulumi_mocks, bootstrap_lookups, environment, external
):
    args = inputs(environment)
    settings = replace(args.settings, repo="user-service-infrastructure")
    mapping = {
        ci_config._ci_config_read_role_name(settings, suffix): BOUNDARY
        for suffix in ci_config._ci_secret_suffixes(environment)
    }
    ci_config.CiConfiguration(
        "external-config",
        args=ci_config.CiConfigurationArgs(
            settings=settings,
            repo=settings.repo,
            oidc_provider_arn=args.provider_arn,
            permissions_boundary=BOUNDARY,
            external_role_boundaries=mapping if external else None,
        ),
    )
    states = role_states(pulumi_mocks)
    assert set(states) == set(mapping)
    assert all(state["permissionsBoundary"] == BOUNDARY for state in states.values())


def test_config_rejects_conflicting_service_boundary(pulumi_mocks, bootstrap_lookups):
    args = inputs()
    mapping = boundary_map(bootstrap_names("test"), "test")
    with pytest.raises(ValueError, match="Conflicting external boundary"):
        ci_config.CiConfiguration(
            "external-config-conflict",
            args=ci_config.CiConfigurationArgs(
                settings=args.settings,
                oidc_provider_arn=args.provider_arn,
                permissions_boundary=BOUNDARY,
                external_role_boundaries=mapping,
            ),
        )
    _sync_await(wait_for_rpcs())


@pytest.mark.parametrize("environment", ["test", "prod"])
@pytest.mark.parametrize("external", [True, False])
def test_governors_retain_individual_boundaries_without_changing_policy_ownership(
    pulumi_mocks, environment, external
):
    names = [
        f"GitHubGovernance{purpose}-{environment}"
        for purpose in ("Preview", "Apply", "Drift")
    ]
    mapping = boundary_map(names, environment)
    component = governance_automation.GovernanceAutomation(
        "external-governor",
        args=inputs(
            environment, external_role_boundaries=mapping if external else None
        ),
    )
    states = role_states(pulumi_mocks)
    assert set(states) == set(names)
    for name, state in states.items():
        assert state.get("permissionsBoundary") == (mapping[name] if external else None)
        assert "managedPolicyArns" not in state
    assert len(component.boundaries) == 2
    assert not any("Exclusive" in kind for kind, _, _ in pulumi_mocks.resources)


@pytest.mark.parametrize("purpose", ["Preview", "Apply", "Drift"])
def test_governors_reject_each_missing_boundary(pulumi_mocks, purpose):
    names = [f"GitHubGovernance{value}-test" for value in ("Preview", "Apply", "Drift")]
    mapping = boundary_map(names, "test")
    del mapping[f"GitHubGovernance{purpose}-test"]
    with pytest.raises(ValueError, match="Missing or invalid external boundary"):
        governance_automation.GovernanceAutomation(
            "missing-governor-boundary", args=inputs(external_role_boundaries=mapping)
        )
    _sync_await(wait_for_rpcs())
