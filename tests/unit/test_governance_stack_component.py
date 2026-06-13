"""Unit tests for ``governance.GovernanceStack`` (Story 1.5 / E1.S4b).

Covers the stack half of ``governance.py``: the ``GovernanceStack`` loop that
consumes its account's GitHub OIDC provider **by pinned ARN via ``.get()``**
(zero create branch — AWS-SRE-2, FR7), asserts the live account against the
injectable, per-stack ``expected_account_id`` (D1), instantiates one
``RepoGovernance`` per catalog repo, and registers the stable §3.4 outputs map.

All resources render under the session Pulumi mocks (``tests/conftest.py``):
account ``123456789012``, region ``us-east-1``. The account-assertion seam is
exercised through the injectable ``expected_account_id`` (AWS-SRE-5 / FEAS-3):
``"123456789012"`` (the mock account) drives the non-raise branch and any other
value drives the raise branch — both reachable under mocks, with no hardcoded
``891377212104``/``eu-central-1`` literal in component code.
"""

from __future__ import annotations

import pytest
from infra import ci_config, config, governance, pulumi_secrets, pulumi_state
from infra.governance import (
    GovernanceStack,
    GovernanceStackArgs,
    RepoGovernance,
)
from infra.iam import github_oidc
from infra.managed_repository import ManagedRepository
from infra.repository_catalog import ManagedRepositoryCatalog
from infra.utils.outputs import future_output
from pulumi.runtime.sync_await import _sync_await


def _flush_stack(stack: GovernanceStack) -> None:
    """Force every resource the stack registers to land in the mock list.

    Pulumi registers resources asynchronously, so the mock ``resources`` list is
    appended to only once each registration RPC resolves. Awaiting the consumed
    OIDC provider ARN plus every per-repo deploy/config-read role ARN, state
    bucket and KMS alias drives those RPCs to completion, so a scan run
    immediately afterwards sees every resource the stack created instead of
    racing a still-in-flight registration.
    """
    _sync_await(future_output(stack.oidc_provider_arn))
    for component in stack.repo_components.values():
        for arn in component.deployment_role_arns.values():
            _sync_await(future_output(arn))
        for arn in component.config_read_role_arns.values():
            _sync_await(future_output(arn))
        _sync_await(future_output(component.state_bucket_name))
        _sync_await(future_output(component.state_bucket_arn))
        _sync_await(future_output(component.secrets_alias_name))
        _sync_await(future_output(component.secrets_key_arn))


_MOCK_ACCOUNT_ID = "123456789012"
_MOCK_PROVIDER_ARN = (
    "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
)


def _governance_settings(environment: str = "test") -> config.BootstrapSettings:
    """Return settings for governance stack tests (mock account/region)."""
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


def _two_repo_catalog() -> ManagedRepositoryCatalog:
    """Return a synthetic 2-repo catalog for the loop tests."""
    return ManagedRepositoryCatalog(
        [
            ManagedRepository(
                name="user-service-infrastructure",
                default_branch="main",
                project="user-service-infrastructure",
            ),
            ManagedRepository(
                name="billing-service-infrastructure",
                default_branch="main",
                project="billing-service-infrastructure",
            ),
        ]
    )


def _no_existing_resources(monkeypatch) -> None:
    """Stub all AWS existence lookups so resources are created fresh."""
    monkeypatch.setattr(ci_config, "_secret_import_id", lambda _name: None)
    monkeypatch.setattr(ci_config, "_iam_role_exists", lambda _name: False)
    monkeypatch.setattr(governance, "_iam_role_exists", lambda _name: False)
    monkeypatch.setattr(pulumi_state, "_bucket_exists", lambda *a, **k: False)
    monkeypatch.setattr(pulumi_secrets, "_kms_alias_exists", lambda _name: False)
    monkeypatch.setattr(
        github_oidc,
        "_existing_github_oidc_provider_arn",
        lambda: None,
    )


def _stack_args(
    *,
    environment: str = "test",
    expected_account_id: str | None = _MOCK_ACCOUNT_ID,
    oidc_provider_arn: str | None = _MOCK_PROVIDER_ARN,
    catalog: ManagedRepositoryCatalog | None = None,
) -> GovernanceStackArgs:
    """Build mock-friendly governance stack args."""
    return GovernanceStackArgs(
        settings=_governance_settings(environment),
        repository_catalog=catalog or _two_repo_catalog(),
        expected_account_id=expected_account_id,
        oidc_provider_arn=oidc_provider_arn,
        region="us-east-1",
    )


def _build_stack(
    name: str = "governance-test",
    **kwargs,
) -> GovernanceStack:
    """Instantiate one ``GovernanceStack`` under the mocks."""
    return GovernanceStack(name, args=_stack_args(**kwargs))


def _resources_created_since(pulumi_mocks, start: int):
    """Return only resources this test created (after the ``start`` snapshot).

    ``pulumi_mocks.resources`` is session-scoped: it accumulates every resource
    registered by every test in the run. Slicing from a per-test snapshot keeps
    each scan scoped to the stack under test, so prior tests' resources can
    never be matched by type/name.
    """
    return pulumi_mocks.resources[start:]


# --- account assertion (D1, injectable seam — AWS-SRE-5 / FEAS-3) ---------------


def test_stack_proceeds_when_expected_account_matches_mock(pulumi_mocks, monkeypatch):  # noqa: ARG001
    """``expected_account_id == mock account`` proceeds (non-raise branch)."""
    _no_existing_resources(monkeypatch)

    stack = _build_stack(expected_account_id=_MOCK_ACCOUNT_ID)

    assert stack.managed_repositories == [  # nosec B101
        "billing-service-infrastructure",
        "user-service-infrastructure",
    ]


def test_stack_raises_when_expected_account_mismatches(pulumi_mocks, monkeypatch):  # noqa: ARG001
    """A mismatched ``expected_account_id`` raises ``ValueError`` (raise branch)."""
    _no_existing_resources(monkeypatch)

    with pytest.raises(ValueError, match="account"):
        _build_stack(expected_account_id="891377212104")


def test_stack_proceeds_when_expected_account_id_unset(pulumi_mocks, monkeypatch):  # noqa: ARG001
    """An unset ``expected_account_id`` skips the assertion and proceeds."""
    _no_existing_resources(monkeypatch)

    stack = _build_stack(expected_account_id=None)

    assert set(stack.per_repo) == {  # nosec B101
        "user-service-infrastructure",
        "billing-service-infrastructure",
    }


# --- OIDC provider by pinned ARN (FR7, AWS-SRE-2) -------------------------------


def test_stack_raises_when_oidc_provider_arn_unset(pulumi_mocks, monkeypatch):  # noqa: ARG001
    """An unset ``oidc_provider_arn`` raises (it must not fall back to create)."""
    _no_existing_resources(monkeypatch)

    with pytest.raises(ValueError, match="oidc"):
        _build_stack(oidc_provider_arn=None)


def test_stack_registers_zero_oidc_provider_create(pulumi_mocks, monkeypatch):  # noqa: ARG001
    """The OIDC provider is consumed via ``.get()`` — never CREATED (AWS-SRE-2).

    A ``.get()`` adopt records the provider as a read whose mock state carries
    only the pinned ``arn`` — never the create-only inputs (``clientIdLists`` /
    ``thumbprintLists`` / ``url``). Asserting the absence of every create-only
    input is the structural guarantee that no ``OpenIdConnectProvider`` create
    branch ran in the governance project (FR7 verify, §3.2 step 2).
    """
    _no_existing_resources(monkeypatch)

    start = len(pulumi_mocks.resources)
    stack = _build_stack()
    _flush_stack(stack)

    provider_states = [
        state
        for typ, _name, state in _resources_created_since(pulumi_mocks, start)
        if typ == "aws:iam/openIdConnectProvider:OpenIdConnectProvider"
    ]
    create_only_inputs = {"clientIdLists", "thumbprintLists", "url"}
    for state in provider_states:
        assert create_only_inputs.isdisjoint(state)  # nosec B101


def test_stack_exposes_consumed_provider_arn(pulumi_mocks, monkeypatch):  # noqa: ARG001
    """The stack exposes the pinned provider ARN it consumed by ``.get()``."""
    _no_existing_resources(monkeypatch)

    stack = _build_stack()

    arn = _sync_await(future_output(stack.oidc_provider_arn))
    assert arn == _MOCK_PROVIDER_ARN  # nosec B101


# --- the per-repo loop (3N deploy roles) ----------------------------------------


def test_stack_loop_yields_exactly_three_deploy_roles_per_repo(
    pulumi_mocks,
    monkeypatch,
):  # noqa: ARG001
    """N repos → exactly 3N deploy roles (preview/apply/drift each)."""
    _no_existing_resources(monkeypatch)
    catalog = _two_repo_catalog()
    repo_count = len(catalog.repositories)

    start = len(pulumi_mocks.resources)
    stack = _build_stack(catalog=catalog)

    # Force every deploy-role registration RPC to flush before counting.
    _flush_stack(stack)

    deploy_role_names = [
        name
        for typ, name, _state in _resources_created_since(pulumi_mocks, start)
        if typ == "aws:iam/role:Role"
        and (
            name.endswith("-preview-role")
            or name.endswith("-apply-role")
            or name.endswith("-drift-role")
        )
    ]
    assert len(deploy_role_names) == 3 * repo_count  # nosec B101
    assert len(stack.per_repo) == repo_count  # nosec B101
    for repo_outputs in stack.per_repo.values():
        assert set(repo_outputs["deploymentRoleArns"]) == {  # nosec B101
            "preview",
            "apply",
            "drift",
        }


def test_stack_instantiates_one_repo_governance_child_per_repo(
    pulumi_mocks,  # noqa: ARG001
    monkeypatch,
):  # noqa: ARG001
    """Each catalog repo gets exactly one ``RepoGovernance`` child component."""
    _no_existing_resources(monkeypatch)
    catalog = _two_repo_catalog()

    stack = _build_stack(catalog=catalog)

    assert all(  # nosec B101
        isinstance(child, RepoGovernance) for child in stack.repo_components.values()
    )
    assert set(stack.repo_components) == {  # nosec B101
        "user-service-infrastructure",
        "billing-service-infrastructure",
    }


# --- §3.4 stable outputs map ----------------------------------------------------


def test_stack_outputs_map_shape_is_stable(pulumi_mocks, monkeypatch):  # noqa: ARG001
    """The outputs map matches §3.4: per-repo keys + sorted managedRepositories."""
    _no_existing_resources(monkeypatch)

    stack = _build_stack()

    assert stack.managed_repositories == [  # nosec B101
        "billing-service-infrastructure",
        "user-service-infrastructure",
    ]
    repo = stack.per_repo["user-service-infrastructure"]
    assert set(repo) == {  # nosec B101
        "stateBucketName",
        "stateBackendUrl",
        "secretsAlias",
        "secretsProvider",
        "deploymentRoleArns",
        "configReadRoleArns",
        "ciConfigSecretIds",
        "githubVariables",
    }


def test_stack_outputs_are_repo_scoped(pulumi_mocks, monkeypatch):  # noqa: ARG001
    """Per-repo backend/secrets/secret-id outputs are scoped to that repo."""
    _no_existing_resources(monkeypatch)

    stack = _build_stack()

    repo = stack.per_repo["user-service-infrastructure"]
    backend = _sync_await(future_output(repo["stateBackendUrl"]))
    assert backend == "s3://pulumi-user-service-infrastructure-test-state"  # nosec B101
    secrets_provider = _sync_await(future_output(repo["secretsProvider"]))
    assert secrets_provider == (  # nosec B101
        "awskms://alias/pulumi-user-service-infrastructure-test-secrets"
        "?region=us-east-1"
    )
    assert repo["ciConfigSecretIds"] == {  # nosec B101
        "test-pr": "/user-service-infrastructure/ci/test-pr",
        "test": "/user-service-infrastructure/ci/test",
    }


def test_stack_outputs_do_not_cross_repos(pulumi_mocks, monkeypatch):  # noqa: ARG001
    """Repo A's outputs never reference repo B's bucket/alias (isolation)."""
    _no_existing_resources(monkeypatch)

    stack = _build_stack()

    repo_a = stack.per_repo["user-service-infrastructure"]
    backend_a = _sync_await(future_output(repo_a["stateBackendUrl"]))
    secrets_a = _sync_await(future_output(repo_a["secretsProvider"]))
    assert "billing-service-infrastructure" not in backend_a  # nosec B101
    assert "billing-service-infrastructure" not in secrets_a  # nosec B101


def test_stack_outputs_are_account_and_region_parametric(pulumi_mocks, monkeypatch):  # noqa: ARG001
    """No hardcoded ``891377212104``/``eu-central-1`` literal in stack outputs."""
    _no_existing_resources(monkeypatch)

    stack = _build_stack()

    repo = stack.per_repo["user-service-infrastructure"]
    secrets_provider = _sync_await(future_output(repo["secretsProvider"]))
    assert "891377212104" not in secrets_provider  # nosec B101
    assert "eu-central-1" not in secrets_provider  # nosec B101
    assert "us-east-1" in secrets_provider  # nosec B101


def test_stack_github_variables_use_injected_region(pulumi_mocks, monkeypatch):  # noqa: ARG001
    """``githubVariables`` carry the injected (mock) region, not a literal."""
    _no_existing_resources(monkeypatch)

    stack = _build_stack()

    repo = stack.per_repo["user-service-infrastructure"]
    variables = repo["githubVariables"]
    assert variables["AWS_TEST_REGION"] == "us-east-1"  # nosec B101


def test_stack_default_region_is_eu_central_1():
    """``GovernanceStackArgs`` keeps the ``eu-central-1`` default for real applies."""
    assert GovernanceStackArgs().region == "eu-central-1"  # nosec B101
