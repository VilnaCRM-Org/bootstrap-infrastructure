"""Unit tests for ``governance.RepoGovernance`` (Story 1.4 / E1.S4a).

Covers the per-repo half of ``governance.py``: ``GovernanceStackArgs`` (incl.
the injectable ``region`` and ``oidc_provider_arn``), the ``RepoGovernance``
component (state bucket + replica, KMS key + alias, CI-config secret +
config-read role, the preview/apply/drift trio), the governance CI-config
payload builder (no operations-triage requirement), and the
``_governance_apply_subjects`` override (§5.1a, SECURITY-2): the governance
apply role trusts ONLY ``environment:governance`` for BOTH the test and prod
stacks.

All resources render under the session Pulumi mocks (``tests/conftest.py``):
account ``123456789012``, region ``us-east-1``. Policy ARNs use
``{account_id}``/``{region}`` interpolation, never a hardcoded
``891377212104``/``eu-central-1`` literal (FEAS-3), so the documents are
mock-renderable.
"""

from __future__ import annotations

import json

from infra import ci_config, config, governance, pulumi_secrets, pulumi_state
from infra.governance import GovernanceStackArgs, RepoGovernance, _governance_payloads
from infra.iam import github_oidc
from infra.managed_repository import ManagedRepository
from infra.utils.outputs import future_output
from pulumi.runtime.sync_await import _sync_await

_MOCK_PROVIDER_ARN = (
    "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
)


def _governance_settings(environment: str) -> config.BootstrapSettings:
    """Return settings for governance component tests (mock account/region)."""
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


def _synthetic_repo(name: str = "user-service-infrastructure") -> ManagedRepository:
    """Return a single synthetic managed repository for governance tests."""
    return ManagedRepository(
        name=name,
        default_branch="main",
        project=name,
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


def _build_repo_governance(
    name: str,
    *,
    repo: ManagedRepository,
    settings: config.BootstrapSettings,
    region: str = "us-east-1",
    write_secret_values: bool = True,
) -> RepoGovernance:
    """Instantiate one ``RepoGovernance`` with explicit mock-friendly inputs."""
    return RepoGovernance(
        name,
        repo=repo,
        settings=settings,
        provider_arn=_MOCK_PROVIDER_ARN,
        account_id="123456789012",
        partition="aws",
        region=region,
        pulumi_dir="pulumi",
        pulumi_backend_url=None,
        pulumi_secrets_provider=None,
        write_secret_values=write_secret_values,
        protect_resources=True,
    )


def _state_by_name(pulumi_mocks, name: str) -> dict:
    """Return the recorded mock state for a registered resource by name."""
    for _typ, resource_name, state in pulumi_mocks.resources:
        if resource_name == name:
            return state
    raise AssertionError(f"resource {name!r} was not registered")


# --- _governance_apply_subjects (§5.1a, SECURITY-2) -----------------------------


def test_governance_apply_subjects_is_environment_governance_only_for_test():
    """Test-stack governance apply trusts ONLY ``environment:governance``."""
    settings = _governance_settings("test")
    subjects = governance._governance_apply_subjects(settings, "org/repo")

    assert subjects == ["repo:org/repo:environment:governance"]  # nosec B101


def test_governance_apply_subjects_is_environment_governance_only_for_prod():
    """Prod-stack governance apply trusts ONLY ``environment:governance``."""
    settings = _governance_settings("prod")
    subjects = governance._governance_apply_subjects(settings, "org/repo")

    assert subjects == ["repo:org/repo:environment:governance"]  # nosec B101


def test_governance_apply_subjects_excludes_branch_ref_and_environment_test():
    """No bare branch-ref or ``environment:test`` subject leaks into apply trust."""
    settings = _governance_settings("test")
    serialized = json.dumps(governance._governance_apply_subjects(settings, "org/repo"))

    assert "ref:refs/heads/main" not in serialized  # nosec B101
    assert "environment:test" not in serialized  # nosec B101
    assert "pull_request" not in serialized  # nosec B101


# --- _governance_payloads (no operations triage) --------------------------------


def test_governance_payloads_test_stack_has_no_operations_keys():
    """Governance test payload omits every operations-triage key."""
    settings = _governance_settings("test")
    repo = _synthetic_repo()
    payloads = _governance_payloads(
        settings=settings,
        repo=repo,
        account_id="123456789012",
        region="eu-central-1",
        pulumi_dir="pulumi",
        role_arns={
            "preview": "arn:preview",
            "apply": "arn:apply",
            "drift": "arn:drift",
        },
    )

    assert set(payloads) == {"test-pr", "test"}  # nosec B101
    serialized = json.dumps(payloads)
    assert "OPERATIONS_TOPIC_ARN" not in serialized  # nosec B101
    assert "OPERATIONS_ALERT_QUEUE_NAME" not in serialized  # nosec B101
    assert "AWS_OPERATIONS_ALERT_TRIAGE_ROLE_ARN" not in serialized  # nosec B101
    assert sorted(payloads["test-pr"]) == [  # nosec B101
        "AWS_ACCOUNT_ID",
        "AWS_PREVIEW_ROLE_ARN",
        "AWS_REGION",
        "PULUMI_BACKEND_URL",
        "PULUMI_DIR",
        "PULUMI_PREVIEW_STACKS",
        "PULUMI_SECRETS_PROVIDER",
    ]
    assert sorted(payloads["test"]) == [  # nosec B101
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


def test_governance_payloads_uses_repo_scoped_backend_and_secrets_provider():
    """Payloads point at the repo's own state bucket and KMS alias, with region."""
    settings = _governance_settings("test")
    repo = _synthetic_repo("user-service-infrastructure")
    payloads = _governance_payloads(
        settings=settings,
        repo=repo,
        account_id="123456789012",
        region="eu-central-1",
        pulumi_dir="pulumi",
        role_arns={
            "preview": "arn:preview",
            "apply": "arn:apply",
            "drift": "arn:drift",
        },
    )

    backend = payloads["test"]["PULUMI_BACKEND_URL"]
    provider = payloads["test"]["PULUMI_SECRETS_PROVIDER"]
    assert backend == "s3://pulumi-user-service-infrastructure-test-state"  # nosec B101
    assert provider == (  # nosec B101
        "awskms://alias/pulumi-user-service-infrastructure-test-secrets"
        "?region=eu-central-1"
    )
    assert payloads["test"]["AWS_REGION"] == "eu-central-1"  # nosec B101
    assert payloads["test"]["PULUMI_PREVIEW_STACKS"] == "test"  # nosec B101
    assert payloads["test"]["PULUMI_DRIFT_STACKS"] == "test"  # nosec B101


def test_governance_payloads_prod_stack_shape():
    """Governance prod payload splits preview/drift from the gated apply env."""
    settings = _governance_settings("prod")
    repo = _synthetic_repo()
    payloads = _governance_payloads(
        settings=settings,
        repo=repo,
        account_id="123456789012",
        region="eu-central-1",
        pulumi_dir="pulumi",
        role_arns={
            "preview": "arn:preview",
            "apply": "arn:apply",
            "drift": "arn:drift",
        },
    )

    assert set(payloads) == {"prod-preview", "prod"}  # nosec B101
    assert "AWS_APPLY_ROLE_ARN" not in payloads["prod-preview"]  # nosec B101
    assert payloads["prod"]["AWS_APPLY_ROLE_ARN"] == "arn:apply"  # nosec B101


# --- RepoGovernance component (positive) ----------------------------------------


def test_repo_governance_renders_full_per_repo_surface(pulumi_mocks, monkeypatch):  # noqa: ARG001
    """A single repo yields bucket+replica, KMS key+alias, trio + config-read."""
    _no_existing_resources(monkeypatch)
    settings = _governance_settings("test")
    repo = _synthetic_repo("user-service-infrastructure")

    component = _build_repo_governance(
        "gov-test-user-service-infrastructure",
        repo=repo,
        settings=settings,
    )

    _sync_await(future_output(component.deployment_role_arns["preview"]))
    _sync_await(future_output(component.deployment_role_arns["apply"]))
    _sync_await(future_output(component.deployment_role_arns["drift"]))
    _sync_await(future_output(component.config_read_role_arns["test-pr"]))
    _sync_await(future_output(component.config_read_role_arns["test"]))
    _sync_await(future_output(component.state_bucket_name))
    _sync_await(future_output(component.secrets_alias_name))

    assert set(component.deployment_role_arns) == {  # nosec B101
        "preview",
        "apply",
        "drift",
    }
    registered = {name for _typ, name, _state in pulumi_mocks.resources}
    # state bucket + replica
    assert any("-user-service-infrastructure" in n for n in registered)  # nosec B101
    bucket_state = _state_by_name(
        pulumi_mocks,
        "gov-test-user-service-infrastructure-state-user-service-infrastructure",
    )
    assert (  # nosec B101
        bucket_state["bucket"] == "pulumi-user-service-infrastructure-test-state"
    )
    # KMS alias name is repo-scoped
    alias_name = _sync_await(future_output(component.secrets_alias_name))
    assert alias_name == (  # nosec B101
        "alias/pulumi-user-service-infrastructure-test-secrets"
    )
    # CI-config secret IDs are repo-scoped
    assert component.ci_config_secret_ids == {  # nosec B101
        "test-pr": "/user-service-infrastructure/ci/test-pr",
        "test": "/user-service-infrastructure/ci/test",
    }


def test_repo_governance_apply_role_trust_is_environment_governance_only(
    pulumi_mocks,
    monkeypatch,
):  # noqa: ARG001
    """The rendered apply role trusts ONLY ``environment:governance`` (test)."""
    _no_existing_resources(monkeypatch)
    settings = _governance_settings("test")
    repo = _synthetic_repo("user-service-infrastructure")

    _build_repo_governance(
        "gov-test-user-service-infrastructure",
        repo=repo,
        settings=settings,
    )

    apply_state = _state_by_name(
        pulumi_mocks,
        "gov-test-user-service-infrastructure-apply-role",
    )
    apply_trust = json.loads(apply_state["assumeRolePolicy"])
    subjects = apply_trust["Statement"][0]["Condition"]["StringEquals"][
        "token.actions.githubusercontent.com:sub"
    ]
    assert subjects == [  # nosec B101
        "repo:VilnaCRM-Org/user-service-infrastructure:environment:governance"
    ]


def test_repo_governance_prod_apply_role_trust_is_environment_governance_only(
    pulumi_mocks,
    monkeypatch,
):  # noqa: ARG001
    """The rendered apply role trusts ONLY ``environment:governance`` (prod)."""
    _no_existing_resources(monkeypatch)
    settings = _governance_settings("prod")
    repo = _synthetic_repo("user-service-infrastructure")

    _build_repo_governance(
        "gov-prod-user-service-infrastructure",
        repo=repo,
        settings=settings,
    )

    apply_state = _state_by_name(
        pulumi_mocks,
        "gov-prod-user-service-infrastructure-apply-role",
    )
    apply_trust = json.loads(apply_state["assumeRolePolicy"])
    subjects = apply_trust["Statement"][0]["Condition"]["StringEquals"][
        "token.actions.githubusercontent.com:sub"
    ]
    assert subjects == [  # nosec B101
        "repo:VilnaCRM-Org/user-service-infrastructure:environment:governance"
    ]


def test_repo_governance_preview_role_keeps_existing_subjects(
    pulumi_mocks,
    monkeypatch,
):  # noqa: ARG001
    """preview/drift roles keep their existing (non-governance) subjects."""
    _no_existing_resources(monkeypatch)
    settings = _governance_settings("test")
    repo = _synthetic_repo("user-service-infrastructure")

    _build_repo_governance(
        "gov-test-user-service-infrastructure",
        repo=repo,
        settings=settings,
    )

    preview_state = _state_by_name(
        pulumi_mocks,
        "gov-test-user-service-infrastructure-preview-role",
    )
    preview_trust = json.loads(preview_state["assumeRolePolicy"])
    subjects = preview_trust["Statement"][0]["Condition"]["StringEquals"][
        "token.actions.githubusercontent.com:sub"
    ]
    assert subjects == [  # nosec B101
        "repo:VilnaCRM-Org/user-service-infrastructure:ref:refs/heads/main",
        "repo:VilnaCRM-Org/user-service-infrastructure:pull_request",
        "repo:VilnaCRM-Org/user-service-infrastructure:environment:test",
    ]


# --- RepoGovernance component (negative / least privilege) -----------------------


def test_repo_governance_deploy_policy_has_no_other_repo_or_platform_reference(
    pulumi_mocks,
    monkeypatch,
):  # noqa: ARG001
    """Repo A's deploy policy references neither repo B nor platform-bootstrap."""
    _no_existing_resources(monkeypatch)
    settings = _governance_settings("test")
    repo_a = _synthetic_repo("user-service-infrastructure")

    _build_repo_governance(
        "gov-test-user-service-infrastructure",
        repo=repo_a,
        settings=settings,
    )

    other_repo = "billing-service-infrastructure"
    policy_blobs = [
        state["policy"]
        for typ, _name, state in pulumi_mocks.resources
        if typ in {"aws:iam/policy:Policy", "aws:iam/rolePolicy:RolePolicy"}
        and "policy" in state
    ]
    assert policy_blobs  # nosec B101
    for blob in policy_blobs:
        assert other_repo not in blob  # nosec B101
        assert "pulumi-platform-bootstrap" not in blob  # nosec B101


def test_repo_governance_deploy_policies_have_no_allow_wildcard(
    pulumi_mocks,
    monkeypatch,
):  # noqa: ARG001
    """No ``Effect:Allow`` statement carries a bare ``Action:*`` (FR23)."""
    _no_existing_resources(monkeypatch)
    settings = _governance_settings("test")
    repo = _synthetic_repo("user-service-infrastructure")

    _build_repo_governance(
        "gov-test-user-service-infrastructure",
        repo=repo,
        settings=settings,
    )

    for typ, _name, state in pulumi_mocks.resources:
        if typ not in {
            "aws:iam/policy:Policy",
            "aws:iam/rolePolicy:RolePolicy",
        }:
            continue
        if "policy" not in state:
            continue
        document = json.loads(state["policy"])
        statements = document["Statement"]
        if isinstance(statements, dict):
            statements = [statements]
        for statement in statements:
            if statement.get("Effect") != "Allow":
                continue
            actions = statement["Action"]
            if isinstance(actions, str):
                actions = [actions]
            assert "*" not in actions  # nosec B101


def test_repo_governance_apply_policy_denies_foreign_secret_reads(
    pulumi_mocks,
    monkeypatch,
):  # noqa: ARG001
    """The apply role denies leaky reads except its own ``/{project}/ci/*``."""
    _no_existing_resources(monkeypatch)
    settings = _governance_settings("test")
    repo = _synthetic_repo("user-service-infrastructure")

    _build_repo_governance(
        "gov-test-user-service-infrastructure",
        repo=repo,
        settings=settings,
    )

    deny_statements = []
    for typ, _name, state in pulumi_mocks.resources:
        if typ != "aws:iam/policy:Policy" or "policy" not in state:
            continue
        document = json.loads(state["policy"])
        statements = document["Statement"]
        if isinstance(statements, dict):
            statements = [statements]
        deny_statements.extend(
            statement
            for statement in statements
            if statement.get("Sid") == "DenySecretLeakingReadsApply"
        )
    assert deny_statements  # nosec B101
    statement = deny_statements[0]
    assert statement["Effect"] == "Deny"  # nosec B101
    assert "secretsmanager:GetSecretValue" in statement["Action"]  # nosec B101
    assert statement["NotResource"] == [  # nosec B101
        "arn:aws:secretsmanager:us-east-1:123456789012:secret:"
        "/user-service-infrastructure/ci/*"
    ]


def test_repo_governance_backend_policy_is_account_and_region_parametric(
    pulumi_mocks,
    monkeypatch,
):  # noqa: ARG001
    """Backend policy renders under mock account/region, no hardcoded literals."""
    _no_existing_resources(monkeypatch)
    settings = _governance_settings("test")
    repo = _synthetic_repo("user-service-infrastructure")

    _build_repo_governance(
        "gov-test-user-service-infrastructure",
        repo=repo,
        settings=settings,
    )

    backend_statements = None
    for typ, _name, state in pulumi_mocks.resources:
        if typ not in {
            "aws:iam/policy:Policy",
            "aws:iam/rolePolicy:RolePolicy",
        }:
            continue
        if "policy" not in state:
            continue
        document = json.loads(state["policy"])
        statements = document["Statement"]
        if isinstance(statements, dict):
            statements = [statements]
        by_sid = {s.get("Sid"): s for s in statements}
        if "UsePulumiSecretsProviderKey" in by_sid:
            backend_statements = by_sid
            break
    assert backend_statements is not None  # nosec B101
    kms_statement = backend_statements["UsePulumiSecretsProviderKey"]
    assert kms_statement["Resource"] == (  # nosec B101
        "arn:aws:kms:us-east-1:123456789012:key/*"
    )
    assert "891377212104" not in json.dumps(backend_statements)  # nosec B101
    assert "eu-central-1" not in json.dumps(backend_statements)  # nosec B101
    aliases = kms_statement["Condition"]["ForAnyValue:StringLike"][
        "kms:ResourceAliases"
    ]
    assert aliases == [  # nosec B101
        "alias/pulumi-user-service-infrastructure-test-secrets"
    ]


# --- RepoGovernance component (edge) --------------------------------------------


def test_repo_governance_skips_secret_versions_when_not_writing(
    pulumi_mocks,
    monkeypatch,
):  # noqa: ARG001
    """``write_secret_values=False`` creates no secret-version resource."""
    _no_existing_resources(monkeypatch)
    settings = _governance_settings("test")
    repo = _synthetic_repo("user-service-infrastructure")

    component = _build_repo_governance(
        "gov-test-user-service-infrastructure",
        repo=repo,
        settings=settings,
        write_secret_values=False,
    )

    _sync_await(future_output(component.deployment_role_arns["apply"]))
    assert component.secret_versions == {}  # nosec B101
    assert not any(  # nosec B101
        typ == "aws:secretsmanager/secretVersion:SecretVersion"
        for typ, _name, _state in pulumi_mocks.resources
    )


def test_repo_governance_writes_secret_versions_by_default(
    pulumi_mocks,
    monkeypatch,
):  # noqa: ARG001
    """``write_secret_values=True`` writes one secret version per suffix."""
    _no_existing_resources(monkeypatch)
    settings = _governance_settings("test")
    repo = _synthetic_repo("user-service-infrastructure")

    component = _build_repo_governance(
        "gov-test-user-service-infrastructure",
        repo=repo,
        settings=settings,
        write_secret_values=True,
    )

    assert set(component.secret_versions) == {"test-pr", "test"}  # nosec B101


# --- GovernanceStackArgs --------------------------------------------------------


def test_governance_stack_args_defaults_region_to_eu_central_1():
    """The region default is ``eu-central-1`` but stays overridable."""
    args = GovernanceStackArgs()

    assert args.region == "eu-central-1"  # nosec B101
    assert args.oidc_provider_arn is None  # nosec B101
    assert args.write_secret_values is True  # nosec B101


def test_governance_stack_args_accepts_injected_region_and_provider():
    """A test can inject the mock region and a pinned provider ARN."""
    args = GovernanceStackArgs(
        region="us-east-1",
        oidc_provider_arn=_MOCK_PROVIDER_ARN,
        expected_account_id="123456789012",
    )

    assert args.region == "us-east-1"  # nosec B101
    assert args.oidc_provider_arn == _MOCK_PROVIDER_ARN  # nosec B101
    assert args.expected_account_id == "123456789012"  # nosec B101
