import runpy
from pathlib import Path

import pytest
from pulumi.runtime.sync_await import _sync_await

import pulumi
from infra import (
    CentralLoggingBuckets,
    PulumiSecretsKeys,
    PulumiStateBuckets,
    S3BackupPlan,
    config,
    logging_bucket,
    pulumi_secrets,
    pulumi_state,
)
from infra.iam import GitHubOidcRoles, github_oidc


def test_central_logging_buckets_rejects_long_replica(monkeypatch):
    monkeypatch.setattr(
        logging_bucket, "central_logging_bucket_name", lambda _region: "a" * 60
    )
    with pytest.raises(ValueError):
        CentralLoggingBuckets("central-logs")


def test_components_build(pulumi_mocks, monkeypatch):  # noqa: ARG001
    monkeypatch.setattr(config.settings, "logging_prefix", "company")
    monkeypatch.setattr(config.settings, "environment", "test")
    monkeypatch.setattr(config.settings, "replication_region", "us-west-2")
    monkeypatch.setattr(pulumi_state, "_bucket_exists", lambda _name: False)

    repos = [config.ManagedRepository(name="repo", default_branch="main")]

    logging = CentralLoggingBuckets("central-logging")
    state = PulumiStateBuckets(
        "pulumi-state", repositories=repos, replication_region=""
    )
    secrets = PulumiSecretsKeys("pulumi-secrets", repositories=repos)
    oidc = GitHubOidcRoles(
        "github-oidc", repositories=repos, secrets_key_arns=secrets.key_arns
    )
    S3BackupPlan(
        "backup", backup_target_arns=[logging.bucket.arn, *state.bucket_arns.values()]
    )

    assert logging.bucket is not None  # nosec B101
    assert state.backend_urls  # nosec B101
    assert secrets.provider_urls  # nosec B101
    assert oidc.deploy_role_arns  # nosec B101


def test_state_buckets_reject_same_replication_region(monkeypatch):
    monkeypatch.setattr(config.settings, "replication_region", "us-east-1")

    repos = [config.ManagedRepository(name="repo", default_branch="main")]

    with pytest.raises(ValueError, match="must differ from primary region"):
        PulumiStateBuckets("pulumi-state-invalid", repositories=repos)


def test_github_oidc_roles_with_existing_provider(monkeypatch):
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


def test_pulumi_secrets_key_policy_uses_account_root():
    import json

    policy = json.loads(pulumi_secrets._key_policy("123456789012"))
    statement = policy["Statement"][0]
    assert policy["Version"] == "2012-10-17"  # nosec B101
    assert statement["Sid"] == "EnableAccountPermissions"  # nosec B101
    assert statement["Effect"] == "Allow"  # nosec B101
    assert statement["Principal"]["AWS"] == "arn:aws:iam::123456789012:root"  # nosec B101
    assert statement["Action"] == "kms:*"  # nosec B101
    assert statement["Resource"] == "*"  # nosec B101


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

    component_urn = _sync_await(secrets.urn.future())
    provider_url = _sync_await(secrets.provider_urls["repo"].future())
    alias_name_output = _sync_await(secrets.alias_names["repo"].future())
    key_arn_output = _sync_await(secrets.key_arns["repo"].future())

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


def test_github_oidc_roles_require_matching_kms_key(monkeypatch):
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


def test_github_oidc_role_name_limits_length():
    long_suffix = "a" * 70
    role_name = github_oidc._role_name_for_suffix(long_suffix)
    assert role_name.startswith(github_oidc._ROLE_NAME_PREFIX)  # nosec B101
    assert len(role_name) <= github_oidc._MAX_IAM_ROLE_NAME_LENGTH  # nosec B101


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


def test_stack_main_executes(monkeypatch):
    config.managed_repositories.cache_clear()
    monkeypatch.setattr(config.settings, "repo", "repo")
    monkeypatch.setattr(config.settings, "environment", "test")
    monkeypatch.setattr(config.settings, "replication_region", "us-west-2")
    monkeypatch.setattr(config.settings, "managed_repo_overrides", None)
    stack_path = Path(__file__).resolve().parents[2] / "pulumi" / "__main__.py"
    # Keep a fast smoke test for the stack entrypoint alongside the integration suite.
    runpy.run_path(stack_path)
