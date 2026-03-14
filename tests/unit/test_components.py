import runpy
from pathlib import Path

import pytest
from pulumi.runtime.sync_await import _sync_await

import pulumi
from infra import (
    CentralLoggingBuckets,
    GitHubAutomation,
    PulumiSecretsKeys,
    PulumiStateBuckets,
    S3BackupPlan,
    config,
    logging_bucket,
    pulumi_secrets,
    pulumi_state,
)
from infra.iam import GitHubOidcRoles, github_oidc
from infra.utils.outputs import future_output


def test_central_logging_buckets_rejects_long_replica(monkeypatch):
    monkeypatch.setattr(
        logging_bucket, "central_logging_bucket_name", lambda _region: "a" * 60
    )
    monkeypatch.setattr(config.settings, "replication_region", "us-west-2")
    with pytest.raises(ValueError):
        CentralLoggingBuckets("central-logs")


def test_central_logging_buckets_reject_same_replication_region():
    with pytest.raises(ValueError, match="must differ from primary region"):
        CentralLoggingBuckets("central-logs", replication_region="us-east-1")


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

    assert logging.bucket is not None  # nosec B101
    assert state.backend_urls  # nosec B101
    assert secrets.provider_urls  # nosec B101
    assert oidc.deploy_role_arns  # nosec B101
    assert automation.repository.repository_url is not None  # nosec B101


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
    automation = GitHubAutomation("github-automation")

    repository_url = _sync_await(future_output(automation.repository.repository_url))
    role_arn = _sync_await(future_output(automation.role.arn))
    assert repository_url is not None  # nosec B101
    assert role_arn is not None  # nosec B101
    assert repository_url.endswith("/pulumi-runner/bootstrap-infrastructure-test")  # nosec B101
    assert role_arn.endswith(":role/PulumiAutomation-bootstrap-infrastructure-test")  # nosec B101

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

    assert repository_type == "aws:ecr/repository:Repository"  # nosec B101
    assert repository_state["name"] == "pulumi-runner/bootstrap-infrastructure-test"  # nosec B101
    assert repository_state["imageTagMutability"] == "IMMUTABLE"  # nosec B101
    assert repository_state["imageScanningConfiguration"]["scanOnPush"] is True  # nosec B101
    assert role_type == "aws:iam/role:Role"  # nosec B101
    assert (
        "repo:VilnaCRM-Org/bootstrap-infrastructure:environment:test"
        in role_state["assumeRolePolicy"]
    )  # nosec B101


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


def test_github_oidc_roles_create_provider_when_missing(monkeypatch, pulumi_mocks):  # noqa: ARG001
    monkeypatch.setattr(github_oidc.settings, "github_oidc_provider_arn", None)
    monkeypatch.setattr(github_oidc.settings, "org", "VilnaCRM-Org")

    repos = [config.ManagedRepository(name="repo3", default_branch="main")]
    roles = GitHubOidcRoles("github-oidc-created", repositories=repos)

    assert roles.deploy_role_arns  # nosec B101


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


def test_stack_main_executes(monkeypatch):
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
