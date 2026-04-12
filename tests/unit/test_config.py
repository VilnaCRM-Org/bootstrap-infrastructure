"""Unit tests for Pulumi configuration helpers."""

import json
import os
import sys
from pathlib import Path

import pytest

import pulumi

os.environ.setdefault("PULUMI_ALLOW_TEST_DEFAULTS", "1")

sys.path.append(str(Path(__file__).resolve().parents[2] / "pulumi"))

from infra import BootstrapSettings, ManagedRepositoryCatalog, config, logging_bucket
from infra.config import (
    _sanitize_bucket_component,
    automation_role_name,
    central_logging_bucket_name,
    pulumi_secrets_alias_name_for_repo,
    pulumi_secrets_provider_for_repo,
    runner_ecr_repository_name,
    settings,
    state_bucket_name_for_repo,
)


class DummyPulumiConfig:
    def __init__(self, *, values=None, objects=None, secrets=None):
        self._values = values or {}
        self._objects = objects or {}
        self._secrets = secrets or {}

    def get(self, key):
        return self._values.get(key)

    def get_object(self, key):
        return self._objects.get(key)

    def get_secret(self, key):
        return self._secrets.get(key)


def _bootstrap_settings(**overrides) -> BootstrapSettings:
    defaults = {
        "org": "VilnaCRM-Org",
        "repo": "bootstrap-infrastructure",
        "environment": "dev",
        "owner": "platform",
        "cost_center": "engineering",
        "github_branch": None,
        "logging_prefix": "company",
        "replication_region": "us-west-2",
        "github_token": None,
        "github_oidc_provider_arn": None,
        "repository_catalog_path": None,
        "managed_repo_overrides": None,
    }
    defaults.update(overrides)
    return BootstrapSettings(**defaults)


def test_sanitize_bucket_component_normalizes_case_and_invalid_chars():
    """Sanitizer should lowercase and replace invalid characters."""
    assert _sanitize_bucket_component("My_App.repo", "repoSlug") == "my-app.repo"  # nosec B101


def test_sanitize_bucket_component_collapses_sequences_and_trims():
    """Sanitizer should collapse repeated separators and trim edges."""
    dirty = "..My--Repo__Name.."
    assert _sanitize_bucket_component(dirty, "repoSlug") == "my-repo-name"  # nosec B101


def test_sanitize_bucket_component_rejects_empty_result():
    """Sanitizer should reject values that collapse to empty."""
    with pytest.raises(ValueError):
        _sanitize_bucket_component("???", "repoSlug")


def test_sanitize_bucket_component_length_constraints():
    """Sanitizer should reject values shorter than 3 chars."""
    with pytest.raises(ValueError):
        _sanitize_bucket_component("aa", "repoSlug")


def test_sanitize_bucket_component_rejects_ipv4():
    """Sanitizer should reject IPv4 addresses."""
    with pytest.raises(ValueError):
        _sanitize_bucket_component("192.168.0.1", "repoSlug")


def test_sanitize_bucket_component_rejects_ipv4_after_sanitize():
    """Sanitizer should reject IPv4 addresses after normalization."""
    with pytest.raises(ValueError):
        _sanitize_bucket_component("192.168.0.1-", "repoSlug")


def test_sanitize_bucket_component_rejects_ipv6():
    """Sanitizer should reject IPv6 addresses."""
    with pytest.raises(ValueError):
        _sanitize_bucket_component(
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334", "repoSlug"
        )


def test_sanitize_bucket_component_allows_non_ipv6_hex_colons():
    """Non-address colon-delimited strings should sanitize like normal input."""
    assert _sanitize_bucket_component("face:feed", "repoSlug") == "face-feed"  # nosec B101


def test_sanitize_bucket_component_rejects_dot_hyphen_adjacency():
    """Sanitizer should reject dot-hyphen adjacency in DNS labels."""
    with pytest.raises(ValueError):
        _sanitize_bucket_component("my-.repo", "repoSlug")
    with pytest.raises(ValueError):
        _sanitize_bucket_component("my.-repo", "repoSlug")


def test_public_sanitize_bucket_component_wrapper():
    """The public compatibility wrapper delegates to the typed settings object."""
    assert config.sanitize_bucket_component("My_App.repo", "repoSlug") == "my-app.repo"  # nosec B101


def test_require_config_value_fallback(monkeypatch):
    """Fallbacks are used when test defaults are allowed."""

    class DummyCfg:
        def get(self, key):
            return None

    monkeypatch.setattr(config, "cfg", DummyCfg())
    monkeypatch.setattr(config, "_ALLOW_TEST_DEFAULTS", True)
    assert config._require_config_value("missing", "fallback") == "fallback"  # nosec B101


def test_require_config_value_raises(monkeypatch):
    """Missing values raise when defaults are not allowed."""

    class DummyCfg:
        def get(self, key):
            return None

    monkeypatch.setattr(config, "cfg", DummyCfg())
    monkeypatch.setattr(config, "_ALLOW_TEST_DEFAULTS", False)
    with pytest.raises(pulumi.ConfigMissingError):
        config._require_config_value("missing", "fallback")


def test_require_config_value_returns_value(monkeypatch):
    """Provided config values are returned unchanged."""

    class DummyCfg:
        def get(self, key):
            return "value"

    monkeypatch.setattr(config, "cfg", DummyCfg())
    monkeypatch.setattr(config, "_ALLOW_TEST_DEFAULTS", False)
    assert config._require_config_value("present", "fallback") == "value"  # nosec B101


def test_bootstrap_settings_require_config_value_returns_value(monkeypatch):
    """Typed settings helpers should return configured values unchanged."""

    class DummyCfg:
        def get(self, key):
            return "value"

    monkeypatch.delenv("PULUMI_ALLOW_TEST_DEFAULTS", raising=False)
    assert (
        BootstrapSettings.require_config_value(DummyCfg(), "present", "fallback")
        == "value"
    )  # nosec B101


def test_bootstrap_settings_require_config_value_raises(monkeypatch):
    """Typed settings helpers should raise when defaults are disabled."""

    class DummyCfg:
        def get(self, key):
            return None

    monkeypatch.delenv("PULUMI_ALLOW_TEST_DEFAULTS", raising=False)
    with pytest.raises(pulumi.ConfigMissingError):
        BootstrapSettings.require_config_value(DummyCfg(), "missing", "fallback")


def test_bootstrap_settings_from_pulumi_config_uses_defaults_and_stack_fallback(
    monkeypatch,
):
    """BootstrapSettings should honor Pulumi defaults and secret-aware token reads."""
    github_token = pulumi.Output.from_input("token")
    config_obj = DummyPulumiConfig(secrets={"githubToken": github_token})

    monkeypatch.setenv("PULUMI_ALLOW_TEST_DEFAULTS", "1")
    monkeypatch.setattr(pulumi, "get_stack", lambda: "test")

    settings_obj = BootstrapSettings.from_pulumi_config(config_obj)

    assert settings_obj.org == "test-org"  # nosec B101
    assert settings_obj.repo is None  # nosec B101
    assert settings_obj.environment == "test"  # nosec B101
    assert settings_obj.owner == "platform"  # nosec B101
    assert settings_obj.cost_center == "core"  # nosec B101
    assert settings_obj.github_branch is None  # nosec B101
    assert settings_obj.logging_prefix == "company"  # nosec B101
    assert settings_obj.replication_region is None  # nosec B101
    assert settings_obj.github_token is github_token  # nosec B101
    assert settings_obj.github_oidc_provider_arn is None  # nosec B101
    assert settings_obj.repository_catalog_path is None  # nosec B101


def test_bootstrap_settings_from_pulumi_config_uses_explicit_values(monkeypatch):
    """Explicit config values should override defaults in BootstrapSettings."""
    github_token = pulumi.Output.from_input("token")
    config_obj = DummyPulumiConfig(
        values={
            "githubOrg": "VilnaCRM-Org",
            "repoSlug": "core-service-infrastructure",
            "environment": "prod.eu",
            "owner": "sre",
            "costCenter": "platform",
            "githubBranch": "release",
            "loggingPrefix": "vilna",
            "replicationRegion": "eu-west-1",
            "githubOidcProviderArn": "arn:aws:iam::123456789012:oidc-provider/test",
            "repositoryCatalogPath": "repositories.json",
        },
        secrets={"githubToken": github_token},
    )

    monkeypatch.delenv("PULUMI_ALLOW_TEST_DEFAULTS", raising=False)

    settings_obj = BootstrapSettings.from_pulumi_config(config_obj)

    assert settings_obj.org == "VilnaCRM-Org"  # nosec B101
    assert settings_obj.repo == "core-service-infrastructure"  # nosec B101
    assert settings_obj.environment == "prod.eu"  # nosec B101
    assert settings_obj.owner == "sre"  # nosec B101
    assert settings_obj.cost_center == "platform"  # nosec B101
    assert settings_obj.github_branch == "release"  # nosec B101
    assert settings_obj.logging_prefix == "vilna"  # nosec B101
    assert settings_obj.replication_region == "eu-west-1"  # nosec B101
    assert settings_obj.github_token is github_token  # nosec B101
    assert (
        settings_obj.github_oidc_provider_arn
        == "arn:aws:iam::123456789012:oidc-provider/test"
    )  # nosec B101
    assert settings_obj.repository_catalog_path == "repositories.json"  # nosec B101


@pytest.mark.parametrize(
    ("settings_overrides", "managed_repositories", "expected"),
    [
        ({"repo": "repo"}, None, True),
        ({"repo": None, "repository_catalog_path": "repositories.json"}, None, True),
        (
            {
                "repo": None,
                "managed_repo_overrides": [
                    config.ManagedRepository(name="repo", default_branch="main")
                ],
            },
            None,
            True,
        ),
        ({"repo": None}, [{"name": "repo", "defaultBranch": "main"}], True),
        (
            {
                "repo": None,
                "repository_catalog_path": None,
                "managed_repo_overrides": None,
            },
            None,
            False,
        ),
    ],
)
def test_bootstrap_settings_bootstrap_requested(
    settings_overrides, managed_repositories, expected
):
    """BootstrapSettings should only bootstrap when at least one source is set."""
    settings_obj = _bootstrap_settings(**settings_overrides)
    config_obj = DummyPulumiConfig(
        objects={"managedRepositories": managed_repositories}
    )

    assert settings_obj.bootstrap_requested(config_obj) is expected  # nosec B101


def test_load_managed_repo_overrides_validation():
    """managedRepositories input validation enforces structure."""
    assert config._load_managed_repo_overrides(None) is None  # nosec B101
    with pytest.raises(ValueError):
        config._load_managed_repo_overrides([])
    with pytest.raises(ValueError):
        config._load_managed_repo_overrides("not-a-list")
    with pytest.raises(ValueError):
        config._load_managed_repo_overrides([123])
    with pytest.raises(ValueError):
        config._load_managed_repo_overrides([{"defaultBranch": "main"}])
    with pytest.raises(ValueError):
        config._load_managed_repo_overrides([{"name": ""}])
    with pytest.raises(ValueError):
        config._load_managed_repo_overrides([{"name": "repo", "defaultBranch": " "}])


def test_load_managed_repo_overrides_success():
    """Valid managedRepositories values are normalized."""
    overrides = config._load_managed_repo_overrides(
        [
            "repo",
            {
                "name": "repo2",
                "defaultBranch": "dev",
                "project": "core-service",
            },
        ]
    )
    assert overrides is not None  # nosec B101
    assert overrides[0].name == "repo"  # nosec B101
    assert overrides[0].default_branch == "main"  # nosec B101
    assert overrides[0].project_name == "repo"  # nosec B101
    assert overrides[1].name == "repo2"  # nosec B101
    assert overrides[1].default_branch == "dev"  # nosec B101
    assert overrides[1].project_name == "core-service"  # nosec B101


def test_state_bucket_name_requires_repo(monkeypatch):
    """state_bucket_name requires repoSlug when no overrides exist."""
    config.managed_repositories.cache_clear()
    monkeypatch.setattr(settings, "repo", None)
    monkeypatch.setattr(settings, "managed_repo_overrides", None)
    with pytest.raises(ValueError):
        config.state_bucket_name()


def test_state_bucket_name_success(monkeypatch):
    """state_bucket_name uses repoSlug when configured."""
    config.managed_repositories.cache_clear()
    monkeypatch.setattr(settings, "repo", "service")
    monkeypatch.setattr(settings, "environment", "dev")
    assert config.state_bucket_name() == "pulumi-service-dev-state"  # nosec B101


def test_managed_repositories_fallbacks(monkeypatch):
    """managed_repositories follows overrides then repoSlug."""
    config.managed_repositories.cache_clear()
    overrides = [config.ManagedRepository(name="example", default_branch="main")]
    monkeypatch.setattr(settings, "managed_repo_overrides", overrides)
    assert config.managed_repositories() == overrides  # nosec B101

    config.managed_repositories.cache_clear()
    monkeypatch.setattr(settings, "managed_repo_overrides", None)
    monkeypatch.setattr(settings, "repo", "repo")
    monkeypatch.setattr(settings, "github_branch", None)
    repos = config.managed_repositories()
    assert repos[0].name == "repo"  # nosec B101
    assert repos[0].default_branch == "main"  # nosec B101

    config.managed_repositories.cache_clear()
    monkeypatch.setattr(settings, "repo", None)
    with pytest.raises(ValueError):
        config.managed_repositories()


def test_managed_repositories_support_repository_catalog_path(tmp_path, monkeypatch):
    """managed_repositories can be loaded from a JSON repository catalog."""
    config.managed_repositories.cache_clear()
    catalog_path = tmp_path / "repositories.json"
    catalog_path.write_text(
        json.dumps(
            {
                "repositories": [
                    {
                        "name": "user-service-infrastructure",
                        "defaultBranch": "main",
                        "project": "user-service",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(settings, "managed_repo_overrides", None)
    monkeypatch.setattr(settings, "repo", None)
    monkeypatch.setattr(settings, "repository_catalog_path", str(catalog_path))

    repos = config.managed_repositories()

    assert repos[0].name == "user-service-infrastructure"  # nosec B101
    assert repos[0].default_branch == "main"  # nosec B101
    assert repos[0].project_name == "user-service"  # nosec B101

    config.managed_repositories.cache_clear()
    monkeypatch.setattr(settings, "repository_catalog_path", None)


def test_managed_repository_catalog_rejects_empty_list():
    """Repository catalogs must contain at least one repository."""
    with pytest.raises(ValueError):
        ManagedRepositoryCatalog([])


def test_managed_repository_catalog_load_from_items_none():
    """`None` input is treated as an unset inline config value."""
    assert ManagedRepositoryCatalog.load_from_items(None) == []  # nosec B101


def test_managed_repository_catalog_from_settings_uses_inline_config():
    """Inline Pulumi config can define the managed repository catalog."""

    class DummyCfg:
        def get_object(self, key):
            if key == "managedRepositories":
                return [
                    {
                        "name": "core-service-infrastructure",
                        "defaultBranch": "main",
                        "project": "core-service",
                    }
                ]
            return None

    catalog = ManagedRepositoryCatalog.from_settings(
        _bootstrap_settings(repo=None),
        DummyCfg(),
    )

    assert catalog.project_mapping() == {"core-service-infrastructure": "core-service"}  # nosec B101


def test_managed_repository_catalog_load_from_json_relative_path(tmp_path, monkeypatch):
    """Relative repository catalog paths resolve from the current working directory."""
    catalog_path = tmp_path / "repositories.json"
    catalog_path.write_text(
        json.dumps(
            {
                "repositories": [
                    {
                        "name": "user-service-infrastructure",
                        "defaultBranch": "main",
                        "project": "user-service",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.chdir(tmp_path)
    repositories = ManagedRepositoryCatalog.load_from_json_file("repositories.json")

    assert repositories[0].project_name == "user-service"  # nosec B101


def test_managed_repository_catalog_load_from_json_requires_file(tmp_path):
    """Repository catalog paths must point to an existing JSON file."""
    with pytest.raises(ValueError, match="must point to a JSON file"):
        ManagedRepositoryCatalog.load_from_json_file(str(tmp_path / "missing.json"))


def test_managed_repository_catalog_load_from_json_requires_object(tmp_path):
    """Repository catalog files must contain an object payload."""
    catalog_path = tmp_path / "repositories.json"
    catalog_path.write_text("[]", encoding="utf-8")

    with pytest.raises(ValueError, match="must be an object"):
        ManagedRepositoryCatalog.load_from_json_file(str(catalog_path))


def test_managed_repository_catalog_load_from_json_requires_repositories_key(tmp_path):
    """Repository catalog files must expose the `repositories` key."""
    catalog_path = tmp_path / "repositories.json"
    catalog_path.write_text(json.dumps({"items": []}), encoding="utf-8")

    with pytest.raises(ValueError, match="must include 'repositories'"):
        ManagedRepositoryCatalog.load_from_json_file(str(catalog_path))


def test_managed_repository_catalog_requires_non_empty_project_name():
    """Repository catalog entries must define a non-empty project name."""
    with pytest.raises(ValueError, match="non-empty 'project'"):
        ManagedRepositoryCatalog.repository_from_item(
            {"name": "repo", "defaultBranch": "main", "project": " "}
        )


def test_managed_repository_catalog_normalizes_string_entries():
    """Bare repository names should be trimmed before use."""
    repository = ManagedRepositoryCatalog.repository_from_item(" repo ")

    assert repository.name == "repo"  # nosec B101
    assert repository.default_branch == "main"  # nosec B101
    assert repository.project_name == "repo"  # nosec B101


def test_managed_repository_catalog_rejects_blank_string_entries():
    """Whitespace-only repository names should fail fast."""
    with pytest.raises(ValueError, match="non-empty string"):
        ManagedRepositoryCatalog.repository_from_item("   ")


def test_managed_repository_catalog_normalizes_mapping_entries():
    """Mapping repository entries should be stripped before validation."""
    repository = ManagedRepositoryCatalog.repository_from_item(
        {
            "name": " repo ",
            "defaultBranch": " main ",
            "project": " platform ",
        }
    )

    assert repository.name == "repo"  # nosec B101
    assert repository.default_branch == "main"  # nosec B101
    assert repository.project_name == "platform"  # nosec B101


def test_managed_repository_catalog_rejects_duplicate_names():
    """Duplicate repository names should be rejected regardless of case."""
    with pytest.raises(ValueError, match="must be unique"):
        ManagedRepositoryCatalog.load_from_items(["Repo", " repo "])


def test_managed_repository_catalog_constructor_rejects_duplicate_names():
    """Direct catalog construction should reject duplicate repository names."""
    with pytest.raises(ValueError, match="must be unique"):
        ManagedRepositoryCatalog(
            [
                config.ManagedRepository(name="Repo", default_branch="main"),
                config.ManagedRepository(name="repo", default_branch="main"),
            ]
        )


def test_state_bucket_name_length_guard(monkeypatch):
    """Repo + environment should not exceed S3 length limits."""
    monkeypatch.setattr(settings, "environment", "e" * 40)
    with pytest.raises(ValueError):
        state_bucket_name_for_repo("r" * 40)


def test_pulumi_secrets_alias_name_for_repo(monkeypatch):
    """Pulumi secrets aliases are sanitized and environment-scoped."""
    monkeypatch.setattr(settings, "environment", "test")
    assert (
        pulumi_secrets_alias_name_for_repo("My.Repo")
        == "alias/pulumi-my-repo-test-secrets"
    )  # nosec B101


def test_pulumi_secrets_alias_name_for_repo_normalizes_environment_dots(monkeypatch):
    """KMS aliases should replace environment dots with hyphens."""
    monkeypatch.setattr(settings, "environment", "test.env")
    assert (
        pulumi_secrets_alias_name_for_repo("repo")
        == "alias/pulumi-repo-test-env-secrets"
    )  # nosec B101


def test_pulumi_secrets_alias_name_for_repo_reports_repo_slug_label(monkeypatch):
    monkeypatch.setattr(settings, "environment", "test")
    with pytest.raises(ValueError, match=r"^repoSlug\b"):
        pulumi_secrets_alias_name_for_repo("???")


def test_pulumi_secrets_alias_name_for_repo_reports_environment_label(monkeypatch):
    monkeypatch.setattr(settings, "environment", "??")
    with pytest.raises(ValueError, match=r"^environment\b"):
        pulumi_secrets_alias_name_for_repo("repo")


def test_pulumi_secrets_provider_for_repo(monkeypatch):
    """Pulumi secrets provider URIs use the KMS alias and region."""
    monkeypatch.setattr(settings, "environment", "test")
    provider = pulumi_secrets_provider_for_repo("repo", "eu-central-1")
    assert provider == "awskms://alias/pulumi-repo-test-secrets?region=eu-central-1"  # nosec B101


def test_pulumi_secrets_provider_for_repo_reports_region_label(monkeypatch):
    monkeypatch.setattr(settings, "environment", "test")
    with pytest.raises(ValueError, match=r"^region\b"):
        pulumi_secrets_provider_for_repo("repo", "??")


def test_runner_ecr_repository_name(monkeypatch):
    monkeypatch.setattr(settings, "environment", "test")
    assert runner_ecr_repository_name("My.Repo") == "pulumi-runner/my-repo-test"  # nosec B101


def test_automation_role_name(monkeypatch):
    monkeypatch.setattr(settings, "environment", "test")
    assert automation_role_name("My.Repo") == "PulumiAutomation-my-repo-test"  # nosec B101


def test_automation_role_name_length_guard(monkeypatch):
    monkeypatch.setattr(settings, "environment", "e" * 40)
    with pytest.raises(ValueError):
        automation_role_name("r" * 40)


def test_managed_repository_validation_rejects_blank_name():
    with pytest.raises(ValueError, match="name must be a non-empty string"):
        config.ManagedRepository(name=" ", default_branch="main")


def test_managed_repository_validation_rejects_blank_default_branch():
    with pytest.raises(ValueError, match="default_branch must be non-empty"):
        config.ManagedRepository(name="repo", default_branch=" ")


def test_managed_repository_validation_rejects_blank_project():
    with pytest.raises(ValueError, match="project must be non-empty"):
        config.ManagedRepository(name="repo", default_branch="main", project=" ")


def test_managed_repository_validation_rejects_non_string_fields():
    with pytest.raises(TypeError, match="name must be a string"):
        config.ManagedRepository(name=123, default_branch="main")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="default_branch must be a string"):
        config.ManagedRepository(name="repo", default_branch=123)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="project must be a string"):
        config.ManagedRepository(
            name="repo",
            default_branch="main",
            project=123,  # type: ignore[arg-type]
        )


def test_primary_logging_bucket_name_uses_injected_settings():
    """The logging bucket helper can resolve names from injected settings."""
    injected_settings = _bootstrap_settings(
        repo=None,
        environment="test",
        logging_prefix="company",
    )

    assert (
        logging_bucket._primary_bucket_name(injected_settings, "eu-central-1")
        == "company-central-logs-eu-central-1-test"
    )  # nosec B101


def test_central_logging_bucket_length_guard(monkeypatch):
    """Central logging bucket should not exceed S3 length limits."""
    monkeypatch.setattr(settings, "logging_prefix", "x" * 50)
    monkeypatch.setattr(settings, "environment", "e" * 40)
    with pytest.raises(ValueError):
        central_logging_bucket_name("regionname")
