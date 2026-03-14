"""Unit tests for Pulumi configuration helpers."""

import os
import sys
from pathlib import Path

import pytest

import pulumi

os.environ.setdefault("PULUMI_ALLOW_TEST_DEFAULTS", "1")

sys.path.append(str(Path(__file__).resolve().parents[2] / "pulumi"))

from infra import config
from infra.config import (
    _sanitize_bucket_component,
    central_logging_bucket_name,
    pulumi_secrets_alias_name_for_repo,
    pulumi_secrets_provider_for_repo,
    settings,
    state_bucket_name_for_repo,
)


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


def test_sanitize_bucket_component_rejects_dot_hyphen_adjacency():
    """Sanitizer should reject dot-hyphen adjacency in DNS labels."""
    with pytest.raises(ValueError):
        _sanitize_bucket_component("my-.repo", "repoSlug")
    with pytest.raises(ValueError):
        _sanitize_bucket_component("my.-repo", "repoSlug")


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
        ["repo", {"name": "repo2", "defaultBranch": "dev"}]
    )
    assert overrides[0].name == "repo"  # nosec B101
    assert overrides[0].default_branch == "main"  # nosec B101
    assert overrides[1].name == "repo2"  # nosec B101
    assert overrides[1].default_branch == "dev"  # nosec B101


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


def test_central_logging_bucket_length_guard(monkeypatch):
    """Central logging bucket should not exceed S3 length limits."""
    monkeypatch.setattr(settings, "logging_prefix", "x" * 50)
    monkeypatch.setattr(settings, "environment", "e" * 40)
    with pytest.raises(ValueError):
        central_logging_bucket_name("regionname")
