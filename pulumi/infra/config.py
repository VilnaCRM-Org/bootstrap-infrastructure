"""Compatibility helpers around the class-based bootstrap configuration model."""

from __future__ import annotations

import os
from functools import lru_cache
from typing import Any

import pulumi

from .bootstrap_settings import BootstrapSettings
from .managed_repository import ManagedRepository
from .repository_catalog import ManagedRepositoryCatalog

cfg = pulumi.Config()
_ALLOW_TEST_DEFAULTS = os.getenv("PULUMI_ALLOW_TEST_DEFAULTS") == "1"


def _require_config_value(key: str, fallback: str) -> str:
    """Load a required Pulumi config value with optional test fallback."""
    value = cfg.get(key)
    if value is None:
        if _ALLOW_TEST_DEFAULTS:
            return fallback
        raise pulumi.ConfigMissingError(key, False)
    return value


settings = BootstrapSettings.from_pulumi_config(cfg)


def _sanitize_bucket_component(value: str, label: str) -> str:
    """Compatibility wrapper for legacy bucket sanitization tests."""
    return settings.sanitize_bucket_component(value, label)


def sanitize_bucket_component(value: str, label: str) -> str:
    """Public compatibility wrapper for bucket component sanitization."""
    return settings.sanitize_bucket_component(value, label)


def _load_managed_repo_overrides(raw: Any) -> list[ManagedRepository] | None:
    """Normalize managedRepositories config entries into typed repository configs."""
    if raw is None:
        return None
    return ManagedRepositoryCatalog.load_from_items(raw)


@lru_cache(maxsize=1)
def managed_repositories() -> list[ManagedRepository]:
    """Return the repositories managed by the current stack configuration."""
    return ManagedRepositoryCatalog.from_settings(settings, cfg).repositories


def state_bucket_name_for_repo(repo_name: str) -> str:
    """Compute the full state bucket name for a repository."""
    return settings.state_bucket_name_for_repo(repo_name)


def state_bucket_name() -> str:
    """Compute the state bucket name for the configured repository."""
    return settings.state_bucket_name()


def pulumi_secrets_alias_name_for_repo(repo_name: str) -> str:
    """Compute the KMS alias used for Pulumi secrets for a repository."""
    return settings.pulumi_secrets_alias_name_for_repo(repo_name)


def pulumi_secrets_provider_for_repo(repo_name: str, region: str) -> str:
    """Build the Pulumi AWS KMS secrets provider URI for a repository."""
    return settings.pulumi_secrets_provider_for_repo(repo_name, region)


def runner_ecr_repository_name(repo_name: str) -> str:
    """Compute the ECR repository name used by automation runners."""
    return settings.runner_ecr_repository_name(repo_name)


def automation_role_name(repo_name: str) -> str:
    """Compute the GitHub automation role name for this repository/environment."""
    return settings.automation_role_name(repo_name)


def central_logging_bucket_name(region: str) -> str:
    """Compute the central logging bucket name for a given region."""
    return settings.central_logging_bucket_name(region)
