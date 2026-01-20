"""Configuration helpers for Pulumi infrastructure stacks."""

import os
from dataclasses import dataclass, field
from functools import lru_cache
import re
from typing import Any, List, Optional

import pulumi


@dataclass
class RepoSettings:
  """Strongly-typed configuration values for the stack."""
  org: str
  repo: Optional[str]
  environment: str
  owner: str
  cost_center: str
  github_branch: Optional[str]
  logging_prefix: str
  github_token: Optional[str]
  github_oidc_provider_arn: Optional[str]
  managed_repo_overrides: Optional[List["ManagedRepository"]] = field(default=None)


@dataclass
class ManagedRepository:
  """Configuration for a managed repository and its default branch."""
  name: str
  default_branch: str


cfg = pulumi.Config()
_ALLOW_TEST_DEFAULTS = os.getenv("PULUMI_ALLOW_TEST_DEFAULTS") == "1"


def _require_config_value(key: str, fallback: str) -> str:
  """Load a required Pulumi config value, with optional test fallback."""
  value = cfg.get(key)
  if value is None:
    if _ALLOW_TEST_DEFAULTS:
      return fallback
    raise pulumi.ConfigMissingError(f"Missing required config value '{key}'.")
  return value


settings = RepoSettings(
  org=_require_config_value("githubOrg", "test-org"),
  repo=cfg.get("repoSlug"),
  environment=cfg.get("environment") or pulumi.get_stack(),
  owner=cfg.get("owner") or "platform",
  cost_center=cfg.get("costCenter") or "core",
  github_branch=cfg.get("githubBranch"),
  logging_prefix=cfg.get("loggingPrefix") or "company",
  github_token=cfg.get("githubToken"),
  github_oidc_provider_arn=cfg.get("githubOidcProviderArn"),
  managed_repo_overrides=None,
)


_VALID_CHARS_PATTERN = re.compile(r"[^a-z0-9.-]")
_SEQUENTIAL_DOTS = re.compile(r"\.{2,}")
_SEQUENTIAL_HYPHENS = re.compile(r"-{2,}")
_LEADING_TRAILING_NON_ALNUM = re.compile(r"^[^a-z0-9]+|[^a-z0-9]+$")
_IPV4_PATTERN = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_IPV6_PATTERN = re.compile(r"^[0-9a-f:]+$")


def _load_managed_repo_overrides(raw: Any) -> Optional[List[ManagedRepository]]:
  """Normalize managedRepositories config entries into structured objects."""
  if raw is None:
    return None
  if not isinstance(raw, list):
    raise ValueError("managedRepositories config must be a list of repository names or objects.")
  overrides: List[ManagedRepository] = []
  for item in raw:
    if isinstance(item, str):
      name = item
      default_branch = "main"
    elif isinstance(item, dict):
      name = item.get("name")
      default_branch = item.get("defaultBranch") or "main"
    else:
      raise ValueError("Each managedRepositories entry must be a string or an object with 'name'.")
    if not isinstance(name, str) or not name.strip():
      raise ValueError("Each managedRepositories entry must include a non-empty 'name'.")
    if not isinstance(default_branch, str) or not default_branch.strip():
      raise ValueError("managedRepositories defaultBranch values must be non-empty strings.")
    overrides.append(ManagedRepository(name=name.strip(), default_branch=default_branch.strip()))
  if not overrides:
    raise ValueError("managedRepositories config cannot be empty.")
  return overrides


settings.managed_repo_overrides = _load_managed_repo_overrides(cfg.get_object("managedRepositories"))


def _sanitize_bucket_component(value: str, label: str) -> str:
  """Return a DNS-safe S3 bucket component derived from user input."""
  normalized = value.strip().lower()

  if _IPV4_PATTERN.match(normalized):
    raise ValueError(f"{label} cannot be an IPv4 address.")
  if ":" in normalized and _IPV6_PATTERN.match(normalized):
    raise ValueError(f"{label} cannot be an IPv6 address.")

  candidate = normalized
  candidate = _VALID_CHARS_PATTERN.sub("-", candidate)
  candidate = _SEQUENTIAL_DOTS.sub(".", candidate)
  candidate = _SEQUENTIAL_HYPHENS.sub("-", candidate)
  candidate = _LEADING_TRAILING_NON_ALNUM.sub("", candidate)

  if _IPV4_PATTERN.match(candidate):
    raise ValueError(f"{label} cannot be an IPv4 address.")

  if not candidate:
    raise ValueError(f"{label} cannot be fully sanitized; please use a different value.")
  if len(candidate) < 3 or len(candidate) > 63:
    raise ValueError(f"{label} must resolve to between 3 and 63 characters for S3 buckets.")

  return candidate


def sanitize_bucket_component(value: str, label: str) -> str:
  """Public wrapper for bucket component sanitization."""
  return _sanitize_bucket_component(value, label)


def state_bucket_name_for_repo(repo_name: str) -> str:
  """Compute the full state bucket name for a repository."""
  repo_part = _sanitize_bucket_component(repo_name, "repoSlug")
  env_part = _sanitize_bucket_component(settings.environment, "environment")
  name = f"pulumi-{repo_part}-{env_part}-state"
  if len(name) > 63:
    raise ValueError(
      f"Combined repo/environment ('{repo_part}', '{env_part}') produce bucket name '{name}' longer than 63 characters."
    )
  return name


def state_bucket_name() -> str:
  """Compute the state bucket name for the configured repository."""
  if not settings.repo:
    raise ValueError("repoSlug config is not set; use state_bucket_name_for_repo(repo) instead.")
  return state_bucket_name_for_repo(settings.repo)


def central_logging_bucket_name(region: str) -> str:
  """Compute the central logging bucket name for a given region."""
  prefix_part = _sanitize_bucket_component(settings.logging_prefix, "loggingPrefix")
  env_part = _sanitize_bucket_component(settings.environment, "environment")
  region_part = _sanitize_bucket_component(region, "region")
  name = f"{prefix_part}-central-logs-{region_part}-{env_part}"
  if len(name) > 63:
    raise ValueError("Combined logging prefix/region/environment results in an S3 bucket name longer than 63 characters.")
  return name


@lru_cache(maxsize=1)
def managed_repositories() -> List[ManagedRepository]:
  """Return the list of repositories to provision state buckets for."""
  if settings.managed_repo_overrides:
    return settings.managed_repo_overrides
  if settings.repo:
    return [ManagedRepository(name=settings.repo, default_branch=settings.github_branch or "main")]
  raise ValueError(
    "No managed repositories specified. Set bootstrap-infrastructure:managedRepositories "
    "to a list of repo names (optionally with defaultBranch)."
  )
