from dataclasses import dataclass
import re

import pulumi


@dataclass
class RepoSettings:
  org: str
  repo: str
  environment: str
  owner: str
  cost_center: str
  github_branch: str


cfg = pulumi.Config()

settings = RepoSettings(
  org=cfg.require("githubOrg"),
  repo=cfg.require("repoSlug"),
  environment=cfg.get("environment") or pulumi.get_stack(),
  owner=cfg.get("owner") or "platform",
  cost_center=cfg.get("costCenter") or "core",
  github_branch=cfg.get("githubBranch") or "main",
)


_VALID_CHARS_PATTERN = re.compile(r"[^a-z0-9.-]")
_SEQUENTIAL_DOTS = re.compile(r"\.{2,}")
_SEQUENTIAL_HYPHENS = re.compile(r"-{2,}")
_LEADING_TRAILING_NON_ALNUM = re.compile(r"^[^a-z0-9]+|[^a-z0-9]+$")
_IPV4_PATTERN = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_IPV6_PATTERN = re.compile(r"^[0-9a-f:]+$")


def _sanitize_bucket_component(value: str, label: str) -> str:
  """Sanitize repo/environment names for S3 bucket compatibility."""
  candidate = value.strip().lower()
  candidate = _VALID_CHARS_PATTERN.sub("-", candidate)
  candidate = _SEQUENTIAL_DOTS.sub(".", candidate)
  candidate = _SEQUENTIAL_HYPHENS.sub("-", candidate)
  candidate = _LEADING_TRAILING_NON_ALNUM.sub("", candidate)

  if not candidate:
    raise ValueError(f"{label} cannot be fully sanitized; please use a different value.")
  if len(candidate) < 3 or len(candidate) > 63:
    raise ValueError(f"{label} must resolve to between 3 and 63 characters for S3 buckets.")
  if _IPV4_PATTERN.match(candidate):
    raise ValueError(f"{label} cannot be an IPv4 address.")
  if _IPV6_PATTERN.match(candidate) and ":" in candidate:
    raise ValueError(f"{label} cannot be an IPv6 address.")

  return candidate


def state_bucket_name() -> str:
  repo_part = _sanitize_bucket_component(settings.repo, "repoSlug")
  env_part = _sanitize_bucket_component(settings.environment, "environment")
  name = f"pulumi-{repo_part}-{env_part}-state"
  if len(name) > 63:
    raise ValueError("Combined repoSlug/environment results in an S3 bucket name longer than 63 characters.")
  return name


def central_logging_bucket_name(region: str) -> str:
  prefix = cfg.get("loggingPrefix") or "company"
  prefix_part = _sanitize_bucket_component(prefix, "loggingPrefix")
  env_part = _sanitize_bucket_component(settings.environment, "environment")
  region_part = _sanitize_bucket_component(region, "region")
  name = f"{prefix_part}-central-logs-{region_part}-{env_part}"
  if len(name) > 63:
    raise ValueError("Combined logging prefix/region/environment results in an S3 bucket name longer than 63 characters.")
  return name
