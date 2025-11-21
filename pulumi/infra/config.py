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

  return candidate


def state_bucket_name() -> str:
  repo_part = _sanitize_bucket_component(settings.repo, "repoSlug")
  env_part = _sanitize_bucket_component(settings.environment, "environment")
  return f"pulumi-{repo_part}-{env_part}-state"


def central_logging_bucket_name(region: str) -> str:
  prefix = cfg.get("loggingPrefix") or "company"
  prefix_part = _sanitize_bucket_component(prefix, "loggingPrefix")
  env_part = _sanitize_bucket_component(settings.environment, "environment")
  region_part = _sanitize_bucket_component(region, "region")
  return f"{prefix_part}-central-logs-{region_part}-{env_part}"
