import json
import os
from dataclasses import dataclass
from functools import lru_cache
import re
from typing import List, Optional
from urllib import error as urllib_error
from urllib import parse as urllib_parse
from urllib import request as urllib_request

import pulumi


@dataclass
class RepoSettings:
  org: str
  repo: Optional[str]
  environment: str
  owner: str
  cost_center: str
  github_branch: Optional[str]
  managed_topic: str
  logging_prefix: str
  github_token: Optional[str]


@dataclass
class ManagedRepository:
  name: str
  default_branch: str


cfg = pulumi.Config()
_ALLOW_TEST_DEFAULTS = os.getenv("PULUMI_ALLOW_TEST_DEFAULTS") == "1"


def _require_config_value(key: str, fallback: str) -> str:
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
  managed_topic=cfg.get("managedTopic") or "pulumi-state",
  logging_prefix=cfg.get("loggingPrefix") or "company",
  github_token=cfg.get_secret("githubToken"),
)


_VALID_CHARS_PATTERN = re.compile(r"[^a-z0-9.-]")
_SEQUENTIAL_DOTS = re.compile(r"\.{2,}")
_SEQUENTIAL_HYPHENS = re.compile(r"-{2,}")
_LEADING_TRAILING_NON_ALNUM = re.compile(r"^[^a-z0-9]+|[^a-z0-9]+$")
_IPV4_PATTERN = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_IPV6_PATTERN = re.compile(r"^[0-9a-f:]+$")


def _sanitize_bucket_component(value: str, label: str) -> str:
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


def state_bucket_name_for_repo(repo_name: str) -> str:
  repo_part = _sanitize_bucket_component(repo_name, "repoSlug")
  env_part = _sanitize_bucket_component(settings.environment, "environment")
  name = f"pulumi-{repo_part}-{env_part}-state"
  if len(name) > 63:
    raise ValueError(
      f"Combined repo/environment ('{repo_part}', '{env_part}') produce bucket name '{name}' longer than 63 characters."
    )
  return name


def state_bucket_name() -> str:
  if not settings.repo:
    raise ValueError("repoSlug config is not set; use state_bucket_name_for_repo(repo) instead.")
  return state_bucket_name_for_repo(settings.repo)


def central_logging_bucket_name(region: str) -> str:
  prefix_part = _sanitize_bucket_component(settings.logging_prefix, "loggingPrefix")
  env_part = _sanitize_bucket_component(settings.environment, "environment")
  region_part = _sanitize_bucket_component(region, "region")
  name = f"{prefix_part}-central-logs-{region_part}-{env_part}"
  if len(name) > 63:
    raise ValueError("Combined logging prefix/region/environment results in an S3 bucket name longer than 63 characters.")
  return name


@lru_cache(maxsize=1)
def managed_repositories() -> List[ManagedRepository]:
  topic = settings.managed_topic
  query = f"topic:{topic}+org:{settings.org}"
  headers = {
    "Accept": "application/vnd.github+json",
    "User-Agent": "bootstrap-infrastructure/1.0",
  }
  if settings.github_token:
    headers["Authorization"] = f"Bearer {settings.github_token}"

  repos: List[ManagedRepository] = []
  page = 1
  while True:
    params = urllib_parse.urlencode({"q": query, "per_page": 100, "page": page})
    url = f"https://api.github.com/search/repositories?{params}"
    req = urllib_request.Request(url, headers=headers, method="GET")
    try:
      with urllib_request.urlopen(req, timeout=30) as resp:
        data = json.load(resp)
    except urllib_error.HTTPError as http_err:
      if http_err.code == 403 and http_err.headers and http_err.headers.get("X-RateLimit-Remaining") == "0":
        raise RuntimeError(
          "GitHub API rate limit exceeded while fetching repositories. "
          "Provide a githubToken config value to raise the limit."
        ) from http_err
      raise RuntimeError(f"Failed to fetch repositories from GitHub API: {http_err}") from http_err

    items = data.get("items", [])
    for item in items:
      repos.append(ManagedRepository(name=item["name"], default_branch=item.get("default_branch") or "main"))
    if len(repos) >= data.get("total_count", 0) or not items:
      break
    page += 1

  if not repos:
    raise ValueError(
      f"No repositories in org '{settings.org}' are tagged with topic '{topic}'. "
      "Add the topic to application repositories that need managed Pulumi state."
    )
  return repos
