from dataclasses import dataclass

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


def state_bucket_name() -> str:
  return f"pulumi-{settings.repo}-state"


def central_logging_bucket_name(region: str) -> str:
  return f"company-central-logs-{region}"
