import runpy
from pathlib import Path

import pulumi
import pytest

from infra import CentralLoggingBuckets, PulumiStateBuckets, S3BackupPlan
from infra import config
from infra.iam import GitHubOidcRoles
from infra.iam import github_oidc
from infra import logging_bucket
from infra import pulumi_state


def test_central_logging_buckets_rejects_long_replica(monkeypatch):
  monkeypatch.setattr(logging_bucket, "central_logging_bucket_name", lambda region: "a" * 60)
  with pytest.raises(ValueError):
    CentralLoggingBuckets("central-logs")


def test_components_build(pulumi_mocks, monkeypatch):
  monkeypatch.setattr(config.settings, "logging_prefix", "company")
  monkeypatch.setattr(config.settings, "environment", "test")
  monkeypatch.setattr(config.settings, "replication_region", "us-west-2")
  monkeypatch.setattr(pulumi_state, "_bucket_exists", lambda _name: False)

  repos = [config.ManagedRepository(name="repo", default_branch="main")]

  logging = CentralLoggingBuckets("central-logging")
  state = PulumiStateBuckets("pulumi-state", repositories=repos, replication_region="")
  oidc = GitHubOidcRoles("github-oidc", repositories=repos)
  S3BackupPlan("backup", backup_target_arns=[logging.bucket.arn, *state.bucket_arns.values()])

  assert logging.bucket is not None
  assert state.backend_urls
  assert oidc.deploy_role_arns


def test_github_oidc_roles_with_existing_provider(monkeypatch):
  class FakeProvider:
    arn = pulumi.Output.from_input("arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com")

  monkeypatch.setattr(github_oidc.settings, "github_oidc_provider_arn", "arn:existing")
  monkeypatch.setattr(github_oidc.aws.iam.OpenIdConnectProvider, "get", lambda *args, **kwargs: FakeProvider())

  repos = [config.ManagedRepository(name="repo2", default_branch="main")]
  roles = GitHubOidcRoles("github-oidc-existing", repositories=repos)
  assert roles.deploy_role_arns


def test_task_roles_module_has_no_exports():
  from infra.iam import task_roles

  assert task_roles.__all__ == []


def test_stack_main_executes(monkeypatch):
  config.managed_repositories.cache_clear()
  monkeypatch.setattr(config.settings, "repo", "repo")
  monkeypatch.setattr(config.settings, "environment", "test")
  monkeypatch.setattr(config.settings, "managed_repo_overrides", None)
  stack_path = Path(__file__).resolve().parents[2] / "pulumi" / "__main__.py"
  runpy.run_path(stack_path)
