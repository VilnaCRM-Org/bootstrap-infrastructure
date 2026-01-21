import pulumi.errors as pulumi_errors
import pytest

from infra import config
from infra import pulumi_state


def test_bucket_exists_true(monkeypatch):
  monkeypatch.setattr(pulumi_state.aws.s3, "get_bucket", lambda bucket: {"id": bucket})
  assert pulumi_state._bucket_exists("bucket") is True


def test_bucket_exists_not_found(monkeypatch):
  def raise_not_found(*_args, **_kwargs):
    raise pulumi_errors.RunError("NotFound")

  monkeypatch.setattr(pulumi_state.aws.s3, "get_bucket", raise_not_found)
  assert pulumi_state._bucket_exists("missing") is False


def test_bucket_exists_raises_unexpected(monkeypatch):
  def raise_other(*_args, **_kwargs):
    raise pulumi_errors.RunError("Boom")

  monkeypatch.setattr(pulumi_state.aws.s3, "get_bucket", raise_other)
  with pytest.raises(pulumi_errors.RunError):
    pulumi_state._bucket_exists("oops")


def test_resource_suffix_sanitizes():
  assert pulumi_state._resource_suffix("Repo.Name") == "repo-name"


def test_replica_bucket_name_length_guard(monkeypatch):
  monkeypatch.setattr(pulumi_state, "state_bucket_name_for_repo", lambda _repo: "a" * 60)
  monkeypatch.setattr(pulumi_state, "_bucket_exists", lambda _name: False)
  repos = [config.ManagedRepository(name="repo", default_branch="main")]
  with pytest.raises(ValueError):
    pulumi_state.PulumiStateBuckets("pulumi-state", repositories=repos, replication_region="us-west-2")
