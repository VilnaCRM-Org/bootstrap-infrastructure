import pulumi.errors as pulumi_errors
import pytest

from infra import config, pulumi_state


def test_bucket_exists_true(monkeypatch):
    monkeypatch.setattr(
        pulumi_state.aws.s3, "get_bucket", lambda bucket: {"id": bucket}
    )
    assert pulumi_state._bucket_exists("bucket") is True  # nosec B101


def test_bucket_exists_not_found(monkeypatch):
    def raise_not_found(*_args, **_kwargs):
        raise pulumi_errors.RunError("NotFound")

    monkeypatch.setattr(pulumi_state.aws.s3, "get_bucket", raise_not_found)
    assert pulumi_state._bucket_exists("missing") is False  # nosec B101


def test_bucket_exists_handles_invoke_not_found(monkeypatch):
    def raise_not_found(*_args, **_kwargs):
        raise Exception("couldn't find resource")  # noqa: TRY002

    monkeypatch.setattr(pulumi_state.aws.s3, "get_bucket", raise_not_found)
    assert pulumi_state._bucket_exists("missing") is False  # nosec B101


def test_bucket_exists_raises_unexpected(monkeypatch):
    def raise_other(*_args, **_kwargs):
        raise pulumi_errors.RunError("Boom")

    monkeypatch.setattr(pulumi_state.aws.s3, "get_bucket", raise_other)
    with pytest.raises(pulumi_errors.RunError):
        pulumi_state._bucket_exists("oops")


def test_resource_suffix_sanitizes():
    assert pulumi_state._resource_suffix("Repo.Name") == "repo-name"  # nosec B101


def test_replication_role_name_limits_length():
    role_name = pulumi_state._replication_role_name("a" * 80)
    assert role_name.startswith(pulumi_state._REPLICATION_ROLE_NAME_PREFIX)  # nosec B101
    assert len(role_name) <= pulumi_state._MAX_IAM_ROLE_NAME_LENGTH  # nosec B101


def test_replica_bucket_name_length_guard(monkeypatch):
    monkeypatch.setattr(
        pulumi_state, "state_bucket_name_for_repo", lambda _repo: "a" * 60
    )
    monkeypatch.setattr(pulumi_state, "_bucket_exists", lambda _name: False)
    repos = [config.ManagedRepository(name="repo", default_branch="main")]
    with pytest.raises(ValueError):
        pulumi_state.PulumiStateBuckets(
            "pulumi-state", repositories=repos, replication_region="us-west-2"
        )
