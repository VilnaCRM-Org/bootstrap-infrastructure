"""Worker rechecks use real collectors over fake transport and never reclaim."""

from __future__ import annotations

import sys
from copy import deepcopy
from datetime import datetime, timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))

import deployment_worker_recheck as worker  # noqa: E402
from deployment_contract_io import decode_deployment_contract  # noqa: E402
from test_deployment_controller_runtime import (  # noqa: E402
    github as github,
)
from test_deployment_controller_runtime import set_request  # noqa: E402

ROOT_ENDPOINT = f"repos/{worker.REPOSITORY}/actions/runs/100"


@pytest.fixture
def admitted(github):
    """Produce a real admitted artifact, then observe only subsequent worker reads."""
    from deployment_controller_runtime import accept

    accept()
    contract = decode_deployment_contract(github.contract.read_bytes())
    repository = {
        "full_name": worker.REPOSITORY,
        "id": worker.REPOSITORY_ID,
        "owner": {"id": worker.OWNER_ID},
    }
    github.overrides[ROOT_ENDPOINT] = {
        "id": 100,
        "run_attempt": 1,
        "event": "repository_dispatch",
        "path": worker.WORKFLOW,
        "head_branch": "main",
        "head_sha": contract.identity.controller.sha,
        "repository": repository,
        "head_repository": deepcopy(repository),
    }
    github.calls.clear()
    github.events.clear()
    github.writes.clear()
    original_artifact = github.contract.read_bytes()
    original_output = github.output.read_bytes()
    yield contract
    assert not github.writes
    assert not any("POST" in args for _, args in github.calls)
    assert not any("/statuses" in path for path, _ in github.calls)
    assert github.contract.read_bytes() == original_artifact
    assert github.output.read_bytes() == original_output


@pytest.mark.parametrize("scope", ["operator", "governance", "platform"])
@pytest.mark.parametrize("environment", ["test", "prod"])
def test_selected_worker_returns_exact_account_schedule(
    admitted, github, scope, environment
):
    steps = worker.recheck_worker(admitted, scope=scope, environment=environment)
    assert steps == tuple(
        step
        for step in admitted.schedule
        if step.scope == scope and step.environment == environment
    )
    assert [step.operation for step in steps] == ["plan", "apply", "drift"]
    assert github.calls[0][0] == ROOT_ENDPOINT
    assert [event[0] for event in github.events] == ["download"]
    assert any("/environments/" in path for path, _ in github.calls)


def test_legitimate_long_protected_approval_keeps_original_timestamps(
    admitted, github, monkeypatch
):
    created = github.evidence["comment"]["created_at"]

    class AfterApproval(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime.now(tz) + timedelta(days=3)

    monkeypatch.setattr(worker.preflight, "datetime", AfterApproval)
    evidence = worker.preflight.collect_evidence(github.request)
    with pytest.raises(ValueError, match="Expired command"):
        worker.preflight.validate_request_identity(github.request, evidence)
    assert worker.recheck_worker(admitted, scope="operator", environment="test")
    assert github.evidence["comment"]["created_at"] == created


@pytest.mark.parametrize(
    "name,value",
    [
        ("DEPLOYMENT_COORDINATOR_MODE", "inactive"),
        ("GITHUB_SHA", "d" * 40),
        ("GITHUB_RUN_ID", "101"),
        ("GITHUB_RUN_ATTEMPT", "2"),
        ("GITHUB_REPOSITORY", "foreign/repo"),
        ("GITHUB_REPOSITORY_ID", "1"),
        ("GITHUB_REPOSITORY_OWNER_ID", "1"),
        ("GITHUB_REF", "refs/heads/other"),
        ("GITHUB_WORKFLOW_REF", "foreign/workflow@refs/heads/main"),
        ("GITHUB_EVENT_NAME", "workflow_dispatch"),
    ],
)
def test_foreign_worker_context_stops_before_api(
    admitted, github, monkeypatch, name, value
):
    monkeypatch.setenv(name, value)
    with pytest.raises(ValueError):
        worker.recheck_worker(admitted, scope="operator", environment="test")
    assert not github.calls


@pytest.mark.parametrize(
    "scope,environment",
    [("unknown", "test"), ("operator", "stage"), ("", ""), (None, "test")],
)
def test_unknown_worker_node_stops_before_api(admitted, github, scope, environment):
    with pytest.raises(ValueError, match="not selected"):
        worker.recheck_worker(admitted, scope=scope, environment=environment)
    assert not github.calls


@pytest.mark.parametrize("scopes", [(), ("platform",)])
def test_unselected_or_docs_only_worker_is_rejected(github, monkeypatch, scopes):
    from deployment_controller_runtime import accept

    set_request(github, monkeypatch, scopes=scopes)
    contract = accept()
    github.calls.clear()
    with pytest.raises(ValueError, match="not selected"):
        worker.recheck_worker(contract, scope="operator", environment="test")
    assert not github.calls
    assert len(github.writes) == 1  # Initial admission only.


def test_prod_account_requires_original_prod_request(github, monkeypatch):
    from deployment_controller_runtime import accept

    set_request(github, monkeypatch, target="test")
    contract = accept()
    github.calls.clear()
    with pytest.raises(ValueError, match="not selected"):
        worker.recheck_worker(contract, scope="operator", environment="prod")
    assert not github.calls


@pytest.mark.parametrize("change", ["different", "missing"])
def test_installed_selector_must_match_admitted_bytes(
    admitted, github, monkeypatch, tmp_path, change
):
    path = tmp_path / "selector.py"
    if change == "different":
        path.write_text("# another installed selector")
    monkeypatch.setattr(worker.deployment_scopes, "__file__", str(path))
    with pytest.raises((ValueError, FileNotFoundError)):
        worker.recheck_worker(admitted, scope="operator", environment="test")
    assert not github.calls


@pytest.mark.parametrize(
    "path,value",
    [
        (("id",), 101),
        (("id",), "100"),
        (("run_attempt",), 2),
        (("run_attempt",), True),
        (("event",), "workflow_dispatch"),
        (("path",), ".github/workflows/foreign.yml"),
        (("head_branch",), "feature"),
        (("head_sha",), "d" * 40),
        (("repository", "id"), 1),
        (("repository", "id"), True),
        (("repository", "full_name"), "foreign/repo"),
        (("repository", "owner", "id"), 1),
        (("repository", "owner", "id"), True),
        (("head_repository", "id"), 1),
        (("head_repository", "full_name"), "foreign/repo"),
        (("repository",), None),
        (("repository", "owner"), None),
        (("head_repository",), None),
    ],
)
def test_actual_root_run_must_match_trusted_admission(admitted, github, path, value):
    current = github.overrides[ROOT_ENDPOINT]
    for key in path[:-1]:
        current = current[key]
    current[path[-1]] = value
    with pytest.raises(ValueError):
        worker.recheck_worker(admitted, scope="operator", environment="test")
    assert len(github.calls) == 1


@pytest.mark.parametrize("response", [None, [], RuntimeError("root unavailable")])
def test_unreadable_controller_run_fails_closed(admitted, github, response):
    github.overrides[ROOT_ENDPOINT] = response
    with pytest.raises((ValueError, RuntimeError)):
        worker.recheck_worker(admitted, scope="operator", environment="test")


@pytest.mark.parametrize(
    "path,value",
    [
        (("comment", "updated_at"), "2026-09-05T12:00:01Z"),
        (("comment", "user", "id"), 99),
        (("comment", "body"), "/pulumi test up"),
        (("run", "actor", "id"), 99),
        (("run", "run_attempt"), 2),
        (("run", "path"), ".github/workflows/foreign.yml"),
        (("run", "head_repository", "id"), 1),
        (("pr", "head", "sha"), "d" * 40),
        (("pr", "state"), "closed"),
        (("pr", "merged"), True),
        (("pr", "base", "ref"), "feature"),
        (("pr", "head", "repo", "full_name"), "foreign/repo"),
        (("pr", "head", "repo", "id"), 1),
        (("pr", "base", "repo", "owner", "id"), 1),
        (("permission",), "read"),
        (("pr", "changed_files"), 999),
    ],
)
def test_current_intake_pr_and_writer_are_reauthenticated(
    admitted, github, path, value
):
    current = github.evidence
    for key in path[:-1]:
        current = current[key]
    current[path[-1]] = value
    with pytest.raises(ValueError):
        worker.recheck_worker(admitted, scope="operator", environment="test")
    assert not any("/environments/" in path for path, _ in github.calls)


def test_forged_original_request_artifact_rejected(admitted, github):
    github.artifact["comment_id"] = "10"
    with pytest.raises(ValueError, match="artifact"):
        worker.recheck_worker(admitted, scope="operator", environment="test")


def test_same_head_with_new_base_requires_new_admission(admitted, github):
    github.evidence["pr"]["base"]["sha"] = "d" * 40
    github.overrides[f"repos/{worker.REPOSITORY}/compare/{'d' * 40}...{'a' * 40}"] = {
        "files": github.evidence["changed_file_records"]
    }
    with pytest.raises(ValueError, match="Admitted PR base moved"):
        worker.recheck_worker(admitted, scope="operator", environment="test")


def test_changed_classification_at_same_revisions_fails_closed(admitted, github):
    github.evidence["changed_file_records"][0]["filename"] = "README.md"
    with pytest.raises(ValueError, match="selection changed"):
        worker.recheck_worker(admitted, scope="operator", environment="test")


@pytest.mark.parametrize("observation", [1, 2])
def test_head_race_during_current_collection_is_rejected(admitted, github, observation):
    github.pr_observations = [deepcopy(github.evidence["pr"]) for _ in range(3)]
    github.pr_observations[observation]["head"]["sha"] = "d" * 40
    with pytest.raises(ValueError, match="head moved"):
        worker.recheck_worker(admitted, scope="operator", environment="test")


@pytest.mark.parametrize("failure", ["missing", "weakened", "incomplete"])
def test_current_environment_protection_required(admitted, github, failure):
    if failure == "missing":
        github.overrides[f"repos/{worker.REPOSITORY}/environments/operator"] = (
            RuntimeError("environment missing")
        )
    elif failure == "weakened":
        github.protected["can_admins_bypass"] = True
    else:
        github.policies["total_count"] = 2
    with pytest.raises((ValueError, RuntimeError)):
        worker.recheck_worker(admitted, scope="operator", environment="test")


def test_undecoded_or_mutated_contract_cannot_recheck(admitted, github):
    with pytest.raises(ValueError, match="Invalid deployment contract"):
        worker.recheck_worker({}, scope="operator", environment="test")
    assert not github.calls
