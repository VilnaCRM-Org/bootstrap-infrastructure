"""Receipt provenance uses real validators over bounded fake GitHub transport."""

from __future__ import annotations

import hashlib
import json
import sys
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))

import deployment_receipt_runtime as runtime  # noqa: E402
from deployment_controller_runtime import accept  # noqa: E402
from deployment_worker_receipt import (  # noqa: E402
    build_worker_receipt,
    persist_receipt,
)
from test_deployment_controller_runtime import (  # noqa: E402
    github as _github_fixture,
)
from test_deployment_controller_runtime import set_request  # noqa: E402
from test_deployment_worker_runtime import make_zip  # noqa: E402

github = _github_fixture
ROOT = Path(__file__).resolve().parents[2]
ARTIFACT_PATH = f"repos/{runtime.REPOSITORY}/actions/artifacts/123"
JOBS_PATH = f"repos/{runtime.REPOSITORY}/actions/runs/100/attempts/1/jobs"


def publish_jobs(state):
    """Serve precisely paginated API responses, including unrelated root jobs."""
    for index in range(0, len(state.jobs), runtime.PAGE_SIZE):
        page = index // runtime.PAGE_SIZE + 1
        state.github.overrides[f"{JOBS_PATH}?per_page=100&page={page}"] = {
            "total_count": len(state.jobs),
            "jobs": deepcopy(state.jobs[index : index + runtime.PAGE_SIZE]),
        }


def publish_payload(state, payload):
    """Rehash transport after an edit, without granting provenance to its contents."""
    state.raw = make_zip([("receipt.json", payload)])
    state.outputs["receipt_artifact_sha256"] = hashlib.sha256(state.raw).hexdigest()
    state.outputs["receipt_file_sha256"] = hashlib.sha256(payload).hexdigest()
    state.github.overrides[ARTIFACT_PATH]["digest"] = (
        "sha256:" + state.outputs["receipt_artifact_sha256"]
    )
    state.github.overrides[ARTIFACT_PATH]["size_in_bytes"] = len(state.raw)


@pytest.fixture
def receipt_data(github, monkeypatch, tmp_path, request):
    """Build actual admission and receipt bytes; mock only remote observations."""
    scope, environment, command, *selected = getattr(
        request, "param", ("platform", "test", "up")
    )
    set_request(
        github, monkeypatch, command=command, scopes=selected[0] if selected else None
    )
    contract = accept()
    controller = contract.identity.controller
    repository = github.evidence["pr"]["base"]["repo"]
    github.overrides[f"repos/{runtime.REPOSITORY}/actions/runs/100"] = {
        "id": 100,
        "run_attempt": 1,
        "event": "repository_dispatch",
        "path": ".github/workflows/pulumi-pr-command-runner.yml",
        "head_branch": "main",
        "head_sha": controller.sha,
        "repository": deepcopy(repository),
        "head_repository": deepcopy(repository),
    }
    results = dict.fromkeys(("plan", "destructive", "iam", "apply", "drift"), "success")
    if command == "plan":
        results.update(apply="skipped", drift="skipped")
    receipt = build_worker_receipt(
        contract, scope=scope, environment=environment, results=results
    )
    path = tmp_path / "receipt.json"
    outputs = persist_receipt(receipt, path)
    outputs.update(result="success", receipt_artifact_id="123")
    github.overrides[ARTIFACT_PATH] = {
        "id": 123,
        "name": (
            f"deployment-receipt-100-1-{scope}-{environment}"
            f"-{contract.identity.head_sha}"
        ),
        "expired": False,
        "workflow_run": {
            "id": 100,
            "repository_id": contract.identity.repository_id,
            "head_repository_id": contract.identity.repository_id,
            "head_branch": "main",
            "head_sha": controller.sha,
        },
    }
    jobs = []
    for index, (name, stage) in enumerate(
        runtime._worker_names(scope, environment).items()
    ):
        skipped = command == "plan" and stage in ("apply", "post_apply_drift")
        jobs.append(
            {
                "id": index + 1000,
                "name": name,
                "run_id": 100,
                "run_attempt": 1,
                "run_url": f"https://api.github.com/repos/{runtime.REPOSITORY}/actions/runs/100",
                "head_sha": controller.sha,
                "head_branch": "main",
                "status": "completed",
                "conclusion": "skipped" if skipped else "success",
            }
        )
    state = SimpleNamespace(
        github=github,
        contract=contract,
        receipt=receipt,
        payload=path.read_bytes(),
        outputs=outputs,
        jobs=jobs,
        scope=scope,
        environment=environment,
    )
    publish_payload(state, state.payload)
    publish_jobs(state)
    monkeypatch.setattr(runtime, "_download_zip", lambda identifier: state.raw)
    github.calls.clear()
    github.writes.clear()
    yield state
    assert not github.writes
    assert not any("POST" in arguments for _, arguments in github.calls)


def load(state, **changes):
    return runtime.load_verified_receipt(
        state.contract,
        **{
            "scope": state.scope,
            "environment": state.environment,
            "outputs": state.outputs,
            **changes,
        },
    )


@pytest.mark.parametrize(
    "receipt_data",
    [
        (scope, environment, command)
        for scope in ("platform", "governance", "operator")
        for environment in ("test", "prod")
        for command in ("up", "plan")
    ],
    indirect=True,
)
def test_authenticates_selected_node_and_all_actual_jobs(receipt_data):
    assert load(receipt_data) == receipt_data.receipt
    paths = [path for path, _ in receipt_data.github.calls]
    assert ARTIFACT_PATH in paths
    assert f"{JOBS_PATH}?per_page=100&page=1" in paths
    assert any("/environments/" in path for path in paths)


@pytest.mark.parametrize("scope", ["platform", "governance", "operator"])
def test_fixed_job_names_and_outputs_match_installed_reusable_workers(scope):
    workflow = yaml.safe_load(
        (ROOT / f".github/workflows/pulumi-{scope}-account.yml").read_text()
    )
    for environment in ("test", "prod"):
        assert runtime._worker_names(scope, environment) == {
            f"{scope}_{environment} / {job['name']}": stage
            for stage, job in workflow["jobs"].items()
        }
    assert set(workflow["on"]["workflow_call"]["outputs"]) == runtime.OUTPUT_FIELDS


@pytest.mark.parametrize(
    "scope,environment",
    [
        ("unknown", "test"),
        (None, "test"),
        ([], "test"),
        ("platform", "stage"),
        ("platform", []),
    ],
)
def test_unsupported_nodes_fail_before_io(receipt_data, scope, environment):
    with pytest.raises(ValueError):
        load(receipt_data, scope=scope, environment=environment)
    assert not receipt_data.github.calls


@pytest.mark.parametrize("outputs", [None, [], {}, True])
def test_malformed_output_envelopes_fail_before_io(receipt_data, outputs):
    with pytest.raises(ValueError):
        load(receipt_data, outputs=outputs)
    assert not receipt_data.github.calls


@pytest.mark.parametrize("field", sorted(runtime.OUTPUT_FIELDS))
@pytest.mark.parametrize("value", [None, True, "wrong"])
def test_each_output_binding_rejects_wrong_values(receipt_data, field, value):
    receipt_data.outputs[field] = value
    with pytest.raises(ValueError):
        load(receipt_data)


@pytest.mark.parametrize("change", ["missing", "extra"])
def test_output_fields_are_closed(receipt_data, change):
    if change == "missing":
        del receipt_data.outputs["result"]
    else:
        receipt_data.outputs["arbitrary"] = "success"
    with pytest.raises(ValueError):
        load(receipt_data)


@pytest.mark.parametrize(
    "field,value",
    [
        ("name", "deployment-selection-100-1"),
        ("name", "deployment-receipt-100-1-governance-test-" + "a" * 40),
        ("expired", True),
        ("id", 124),
        ("digest", "sha256:" + "f" * 64),
    ],
)
def test_artifact_identity_must_match_trusted_worker_edge(receipt_data, field, value):
    receipt_data.github.overrides[ARTIFACT_PATH][field] = value
    with pytest.raises(ValueError):
        load(receipt_data)


@pytest.mark.parametrize(
    "field,value",
    [
        ("id", 101),
        ("repository_id", 1),
        ("head_repository_id", 1),
        ("head_sha", "f" * 40),
        ("head_branch", "feature"),
    ],
)
def test_foreign_artifact_run_is_rejected(receipt_data, field, value):
    receipt_data.github.overrides[ARTIFACT_PATH]["workflow_run"][field] = value
    with pytest.raises(ValueError):
        load(receipt_data)


def test_zip_digest_must_match_downloaded_bytes(receipt_data):
    receipt_data.raw += b"changed"
    with pytest.raises(ValueError, match="ZIP SHA256"):
        load(receipt_data)


def test_file_digest_is_distinct_from_semantic_digest(receipt_data):
    receipt_data.outputs["receipt_file_sha256"] = receipt_data.outputs["receipt_digest"]
    with pytest.raises(ValueError, match="file SHA256"):
        load(receipt_data)


@pytest.mark.parametrize(
    "change", ["failure", "scope", "identity", "duplicate", "unknown"]
)
def test_rehashed_receipt_edits_cannot_bypass_strict_semantics(receipt_data, change):
    document = json.loads(receipt_data.payload)
    if change == "failure":
        document["stages"][0]["result"] = "failure"
    elif change == "scope":
        document["scope"] = "governance"
    elif change == "identity":
        document["identity"]["head_sha"] = "b" * 40
    elif change == "unknown":
        document["unexpected"] = True
    payload = json.dumps(document).encode()
    if change == "duplicate":
        payload = payload.replace(
            b'"scope": "platform"', b'"scope": "platform", "scope": "platform"'
        )
    publish_payload(receipt_data, payload)
    with pytest.raises(ValueError):
        load(receipt_data)


@pytest.mark.parametrize(
    "field,value",
    [
        ("id", True),
        ("id", 0),
        ("run_id", 101),
        ("run_id", True),
        ("run_attempt", 2),
        ("run_attempt", True),
        ("head_sha", "f" * 40),
        ("head_branch", "feature"),
        ("run_url", "https://api.github.com/repos/foreign/repo/actions/runs/100"),
        ("name", None),
    ],
)
def test_job_provenance_is_exact(receipt_data, field, value):
    receipt_data.jobs[0][field] = value
    publish_jobs(receipt_data)
    with pytest.raises(ValueError):
        load(receipt_data)


@pytest.mark.parametrize(
    "receipt_data",
    [
        ("platform", "test", "up"),
        ("operator", "test", "up"),
        ("operator", "prod", "up"),
    ],
    indirect=True,
)
@pytest.mark.parametrize("stage", range(7))
@pytest.mark.parametrize("result", ["failure", "cancelled", "skipped", None])
def test_no_selected_up_stage_may_fail_or_skip(receipt_data, stage, result):
    receipt_data.jobs[stage]["conclusion"] = result
    publish_jobs(receipt_data)
    with pytest.raises(ValueError):
        load(receipt_data)


@pytest.mark.parametrize(
    "receipt_data",
    [
        ("platform", "test", "up"),
        ("operator", "test", "up"),
        ("operator", "prod", "up"),
    ],
    indirect=True,
)
@pytest.mark.parametrize("stage", range(7))
def test_every_selected_stage_must_exist(receipt_data, stage):
    receipt_data.jobs.pop(stage)
    publish_jobs(receipt_data)
    with pytest.raises(ValueError, match="Missing selected"):
        load(receipt_data)


@pytest.mark.parametrize(
    "change",
    [
        "duplicate_id",
        "duplicate_name",
        "unexpected_stage",
        "wrong_account",
        "wrong_scope",
        "running",
        "malformed",
    ],
)
def test_job_inventory_cannot_substitute_other_evidence(receipt_data, change):
    if change in ("duplicate_id", "duplicate_name"):
        job = deepcopy(receipt_data.jobs[0])
        if change == "duplicate_name":
            job["id"] = 2000
        receipt_data.jobs.append(job)
    elif change == "unexpected_stage":
        receipt_data.jobs[0]["name"] = "platform_test / Fake success"
    elif change in ("wrong_account", "wrong_scope"):
        replacement = (
            "platform_prod" if change == "wrong_account" else "governance_test"
        )
        receipt_data.jobs[0]["name"] = receipt_data.jobs[0]["name"].replace(
            "platform_test", replacement
        )
    elif change == "running":
        receipt_data.jobs[0]["status"] = "in_progress"
    else:
        receipt_data.jobs[0] = None
    publish_jobs(receipt_data)
    with pytest.raises(ValueError):
        load(receipt_data)


@pytest.mark.parametrize(
    "response",
    [
        None,
        [],
        {"total_count": True, "jobs": []},
        {"total_count": 0, "jobs": []},
        {"total_count": 501, "jobs": []},
        {"total_count": 7, "jobs": None},
        {"total_count": 7, "jobs": []},
    ],
)
def test_malformed_or_incomplete_page_is_rejected(receipt_data, response):
    receipt_data.github.overrides[f"{JOBS_PATH}?per_page=100&page=1"] = response
    with pytest.raises(ValueError):
        load(receipt_data)


def add_unrelated_jobs(state):
    template = state.jobs[0]
    state.jobs = [
        {
            **template,
            "id": index + 2000,
            "name": f"Unrelated {index}",
            "status": "in_progress",
            "conclusion": None,
        }
        for index in range(100)
    ] + state.jobs
    publish_jobs(state)


def test_complete_pagination_includes_selected_jobs_after_first_page(receipt_data):
    add_unrelated_jobs(receipt_data)
    assert load(receipt_data) == receipt_data.receipt
    assert any("page=2" in path for path, _ in receipt_data.github.calls)


@pytest.mark.parametrize("change", ["count", "short", "duplicate"])
def test_paginated_inventory_rejects_races_and_repeated_evidence(receipt_data, change):
    add_unrelated_jobs(receipt_data)
    second = receipt_data.github.overrides[f"{JOBS_PATH}?per_page=100&page=2"]
    if change == "count":
        second["total_count"] += 1
    elif change == "short":
        second["jobs"].pop()
    else:
        second["jobs"][0] = deepcopy(receipt_data.jobs[0])
    with pytest.raises(ValueError):
        load(receipt_data)


@pytest.mark.parametrize("receipt_data", [("platform", "test", "plan")], indirect=True)
@pytest.mark.parametrize("stage", [4, 5])
def test_plan_cannot_receipt_actual_apply_or_drift_execution(receipt_data, stage):
    receipt_data.jobs[stage]["conclusion"] = "success"
    publish_jobs(receipt_data)
    with pytest.raises(ValueError):
        load(receipt_data)


@pytest.mark.parametrize(
    "receipt_data",
    [
        ("platform", "test", "up"),
        ("operator", "test", "up"),
        ("operator", "prod", "up"),
    ],
    indirect=True,
)
def test_current_source_and_permission_are_rechecked(receipt_data):
    receipt_data.github.evidence["permission"] = "read"
    with pytest.raises(ValueError):
        load(receipt_data)
    assert ARTIFACT_PATH not in [path for path, _ in receipt_data.github.calls]
