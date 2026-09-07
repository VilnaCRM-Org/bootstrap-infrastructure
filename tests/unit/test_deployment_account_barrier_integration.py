"""Compose real admission, artifact, job and barrier checks over fake transport."""

from __future__ import annotations

import hashlib
import json
import sys
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))

import deployment_account_barrier as barrier  # noqa: E402
import deployment_receipt_runtime as receipt_runtime  # noqa: E402
import deployment_worker_runtime as worker_runtime  # noqa: E402
from deployment_worker_receipt import (  # noqa: E402
    build_worker_receipt,
    persist_receipt,
)
from test_deployment_account_barrier import job, needs  # noqa: E402
from test_deployment_receipt_runtime import (  # noqa: E402
    ARTIFACT_PATH,
    publish_jobs,
)
from test_deployment_receipt_runtime import (
    github as _github_fixture,
)
from test_deployment_receipt_runtime import (
    receipt_data as _receipt_fixture,
)
from test_deployment_worker_runtime import make_zip  # noqa: E402

github = _github_fixture
receipt_data = _receipt_fixture
PLATFORM_ONLY = ("platform", "test", "up", ("platform",))


@pytest.fixture
def graph(receipt_data, monkeypatch, tmp_path):
    """Serve real canonical admission/receipt archives without replacing validators."""
    state = receipt_data
    admission_payload = state.github.contract.read_bytes()
    admission_raw = make_zip([("contract.json", admission_payload)])
    admission_digest = hashlib.sha256(admission_raw).hexdigest()
    admission = deepcopy(state.github.overrides[ARTIFACT_PATH])
    admission.update(
        id=999,
        name="deployment-selection-100-1",
        digest=f"sha256:{admission_digest}",
        size_in_bytes=len(admission_raw),
    )
    state.github.overrides[ARTIFACT_PATH.replace("/123", "/999")] = admission
    archives = {"999": admission_raw, "123": state.raw}
    downloads = []

    def download(identifier):
        downloads.append(identifier)
        return archives[identifier]

    monkeypatch.setattr(worker_runtime, "_download_zip", download)
    monkeypatch.setattr(receipt_runtime, "_download_zip", download)
    return SimpleNamespace(
        state=state,
        archives=archives,
        downloads=downloads,
        admission_digest=admission_digest,
        admission_file_digest=hashlib.sha256(admission_payload).hexdigest(),
        directory=tmp_path,
    )


def account_needs(graph, environment):
    result = needs(graph.state.contract, environment)
    result["platform_test"] = job(outputs=graph.state.outputs)
    return result


def run_cli(graph, monkeypatch, environment, dependencies):
    monkeypatch.setenv("BARRIER_NEEDS", json.dumps(dependencies))
    path = graph.directory / f"barrier-{environment}.json"
    output = graph.directory / f"output-{environment}"
    code = barrier.main(
        [
            "--artifact-id",
            "999",
            "--artifact-sha256",
            graph.admission_digest,
            "--contract-sha256",
            graph.admission_file_digest,
            "--environment",
            environment,
            "--barrier-path",
            str(path),
            "--output",
            str(output),
        ]
    )
    return code, path, output


def publish_prod(graph):
    """Add a second actual receipt and jobs while preserving the original TEST data."""
    state = graph.state
    contract = state.contract
    receipt = build_worker_receipt(
        contract,
        scope="platform",
        environment="prod",
        results=dict.fromkeys(
            ("plan", "destructive", "iam", "apply", "drift"), "success"
        ),
    )
    path = graph.directory / "prod-receipt.json"
    outputs = persist_receipt(receipt, path)
    raw = make_zip([("receipt.json", path.read_bytes())])
    outputs.update(
        result="success",
        receipt_artifact_id="124",
        receipt_artifact_sha256=hashlib.sha256(raw).hexdigest(),
    )
    graph.archives["124"] = raw
    metadata = deepcopy(state.github.overrides[ARTIFACT_PATH])
    metadata.update(
        id=124,
        name=f"deployment-receipt-100-1-platform-prod-{contract.identity.head_sha}",
        digest="sha256:" + outputs["receipt_artifact_sha256"],
        size_in_bytes=len(raw),
    )
    state.github.overrides[ARTIFACT_PATH.replace("/123", "/124")] = metadata
    prod_jobs = deepcopy(state.jobs)
    for item in prod_jobs:
        item["id"] += 100
        item["name"] = item["name"].replace("platform_test /", "platform_prod /")
    state.jobs.extend(prod_jobs)
    publish_jobs(state)
    return outputs


def production_needs(graph):
    """Obtain real TEST proof once, then require the PROD path to authenticate again."""
    contract = graph.state.contract
    test = barrier.build_verified_barrier(
        contract,
        environment="test",
        needs_payload=json.dumps(account_needs(graph, "test")),
    )
    result = account_needs(graph, "prod")
    result["whole_test"] = job(outputs=barrier.barrier_outputs(test))
    result["platform_prod"] = job(outputs=publish_prod(graph))
    graph.downloads.clear()
    graph.state.github.calls.clear()
    return result, test


@pytest.mark.parametrize("receipt_data", [PLATFORM_ONLY], indirect=True)
def test_cli_composes_authenticated_platform_test_receipt_and_barrier(
    graph, monkeypatch
):
    code, path, output = run_cli(
        graph, monkeypatch, "test", account_needs(graph, "test")
    )
    assert code == 0
    result = json.loads(path.read_bytes())
    assert result["environment"] == "test"
    assert result["completion_kind"] == "apply-drift"
    assert result["receipt_digests"] == [
        ["platform", graph.state.outputs["receipt_digest"]]
    ]
    assert result["test_barrier_digest"] is None
    assert graph.downloads == ["999", "123"]
    assert "barrier_digest=" + result["barrier_digest"] in output.read_text()


@pytest.mark.parametrize("receipt_data", [PLATFORM_ONLY], indirect=True)
def test_valid_receipt_cannot_hide_failed_actual_iam_job(graph, monkeypatch):
    graph.state.jobs[3]["conclusion"] = "failure"
    publish_jobs(graph.state)
    with pytest.raises(ValueError, match="iam_validation"):
        run_cli(graph, monkeypatch, "test", account_needs(graph, "test"))
    assert graph.downloads == ["999", "123"]
    assert not (graph.directory / "barrier-test.json").exists()
    assert not (graph.directory / "output-test").exists()


@pytest.mark.parametrize("receipt_data", [PLATFORM_ONLY], indirect=True)
def test_prod_reauthenticates_test_before_accepting_prod_receipt(graph, monkeypatch):
    dependencies, test = production_needs(graph)
    code, path, _ = run_cli(graph, monkeypatch, "prod", dependencies)
    assert code == 0
    result = json.loads(path.read_bytes())
    assert result["environment"] == "prod"
    assert result["test_barrier_digest"] == test.barrier_digest
    assert graph.downloads == ["999", "123", "124"]


@pytest.mark.parametrize("receipt_data", [PLATFORM_ONLY], indirect=True)
@pytest.mark.parametrize("change", ["expired", "zip", "job"])
def test_cached_test_digest_cannot_replace_fresh_artifact_and_job_checks(
    graph, monkeypatch, change
):
    dependencies, test = production_needs(graph)
    if change == "expired":
        graph.state.github.overrides[ARTIFACT_PATH]["expired"] = True
    elif change == "zip":
        graph.archives["123"] += b"tampered"
    else:
        graph.state.jobs[3]["conclusion"] = "failure"
        publish_jobs(graph.state)
    assert (
        dependencies["whole_test"]["outputs"]["barrier_digest"] == test.barrier_digest
    )
    with pytest.raises(ValueError):
        run_cli(graph, monkeypatch, "prod", dependencies)
    assert "124" not in graph.downloads
    assert ARTIFACT_PATH.replace("/123", "/124") not in [
        path for path, _ in graph.state.github.calls
    ]
    assert not (graph.directory / "barrier-prod.json").exists()
    assert not (graph.directory / "output-prod").exists()


@pytest.mark.parametrize(
    "receipt_data",
    [("platform", "test", "up", ("operator", "platform"))],
    indirect=True,
)
def test_operator_selection_requires_authenticated_worker_receipt(graph, monkeypatch):
    with pytest.raises(ValueError, match="Worker outputs must contain exactly"):
        run_cli(graph, monkeypatch, "test", account_needs(graph, "test"))
    assert graph.downloads == ["999"]
    assert not (graph.directory / "barrier-test.json").exists()
