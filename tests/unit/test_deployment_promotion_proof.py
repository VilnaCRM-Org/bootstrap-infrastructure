"""Compose real admission, receipts, barriers and aggregate proof over fake APIs."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from copy import deepcopy
from dataclasses import asdict
from datetime import timedelta
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))

import deployment_account_barrier as barrier  # noqa: E402
import deployment_promotion_proof as runtime  # noqa: E402
from deployment_worker_receipt import (  # noqa: E402
    build_worker_receipt,
    persist_receipt,
)
from test_deployment_account_barrier import job, needs  # noqa: E402
from test_deployment_account_barrier_integration import (  # noqa: E402
    PLATFORM_ONLY,
)
from test_deployment_account_barrier_integration import (
    graph as _graph_fixture,  # noqa: E402
)
from test_deployment_controller import build  # noqa: E402
from test_deployment_receipt_runtime import ARTIFACT_PATH, publish_jobs  # noqa: E402
from test_deployment_receipt_runtime import github as _github_fixture  # noqa: E402
from test_deployment_receipt_runtime import (
    receipt_data as _receipt_fixture,  # noqa: E402
)
from test_deployment_worker_runtime import make_zip  # noqa: E402

github = _github_fixture
receipt_data = _receipt_fixture
graph = _graph_fixture
PROCESS = subprocess.run


def timestamp(minute, second=0):
    return f"2026-09-07T00:{minute:02}:{second:02}Z"


def publish_barrier(graph, account, value, identifier):
    payload = runtime._canonical(asdict(value)) + b"\n"
    raw = make_zip([(f"{account}.json", payload)])
    archive_sha = hashlib.sha256(raw).hexdigest()
    graph.archives[identifier] = raw
    metadata = deepcopy(graph.state.github.overrides[ARTIFACT_PATH])
    metadata.update(
        id=int(identifier),
        name=f"deployment-barrier-100-1-{account}",
        digest="sha256:" + archive_sha,
        size_in_bytes=len(raw),
    )
    graph.state.github.overrides[ARTIFACT_PATH.replace("/123", "/" + identifier)] = (
        metadata
    )
    return {
        **barrier.barrier_outputs(value),
        "barrier_file_sha256": hashlib.sha256(payload).hexdigest(),
        "artifact_id": identifier,
        "artifact_sha256": archive_sha,
    }


def publish_worker(graph, scope, account, identifier):
    state = graph.state
    receipt = build_worker_receipt(
        state.contract,
        scope=scope,
        environment=account,
        results=dict.fromkeys(
            ("plan", "destructive", "iam", "apply", "drift"), "success"
        ),
    )
    path = graph.directory / f"{scope}-{account}-receipt.json"
    outputs = persist_receipt(receipt, path)
    raw = make_zip([("receipt.json", path.read_bytes())])
    outputs.update(
        result="success",
        receipt_artifact_id=identifier,
        receipt_artifact_sha256=hashlib.sha256(raw).hexdigest(),
    )
    graph.archives[identifier] = raw
    metadata = deepcopy(state.github.overrides[ARTIFACT_PATH])
    metadata.update(
        id=int(identifier),
        name=f"deployment-receipt-100-1-{scope}-{account}-{state.contract.identity.head_sha}",
        digest="sha256:" + outputs["receipt_artifact_sha256"],
        size_in_bytes=len(raw),
    )
    state.github.overrides[ARTIFACT_PATH.replace("/123", "/" + identifier)] = metadata
    first_id = max(item["id"] for item in state.jobs) + 1
    for index, name in enumerate(runtime._worker_names(scope, account)):
        state.jobs.append(
            {**deepcopy(state.jobs[0]), "id": first_id + index, "name": name}
        )
    return outputs


def promotion_dependencies(graph):
    contract = graph.state.contract
    dependencies = needs(contract, "prod")
    identifier = 124
    for account in ("test", "prod"):
        for scope in contract.selection.stacks:
            if scope == graph.state.scope and account == "test":
                outputs = graph.state.outputs
            else:
                outputs = publish_worker(graph, scope, account, str(identifier))
                identifier += 1
            dependencies[f"{scope}_{account}"] = job(outputs=outputs)
    publish_jobs(graph.state)
    test = barrier.build_verified_barrier(
        contract,
        environment="test",
        needs_payload=runtime._barrier_needs(dependencies, "test"),
    )
    dependencies["whole_test"] = job(
        outputs=publish_barrier(graph, "test", test, "201")
    )
    prod = barrier.build_verified_barrier(
        contract,
        environment="prod",
        needs_payload=runtime._barrier_needs(dependencies, "prod"),
    )
    dependencies["whole_prod"] = job(
        outputs=publish_barrier(graph, "prod", prod, "202")
    )
    return dependencies


@pytest.fixture
def promotion(graph, monkeypatch):
    dependencies = promotion_dependencies(graph)
    # Synthetic API fixtures model distinct jobs; they are not hosted QA evidence.
    stages = {}
    for scope in graph.state.contract.selection.stacks:
        for account in ("test", "prod"):
            for index, name in enumerate(runtime._worker_names(scope, account)):
                stages[name] = index * 8
    for item in graph.state.jobs:
        minute = 2 if "_test / " in item["name"] else 4
        second = stages[item["name"]]
        item.update(
            started_at=timestamp(minute, second),
            completed_at=timestamp(minute, second + 4),
        )
    for index, (name, minute) in enumerate(
        zip(runtime.ROOT_JOBS, (0, 1, 3, 5), strict=True)
    ):
        graph.state.jobs.append(
            {
                **deepcopy(graph.state.jobs[0]),
                "id": 3000 + index,
                "name": name,
                "started_at": timestamp(minute),
                "completed_at": timestamp(minute + 1),
            }
        )
    publish_jobs(graph.state)
    graph.dependencies = dependencies
    graph.args = dict(
        artifact_id="999",
        artifact_sha256=graph.admission_digest,
        contract_sha256=graph.admission_file_digest,
    )
    graph.proof_path = graph.directory / "proof.json"
    graph.output_path = graph.directory / "proof-output"
    monkeypatch.setattr(
        runtime, "_download_zip", lambda identifier: graph.archives[identifier]
    )
    graph.downloads.clear()
    graph.state.github.calls.clear()
    return graph


def prove(graph):
    return runtime.build_promotion_proof(
        **graph.args, needs_payload=json.dumps(graph.dependencies)
    )


def cli(graph, monkeypatch):
    monkeypatch.setenv("PROMOTION_NEEDS", json.dumps(graph.dependencies))
    arguments = {
        **graph.args,
        "proof_path": str(graph.proof_path),
        "output": str(graph.output_path),
    }
    return runtime.main(
        [
            "prepare",
            *[
                part
                for name, value in arguments.items()
                for part in ("--" + name.replace("_", "-"), value)
            ],
        ]
    )


@pytest.mark.parametrize("receipt_data", [PLATFORM_ONLY], indirect=True)
def test_real_composition_binds_current_identity_and_both_accounts(promotion):
    proof = prove(promotion)
    assert proof["protocol"] == "central-v2"
    assert proof["schema_version"] == 2
    assert proof["evidence_kind"] == "receipt-and-job-provenance"
    assert proof["completion_kind"] == "apply-drift"
    assert proof["scopes"] == ["platform"]
    assert proof["identity"] == asdict(promotion.state.contract.identity)
    assert proof["admission"] == promotion.args
    assert proof["workers"] == {
        name: promotion.dependencies[name] for name in runtime.WORKERS
    }
    assert (
        proof["barriers"]["prod"]["barrier"]["test_barrier_digest"]
        == proof["barriers"]["test"]["barrier"]["barrier_digest"]
    )
    assert len(proof["jobs"]) == 18
    assert promotion.downloads == ["999", "123", "123", "124"]
    assert not promotion.proof_path.exists() and not promotion.output_path.exists()
    assert "plan_artifact" not in json.dumps(proof)


@pytest.mark.parametrize(
    "receipt_data",
    [("operator", "test", "up", ("operator", "governance", "platform"))],
    indirect=True,
)
@pytest.mark.parametrize("failed_account", [None, "test", "prod"])
def test_all_three_scopes_require_actual_operator_jobs(promotion, failed_account):
    if failed_account:
        selected = next(
            item
            for item in promotion.state.jobs
            if item["name"] == f"operator_{failed_account} / Apply saved operator plan"
        )
        selected["conclusion"] = "failure"
        publish_jobs(promotion.state)
        with pytest.raises(ValueError, match="did not complete"):
            prove(promotion)
        return
    proof = prove(promotion)
    assert proof["scopes"] == ["operator", "governance", "platform"]
    assert len(proof["jobs"]) == 46
    assert all(
        proof["workers"][name]["result"] == "success" for name in runtime.WORKERS
    )
    assert (
        proof["barriers"]["prod"]["barrier"]["test_barrier_digest"]
        == (proof["barriers"]["test"]["barrier"]["barrier_digest"])
    )


@pytest.mark.parametrize("receipt_data", [PLATFORM_ONLY], indirect=True)
def test_prepare_cli_writes_only_after_verification(promotion, monkeypatch):
    assert cli(promotion, monkeypatch) == 0
    payload = promotion.proof_path.read_bytes()
    assert payload == runtime._canonical(json.loads(payload)) + b"\n"
    outputs = dict(
        line.split("=", 1) for line in promotion.output_path.read_text().splitlines()
    )
    assert outputs["proof_file_sha256"] == hashlib.sha256(payload).hexdigest()
    assert outputs["proof_digest"] == hashlib.sha256(payload[:-1]).hexdigest()
    assert outputs["proof_file_sha256"] != outputs["proof_digest"]
    assert outputs["head_sha"] == promotion.state.contract.identity.head_sha
    assert "::" not in promotion.output_path.read_text()
    with pytest.raises(FileExistsError):
        cli(promotion, monkeypatch)


@pytest.mark.parametrize(
    "command,target,scopes",
    [
        ("plan", "prod", ("platform",)),
        ("up", "test", ("platform",)),
        ("up", "prod", ()),
    ],
)
def test_non_deployment_requests_rejected(monkeypatch, command, target, scopes):
    monkeypatch.setattr(
        runtime,
        "load_verified_admission",
        lambda **_: build(scopes, command=command, target=target),
    )
    with pytest.raises(ValueError, match="prod up|Empty selection"):
        runtime.build_promotion_proof(
            artifact_id="1",
            artifact_sha256="a" * 64,
            contract_sha256="b" * 64,
            needs_payload="{}",
        )


@pytest.mark.parametrize("receipt_data", [PLATFORM_ONLY], indirect=True)
@pytest.mark.parametrize(
    "field,value", [("permission", "read"), ("comment_body", "edited")]
)
def test_authentication_failure_has_no_proof_or_output(
    promotion, monkeypatch, field, value
):
    if field == "permission":
        promotion.state.github.evidence[field] = value
    else:
        promotion.state.github.evidence["comment"]["body"] = value
    with pytest.raises(ValueError):
        cli(promotion, monkeypatch)
    assert not promotion.proof_path.exists() and not promotion.output_path.exists()


@pytest.mark.parametrize("receipt_data", [PLATFORM_ONLY], indirect=True)
@pytest.mark.parametrize("name", runtime.ROOT_JOBS)
@pytest.mark.parametrize("result", ["failure", "cancelled", "skipped"])
def test_root_needs_failure_rejected(promotion, name, result):
    promotion.dependencies[name]["result"] = result
    with pytest.raises(ValueError, match="did not succeed"):
        prove(promotion)
    assert promotion.downloads == ["999"]


@pytest.mark.parametrize("receipt_data", [PLATFORM_ONLY], indirect=True)
@pytest.mark.parametrize("change", ["missing", "extra", "old_single_scope"])
def test_exact_aggregate_dependency_schema(promotion, change):
    if change == "missing":
        del promotion.dependencies["operator_prod"]
    elif change == "extra":
        promotion.dependencies["old_promotion"] = job()
    else:
        promotion.dependencies = {
            "preflight": job(),
            "test_apply": job(),
            "prod_apply": job(),
        }
    with pytest.raises(ValueError, match="graph differs"):
        prove(promotion)


def test_duplicate_needs_rejected():
    with pytest.raises(ValueError, match="Duplicate"):
        runtime._needs('{"preflight":{},"preflight":{}}')


@pytest.mark.parametrize("receipt_data", [PLATFORM_ONLY], indirect=True)
@pytest.mark.parametrize("account", ["test", "prod"])
@pytest.mark.parametrize(
    "change",
    ["schema", "digest", "selection", "file_hash", "zip_hash", "extra", "artifact_id"],
)
def test_barrier_outputs_fail_closed(promotion, account, change):
    outputs = promotion.dependencies[f"whole_{account}"]["outputs"]
    if change == "schema":
        del outputs["barrier_digest"]
    elif change == "extra":
        outputs["extra"] = "ignored"
    else:
        field = {
            "digest": "barrier_digest",
            "selection": "selection_digest",
            "file_hash": "barrier_file_sha256",
            "zip_hash": "artifact_sha256",
            "artifact_id": "artifact_id",
        }[change]
        outputs[field] = "0" if change == "artifact_id" else "f" * 64
    with pytest.raises(ValueError):
        prove(promotion)


@pytest.mark.parametrize("receipt_data", [PLATFORM_ONLY], indirect=True)
@pytest.mark.parametrize("account,identifier", [("test", "201"), ("prod", "202")])
@pytest.mark.parametrize(
    "change", ["expired", "name", "run", "zip", "file", "rehashed", "member"]
)
def test_barrier_artifact_authentication(promotion, account, identifier, change):
    metadata = promotion.state.github.overrides[
        ARTIFACT_PATH.replace("/123", "/" + identifier)
    ]
    outputs = promotion.dependencies[f"whole_{account}"]["outputs"]
    if change == "expired":
        metadata["expired"] = True
    elif change == "name":
        metadata["name"] = "governance-promotion"
    elif change == "run":
        metadata["workflow_run"]["id"] = 101
    elif change == "zip":
        promotion.archives[identifier] += b"tampered"
    else:
        payload = b'{"old_scope":"governance"}\n'
        name = "contract.json" if change == "member" else f"{account}.json"
        raw = make_zip([(name, payload)])
        promotion.archives[identifier] = raw
        archive_sha = hashlib.sha256(raw).hexdigest()
        outputs["artifact_sha256"] = archive_sha
        metadata.update(digest="sha256:" + archive_sha, size_in_bytes=len(raw))
        if change != "file":
            outputs["barrier_file_sha256"] = hashlib.sha256(payload).hexdigest()
    with pytest.raises(ValueError):
        prove(promotion)


@pytest.mark.parametrize("receipt_data", [PLATFORM_ONLY], indirect=True)
@pytest.mark.parametrize("name", runtime.ROOT_JOBS)
@pytest.mark.parametrize("change", ["missing", "duplicate", "failure", "running"])
def test_actual_root_jobs_required(promotion, name, change):
    row = next(item for item in promotion.state.jobs if item["name"] == name)
    if change == "missing":
        promotion.state.jobs.remove(row)
    elif change == "duplicate":
        promotion.state.jobs.append({**row, "id": row["id"] + 100})
    elif change == "failure":
        row["conclusion"] = "failure"
    else:
        row["status"] = "in_progress"
    publish_jobs(promotion.state)
    with pytest.raises(ValueError, match="promotion job|Promotion job"):
        prove(promotion)


@pytest.mark.parametrize("receipt_data", [PLATFORM_ONLY], indirect=True)
@pytest.mark.parametrize(
    "name,field,value",
    [
        ("whole_test", "completed_at", None),
        ("whole_test", "started_at", "bad"),
        ("whole_prod", "completed_at", "2026-99-01T00:00:00Z"),
        ("whole_prod", "started_at", timestamp(7)),
        ("validate_inputs", "started_at", timestamp(0)),
        ("whole_prod", "started_at", timestamp(3)),
        ("platform_test / Platform account plan", "started_at", timestamp(1)),
        ("platform_test / Platform account plan", "completed_at", timestamp(4)),
        ("platform_prod / Platform account plan", "started_at", timestamp(3)),
        ("platform_prod / Platform account plan", "completed_at", timestamp(6)),
    ],
)
def test_job_timing_cannot_skip_full_test_barrier(promotion, name, field, value):
    row = next(item for item in promotion.state.jobs if item["name"] == name)
    row[field] = value
    publish_jobs(promotion.state)
    with pytest.raises(ValueError, match="timestamp|precedes|preceded"):
        prove(promotion)


@pytest.mark.parametrize("receipt_data", [PLATFORM_ONLY], indirect=True)
@pytest.mark.parametrize("account", ["test", "prod"])
def test_real_receipt_cannot_hide_failed_iam_gate(promotion, account):
    row = next(
        item
        for item in promotion.state.jobs
        if item["name"] == f"platform_{account} / Platform IAM validation"
    )
    row["conclusion"] = "failure"
    publish_jobs(promotion.state)
    with pytest.raises(ValueError, match="iam_validation"):
        prove(promotion)


@pytest.mark.parametrize("receipt_data", [PLATFORM_ONLY], indirect=True)
def test_foreign_actual_job_identity_rejected(promotion):
    promotion.state.jobs[-1]["run_id"] = 101
    publish_jobs(promotion.state)
    with pytest.raises(ValueError, match="run_id"):
        prove(promotion)


@pytest.mark.parametrize("receipt_data", [PLATFORM_ONLY], indirect=True)
def test_incomplete_job_pagination_rejected(promotion):
    from test_deployment_receipt_runtime import JOBS_PATH

    promotion.state.github.overrides[f"{JOBS_PATH}?per_page=100&page=1"][
        "total_count"
    ] += 1
    with pytest.raises(ValueError, match="Incomplete"):
        prove(promotion)


def test_isolated_cli_ignores_pr_imports(tmp_path):
    marker = tmp_path / "injected"
    for name in ("json.py", "sitecustomize.py", "deployment_worker_runtime.py"):
        (tmp_path / name).write_text(f"open({str(marker)!r}, 'w').write('bad')\n")
    env = {**os.environ, "PYTHONPATH": str(tmp_path)}
    result = PROCESS(
        [sys.executable, "-I", runtime.__file__, "--help"],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert not marker.exists()
    control = PROCESS(
        [sys.executable, "-c", "import json"],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        check=False,
    )
    assert control.returncode == 0 and marker.exists()


@pytest.mark.parametrize(
    "receipt_data",
    [
        ("governance", "test", "up", ("governance",)),
        ("platform", "test", "up", ("governance", "platform")),
    ],
    indirect=True,
)
def test_all_selected_receipts_are_reauthenticated(promotion):
    proof = prove(promotion)
    scopes = promotion.state.contract.selection.stacks
    assert proof["scopes"] == list(scopes)
    assert len(proof["jobs"]) == 4 + 14 * len(scopes)
    assert all(
        proof["workers"][f"{scope}_{account}"]["result"] == "success"
        for scope in scopes
        for account in ("test", "prod")
    )


@pytest.mark.parametrize("receipt_data", [PLATFORM_ONLY], indirect=True)
def test_current_publisher_job_is_not_completed_evidence(promotion):
    promotion.state.jobs.append(
        {
            **promotion.state.jobs[0],
            "id": 4000,
            "name": "promotion",
            "status": "in_progress",
            "conclusion": None,
            "completed_at": None,
        }
    )
    publish_jobs(promotion.state)
    assert "promotion" not in prove(promotion)["jobs"]


@pytest.mark.parametrize("receipt_data", [PLATFORM_ONLY], indirect=True)
@pytest.mark.parametrize("scope", ["operator", "governance"])
def test_unselected_scope_cannot_present_success_or_receipts(promotion, scope):
    promotion.dependencies[f"{scope}_test"] = job(outputs=promotion.state.outputs)
    with pytest.raises(ValueError, match="did not skipped"):
        prove(promotion)


@pytest.mark.parametrize("receipt_data", [PLATFORM_ONLY], indirect=True)
@pytest.mark.parametrize("stage", range(7))
def test_every_prod_stage_waits_for_whole_test(promotion, stage):
    prod = [
        item
        for item in promotion.state.jobs
        if item["name"].startswith("platform_prod / ")
    ]
    prod[stage]["started_at"] = timestamp(3)
    publish_jobs(promotion.state)
    with pytest.raises(ValueError, match="PROD execution preceded full TEST"):
        prove(promotion)


@pytest.mark.parametrize("receipt_data", [PLATFORM_ONLY], indirect=True)
@pytest.mark.parametrize("identifier", ["201", "202"])
def test_failed_barrier_writes_nothing(promotion, monkeypatch, identifier):
    path = ARTIFACT_PATH.replace("/123", "/" + identifier)
    promotion.state.github.overrides[path]["expired"] = True
    with pytest.raises(ValueError):
        cli(promotion, monkeypatch)
    assert not promotion.proof_path.exists()
    assert not promotion.output_path.exists()


@pytest.mark.parametrize("receipt_data", [PLATFORM_ONLY], indirect=True)
def test_proof_omits_untrusted_metadata_bodies(promotion, monkeypatch, capsys):
    for row in promotion.state.jobs:
        row["steps"] = [{"name": "untrusted-raw-job-body"}]
    publish_jobs(promotion.state)
    assert cli(promotion, monkeypatch) == 0
    assert b"untrusted-raw-job-body" not in promotion.proof_path.read_bytes()
    assert "untrusted-raw-job-body" not in promotion.output_path.read_text()
    captured = capsys.readouterr()
    assert captured.out == promotion.output_path.read_text()
    assert captured.err == ""


@pytest.mark.parametrize("scope", ["operator", "governance", "platform"])
def test_timing_dependencies_match_installed_reusable_jobs(scope):
    path = (
        Path(__file__).resolve().parents[2]
        / ".github/workflows"
        / f"pulumi-{scope}-account.yml"
    )
    jobs = yaml.safe_load(path.read_text())["jobs"]
    assert runtime._worker_dependencies(scope) == {
        name: tuple(job.get("needs", ())) for name, job in jobs.items()
    }


def worker_stage(promotion, account, stage):
    scope = promotion.state.scope
    name = next(
        name
        for name, value in runtime._worker_names(scope, account).items()
        if value == stage
    )
    return next(row for row in promotion.state.jobs if row["name"] == name)


@pytest.mark.parametrize(
    "receipt_data",
    [
        (scope, "test", "up", (scope,))
        for scope in ("operator", "governance", "platform")
    ],
    indirect=True,
)
@pytest.mark.parametrize("account", ["test", "prod"])
@pytest.mark.parametrize(
    "predecessor,successor",
    [
        ("resolve", "preview"),
        ("preview", "destructive_diff"),
        ("preview", "iam_validation"),
        ("destructive_diff", "apply"),
        ("iam_validation", "apply"),
        ("apply", "post_apply_drift"),
        ("post_apply_drift", "receipt"),
    ],
)
def test_worker_stage_cannot_precede_its_authenticated_dependency(
    promotion, monkeypatch, account, predecessor, successor
):
    before = worker_stage(promotion, account, predecessor)
    after = worker_stage(promotion, account, successor)
    early = runtime._timestamp(before["completed_at"]) - timedelta(microseconds=1)
    after["started_at"] = early.isoformat().replace("+00:00", "Z")
    publish_jobs(promotion.state)
    with pytest.raises(ValueError, match="preceded .* completion"):
        cli(promotion, monkeypatch)
    assert not promotion.proof_path.exists()
    assert not promotion.output_path.exists()


@pytest.mark.parametrize(
    "receipt_data",
    [(scope, "test", "up", (scope,)) for scope in ("governance", "platform")],
    indirect=True,
)
@pytest.mark.parametrize("account", ["test", "prod"])
def test_serial_iam_gate_waits_for_destructive_gate(promotion, account):
    destructive = worker_stage(promotion, account, "destructive_diff")
    iam = worker_stage(promotion, account, "iam_validation")
    iam["started_at"] = destructive["started_at"]
    publish_jobs(promotion.state)
    with pytest.raises(ValueError, match="iam_validation preceded destructive_diff"):
        prove(promotion)


@pytest.mark.parametrize(
    "receipt_data", [("operator", "test", "up", ("operator",))], indirect=True
)
@pytest.mark.parametrize("account", ["test", "prod"])
@pytest.mark.parametrize("last_gate", ["iam_validation", "destructive_diff"])
def test_operator_parallel_gates_allow_either_completion_order(
    promotion, account, last_gate
):
    minute = 2 if account == "test" else 4
    for stage in ("iam_validation", "destructive_diff"):
        row = worker_stage(promotion, account, stage)
        row.update(
            started_at=timestamp(minute, 16),
            completed_at=timestamp(minute, 25 if stage == last_gate else 20),
        )
    publish_jobs(promotion.state)
    assert prove(promotion)["completion_kind"] == "apply-drift"


@pytest.mark.parametrize("receipt_data", [PLATFORM_ONLY], indirect=True)
@pytest.mark.parametrize("account", ["test", "prod"])
def test_same_instant_completion_and_start_is_valid(promotion, account):
    before = worker_stage(promotion, account, "apply")
    after = worker_stage(promotion, account, "post_apply_drift")
    after["started_at"] = before["completed_at"]
    publish_jobs(promotion.state)
    assert prove(promotion)["completion_kind"] == "apply-drift"
