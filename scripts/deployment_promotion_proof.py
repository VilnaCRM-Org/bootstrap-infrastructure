"""Reauthenticate aggregate receipt/job evidence without publishing promotion.

Only the installed root may supply admission references and PROMOTION_NEEDS.
A persisted proof is a reviewable snapshot, not publishing authority: the future
publisher must reauthenticate it. No independent plan-artifact provenance is
claimed by this receipt/job protocol.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import pulumi_command_preflight as preflight  # noqa: E402
from deployment_account_barrier import (  # noqa: E402
    _job,
    barrier_outputs,
    build_verified_barrier,
)
from deployment_contract_io import _load_document  # noqa: E402
from deployment_controller import (  # noqa: E402
    AccountBarrier,
    DeploymentContract,
    _object,
)
from deployment_receipt_runtime import _complete_jobs, _worker_names  # noqa: E402
from deployment_scopes import STACK_ORDER  # noqa: E402
from deployment_worker_runtime import (  # noqa: E402
    _check_artifact_arguments,
    _contract_bytes,
    _download_zip,
    _verify_artifact,
    load_verified_admission,
)

ROOT_JOBS = ("preflight", "validate_inputs", "whole_test", "whole_prod")
WORKERS = tuple(
    f"{scope}_{account}" for account in ("test", "prod") for scope in STACK_ORDER
)
BARRIER_OUTPUTS = {
    "barrier_digest",
    "environment",
    "completion_kind",
    "selection_digest",
    "contract_digest",
    "barrier_file_sha256",
    "artifact_id",
    "artifact_sha256",
}


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()


def _needs(payload: str) -> dict[str, dict[str, Any]]:
    document = _object(_load_document(payload), "Promotion dependencies")
    preflight.require(
        set(document) == {*ROOT_JOBS, *WORKERS}, "Promotion dependency graph differs"
    )
    jobs = {name: _job(value) for name, value in document.items()}
    for name in ROOT_JOBS:
        preflight.require(jobs[name]["result"] == "success", f"{name} did not succeed")
    return jobs


def _barrier_needs(jobs: dict[str, dict[str, Any]], account: str) -> str:
    names = {"preflight", "validate_inputs"}
    names.update(f"{scope}_test" for scope in STACK_ORDER)
    if account == "prod":
        names.update(f"{scope}_prod" for scope in STACK_ORDER)
        names.add("whole_test")
    return json.dumps({name: jobs[name] for name in sorted(names)})


def _verify_barrier_artifact(
    contract: DeploymentContract, barrier: AccountBarrier, outputs: dict[str, str]
) -> dict[str, str]:
    preflight.require(set(outputs) == BARRIER_OUTPUTS, "Barrier output fields differ")
    for name, value in barrier_outputs(barrier).items():
        preflight.require(outputs[name] == value, "Recomputed barrier output differs")
    identifier, archive_sha, file_sha = (
        outputs["artifact_id"],
        outputs["artifact_sha256"],
        outputs["barrier_file_sha256"],
    )
    _check_artifact_arguments(identifier, archive_sha, file_sha)
    controller = contract.identity.controller
    _verify_artifact(
        identifier,
        archive_sha,
        controller,
        expected_name=f"deployment-barrier-{controller.run_id}-1-{barrier.environment}",
    )
    archive = _download_zip(identifier)
    preflight.require(
        hashlib.sha256(archive).hexdigest() == archive_sha, "Barrier ZIP SHA256 differs"
    )
    payload = _contract_bytes(archive, member_name=f"{barrier.environment}.json")
    preflight.require(
        hashlib.sha256(payload).hexdigest() == file_sha, "Barrier file SHA256 differs"
    )
    preflight.require(
        payload == _canonical(asdict(barrier)) + b"\n",
        "Barrier artifact differs from recomputed evidence",
    )
    return dict(outputs)


def _timestamp(value: object) -> datetime:
    preflight.require(
        type(value) is str
        and re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z",
            value,
        )
        is not None,
        "Invalid job timestamp",
    )
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        raise ValueError("Invalid job timestamp") from None


def _job_evidence(job: dict[str, Any]) -> dict[str, Any]:
    preflight.require(
        job.get("status") == "completed" and job.get("conclusion") == "success",
        "Promotion job did not complete successfully",
    )
    start, end = _timestamp(job.get("started_at")), _timestamp(job.get("completed_at"))
    preflight.require(start <= end, "Job completion precedes start")
    return {
        name: job[name]
        for name in (
            "id",
            "name",
            "run_id",
            "run_attempt",
            "run_url",
            "head_sha",
            "head_branch",
            "status",
            "conclusion",
            "started_at",
            "completed_at",
        )
    }


def _verify_job_graph(contract: DeploymentContract) -> dict[str, dict[str, Any]]:
    expected = set(ROOT_JOBS)
    for scope in contract.selection.stacks:
        for account in ("test", "prod"):
            expected.update(_worker_names(scope, account))
    selected: dict[str, dict[str, Any]] = {}
    for job in _complete_jobs(contract.identity.controller):
        name = job["name"]
        if name in expected:
            preflight.require(name not in selected, "Duplicate promotion job name")
            selected[name] = _job_evidence(job)
    preflight.require(set(selected) == expected, "Missing promotion jobs")
    _verify_order(contract, selected)
    return selected


def _verify_order(
    contract: DeploymentContract, jobs: dict[str, dict[str, Any]]
) -> None:
    def start(name: str) -> datetime:
        return _timestamp(jobs[name]["started_at"])

    def end(name: str) -> datetime:
        return _timestamp(jobs[name]["completed_at"])

    preflight.require(
        end("preflight") <= start("validate_inputs"),
        "Input validation preceded admission",
    )
    preflight.require(
        end("whole_test") <= start("whole_prod"), "PROD barrier preceded TEST"
    )
    for scope in contract.selection.stacks:
        for name in _worker_names(scope, "test"):
            preflight.require(
                end("validate_inputs") <= start(name),
                "TEST execution preceded validation",
            )
            preflight.require(
                end(name) <= start("whole_test"),
                "TEST barrier preceded TEST completion",
            )
        for name in _worker_names(scope, "prod"):
            preflight.require(
                end("whole_test") <= start(name),
                "PROD execution preceded full TEST completion",
            )
            preflight.require(
                end(name) <= start("whole_prod"),
                "PROD barrier preceded PROD completion",
            )


def build_promotion_proof(
    *, artifact_id: str, artifact_sha256: str, contract_sha256: str, needs_payload: str
) -> dict[str, Any]:
    """Authenticate both original barriers and receipts; never authorize publishing."""
    contract = load_verified_admission(
        artifact_id=artifact_id,
        artifact_sha256=artifact_sha256,
        contract_sha256=contract_sha256,
    )
    preflight.require(
        contract.identity.command == "up"
        and contract.identity.target_environment == "prod",
        "Promotion requires prod up",
    )
    preflight.require(
        bool(contract.selection.stacks), "Empty selection is not deployment proof"
    )
    jobs = _needs(needs_payload)
    barriers = {}
    for account in ("test", "prod"):
        barrier = build_verified_barrier(
            contract, environment=account, needs_payload=_barrier_needs(jobs, account)
        )
        barriers[account] = {
            "barrier": asdict(barrier),
            "artifact": _verify_barrier_artifact(
                contract, barrier, jobs[f"whole_{account}"]["outputs"]
            ),
        }
    actual_jobs = _verify_job_graph(contract)
    return {
        "schema_version": 2,
        "protocol": "central-v2",
        "evidence_kind": "receipt-and-job-provenance",
        "completion_kind": "apply-drift",
        "identity": asdict(contract.identity),
        "scopes": list(contract.selection.stacks),
        "selector_sha256": contract.selector_sha256,
        "selection_digest": contract.selection_digest,
        "contract_digest": contract.contract_digest,
        "admission": {
            "artifact_id": artifact_id,
            "artifact_sha256": artifact_sha256,
            "contract_sha256": contract_sha256,
        },
        "barriers": barriers,
        "workers": {name: jobs[name] for name in WORKERS},
        "jobs": actual_jobs,
    }


def _persist_proof(proof: dict[str, Any], path: Path) -> dict[str, str]:
    payload = _canonical(proof)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(payload + b"\n")
    return {
        "proof_digest": hashlib.sha256(payload).hexdigest(),
        "proof_file_sha256": hashlib.sha256(payload + b"\n").hexdigest(),
        "head_sha": proof["identity"]["head_sha"],
        "base_sha": proof["identity"]["base_sha"],
        "selection_digest": proof["selection_digest"],
        "contract_digest": proof["contract_digest"],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare",))
    for name in ("artifact-id", "artifact-sha256", "contract-sha256", "output"):
        parser.add_argument(f"--{name}", required=True)
    parser.add_argument("--proof-path", type=Path, required=True)
    args = parser.parse_args(argv)
    proof = build_promotion_proof(
        artifact_id=args.artifact_id,
        artifact_sha256=args.artifact_sha256,
        contract_sha256=args.contract_sha256,
        needs_payload=os.environ.get("PROMOTION_NEEDS", ""),
    )
    preflight.write_outputs(_persist_proof(proof, args.proof_path), args.output)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
