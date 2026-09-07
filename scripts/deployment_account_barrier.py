"""Authenticate selected worker receipts before advancing a root account graph.

The installed root supplies ``BARRIER_NEEDS`` from GitHub's ``toJSON(needs)``.
This credential-free runtime does not publish promotion or grant AWS access.
PROD recomputes the complete TEST barrier from authenticated worker evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import pulumi_command_preflight as preflight  # noqa: E402
from deployment_contract_io import _load_document  # noqa: E402
from deployment_controller import (  # noqa: E402
    AccountBarrier,
    AccountNodeReceipt,
    DeploymentContract,
    _object,
    _validate_contract,
    reduce_account_barrier,
)
from deployment_receipt_runtime import load_verified_receipt  # noqa: E402
from deployment_scopes import STACK_ORDER  # noqa: E402
from deployment_worker_runtime import load_verified_admission  # noqa: E402

RESULTS = {"success", "failure", "cancelled", "skipped"}


def _job(value: object) -> dict[str, Any]:
    """Accept only the documented result/output shape from the trusted root."""
    job = _object(value, "Root job")
    preflight.require(set(job) == {"result", "outputs"}, "Unexpected root job fields")
    preflight.require(
        isinstance(job["result"], str) and job["result"] in RESULTS,
        "Invalid root job result",
    )
    outputs = _object(job["outputs"], "Root job outputs")
    preflight.require(
        all(
            isinstance(key, str) and isinstance(value, str)
            for key, value in outputs.items()
        ),
        "Root job outputs must be strings",
    )
    return job


def _needs(payload: str, environment: str) -> dict[str, dict[str, Any]]:
    """Require the exact graph dependencies; absent jobs cannot imply success."""
    preflight.require(environment in ("test", "prod"), "Invalid barrier account")
    accounts = ("test", "prod") if environment == "prod" else ("test",)
    expected = {"preflight", "validate_inputs"}
    expected.update(
        f"{scope}_{account}" for account in accounts for scope in STACK_ORDER
    )
    if environment == "prod":
        expected.add("whole_test")
    value = _object(_load_document(payload), "Root dependencies")
    preflight.require(set(value) == expected, "Root dependency graph differs")
    jobs = {name: _job(job) for name, job in value.items()}
    for name in ("preflight", "validate_inputs"):
        preflight.require(jobs[name]["result"] == "success", f"{name} did not succeed")
    return jobs


def _account_receipts(
    contract: DeploymentContract,
    environment: str,
    jobs: dict[str, dict[str, Any]],
) -> tuple[dict[str, str], dict[str, AccountNodeReceipt]]:
    """Reject selected failures and unselected outputs before authenticating nodes."""
    results: dict[str, str] = {
        scope: jobs[f"{scope}_{environment}"]["result"] for scope in STACK_ORDER
    }
    for scope in STACK_ORDER:
        selected = scope in contract.selection.stacks
        expected = "success" if selected else "skipped"
        preflight.require(
            results[scope] == expected, f"{scope}/{environment} did not {expected}"
        )
        if not selected:
            preflight.require(
                not jobs[f"{scope}_{environment}"]["outputs"],
                "Unselected worker exposed outputs",
            )
    receipts: dict[str, AccountNodeReceipt] = {
        scope: load_verified_receipt(
            contract,
            scope=scope,
            environment=environment,
            outputs=jobs[f"{scope}_{environment}"]["outputs"],
        )
        for scope in contract.selection.stacks
    }
    return results, receipts


def barrier_outputs(barrier: AccountBarrier) -> dict[str, str]:
    """Expose identity-bound semantics; no field claims aggregate promotion."""
    return {
        "barrier_digest": barrier.barrier_digest,
        "environment": barrier.environment,
        "completion_kind": barrier.completion_kind,
        "selection_digest": barrier.selection_digest,
        "contract_digest": barrier.contract_digest,
    }


def build_verified_barrier(
    contract: DeploymentContract, *, environment: str, needs_payload: str
) -> AccountBarrier:
    """Recompute TEST first; only the full verified TEST graph admits PROD results."""
    _validate_contract(contract)
    jobs = _needs(needs_payload, environment)
    test_results, test_receipts = _account_receipts(contract, "test", jobs)
    test_barrier = reduce_account_barrier(
        contract, environment="test", results=test_results, receipts=test_receipts
    )
    if environment == "test":
        return test_barrier
    previous = jobs["whole_test"]
    preflight.require(
        previous["result"] == "success", "Full TEST barrier did not succeed"
    )
    for key, value in barrier_outputs(test_barrier).items():
        preflight.require(
            previous["outputs"].get(key) == value, "Full TEST barrier output differs"
        )
    prod_results, prod_receipts = _account_receipts(contract, "prod", jobs)
    return reduce_account_barrier(
        contract,
        environment="prod",
        results=prod_results,
        receipts=prod_receipts,
        test_barrier=test_barrier,
    )


def persist_barrier(barrier: AccountBarrier, path: Path) -> dict[str, str]:
    """Write exclusively and distinguish file hashes from semantic barrier hashes."""
    contents = (
        json.dumps(
            asdict(barrier), sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )
        + "\n"
    ).encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(contents)
    return {
        **barrier_outputs(barrier),
        "barrier_file_sha256": hashlib.sha256(contents).hexdigest(),
    }


def main(argv: list[str] | None = None) -> int:
    """Authenticate admission and selected jobs before exposing a successful barrier."""
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("artifact-id", "artifact-sha256", "contract-sha256", "output"):
        parser.add_argument(f"--{name}", required=True)
    parser.add_argument("--environment", choices=("test", "prod"), required=True)
    parser.add_argument("--barrier-path", type=Path, required=True)
    args = parser.parse_args(argv)
    contract = load_verified_admission(
        artifact_id=args.artifact_id,
        artifact_sha256=args.artifact_sha256,
        contract_sha256=args.contract_sha256,
    )
    barrier = build_verified_barrier(
        contract,
        environment=args.environment,
        needs_payload=os.environ.get("BARRIER_NEEDS", ""),
    )
    preflight.write_outputs(persist_barrier(barrier, args.barrier_path), args.output)
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI integration exercises main
    raise SystemExit(main())
