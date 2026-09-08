"""Record a worker's trusted job results without credentials or promotion rights.

The installed workflow supplies fixed ``needs`` results. The root publisher must
authenticate the resulting artifact and actual jobs before treating it as proof.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import asdict
from pathlib import Path

# Isolated Python omits the script directory. Admit only this trusted checkout.
sys.path.insert(0, str(Path(__file__).resolve().parent))

import pulumi_command_preflight as preflight  # noqa: E402
from deployment_controller import (  # noqa: E402
    AccountNodeReceipt,
    DeploymentContract,
    StageResult,
    _receipt_digest,
    _validate_contract,
)
from deployment_worker_runtime import load_verified_contract  # noqa: E402

RESULT_NAMES = ("plan", "destructive", "iam", "apply", "drift")
RESULT_STATES = ("success", "failure", "cancelled", "skipped")


def build_worker_receipt(
    contract: DeploymentContract,
    *,
    scope: str,
    environment: str,
    results: dict[str, str],
) -> AccountNodeReceipt:
    """Require successful gates and exactly the requested selected operations."""
    _validate_contract(contract)
    preflight.require(set(results) == set(RESULT_NAMES), "Incomplete worker results")
    for gate in ("plan", "destructive", "iam"):
        preflight.require(results[gate] == "success", f"Worker {gate} did not succeed")
    expected = "success" if contract.identity.command == "up" else "skipped"
    for operation in ("apply", "drift"):
        preflight.require(
            results[operation] == expected,
            f"Worker {operation} result differs from requested command",
        )
    steps = tuple(
        step
        for step in contract.schedule
        if step.scope == scope and step.environment == environment
    )
    preflight.require(bool(steps), "Cannot receipt an unselected worker")
    receipt = AccountNodeReceipt(
        contract.identity,
        contract.contract_digest,
        contract.selection_digest,
        scope,
        environment,
        tuple(StageResult(step.operation, results[step.operation]) for step in steps),
    )
    _receipt_digest(contract, receipt, scope, environment)
    return receipt


def persist_receipt(receipt: AccountNodeReceipt, path: Path) -> dict[str, str]:
    """Write canonical bytes exclusively and distinguish file and semantic hashes."""
    payload = json.dumps(
        asdict(receipt), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    contents = payload + b"\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(contents)
    identity = receipt.identity
    return {
        "receipt_digest": hashlib.sha256(payload).hexdigest(),
        "receipt_file_sha256": hashlib.sha256(contents).hexdigest(),
        "command": identity.command,
        "head_sha": identity.head_sha,
        "base_sha": identity.base_sha,
        "selection_digest": receipt.selection_digest,
        "contract_digest": receipt.contract_digest,
        "scope": receipt.scope,
        "environment": receipt.environment,
        "completion_kind": "apply-drift" if identity.command == "up" else "plan",
    }


def main(argv: list[str] | None = None) -> int:
    """Authenticate admission and current authorization before publishing a receipt."""
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("artifact-id", "artifact-sha256", "contract-sha256"):
        parser.add_argument(f"--{name}", required=True)
    parser.add_argument(
        "--scope", choices=("operator", "governance", "platform"), required=True
    )
    parser.add_argument("--environment", choices=("test", "prod"), required=True)
    for name in RESULT_NAMES:
        parser.add_argument(f"--{name}-result", choices=RESULT_STATES, required=True)
    parser.add_argument("--receipt-path", type=Path, required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    contract = load_verified_contract(
        artifact_id=args.artifact_id,
        artifact_sha256=args.artifact_sha256,
        contract_sha256=args.contract_sha256,
        scope=args.scope,
        environment=args.environment,
    )
    receipt = build_worker_receipt(
        contract,
        scope=args.scope,
        environment=args.environment,
        results={name: getattr(args, f"{name}_result") for name in RESULT_NAMES},
    )
    preflight.write_outputs(persist_receipt(receipt, args.receipt_path), args.output)
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised through main in unit tests
    raise SystemExit(main())
