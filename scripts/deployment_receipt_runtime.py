"""Authenticate selected worker receipts and actual jobs without promotion rights.

The contract must already come from authenticated admission. Worker outputs must
come from fixed trusted ``needs`` edges, never dispatch or pull-request input.
No successful content hash alone establishes artifact or execution provenance.
"""

from __future__ import annotations

import hashlib
from typing import Any

import pulumi_command_preflight as preflight
from deployment_contract_io import decode_account_receipt
from deployment_controller import (
    REPOSITORY,
    AccountNodeReceipt,
    ControllerMetadata,
    DeploymentContract,
    _object,
    _receipt_digest,
    _validate_contract,
)
from deployment_worker_recheck import recheck_worker
from deployment_worker_runtime import (
    _check_arguments,
    _contract_bytes,
    _download_zip,
    _verify_artifact,
)

MAX_JOBS = 500
PAGE_SIZE = 100
OUTPUT_FIELDS = frozenset(
    (
        "receipt_artifact_id",
        "receipt_artifact_sha256",
        "receipt_file_sha256",
        "receipt_digest",
        "selection_digest",
        "contract_digest",
        "completion_kind",
        "result",
        "scope",
        "environment",
        "command",
        "head_sha",
        "base_sha",
    )
)


def _worker_names(scope: str, environment: str) -> dict[str, str]:
    """Match fixed caller names and the installed reusable worker display names."""
    preflight.require(
        scope in ("platform", "governance", "operator"), "Unsupported receipt scope"
    )
    preflight.require(environment in ("test", "prod"), "Invalid receipt environment")
    display_names = {
        "resolve": "Validate fixed account and authenticated admission",
        "preview": f"{scope.title()} account plan",
        "destructive_diff": f"{scope.title()} destructive diff gate",
        "iam_validation": f"{scope.title()} IAM validation",
        "apply": f"Apply saved {scope} plan",
        "post_apply_drift": f"{scope.title()} post-apply drift",
        "receipt": f"Verify complete {scope} account receipt",
    }
    return {
        f"{scope}_{environment} / {name}": stage
        for stage, name in display_names.items()
    }


def _verify_outputs(
    contract: DeploymentContract,
    scope: str,
    environment: str,
    outputs: dict[str, str],
) -> None:
    """Close the trusted edge's entire schema and bind every semantic output."""
    preflight.require(
        type(outputs) is dict and set(outputs) == OUTPUT_FIELDS,
        "Worker outputs must contain exactly the required fields",
    )
    preflight.require(
        all(type(value) is str for value in outputs.values()),
        "Worker outputs must be strings",
    )
    _check_arguments(
        outputs["receipt_artifact_id"],
        outputs["receipt_artifact_sha256"],
        outputs["receipt_file_sha256"],
        scope,
        environment,
    )
    identity = contract.identity
    expected = {
        "result": "success",
        "scope": scope,
        "environment": environment,
        "command": identity.command,
        "head_sha": identity.head_sha,
        "base_sha": identity.base_sha,
        "selection_digest": contract.selection_digest,
        "contract_digest": contract.contract_digest,
        "completion_kind": "apply-drift" if identity.command == "up" else "plan",
    }
    for name, value in expected.items():
        preflight.require(outputs[name] == value, f"Worker output {name} differs")


def _jobs_page(controller: ControllerMetadata, page: int) -> dict[str, Any]:
    """Read a bounded page from the documented attempt-specific jobs endpoint."""
    endpoint = (
        f"repos/{REPOSITORY}/actions/runs/{controller.run_id}/attempts/1/jobs"
        f"?per_page={PAGE_SIZE}&page={page}"
    )
    result = _object(preflight.gh(endpoint), "Jobs page")
    count = result.get("total_count")
    preflight.require(
        type(count) is int and 0 < count <= MAX_JOBS,
        "Jobs total count is invalid or exceeds bound",
    )
    preflight.require(type(result.get("jobs")) is list, "Jobs must be an array")
    return result


def _verify_job_identity(
    job: dict[str, Any], controller: ControllerMetadata, seen_ids: set[int]
) -> None:
    """Reject duplicate jobs and foreign run/revision/attempt metadata."""
    identifier = job.get("id")
    if type(identifier) is not int or identifier <= 0 or identifier in seen_ids:
        raise ValueError("Invalid or duplicate job ID")
    seen_ids.add(identifier)
    expected = {
        "run_id": int(controller.run_id),
        "run_attempt": 1,
        "run_url": f"https://api.github.com/repos/{REPOSITORY}/actions/runs/{controller.run_id}",
        "head_sha": controller.sha,
        "head_branch": "main",
    }
    for name, value in expected.items():
        preflight.require(
            type(job.get(name)) is type(value) and job[name] == value,
            f"Job {name} differs",
        )
    preflight.require(type(job.get("name")) is str, "Job name must be a string")


def _complete_jobs(controller: ControllerMetadata) -> list[dict[str, Any]]:
    """Require complete, count-coherent pagination with no repeated job IDs."""
    first = _jobs_page(controller, 1)
    count = first["total_count"]
    jobs: list[dict[str, Any]] = []
    seen_ids: set[int] = set()
    for page in range(1, (count + PAGE_SIZE - 1) // PAGE_SIZE + 1):
        result = first if page == 1 else _jobs_page(controller, page)
        preflight.require(result["total_count"] == count, "Jobs count changed")
        expected_size = min(PAGE_SIZE, count - len(jobs))
        preflight.require(len(result["jobs"]) == expected_size, "Incomplete jobs page")
        for value in result["jobs"]:
            job = _object(value, "Job")
            _verify_job_identity(job, controller, seen_ids)
            jobs.append(job)
    return jobs


def _verify_jobs(contract: DeploymentContract, scope: str, environment: str) -> None:
    """Require every fixed stage; only plan-command apply/drift may be skipped."""
    expected = _worker_names(scope, environment)
    seen: set[str] = set()
    prefix = f"{scope}_{environment} / "
    for job in _complete_jobs(contract.identity.controller):
        name = job["name"]
        if not name.startswith(prefix):
            continue
        preflight.require(
            name in expected and name not in seen, "Unknown or duplicate worker job"
        )
        seen.add(name)
        stage = expected[name]
        skipped = contract.identity.command == "plan" and stage in (
            "apply",
            "post_apply_drift",
        )
        conclusion = "skipped" if skipped else "success"
        preflight.require(
            job.get("status") == "completed" and job.get("conclusion") == conclusion,
            f"Worker {stage} did not complete with {conclusion}",
        )
    preflight.require(seen == set(expected), "Missing selected worker jobs")


def load_verified_receipt(
    contract: DeploymentContract,
    *,
    scope: str,
    environment: str,
    outputs: dict[str, str],
) -> AccountNodeReceipt:
    """Authenticate a selected receipt, current authorization and actual job results."""
    _worker_names(scope, environment)
    _validate_contract(contract)
    _verify_outputs(contract, scope, environment, outputs)
    recheck_worker(contract, scope=scope, environment=environment)
    controller = contract.identity.controller
    expected_name = (
        f"deployment-receipt-{controller.run_id}-1-{scope}-{environment}"
        f"-{contract.identity.head_sha}"
    )
    artifact_id = outputs["receipt_artifact_id"]
    archive_digest = outputs["receipt_artifact_sha256"]
    _verify_artifact(
        artifact_id, archive_digest, controller, expected_name=expected_name
    )
    raw = _download_zip(artifact_id)
    preflight.require(
        hashlib.sha256(raw).hexdigest() == archive_digest, "Receipt ZIP SHA256 differs"
    )
    payload = _contract_bytes(raw, member_name="receipt.json")
    preflight.require(
        hashlib.sha256(payload).hexdigest() == outputs["receipt_file_sha256"],
        "Receipt file SHA256 differs",
    )
    receipt = decode_account_receipt(
        payload, contract=contract, scope=scope, environment=environment
    )
    preflight.require(
        _receipt_digest(contract, receipt, scope, environment)
        == outputs["receipt_digest"],
        "Receipt semantic digest differs",
    )
    _verify_jobs(contract, scope, environment)
    return receipt
