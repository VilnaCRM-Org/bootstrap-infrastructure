"""Recheck admitted worker inputs immediately before any credential preparation.

The caller must first authenticate the contract artifact's origin in the current
root run and verify its expected file digest, then use the strict decoder. Public
content digests cannot establish provenance. This module grants no credentials,
consumes no claims, and produces no execution receipts or promotion attestations.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import deployment_scopes
import pulumi_command_preflight as preflight
from deployment_controller import (
    OWNER_ID,
    REPOSITORY,
    REPOSITORY_ID,
    REQUEST_PATTERNS,
    WORKFLOW,
    ControllerMetadata,
    DeploymentContract,
    _object,
    _validate_contract,
    _validate_repository,
)
from deployment_controller_runtime import _controller_metadata, _verify_environments
from deployment_schedule import DeploymentStep


def _verify_controller_run(controller: ControllerMetadata) -> None:
    """Read the actual current root run and pin its workflow and repository IDs."""
    run = _object(
        preflight.gh(f"repos/{REPOSITORY}/actions/runs/{controller.run_id}"),
        "Controller run",
    )
    expected = {
        "id": int(controller.run_id),
        "run_attempt": 1,
        "event": "repository_dispatch",
        "path": WORKFLOW,
        "head_branch": "main",
        "head_sha": controller.sha,
    }
    for name, value in expected.items():
        preflight.require(
            type(run.get(name)) is type(value) and run[name] == value,
            f"Controller run {name} differs",
        )
    for name in ("repository", "head_repository"):
        repository = _object(run.get(name), "Controller repository")
        preflight.require(
            repository.get("full_name") == REPOSITORY
            and type(repository.get("id")) is int
            and repository["id"] == REPOSITORY_ID,
            "Controller repository identity differs",
        )
        owner = _object(repository.get("owner"), "Controller repository owner")
        preflight.require(
            type(owner.get("id")) is int and owner["id"] == OWNER_ID,
            "Controller owner identity differs",
        )


def _recheck_selection(contract: DeploymentContract) -> None:
    """Authenticate fresh evidence and reproduce the admitted immutable scope."""
    identity = contract.identity
    request = {key: getattr(identity, key) for key in REQUEST_PATTERNS}
    evidence = preflight.collect_evidence(request)
    _validate_repository(evidence)
    validated = preflight.validate_current_request_identity(request, evidence)
    preflight.require(
        validated["base_sha"] == identity.base_sha, "Admitted PR base moved"
    )
    selection = deployment_scopes.select_deployment_scopes(
        evidence["changed_file_records"],
        base_sha=evidence["scope_base_sha"],
        head_sha=evidence["scope_head_sha"],
        expected_file_count=evidence["changed_file_count"],
        complete=True,
    )
    preflight.require(selection == contract.selection, "Admitted selection changed")


def _admission_controller(contract: DeploymentContract) -> ControllerMetadata:
    """Bind a semantically validated admission to the current trusted context."""
    controller = _controller_metadata()
    _validate_contract(contract)
    preflight.require(
        controller == contract.identity.controller,
        "Worker controller identity differs from admission",
    )
    return controller


def _recheck_admitted_facts(
    contract: DeploymentContract, controller: ControllerMetadata
) -> None:
    """Authenticate current source, rights and protections without claiming again."""
    selector_sha256 = hashlib.sha256(
        Path(deployment_scopes.__file__).read_bytes()
    ).hexdigest()
    preflight.require(
        selector_sha256 == contract.selector_sha256, "Installed selector changed"
    )
    _verify_controller_run(controller)
    _recheck_selection(contract)
    _verify_environments(contract)


def recheck_admission(contract: DeploymentContract) -> None:
    """Recheck a root admission, including an empty scope, without authorizing AWS.

    Root account barriers and credential-free validation use this after artifact
    authentication. Credential workers must still use the selected-node check.
    """
    _recheck_admitted_facts(contract, _admission_controller(contract))


def recheck_worker(
    contract: DeploymentContract, *, scope: str, environment: str
) -> tuple[DeploymentStep, ...]:
    """Return this selected node's schedule after current precredential checks.

    ``contract`` must come from an authenticated artifact in this root run. Fixed
    worker scope/account cannot come from unchecked dispatch fields. Protected
    approval may outlast admission expiry; identity and rights checks still apply.
    PROD ordering and the full TEST barrier remain the coordinator's obligation.
    """
    controller = _admission_controller(contract)
    steps = tuple(
        step
        for step in contract.schedule
        if step.scope == scope and step.environment == environment
    )
    preflight.require(bool(steps), "Worker scope/account is not selected")
    _recheck_admitted_facts(contract, controller)
    return steps
