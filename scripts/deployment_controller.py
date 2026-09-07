"""Pure request contracts and account barriers for the trusted deployment controller.

These functions validate supplied facts; they do not fetch/authenticate GitHub
responses, consume a claim, grant credentials, or attest that a deployment ran.
The caller must establish provenance, claim once, and recheck before execution.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import asdict, dataclass, replace
from typing import Any, Literal, cast

import pulumi_command_preflight as preflight
from deployment_schedule import DeploymentStep, deployment_schedule
from deployment_scopes import (
    STACK_ORDER,
    DeploymentScopes,
    PathImpact,
    select_deployment_scopes,
)

REPOSITORY = "VilnaCRM-Org/bootstrap-infrastructure"
REPOSITORY_ID = 1098568429
OWNER_ID = 114362548
WORKFLOW = ".github/workflows/pulumi-pr-command-runner.yml"
REQUEST_PATTERNS = {
    "pull_request_number": r"[1-9][0-9]*",
    "head_sha": r"[0-9a-f]{40}",
    "comment_id": r"[1-9][0-9]*",
    "source_run_id": r"[1-9][0-9]*",
    "command": r"plan|up",
    "target_environment": r"test|prod",
}
CompletionKind = Literal["plan", "apply-drift", "no-deployment"]


@dataclass(frozen=True)
class ControllerMetadata:
    """Controller facts the caller must obtain from its trusted execution context."""

    sha: str
    run_id: str
    run_attempt: int
    workflow_ref: str


@dataclass(frozen=True)
class DeploymentIdentity:
    """The immutable repository, original request and controller-run identities."""

    repository: str
    repository_id: int
    owner_id: int
    pull_request_number: str
    head_sha: str
    base_sha: str
    comment_id: str
    source_run_id: str
    command: str
    target_environment: str
    controller: ControllerMetadata


@dataclass(frozen=True)
class DeploymentContract:
    """Frozen selection and stage order; never an execution authorization token."""

    schema_version: int
    identity: DeploymentIdentity
    selector_sha256: str
    selection: DeploymentScopes
    selection_digest: str
    schedule: tuple[DeploymentStep, ...]
    contract_digest: str


@dataclass(frozen=True)
class StageResult:
    """One reported schedule operation, whose provenance remains caller-owned."""

    operation: str
    result: str


@dataclass(frozen=True)
class AccountNodeReceipt:
    """One scope/account's reported stage results bound to the complete request."""

    identity: DeploymentIdentity
    contract_digest: str
    selection_digest: str
    scope: str
    environment: str
    stages: tuple[StageResult, ...]


@dataclass(frozen=True)
class AccountBarrier:
    """A reduction of reported results, not independent deployment evidence."""

    identity: DeploymentIdentity
    contract_digest: str
    selection_digest: str
    environment: str
    completion_kind: CompletionKind
    receipt_digests: tuple[tuple[str, str], ...]
    test_barrier_digest: str | None
    barrier_digest: str


def _require(condition: bool, message: str) -> None:
    """Reject contradictory or incomplete caller-supplied facts."""
    if not condition:
        raise ValueError(message)


def _matches(value: object, pattern: str, label: str) -> None:
    """Accept only closed-format string identifiers."""
    _require(
        isinstance(value, str) and re.fullmatch(pattern, value) is not None,
        f"Invalid {label}",
    )


def _digest(value: object) -> str:
    """Hash canonical JSON, including nested frozen dataclass payloads."""
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _payload_digest(value: DeploymentContract | AccountBarrier, field: str) -> str:
    """Exclude only the digest field itself from its complete payload hash."""
    payload = asdict(value)
    del payload[field]
    return _digest(payload)


def _validate_controller(controller: ControllerMetadata) -> None:
    """Pin the workflow identity and reject re-run or malformed metadata."""
    _require(type(controller) is ControllerMetadata, "Invalid controller metadata")
    _matches(controller.sha, r"[0-9a-f]{40}", "controller SHA")
    _matches(controller.run_id, r"[1-9][0-9]*", "controller run ID")
    _require(
        type(controller.run_attempt) is int and controller.run_attempt == 1,
        "Controller re-runs are not accepted",
    )
    _require(
        controller.workflow_ref == f"{REPOSITORY}/{WORKFLOW}@refs/heads/main",
        "Only the fixed trusted main controller workflow is accepted",
    )


def _object(value: object, label: str) -> dict[str, Any]:
    """Reject malformed API object envelopes before inspecting their fields."""
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return cast(dict[str, Any], value)


def _validate_repository(evidence: dict[str, Any]) -> None:
    """Bind actual evidence to fixed IDs; metadata cannot choose another repo."""
    evidence = _object(evidence, "Evidence")
    _require(evidence.get("repository") == REPOSITORY, "Foreign repository")
    pr = _object(evidence.get("pr"), "PR")
    run = _object(evidence.get("run"), "Intake run")
    repositories = [
        _object(_object(pr.get(side), f"PR {side}").get("repo"), "Repository")
        for side in ("base", "head")
    ]
    repositories.append(_object(run.get("head_repository"), "Intake repository"))
    for repository in repositories:
        _require(
            repository.get("full_name") == REPOSITORY
            and type(repository.get("id")) is int
            and repository["id"] == REPOSITORY_ID,
            "Foreign or missing immutable repository identity",
        )
    for repository in repositories:
        owner_id = _object(repository.get("owner"), "Repository owner").get("id")
        _require(
            type(owner_id) is int and owner_id == OWNER_ID,
            "Foreign or missing immutable owner identity",
        )


def build_deployment_contract(
    request: dict[str, str],
    evidence: dict[str, Any],
    *,
    controller: ControllerMetadata,
    selector_sha256: str,
    complete: bool,
) -> DeploymentContract:
    """Validate authenticated input facts and freeze their conservative selection.

    ``complete`` and ``selector_sha256`` must come from the trusted collector and
    installed selector source, not the dispatch payload. This function performs
    no I/O and cannot prove that a caller authenticated those facts externally.
    """
    request = _object(request, "Request")
    _require(set(request) == set(REQUEST_PATTERNS), "Unexpected request fields")
    for key, pattern in REQUEST_PATTERNS.items():
        _matches(request[key], pattern, key)
    _validate_controller(controller)
    _matches(selector_sha256, r"[0-9a-f]{64}", "selector SHA256")
    _validate_repository(evidence)
    validated = preflight.validate_request_identity(request, evidence)
    _require(evidence["scope_head_sha"] == request["head_sha"], "Scope head differs")
    count = evidence["changed_file_count"]
    _require(
        type(evidence["pr"]["changed_files"]) is int
        and count == evidence["pr"]["changed_files"],
        "Scope count differs from current PR",
    )
    selection = select_deployment_scopes(
        evidence["changed_file_records"],
        base_sha=validated["base_sha"],
        head_sha=validated["head_sha"],
        expected_file_count=count,
        complete=complete,
    )
    identity = DeploymentIdentity(
        REPOSITORY,
        REPOSITORY_ID,
        OWNER_ID,
        **{key: validated[key] for key in REQUEST_PATTERNS},
        base_sha=validated["base_sha"],
        controller=controller,
    )
    contract = DeploymentContract(
        2,
        identity,
        selector_sha256,
        selection,
        _digest(asdict(selection)),
        deployment_schedule(
            selection.stacks,
            command=identity.command,
            target_environment=identity.target_environment,
        ),
        "",
    )
    return replace(
        contract, contract_digest=_payload_digest(contract, "contract_digest")
    )


def _validate_contract(contract: DeploymentContract) -> None:
    """Detect altered identities, selections and schedules before reducing results."""
    _require(type(contract) is DeploymentContract, "Invalid deployment contract")
    _require(
        type(contract.schema_version) is int and contract.schema_version == 2,
        "Unsupported contract schema",
    )
    identity = contract.identity
    _require(type(identity) is DeploymentIdentity, "Invalid deployment identity")
    _require(
        (identity.repository, identity.repository_id, identity.owner_id)
        == (REPOSITORY, REPOSITORY_ID, OWNER_ID),
        "Foreign contract identity",
    )
    _validate_controller(identity.controller)
    for key, pattern in REQUEST_PATTERNS.items():
        _matches(getattr(identity, key), pattern, key)
    _matches(identity.base_sha, r"[0-9a-f]{40}", "base SHA")
    _matches(contract.selector_sha256, r"[0-9a-f]{64}", "selector SHA256")
    _require(type(contract.selection) is DeploymentScopes, "Invalid selection")
    _require(
        (contract.selection.base_sha, contract.selection.head_sha)
        == (identity.base_sha, identity.head_sha)
        and identity.base_sha != identity.head_sha,
        "Selection revisions differ from request",
    )
    _require(
        type(contract.selection.reasons) is tuple
        and all(type(reason) is PathImpact for reason in contract.selection.reasons),
        "Selection reasons must be immutable path impacts",
    )
    # Reasons already contain every normalized old/new path. Reclassify those
    # paths; public digests alone cannot reject a self-consistent forged scope.
    canonical_selection = select_deployment_scopes(
        [
            {"filename": reason.path, "status": "modified"}
            for reason in contract.selection.reasons
        ],
        base_sha=identity.base_sha,
        head_sha=identity.head_sha,
        expected_file_count=len(contract.selection.reasons),
        complete=True,
    )
    _require(
        contract.selection == canonical_selection,
        "Selection contradicts installed selector",
    )
    expected = deployment_schedule(
        contract.selection.stacks,
        command=identity.command,
        target_environment=identity.target_environment,
    )
    _require(contract.schedule == expected, "Contract schedule differs")
    _require(
        contract.selection_digest == _digest(asdict(canonical_selection)),
        "Selection digest differs",
    )
    _require(
        contract.contract_digest == _payload_digest(contract, "contract_digest"),
        "Contract digest differs",
    )


def _completion_kind(contract: DeploymentContract) -> CompletionKind:
    """Keep empty selections and plans distinct from reported applies and drift."""
    if not contract.selection.stacks:
        return "no-deployment"
    return "apply-drift" if contract.identity.command == "up" else "plan"


def _validate_test_barrier(
    contract: DeploymentContract, barrier: AccountBarrier
) -> None:
    """Require the matching full TEST reduction before considering any PROD result."""
    _require(type(barrier) is AccountBarrier, "A full TEST barrier is required")
    _require(
        barrier.identity == contract.identity
        and barrier.contract_digest == contract.contract_digest
        and barrier.selection_digest == contract.selection_digest
        and barrier.environment == "test"
        and barrier.completion_kind == _completion_kind(contract)
        and barrier.test_barrier_digest is None,
        "TEST barrier identity or completion kind differs",
    )
    _require(
        type(barrier.receipt_digests) is tuple
        and tuple(scope for scope, _ in barrier.receipt_digests)
        == contract.selection.stacks,
        "TEST barrier must cover every selected scope exactly once",
    )
    for _, digest in barrier.receipt_digests:
        _matches(digest, r"[0-9a-f]{64}", "TEST receipt digest")
    _require(
        barrier.barrier_digest == _payload_digest(barrier, "barrier_digest"),
        "TEST barrier digest differs",
    )


def _receipt_digest(
    contract: DeploymentContract,
    receipt: AccountNodeReceipt,
    scope: str,
    environment: str,
) -> str:
    """Validate one selected node's identity and every scheduled operation."""
    _require(type(receipt) is AccountNodeReceipt, "Invalid account receipt")
    _require(
        receipt.identity == contract.identity
        and receipt.contract_digest == contract.contract_digest
        and receipt.selection_digest == contract.selection_digest
        and receipt.scope == scope
        and receipt.environment == environment,
        "Account receipt identity differs",
    )
    expected = tuple(
        StageResult(step.operation, "success")
        for step in contract.schedule
        if step.environment == environment and step.scope == scope
    )
    _require(receipt.stages == expected, "Receipt stages did not all succeed")
    return _digest(asdict(receipt))


def reduce_account_barrier(
    contract: DeploymentContract,
    *,
    environment: str,
    results: Mapping[str, str],
    receipts: Mapping[str, AccountNodeReceipt],
    test_barrier: AccountBarrier | None = None,
) -> AccountBarrier:
    """Reduce exact scope results; never infer actual success from absent jobs.

    Results must name all three scopes: selected scopes succeed with receipts;
    unselected scopes are skipped without receipts. The caller authenticates
    actual job/artifact provenance. Digests bind content, not its truthfulness.
    """
    _validate_contract(contract)
    _require(environment in {"test", "prod"}, "Unsupported barrier environment")
    if environment == "prod":
        _require(
            contract.identity.target_environment == "prod", "PROD was not requested"
        )
        _validate_test_barrier(contract, test_barrier)  # type: ignore[arg-type]
    else:
        _require(test_barrier is None, "TEST cannot consume another barrier")
    _require(set(results) == set(STACK_ORDER), "Results must name every known scope")
    _require(set(receipts) == set(contract.selection.stacks), "Receipt scopes differ")
    digests = []
    for scope in STACK_ORDER:
        if scope not in contract.selection.stacks:
            _require(results[scope] == "skipped", "Unselected scope was not skipped")
            continue
        _require(results[scope] == "success", "Selected scope did not succeed")
        digests.append(
            (scope, _receipt_digest(contract, receipts[scope], scope, environment))
        )
    barrier = AccountBarrier(
        contract.identity,
        contract.contract_digest,
        contract.selection_digest,
        environment,
        _completion_kind(contract),
        tuple(digests),
        test_barrier.barrier_digest if test_barrier is not None else None,
        "",
    )
    return replace(barrier, barrier_digest=_payload_digest(barrier, "barrier_digest"))
