"""Adverse request and account-result cases for the pure central controller."""

from __future__ import annotations

import hashlib
import json
import sys
from copy import deepcopy
from dataclasses import FrozenInstanceError, asdict, replace
from datetime import datetime, timezone
from itertools import combinations
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))

import deployment_controller as controller  # noqa: E402

SCOPES = controller.STACK_ORDER
SCOPE_PATHS = {
    "operator": "pulumi/github-ci-bootstrap/__main__.py",
    "governance": "pulumi/governance/__main__.py",
    "platform": "pulumi/__main__.py",
}


def input_facts(scopes=SCOPES, *, command="up", target="prod"):
    """Model genuine API facts separately from controller metadata."""
    request = {
        "pull_request_number": "78",
        "head_sha": "a" * 40,
        "comment_id": "9",
        "source_run_id": "12",
        "command": command,
        "target_environment": target,
    }
    repository = {
        "full_name": controller.REPOSITORY,
        "id": controller.REPOSITORY_ID,
        "owner": {"id": controller.OWNER_ID},
    }
    records = [
        {"filename": SCOPE_PATHS[scope], "status": "modified"} for scope in scopes
    ] or [{"filename": "README.md", "status": "modified"}]
    created = "2026-09-05T12:00:00Z"
    evidence = {
        "repository": controller.REPOSITORY,
        "api_url": "https://api.github.com",
        "scope_base_sha": "b" * 40,
        "scope_head_sha": request["head_sha"],
        "changed_file_count": len(records),
        "changed_file_records": records,
        "artifact": dict(request),
        "permission": "write",
        "now": datetime(2026, 9, 5, 12, 1, tzinfo=timezone.utc),
        "pr": {
            "state": "open",
            "merged": False,
            "changed_files": len(records),
            "base": {"ref": "main", "sha": "b" * 40, "repo": deepcopy(repository)},
            "head": {"sha": request["head_sha"], "repo": deepcopy(repository)},
        },
        "comment": {
            "id": 9,
            "issue_url": f"https://api.github.com/repos/{controller.REPOSITORY}/issues/78",
            "created_at": created,
            "updated_at": created,
            "user": {"id": 10, "login": "dmytrocraft"},
            "body": f"/pulumi {target} {command}",
        },
        "run": {
            "id": 12,
            "event": "issue_comment",
            "path": controller.preflight.INTAKE_PATH,
            "head_repository": deepcopy(repository),
            "run_attempt": 1,
            "actor": {"id": 10},
            "created_at": created,
        },
    }
    metadata = controller.ControllerMetadata(
        "c" * 40,
        "100",
        1,
        f"{controller.REPOSITORY}/{controller.WORKFLOW}@refs/heads/main",
    )
    return request, evidence, metadata


def build(scopes=SCOPES, *, command="up", target="prod"):
    """Build through real identity validation and the real selector/scheduler."""
    request, evidence, metadata = input_facts(scopes, command=command, target=target)
    return controller.build_deployment_contract(
        request,
        evidence,
        controller=metadata,
        selector_sha256="d" * 64,
        complete=True,
    )


def node_facts(contract, environment="test"):
    """Supply independent reported operation results for an account."""
    results = {scope: "skipped" for scope in SCOPES}
    receipts = {}
    operations = (
        ("plan", "apply", "drift") if contract.identity.command == "up" else ("plan",)
    )
    for scope in contract.selection.stacks:
        results[scope] = "success"
        receipts[scope] = controller.AccountNodeReceipt(
            contract.identity,
            contract.contract_digest,
            contract.selection_digest,
            scope,
            environment,
            tuple(
                controller.StageResult(operation, "success") for operation in operations
            ),
        )
    return results, receipts


def reduce(contract, environment="test", *, test_barrier=None):
    """Reduce the separately constructed node facts."""
    results, receipts = node_facts(contract, environment)
    return controller.reduce_account_barrier(
        contract,
        environment=environment,
        results=results,
        receipts=receipts,
        test_barrier=test_barrier,
    )


def test_contract_binds_original_identity_and_frozen_selection_without_io(monkeypatch):
    request, evidence, metadata = input_facts()
    calls = []
    original = controller.preflight.validate_request_identity

    def validate(actual_request, actual_evidence):
        calls.append((actual_request, actual_evidence))
        return original(actual_request, actual_evidence)

    def forbidden(*args, **kwargs):
        raise AssertionError("Pure controller performed I/O or consumed a claim")

    monkeypatch.setattr(controller.preflight, "validate_request_identity", validate)
    monkeypatch.setattr(controller.preflight, "gh", forbidden)
    monkeypatch.setattr(controller.preflight, "claim_request", forbidden)
    evidence["changed_file_records"][0]["patch"] = "RAW PATCH MUST NOT BE SERIALIZED"
    contract = controller.build_deployment_contract(
        request,
        evidence,
        controller=metadata,
        selector_sha256="d" * 64,
        complete=True,
    )
    assert calls == [(request, evidence)]
    assert contract.schema_version == 2
    assert contract.identity.repository_id == 1098568429
    assert contract.identity.owner_id == 114362548
    assert contract.identity.controller == metadata
    assert all(
        getattr(contract.identity, key) == value for key, value in request.items()
    )
    assert contract.selection.stacks == SCOPES
    assert len(contract.schedule) == 18
    assert contract.schedule[9].predecessor == "test_platform_drift"
    assert len(contract.contract_digest) == len(contract.selection_digest) == 64
    assert "RAW PATCH MUST NOT BE SERIALIZED" not in str(asdict(contract))
    with pytest.raises(FrozenInstanceError):
        contract.schema_version = 1
    evidence["changed_file_records"].clear()
    request["head_sha"] = "f" * 40
    assert len(contract.selection.reasons) == 3
    assert contract.identity.head_sha == "a" * 40


def test_canonical_selection_order_and_controller_version_are_bound():
    assert build(tuple(reversed(SCOPES))) == build()
    request, evidence, metadata = input_facts()
    baseline = build()
    for extra in (
        {"controller": replace(metadata, sha="e" * 40)},
        {"controller": replace(metadata, run_id="101")},
        {"selector_sha256": "e" * 64},
    ):
        arguments = {
            "controller": metadata,
            "selector_sha256": "d" * 64,
            "complete": True,
        }
        changed = controller.build_deployment_contract(
            request, evidence, **(arguments | extra)
        )
        assert changed.selection_digest == baseline.selection_digest
        assert changed.contract_digest != baseline.contract_digest


@pytest.mark.parametrize("key", tuple(controller.REQUEST_PATTERNS))
@pytest.mark.parametrize("value", [None, "", "injected\nvalue"])
def test_request_fields_are_closed_format(key, value):
    request, evidence, metadata = input_facts()
    request[key] = value
    with pytest.raises(ValueError, match="Invalid"):
        controller.build_deployment_contract(
            request,
            evidence,
            controller=metadata,
            selector_sha256="d" * 64,
            complete=True,
        )


@pytest.mark.parametrize("missing", [False, True])
def test_request_cannot_supply_scope_or_omit_identity(missing):
    request, evidence, metadata = input_facts()
    if missing:
        del request["comment_id"]
    else:
        request["scopes"] = "operator"
    with pytest.raises(ValueError, match="Unexpected request fields"):
        controller.build_deployment_contract(
            request,
            evidence,
            controller=metadata,
            selector_sha256="d" * 64,
            complete=True,
        )


@pytest.mark.parametrize(
    "key,value",
    [
        ("sha", "main"),
        ("run_id", "0"),
        ("run_attempt", 2),
        ("run_attempt", True),
        (
            "workflow_ref",
            f"{controller.REPOSITORY}/{controller.WORKFLOW}@refs/pull/78/head",
        ),
        ("workflow_ref", f"foreign/repo/{controller.WORKFLOW}@refs/heads/main"),
        (
            "workflow_ref",
            f"{controller.REPOSITORY}/.github/workflows/other.yml@refs/heads/main",
        ),
    ],
)
def test_controller_identity_is_fixed_main_and_first_attempt(key, value):
    request, evidence, metadata = input_facts()
    with pytest.raises(ValueError):
        controller.build_deployment_contract(
            request,
            evidence,
            controller=replace(metadata, **{key: value}),
            selector_sha256="d" * 64,
            complete=True,
        )


@pytest.mark.parametrize(
    "metadata,digest",
    [(None, "d" * 64), ("metadata", "d" * 64), ("valid", "d" * 63), ("valid", None)],
)
def test_missing_trusted_metadata_is_not_inferred(metadata, digest):
    request, evidence, valid = input_facts()
    with pytest.raises(ValueError):
        controller.build_deployment_contract(
            request,
            evidence,
            controller=valid if metadata == "valid" else metadata,
            selector_sha256=digest,
            complete=True,
        )


@pytest.mark.parametrize("source", ["base", "head", "intake"])
@pytest.mark.parametrize(
    "key,value",
    [("id", 1), ("id", None), ("id", "1098568429"), ("full_name", "foreign/repo")],
)
def test_supplied_metadata_cannot_authorize_foreign_repository(source, key, value):
    request, evidence, metadata = input_facts()
    repo = (
        evidence["run"]["head_repository"]
        if source == "intake"
        else evidence["pr"][source]["repo"]
    )
    repo[key] = value
    with pytest.raises(ValueError, match="repository identity"):
        controller.build_deployment_contract(
            request,
            evidence,
            controller=metadata,
            selector_sha256="d" * 64,
            complete=True,
        )


@pytest.mark.parametrize("side", ["base", "head", "intake"])
@pytest.mark.parametrize("owner_id", [1, None, "114362548", True])
def test_repository_transfer_or_missing_owner_id_rejected(side, owner_id):
    request, evidence, metadata = input_facts()
    repository = (
        evidence["run"]["head_repository"]
        if side == "intake"
        else evidence["pr"][side]["repo"]
    )
    repository["owner"]["id"] = owner_id
    with pytest.raises(ValueError, match="owner identity"):
        controller.build_deployment_contract(
            request,
            evidence,
            controller=metadata,
            selector_sha256="d" * 64,
            complete=True,
        )


@pytest.mark.parametrize(
    "change",
    [
        "repository",
        "scope_head",
        "count",
        "count_bool",
        "incomplete",
        "records",
        "permission",
        "edited",
    ],
)
def test_inconsistent_or_unauthenticated_snapshot_rejected(change):
    request, evidence, metadata = input_facts()
    complete = True
    if change == "repository":
        evidence["repository"] = "foreign/repo"
    elif change == "scope_head":
        evidence["scope_head_sha"] = "e" * 40
    elif change == "count":
        evidence["changed_file_count"] = 1
    elif change == "count_bool":
        evidence["pr"]["changed_files"] = True
    elif change == "incomplete":
        complete = False
    elif change == "records":
        evidence["changed_file_records"].pop()
    elif change == "permission":
        evidence["permission"] = "read"
    else:
        evidence["comment"]["updated_at"] = "2026-09-05T12:00:01Z"
    with pytest.raises(ValueError):
        controller.build_deployment_contract(
            request,
            evidence,
            controller=metadata,
            selector_sha256="d" * 64,
            complete=complete,
        )


ALL_SUBSETS = [subset for count in range(4) for subset in combinations(SCOPES, count)]


@pytest.mark.parametrize("scopes", ALL_SUBSETS)
@pytest.mark.parametrize("command", ["plan", "up"])
def test_every_selection_requires_whole_test_before_matching_prod(scopes, command):
    contract = build(scopes, command=command)
    test = reduce(contract)
    prod = reduce(contract, "prod", test_barrier=test)
    assert tuple(scope for scope, _ in test.receipt_digests) == scopes
    assert prod.test_barrier_digest == test.barrier_digest
    assert test.completion_kind == (
        "no-deployment" if not scopes else "apply-drift" if command == "up" else "plan"
    )
    assert prod.completion_kind == test.completion_kind
    assert prod.identity == test.identity == contract.identity


@pytest.mark.parametrize("scope", SCOPES)
@pytest.mark.parametrize("result", ["skipped", "failure", "cancelled", "", None])
def test_selected_unsuccessful_job_never_reaches_barrier(scope, result):
    contract = build()
    results, receipts = node_facts(contract)
    results[scope] = result
    with pytest.raises(ValueError, match="Selected scope did not succeed"):
        controller.reduce_account_barrier(
            contract, environment="test", results=results, receipts=receipts
        )


@pytest.mark.parametrize(
    "change",
    [
        "missing_result",
        "extra_result",
        "missing_receipt",
        "extra_receipt",
        "unselected_success",
        "unselected_failure",
        "invalid_receipt",
    ],
)
def test_scope_envelope_is_exact(change):
    contract = build(("platform",))
    results, receipts = node_facts(contract)
    if change == "missing_result":
        del results["operator"]
    elif change == "extra_result":
        results["foreign"] = "success"
    elif change == "missing_receipt":
        del receipts["platform"]
    elif change == "extra_receipt":
        receipts["operator"] = receipts["platform"]
    elif change == "unselected_success":
        results["operator"] = "success"
    elif change == "unselected_failure":
        results["operator"] = "failure"
    else:
        receipts["platform"] = None
    with pytest.raises(ValueError):
        controller.reduce_account_barrier(
            contract, environment="test", results=results, receipts=receipts
        )


@pytest.mark.parametrize(
    "field,value",
    [
        ("contract_digest", "e" * 64),
        ("selection_digest", "e" * 64),
        ("scope", "operator"),
        ("environment", "prod"),
    ],
)
def test_foreign_scope_account_or_contract_receipt_rejected(field, value):
    contract = build(("platform",))
    results, receipts = node_facts(contract)
    receipts["platform"] = replace(receipts["platform"], **{field: value})
    with pytest.raises(ValueError, match="receipt identity"):
        controller.reduce_account_barrier(
            contract, environment="test", results=results, receipts=receipts
        )


@pytest.mark.parametrize(
    "field,value",
    [
        ("repository", "foreign/repo"),
        ("repository_id", 1),
        ("owner_id", 1),
        ("pull_request_number", "79"),
        ("head_sha", "e" * 40),
        ("base_sha", "e" * 40),
        ("comment_id", "10"),
        ("source_run_id", "13"),
        ("command", "plan"),
        ("target_environment", "test"),
    ],
)
def test_receipt_binds_each_original_identity_field(field, value):
    contract = build(("platform",))
    results, receipts = node_facts(contract)
    receipts["platform"] = replace(
        receipts["platform"], identity=replace(contract.identity, **{field: value})
    )
    with pytest.raises(ValueError, match="receipt identity"):
        controller.reduce_account_barrier(
            contract, environment="test", results=results, receipts=receipts
        )


@pytest.mark.parametrize("stage", ["plan", "apply", "drift"])
@pytest.mark.parametrize(
    "outcome", ["missing", "skipped", "failure", "cancelled", "extra"]
)
def test_successful_job_cannot_hide_incomplete_or_extra_stages(stage, outcome):
    contract = build(("platform",))
    results, receipts = node_facts(contract)
    stages = tuple(
        controller.StageResult(item.operation, outcome)
        if item.operation == stage
        else item
        for item in receipts["platform"].stages
        if outcome != "missing" or item.operation != stage
    )
    if outcome == "extra":
        stages += (controller.StageResult("destroy", "success"),)
    receipts["platform"] = replace(receipts["platform"], stages=stages)
    with pytest.raises(ValueError, match="stages did not all succeed"):
        controller.reduce_account_barrier(
            contract, environment="test", results=results, receipts=receipts
        )


def test_plan_receipt_cannot_substitute_for_apply_proof():
    contract = build(("platform",))
    results, receipts = node_facts(contract)
    receipts["platform"] = replace(
        receipts["platform"], stages=(controller.StageResult("plan", "success"),)
    )
    with pytest.raises(ValueError, match="stages did not all succeed"):
        controller.reduce_account_barrier(
            contract, environment="test", results=results, receipts=receipts
        )
    planned = build(("platform",), command="plan")
    with pytest.raises(ValueError, match="TEST barrier identity"):
        reduce(contract, "prod", test_barrier=reduce(planned))


@pytest.mark.parametrize(
    "change",
    [
        "missing",
        "foreign",
        "prod",
        "kind",
        "digest",
        "selection",
        "receipts",
        "receipt_digest",
        "receipt_content",
        "prior",
    ],
)
def test_prod_rejects_missing_partial_foreign_or_tampered_test_barrier(change):
    contract = build()
    barrier = reduce(contract)
    if change == "missing":
        barrier = None
    elif change == "foreign":
        barrier = replace(barrier, identity=replace(contract.identity, comment_id="10"))
    elif change == "prod":
        barrier = replace(barrier, environment="prod")
    elif change == "kind":
        barrier = replace(barrier, completion_kind="plan")
    elif change == "digest":
        barrier = replace(barrier, contract_digest="e" * 64)
    elif change == "selection":
        barrier = replace(barrier, selection_digest="e" * 64)
    elif change == "receipts":
        barrier = replace(barrier, receipt_digests=barrier.receipt_digests[:1])
    elif change == "receipt_digest":
        barrier = replace(
            barrier, receipt_digests=tuple((scope, "bad") for scope in SCOPES)
        )
    elif change == "receipt_content":
        barrier = replace(
            barrier, receipt_digests=tuple((scope, "e" * 64) for scope in SCOPES)
        )
    else:
        barrier = replace(barrier, test_barrier_digest="e" * 64)
    with pytest.raises(ValueError):
        reduce(contract, "prod", test_barrier=barrier)


def test_only_requested_accounts_and_forward_barrier_direction_are_allowed():
    test_only = build(target="test")
    with pytest.raises(ValueError, match="PROD was not requested"):
        reduce(test_only, "prod", test_barrier=reduce(test_only))
    with pytest.raises(ValueError, match="TEST cannot consume"):
        reduce(test_only, test_barrier=reduce(test_only))
    with pytest.raises(ValueError, match="Unsupported barrier environment"):
        reduce(test_only, "staging")


@pytest.mark.parametrize("schema", [None, True, 1])
def test_reducer_rejects_unknown_contract_type_or_schema(schema):
    contract = build()
    results, receipts = node_facts(contract)
    invalid = None if schema is None else replace(contract, schema_version=schema)
    with pytest.raises(ValueError):
        controller.reduce_account_barrier(
            invalid, environment="test", results=results, receipts=receipts
        )


@pytest.mark.parametrize("identity", [None, {}, "invalid", 1])
def test_reducer_rejects_malformed_nested_identity(identity):
    contract = build()
    results, receipts = node_facts(contract)
    with pytest.raises(ValueError, match="Invalid deployment identity"):
        controller.reduce_account_barrier(
            replace(contract, identity=identity),
            environment="test",
            results=results,
            receipts=receipts,
        )


@pytest.mark.parametrize(
    "change",
    [
        "identity",
        "controller",
        "request",
        "base",
        "selector",
        "revisions",
        "same_revision",
        "schedule",
        "selection_digest",
        "contract_digest",
    ],
)
def test_reducer_rejects_altered_contract(change):
    contract = build()
    results, receipts = node_facts(contract)
    if change == "identity":
        contract = replace(
            contract, identity=replace(contract.identity, repository_id=1)
        )
    elif change == "controller":
        contract = replace(
            contract, identity=replace(contract.identity, controller=None)
        )
    elif change == "request":
        contract = replace(
            contract, identity=replace(contract.identity, comment_id="0")
        )
    elif change == "base":
        contract = replace(
            contract, identity=replace(contract.identity, base_sha="main")
        )
    elif change == "selector":
        contract = replace(contract, selector_sha256="invalid")
    elif change == "revisions":
        contract = replace(
            contract, selection=replace(contract.selection, head_sha="e" * 40)
        )
    elif change == "same_revision":
        contract = replace(
            contract,
            identity=replace(contract.identity, base_sha="a" * 40),
            selection=replace(contract.selection, base_sha="a" * 40),
        )
    elif change == "schedule":
        contract = replace(contract, schedule=contract.schedule[:-1])
    elif change == "selection_digest":
        contract = replace(contract, selection_digest="e" * 64)
    else:
        contract = replace(contract, contract_digest="e" * 64)
    with pytest.raises(ValueError):
        controller.reduce_account_barrier(
            contract, environment="test", results=results, receipts=receipts
        )


def rehash_contract(contract):
    """Model an adversary recomputing both public hashes after editing a contract."""

    def digest(payload):
        encoded = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )
        return hashlib.sha256(encoded.encode()).hexdigest()

    contract = replace(contract, selection_digest=digest(asdict(contract.selection)))
    payload = asdict(contract)
    del payload["contract_digest"]
    return replace(contract, contract_digest=digest(payload))


@pytest.mark.parametrize(
    "change",
    [
        "scopes",
        "flags",
        "reason_flags",
        "reason_text",
        "duplicate_paths",
        "unsafe_path",
        "empty_reasons",
        "integer_flag",
    ],
)
def test_rehashed_selection_cannot_contradict_its_normalized_paths(change):
    original = build()
    selection = original.selection
    if change == "scopes":
        selection = replace(selection, stacks=())
    elif change == "flags":
        selection = replace(
            selection,
            scaffold_validation=True,
            execution_validation=True,
            catalog_validation=True,
        )
    elif change == "reason_flags":
        selection = replace(
            selection,
            reasons=(replace(selection.reasons[0], stacks=()), *selection.reasons[1:]),
        )
    elif change == "reason_text":
        selection = replace(
            selection,
            reasons=(
                replace(selection.reasons[0], reason="Fabricated scope explanation"),
                *selection.reasons[1:],
            ),
        )
    elif change == "duplicate_paths":
        selection = replace(
            selection, reasons=(*selection.reasons, selection.reasons[0])
        )
    elif change == "unsafe_path":
        selection = replace(
            selection,
            reasons=(
                replace(selection.reasons[0], path="../elsewhere.py"),
                *selection.reasons[1:],
            ),
        )
    elif change == "empty_reasons":
        selection = replace(selection, stacks=(), reasons=())
    else:
        selection = replace(selection, execution_validation=0)
    forged = rehash_contract(
        replace(
            original,
            selection=selection,
            schedule=controller.deployment_schedule(
                selection.stacks, command="up", target_environment="prod"
            ),
        )
    )
    assert forged.contract_digest != original.contract_digest
    assert forged.selection_digest != original.selection_digest
    with pytest.raises(ValueError):
        reduce(forged)


@pytest.mark.parametrize("selection", [None, "selection"])
def test_malformed_selection_object_is_rejected(selection):
    contract = build()
    results, receipts = node_facts(contract)
    with pytest.raises(ValueError, match="Invalid selection"):
        controller.reduce_account_barrier(
            replace(contract, selection=selection),
            environment="test",
            results=results,
            receipts=receipts,
        )


@pytest.mark.parametrize("reasons", [None, [], (None,)])
def test_malformed_reason_collection_is_rejected(reasons):
    contract = build()
    results, receipts = node_facts(contract)
    malformed = replace(
        contract, selection=replace(contract.selection, reasons=reasons)
    )
    with pytest.raises(ValueError, match="immutable path impacts"):
        controller.reduce_account_barrier(
            malformed,
            environment="test",
            results=results,
            receipts=receipts,
        )


def test_reclassification_preserves_removed_dependency_from_rename():
    request, evidence, metadata = input_facts()
    evidence["changed_file_records"] = [
        {
            "filename": "docs/archived.py",
            "status": "renamed",
            "previous_filename": "pulumi/infra/ci_config.py",
        }
    ]
    evidence["changed_file_count"] = evidence["pr"]["changed_files"] = 1
    contract = controller.build_deployment_contract(
        request,
        evidence,
        controller=metadata,
        selector_sha256="d" * 64,
        complete=True,
    )
    assert {reason.path for reason in contract.selection.reasons} == {
        "docs/archived.py",
        "pulumi/infra/ci_config.py",
    }
    assert contract.selection.stacks == SCOPES
    assert reduce(contract).completion_kind == "apply-drift"


@pytest.mark.parametrize("field", ["request", "evidence"])
@pytest.mark.parametrize("invalid", [None, [], "object", True])
def test_malformed_outer_input_is_value_error(field, invalid):
    request, evidence, metadata = input_facts()
    with pytest.raises(ValueError, match="must be an object"):
        controller.build_deployment_contract(
            invalid if field == "request" else request,
            invalid if field == "evidence" else evidence,
            controller=metadata,
            selector_sha256="d" * 64,
            complete=True,
        )


@pytest.mark.parametrize(
    "path",
    [
        ("pr",),
        ("run",),
        ("pr", "base"),
        ("pr", "head"),
        ("pr", "base", "repo"),
        ("pr", "head", "repo"),
        ("run", "head_repository"),
        ("pr", "base", "repo", "owner"),
        ("pr", "head", "repo", "owner"),
    ],
)
@pytest.mark.parametrize("invalid", [None, [], "missing"])
def test_malformed_repository_or_owner_envelope_is_value_error(path, invalid):
    request, evidence, metadata = input_facts()
    container = evidence
    for segment in path[:-1]:
        container = container[segment]
    if invalid == "missing":
        del container[path[-1]]
    else:
        container[path[-1]] = invalid
    with pytest.raises(ValueError, match="must be an object"):
        controller.build_deployment_contract(
            request,
            evidence,
            controller=metadata,
            selector_sha256="d" * 64,
            complete=True,
        )
