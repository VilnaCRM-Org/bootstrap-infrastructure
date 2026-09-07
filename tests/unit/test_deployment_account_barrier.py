"""Exercise root ordering and rejection; artifact provenance has separate tests."""

from __future__ import annotations

import hashlib
import itertools
import json
import sys
from copy import deepcopy
from dataclasses import asdict
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))

import deployment_account_barrier as runtime  # noqa: E402
from deployment_worker_receipt import build_worker_receipt  # noqa: E402
from test_deployment_controller import build  # noqa: E402


def job(result="success", outputs=None):
    return {"result": result, "outputs": outputs or {}}


def needs(contract, environment):
    accounts = ("test", "prod") if environment == "prod" else ("test",)
    result = {"preflight": job(), "validate_inputs": job()}
    for account in accounts:
        for scope in runtime.STACK_ORDER:
            result[f"{scope}_{account}"] = job(
                "success" if scope in contract.selection.stacks else "skipped"
            )
    if environment == "prod":
        result["whole_test"] = job()
    return result


@pytest.fixture
def receipts(monkeypatch):
    """Use real stage construction while isolating the separately tested API adapter."""
    calls = []

    def load(contract, *, scope, environment, outputs):
        calls.append((scope, environment))
        return build_worker_receipt(
            contract,
            scope=scope,
            environment=environment,
            results={
                "plan": "success",
                "destructive": "success",
                "iam": "success",
                "apply": "success" if contract.identity.command == "up" else "skipped",
                "drift": "success" if contract.identity.command == "up" else "skipped",
            },
        )

    monkeypatch.setattr(runtime, "load_verified_receipt", load)
    return calls


def production_needs(contract):
    test = runtime.build_verified_barrier(
        contract, environment="test", needs_payload=json.dumps(needs(contract, "test"))
    )
    result = needs(contract, "prod")
    result["whole_test"] = job(outputs=runtime.barrier_outputs(test))
    return result, test


SUBSETS = [
    tuple(
        scope
        for scope, enabled in zip(runtime.STACK_ORDER, bits, strict=True)
        if enabled
    )
    for bits in itertools.product((False, True), repeat=3)
]


@pytest.mark.parametrize("scopes", SUBSETS)
@pytest.mark.parametrize("command", ["plan", "up"])
@pytest.mark.parametrize("target", ["test", "prod"])
def test_every_scope_subset_obeys_complete_test_barrier(
    receipts, scopes, command, target
):
    contract = build(scopes, command=command, target=target)
    if target == "prod":
        inputs, test = production_needs(contract)
        receipts.clear()
    else:
        inputs, test = needs(contract, "test"), None
    result = runtime.build_verified_barrier(
        contract, environment=target, needs_payload=json.dumps(inputs)
    )
    accounts = ("test", "prod") if target == "prod" else ("test",)
    assert receipts == [(scope, account) for account in accounts for scope in scopes]
    assert result.test_barrier_digest == (test.barrier_digest if test else None)
    expected = (
        ("apply-drift" if command == "up" else "plan") if scopes else "no-deployment"
    )
    assert result.completion_kind == expected


@pytest.mark.parametrize("scope", runtime.STACK_ORDER)
@pytest.mark.parametrize("failure", ["failure", "cancelled", "skipped"])
def test_selected_test_failure_prevents_any_prod_receipt(receipts, scope, failure):
    contract = build(runtime.STACK_ORDER, target="prod")
    inputs, _ = production_needs(contract)
    receipts.clear()
    inputs[f"{scope}_test"]["result"] = failure
    with pytest.raises(ValueError):
        runtime.build_verified_barrier(
            contract, environment="prod", needs_payload=json.dumps(inputs)
        )
    assert not receipts


def test_unselected_worker_cannot_expose_receipt_outputs(receipts):
    contract = build(("platform",))
    inputs = needs(contract, "test")
    inputs["operator_test"]["outputs"] = {"receipt_digest": "f" * 64}
    with pytest.raises(ValueError, match="Unselected worker"):
        runtime.build_verified_barrier(
            contract, environment="test", needs_payload=json.dumps(inputs)
        )
    assert not receipts


@pytest.mark.parametrize("mutation", ["failed", "digest", "selection", "missing"])
def test_prod_rejects_unverified_test_barrier(receipts, mutation):
    contract = build(runtime.STACK_ORDER, target="prod")
    inputs, _ = production_needs(contract)
    receipts.clear()
    previous = inputs["whole_test"]
    if mutation == "failed":
        previous["result"] = "failure"
    elif mutation == "missing":
        previous["outputs"] = {}
    else:
        field = "barrier_digest" if mutation == "digest" else "selection_digest"
        previous["outputs"][field] = "f" * 64
    with pytest.raises(ValueError, match="Full TEST barrier"):
        runtime.build_verified_barrier(
            contract, environment="prod", needs_payload=json.dumps(inputs)
        )
    assert all(account == "test" for _, account in receipts)


@pytest.mark.parametrize("name", ["preflight", "validate_inputs"])
def test_failed_root_prerequisite_prevents_receipt_reads(receipts, name):
    contract = build()
    inputs = needs(contract, "test")
    inputs[name]["result"] = "skipped"
    with pytest.raises(ValueError, match="did not succeed"):
        runtime.build_verified_barrier(
            contract, environment="test", needs_payload=json.dumps(inputs)
        )
    assert not receipts


@pytest.mark.parametrize(
    "change",
    [
        "missing",
        "extra",
        "job_extra",
        "job_null",
        "outputs_list",
        "outputs_number",
        "result_number",
        "result_unknown",
    ],
)
def test_root_dependency_schema_is_closed(receipts, change):
    contract = build()
    inputs = needs(contract, "test")
    if change == "missing":
        del inputs["operator_test"]
    elif change == "extra":
        inputs["attacker"] = job()
    elif change == "job_extra":
        inputs["preflight"]["attacker"] = True
    elif change == "job_null":
        inputs["preflight"] = None
    elif change.startswith("outputs"):
        inputs["preflight"]["outputs"] = [] if change == "outputs_list" else {"head": 1}
    else:
        inputs["preflight"]["result"] = 1 if change == "result_number" else "pending"
    with pytest.raises(ValueError):
        runtime.build_verified_barrier(
            contract, environment="test", needs_payload=json.dumps(inputs)
        )
    assert not receipts


def test_duplicate_dependency_keys_are_rejected(receipts):
    with pytest.raises(ValueError, match="Duplicate"):
        runtime.build_verified_barrier(
            build(), environment="test", needs_payload='{"preflight":{},"preflight":{}}'
        )


def test_unknown_account_is_rejected(receipts):
    with pytest.raises(ValueError, match="Invalid barrier account"):
        runtime.build_verified_barrier(build(), environment="stage", needs_payload="{}")


def test_receipt_authentication_failure_cannot_create_barrier(receipts, monkeypatch):
    def reject(*args, **kwargs):
        raise ValueError("Wrong artifact provenance")

    monkeypatch.setattr(runtime, "load_verified_receipt", reject)
    contract = build()
    with pytest.raises(ValueError, match="provenance"):
        runtime.build_verified_barrier(
            contract,
            environment="test",
            needs_payload=json.dumps(needs(contract, "test")),
        )


@pytest.mark.parametrize("fail", [False, True])
def test_cli_writes_only_after_admission_and_complete_receipts(
    receipts, monkeypatch, tmp_path, fail
):
    contract = build(("platform",), target="test")
    inputs = needs(contract, "test")
    if fail:
        inputs["platform_test"]["result"] = "failure"
    monkeypatch.setenv("BARRIER_NEEDS", json.dumps(inputs))
    calls = []

    def admission(**kwargs):
        calls.append(kwargs)
        return contract

    monkeypatch.setattr(runtime, "load_verified_admission", admission)
    path, output = tmp_path / "barriers/test.json", tmp_path / "output"
    argv = [
        "--artifact-id",
        "123",
        "--artifact-sha256",
        "a" * 64,
        "--contract-sha256",
        "b" * 64,
        "--environment",
        "test",
        "--barrier-path",
        str(path),
        "--output",
        str(output),
    ]
    if fail:
        with pytest.raises(ValueError):
            runtime.main(argv)
        assert not path.exists() and not output.exists()
    else:
        assert runtime.main(argv) == 0
        expected = runtime.build_verified_barrier(
            contract, environment="test", needs_payload=json.dumps(inputs)
        )
        assert json.loads(path.read_bytes()) == json.loads(json.dumps(asdict(expected)))
        assert (
            f"barrier_file_sha256={hashlib.sha256(path.read_bytes()).hexdigest()}"
            in output.read_text()
        )
        original = deepcopy(path.read_bytes())
        with pytest.raises(FileExistsError):
            runtime.persist_barrier(expected, path)
        assert path.read_bytes() == original
    assert calls == [
        {"artifact_id": "123", "artifact_sha256": "a" * 64, "contract_sha256": "b" * 64}
    ]
