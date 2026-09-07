"""Strict transport and semantic rejection cases for deployment contracts."""

from __future__ import annotations

import hashlib
import json
import sys
from copy import deepcopy
from dataclasses import asdict
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))

import deployment_contract_io as contract_io  # noqa: E402
from deployment_worker_receipt import build_worker_receipt  # noqa: E402
from test_deployment_controller import build  # noqa: E402


@pytest.fixture
def document():
    """Obtain genuine common-identity/selector/scheduler builder output as JSON data."""
    return json.loads(json.dumps(asdict(build())))


def encode(document):
    return json.dumps(document, sort_keys=True, separators=(",", ":"))


def rehash(document):
    """Model an adversary able to recompute every public content hash."""

    def digest(value):
        return hashlib.sha256(encode(value).encode()).hexdigest()

    document["selection_digest"] = digest(document["selection"])
    payload = {
        key: value for key, value in document.items() if key != "contract_digest"
    }
    document["contract_digest"] = digest(payload)
    return encode(document)


def at(document, path):
    for key in path:
        document = document[key]
    return document


@pytest.mark.parametrize(
    "scopes",
    [
        (),
        ("operator",),
        ("governance", "platform"),
        ("operator", "governance", "platform"),
    ],
)
@pytest.mark.parametrize("command", ["plan", "up"])
@pytest.mark.parametrize("target", ["test", "prod"])
@pytest.mark.parametrize("transport", [str, bytes])
def test_actual_builder_contract_roundtrip(scopes, command, target, transport):
    contract = build(scopes, command=command, target=target)
    payload = json.dumps(asdict(contract))
    if transport is bytes:
        payload = payload.encode()
    result = contract_io.decode_deployment_contract(payload)
    assert result == contract
    assert type(result.schedule) is tuple
    assert type(result.selection.reasons) is tuple
    assert type(result.selection.stacks) is tuple
    assert all(type(reason.stacks) is tuple for reason in result.selection.reasons)


OBJECT_PATHS = [
    (),
    ("identity",),
    ("identity", "controller"),
    ("selection",),
    ("selection", "reasons", 0),
    ("schedule", 0),
]


@pytest.mark.parametrize("path", OBJECT_PATHS)
@pytest.mark.parametrize("change", ["unknown", "missing", "array", "null"])
def test_every_nested_object_requires_exact_keys(document, path, change):
    original = at(document, path)
    if change == "unknown":
        original["attacker"] = "extra"
    elif change == "missing":
        del original[next(iter(original))]
    else:
        replacement = [] if change == "array" else None
        if not path:
            document = replacement
        else:
            at(document, path[:-1])[path[-1]] = replacement
    with pytest.raises(ValueError):
        contract_io.decode_deployment_contract(encode(document))


@pytest.mark.parametrize("path", OBJECT_PATHS)
def test_duplicate_keys_rejected_at_every_object_depth(document, path):
    marker = "DUPLICATE_OBJECT_PLACEHOLDER"
    original = at(document, path)
    key = next(iter(original))
    duplicate = (
        encode(original)[:-1] + "," + encode(key) + ":" + encode(original[key]) + "}"
    )
    if path:
        at(document, path[:-1])[path[-1]] = marker
        payload = encode(document).replace(encode(marker), duplicate)
    else:
        payload = duplicate
    with pytest.raises(ValueError, match="Duplicate JSON object key"):
        contract_io.decode_deployment_contract(payload)


def test_duplicate_escaped_keys_are_also_rejected():
    with pytest.raises(ValueError, match="Duplicate"):
        contract_io.decode_deployment_contract('{"identity":{},"identit\\u0079":{}}')


@pytest.mark.parametrize("value", ["NaN", "Infinity", "-Infinity", "1e999", "1.0"])
def test_nonfinite_and_float_numbers_rejected_everywhere(document, value):
    document["identity"]["repository_id"] = "NUMBER_PLACEHOLDER"
    payload = encode(document).replace('"NUMBER_PLACEHOLDER"', value)
    with pytest.raises(ValueError, match="Noninteger JSON numbers"):
        contract_io.decode_deployment_contract(payload)


@pytest.mark.parametrize(
    "path,value",
    [
        (("schema_version",), True),
        (("schema_version",), "2"),
        (("identity", "repository_id"), True),
        (("identity", "owner_id"), True),
        (("identity", "controller", "run_attempt"), True),
        (("identity", "head_sha"), 123),
        (("selection", "scaffold_validation"), 1),
        (("selection", "execution_validation"), "false"),
        (("selection", "catalog_validation"), None),
        (("selection", "reasons", 0, "scaffold_validation"), 0),
        (("selection", "reasons", 0, "execution_validation"), "true"),
        (("selection", "reasons", 0, "catalog_validation"), None),
        (("selection", "reasons", 0, "path"), {}),
        (("selection", "reasons", 0, "reason"), []),
        (("selection", "stacks", 0), 5),
        (("selection", "reasons", 0, "stacks", 0), False),
        (("schedule", 0, "key"), False),
        (("schedule", 0, "environment"), 5),
        (("schedule", 0, "scope"), []),
        (("schedule", 0, "operation"), None),
        (("schedule", 0, "predecessor"), 0),
        (("selection_digest",), None),
        (("contract_digest",), 5),
    ],
)
def test_wrong_primitive_types_rejected_even_after_rehash(document, path, value):
    at(document, path[:-1])[path[-1]] = value
    # Do not repair a deliberately malformed digest field.
    payload = (
        encode(document)
        if path[-1] in {"selection_digest", "contract_digest"}
        else rehash(document)
    )
    with pytest.raises(ValueError):
        contract_io.decode_deployment_contract(payload)


@pytest.mark.parametrize(
    "path",
    [
        ("selection", "stacks"),
        ("selection", "reasons"),
        ("selection", "reasons", 0, "stacks"),
        ("schedule",),
    ],
)
@pytest.mark.parametrize("replacement", [None, {}, "operator", 1])
def test_required_arrays_are_not_coerced(document, path, replacement):
    at(document, path[:-1])[path[-1]] = replacement
    with pytest.raises(ValueError, match="Expected JSON array"):
        contract_io.decode_deployment_contract(encode(document))


@pytest.mark.parametrize("change", ["scopes", "flags", "reason", "schedule", "path"])
def test_rehashed_contradictions_rejected_by_real_selector(document, change):
    if change == "scopes":
        document["selection"]["stacks"] = []
        document["schedule"] = []
    elif change == "flags":
        document["selection"]["scaffold_validation"] = True
    elif change == "reason":
        document["selection"]["reasons"][0]["stacks"] = []
    elif change == "schedule":
        document["schedule"] = document["schedule"][1:]
    else:
        document["selection"]["reasons"][0]["path"] = "../README.md"
    with pytest.raises(ValueError):
        contract_io.decode_deployment_contract(rehash(document))


@pytest.mark.parametrize("field", ["selection_digest", "contract_digest"])
def test_content_digest_tampering_rejected(document, field):
    document[field] = "e" * 64
    with pytest.raises(ValueError, match="digest differs"):
        contract_io.decode_deployment_contract(encode(document))


@pytest.mark.parametrize("payload", [None, {}, [], 1, bytearray(b"{}")])
def test_only_text_or_utf8_byte_payloads_are_accepted(payload):
    with pytest.raises(ValueError, match="payload must be"):
        contract_io.decode_deployment_contract(payload)


@pytest.mark.parametrize("payload", ["", "{", "[]", "null", '"text"', "true", "{} {}"])
def test_malformed_or_nonobject_json_is_rejected(payload):
    with pytest.raises(ValueError):
        contract_io.decode_deployment_contract(payload)


@pytest.mark.parametrize(
    "payload", [b"\xff", b"\xff\xfe{\x00}\x00", "\ud800", '"\\ud800"']
)
def test_non_utf8_and_surrogate_payloads_are_rejected(payload):
    with pytest.raises(ValueError):
        contract_io.decode_deployment_contract(payload)


def test_escaped_surrogate_in_nested_string_rejected(document):
    document["selection"]["reasons"][0]["path"] = "docs/\ud800.md"
    with pytest.raises(ValueError):
        contract_io.decode_deployment_contract(encode(document))


@pytest.mark.parametrize("transport", [str, bytes])
def test_exact_size_limit_accepts_valid_contract_then_rejects_extra_byte(
    document, transport
):
    payload = encode(document)
    payload += " " * (contract_io.MAX_CONTRACT_BYTES - len(payload))
    if transport is bytes:
        payload = payload.encode()
    assert contract_io.decode_deployment_contract(payload) == build()
    extra = " " if transport is str else b" "
    with pytest.raises(ValueError, match="size limit"):
        contract_io.decode_deployment_contract(payload + extra)


def test_size_limit_counts_utf8_bytes_before_json_parsing():
    # Fewer than 1MiB characters, but more than 1MiB in UTF-8.
    payload = "é" * (contract_io.MAX_CONTRACT_BYTES // 2 + 1)
    with pytest.raises(ValueError, match="size limit"):
        contract_io.decode_deployment_contract(payload)


def test_pathological_nesting_is_a_deliberate_rejection():
    payload = "[" * 2000 + "0" + "]" * 2000
    with pytest.raises(ValueError, match="nesting is too deep"):
        contract_io.decode_deployment_contract(payload)


def test_decoding_does_not_consume_claim_or_fetch_external_evidence(
    monkeypatch, document
):
    import deployment_controller

    def forbidden(*args, **kwargs):
        raise AssertionError("Decoder must not perform I/O or authenticate provenance")

    monkeypatch.setattr(deployment_controller.preflight, "gh", forbidden)
    monkeypatch.setattr(deployment_controller.preflight, "claim_request", forbidden)
    original = deepcopy(document)
    result = contract_io.decode_deployment_contract(encode(document))
    assert result == build()
    assert document == original


def receipt_document(contract, scope="operator", environment="test"):
    receipt = build_worker_receipt(
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
    return receipt, json.loads(encode(asdict(receipt)))


@pytest.mark.parametrize("scope", ["operator", "governance", "platform"])
@pytest.mark.parametrize("environment", ["test", "prod"])
@pytest.mark.parametrize("command", ["plan", "up"])
def test_receipt_roundtrip_from_actual_worker(scope, environment, command):
    contract = build((scope,), command=command, target="prod")
    receipt, document = receipt_document(contract, scope, environment)
    result = contract_io.decode_account_receipt(
        (encode(document) + "\n").encode(),
        contract=contract,
        scope=scope,
        environment=environment,
    )
    assert result == receipt
    assert type(result.stages) is tuple


@pytest.mark.parametrize(
    "path,value",
    [
        (("identity", "head_sha"), "f" * 40),
        (("identity", "base_sha"), "f" * 40),
        (("identity", "controller", "run_id"), "99999"),
        (("identity", "controller", "run_attempt"), True),
        (("contract_digest",), "f" * 64),
        (("selection_digest",), "f" * 64),
        (("scope",), "platform"),
        (("environment",), "prod"),
        (("stages",), []),
        (("stages",), None),
        (("stages", 0, "operation"), "apply"),
        (("stages", 0, "result"), "skipped"),
        (("stages", 0, "result"), "failure"),
        (("stages", 0, "result"), "cancelled"),
    ],
)
def test_receipt_cannot_change_identity_or_omit_successful_stages(path, value):
    contract = build(("operator",), command="up", target="test")
    _, document = receipt_document(contract)
    at(document, path[:-1])[path[-1]] = value
    with pytest.raises(ValueError):
        contract_io.decode_account_receipt(
            encode(document), contract=contract, scope="operator", environment="test"
        )


@pytest.mark.parametrize("path", [(), ("identity",), ("stages", 0)])
def test_receipt_cannot_add_claims_or_duplicate_json_fields(path):
    contract = build(("operator",))
    _, document = receipt_document(contract)
    at(document, path)["attacker"] = True
    with pytest.raises(ValueError, match="exactly the required fields"):
        contract_io.decode_account_receipt(
            encode(document), contract=contract, scope="operator", environment="test"
        )
    duplicate = encode(document).replace(
        '"attacker":true', '"attacker":true,"attacker":false'
    )
    with pytest.raises(ValueError, match="Duplicate"):
        contract_io.decode_account_receipt(
            duplicate, contract=contract, scope="operator", environment="test"
        )


@pytest.mark.parametrize(
    "scopes,scope,environment",
    [
        ((), "operator", "test"),
        (("operator",), "governance", "test"),
        (("operator",), "operator", "prod"),
        (("operator",), "operator", "staging"),
    ],
)
def test_empty_or_unrequested_node_cannot_issue_receipt(scopes, scope, environment):
    contract = build(scopes, target="test")
    with pytest.raises(ValueError, match="not selected"):
        contract_io.decode_account_receipt(
            "{}", contract=contract, scope=scope, environment=environment
        )
