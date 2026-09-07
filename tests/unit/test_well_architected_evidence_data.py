"""Advisory integrity checks for selected committed evidence, without live access."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import _well_architected_restore_evidence as restore  # noqa: E402
import _well_architected_structured_evidence as structured  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
SPEC = ROOT / "specs/issue-17-well-architected-5-of-5"
SELECTED = (
    "question-matrix-evidence-2026-09-06.json",
    "external-control-evidence-2026-09-06.json",
    "restore-drill-evidence-2026-09-07.json",
)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        assert key not in result, f"Duplicate JSON field: {key}"
        result[key] = value
    return result


def _payload(path):
    value = json.loads(path.read_text(), object_pairs_hook=_unique_object)
    assert isinstance(value, dict), f"Evidence must be an object: {path}"
    return value


def _receipt_bindings(payload, root):
    bindings = payload.get("receiptBindings")
    assert isinstance(bindings, dict) and bindings, "Missing receiptBindings"
    for name, digest in bindings.items():
        assert isinstance(name, str) and not Path(name).is_absolute()
        assert ".." not in Path(name).parts and Path(name).parts
        assert isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest)
        path = root / name
        assert all(not parent.is_symlink() for parent in (path, *path.parents))
        assert path.is_file(), f"Missing committed receipt: {name}"
        assert hashlib.sha256(path.read_bytes()).hexdigest() == digest, name


def test_selected_question_data_is_consistent_without_claiming_acceptance():
    payload = _payload(SPEC / SELECTED[0])
    assert not structured._structured_evidence_payload_blockers(
        payload, structured.QUESTION_MATRIX_REQUIRED_FIELDS
    )
    assert not structured._question_matrix_source_verification_blockers(payload)
    assert not structured._question_matrix_score_blockers(payload)
    # Unresolved questions remain valid data; only the trusted live collector
    # decides whether that data satisfies full acceptance.
    assert payload["questionCount"] == 57


def test_selected_external_control_data_is_consistent():
    payload = _payload(SPEC / SELECTED[1])
    assert not structured._structured_evidence_payload_blockers(
        payload, structured.EXTERNAL_CONTROL_REQUIRED_FIELDS
    )
    assert not structured._structured_evidence_control_blockers(
        payload, structured.REQUIRED_EXTERNAL_CONTROL_IDS
    )
    assert payload["controlCount"] == 8


def test_selected_restore_data_retains_measured_scope_and_history():
    payload = _payload(SPEC / SELECTED[2])
    assert not restore._restore_drill_payload_blockers(payload)
    assert payload["environment"] == "test"
    assert payload["historicalFailedAttempt"]["drillPassed"] is False
    assert payload["requestMetadataEvidence"]["request_values_verified"] is False


@pytest.mark.parametrize("name", SELECTED)
def test_selected_receipts_match_exact_committed_bytes(name):
    _receipt_bindings(_payload(SPEC / name), ROOT)


@pytest.mark.parametrize("content", ["[]", '{"owner":1,"owner":2}', "{"])
def test_invalid_evidence_json_is_rejected(tmp_path, content):
    path = tmp_path / "record.json"
    path.write_text(content)
    with pytest.raises((AssertionError, json.JSONDecodeError)):
        _payload(path)


@pytest.mark.parametrize("case", ["missing", "tampered", "symlink", "traversal"])
def test_unverifiable_receipts_are_rejected(tmp_path, case):
    receipt = tmp_path / "receipt.json"
    receipt.write_text('{"status":"passed"}')
    digest = hashlib.sha256(receipt.read_bytes()).hexdigest()
    name = "receipt.json"
    if case == "missing":
        receipt.unlink()
    elif case == "tampered":
        receipt.write_text('{"status":"failed"}')
    elif case == "symlink":
        target = tmp_path / "other.json"
        receipt.rename(target)
        receipt.symlink_to(target)
    else:
        name = "../receipt.json"
    with pytest.raises(AssertionError):
        _receipt_bindings({"receiptBindings": {name: digest}}, tmp_path)
