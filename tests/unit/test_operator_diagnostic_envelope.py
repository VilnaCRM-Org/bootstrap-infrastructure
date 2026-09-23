"""Private diagnostic envelopes must not be usable as saved-plan envelopes."""

from __future__ import annotations

import base64
import json
import sys
from dataclasses import replace
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))

import operator_plan_envelope as diagnostic  # noqa: E402
import operator_plan_validation as validator  # noqa: E402
from test_deployment_controller import build  # noqa: E402
from test_operator_plan_envelope import FakeKms, execution  # noqa: E402


def payload(**changes):
    value = {
        "stage": "preview",
        "category": "private-process-failed",
        "exit_code": 1,
        "stdout": base64.b64encode(b"private stdout").decode("ascii"),
        "stderr": base64.b64encode(b"private stderr").decode("ascii"),
        "stdout_truncated": False,
        "stderr_truncated": False,
        "validation_reason": "same-input-diff",
    }
    value.update(changes)
    return value


def seal(kms, value=None, contract=None, context=None):
    return diagnostic.seal_diagnostic(
        value or payload(),
        contract=contract or build(("operator",)),
        execution=context or execution(),
        generate_key=kms.generate,
    )


def unseal(kms, raw, contract=None, context=None):
    return diagnostic.open_diagnostic(
        raw,
        contract=contract or build(("operator",)),
        execution=context or execution(),
        decrypt_key=kms.decrypt,
    )


def test_roundtrip_uses_existing_kms_context_and_distinct_authenticated_kind():
    kms = FakeKms()
    value = payload(exit_code=-9, validation_reason="private-process-timeout")
    raw = seal(kms, value)

    assert unseal(kms, raw) == value
    public = json.loads(raw)
    assert public["schema"] == 1
    assert public["kind"] == diagnostic.DIAGNOSTIC_KIND
    assert public["binding"]["purpose"] == "operator-saved-plan-v1"
    assert (
        kms.generated[0]["EncryptionContext"] == kms.decrypted[0]["EncryptionContext"]
    )
    assert kms.generated[0]["KeyId"] == execution().kms_key_arn
    assert value["stdout"].encode() not in raw
    assert value["stderr"].encode() not in raw


@pytest.mark.parametrize(
    "change",
    [
        {"extra": "field"},
        {"stage": ""},
        {"category": "bad category"},
        {"validation_reason": object()},
        {"validation_reason": "x" * 4097},
        {"validation_reason": "é" * 3000},
        {"validation_reason": "\ud800"},
        {"exit_code": 0},
        {"exit_code": -128},
        {"exit_code": True},
        {"stdout_truncated": 1},
        {"stdout": "not-base64"},
    ],
)
def test_rejects_invalid_or_oversized_private_payload_before_kms(change):
    kms = FakeKms()
    with pytest.raises(diagnostic.DiagnosticEnvelopeError):
        seal(kms, payload(**change))
    assert not kms.generated


def test_empty_authorized_validation_reason_and_null_exit_are_preserved():
    kms = FakeKms()
    value = payload(exit_code=None, validation_reason="")

    assert unseal(kms, seal(kms, value)) == value


def test_maximum_streams_roundtrip_with_real_aes_and_production_limits():
    assert diagnostic.MAX_DIAGNOSTIC_STDOUT_BYTES == validator.MAX_DOCUMENT_BYTES
    assert diagnostic.MAX_DIAGNOSTIC_STDOUT_BYTES == 32 * 1024 * 1024
    assert diagnostic.MAX_DIAGNOSTIC_STDERR_BYTES == 1024 * 1024
    assert diagnostic.MAX_DIAGNOSTIC_PAYLOAD_BYTES == 45 * 1024 * 1024
    assert diagnostic.MAX_DIAGNOSTIC_ENVELOPE_BYTES == 61 * 1024 * 1024
    value = payload(
        stdout=base64.b64encode(b"x" * diagnostic.MAX_DIAGNOSTIC_STDOUT_BYTES).decode(),
        stderr=base64.b64encode(b"y" * diagnostic.MAX_DIAGNOSTIC_STDERR_BYTES).decode(),
        validation_reason="r" * 4096,
    )
    kms = FakeKms()
    raw = seal(kms, value)
    assert len(raw) <= diagnostic.MAX_DIAGNOSTIC_ENVELOPE_BYTES
    assert unseal(kms, raw) == value


@pytest.mark.parametrize("field,maximum", [("stdout", 32), ("stderr", 16)])
def test_split_stream_exact_and_max_plus_one_before_kms(monkeypatch, field, maximum):
    monkeypatch.setattr(diagnostic, "MAX_DIAGNOSTIC_STDOUT_BYTES", 32)
    monkeypatch.setattr(diagnostic, "MAX_DIAGNOSTIC_STDERR_BYTES", 16)
    kms = FakeKms()
    value = payload(**{field: base64.b64encode(b"x" * maximum).decode()})
    assert unseal(kms, seal(kms, value)) == value
    kms.generated.clear()
    value[field] = base64.b64encode(b"x" * (maximum + 1)).decode()
    with pytest.raises(diagnostic.DiagnosticEnvelopeError, match="^payload-stream$"):
        seal(kms, value)
    assert not kms.generated


@pytest.mark.parametrize("field", ["stdout", "stderr"])
def test_decrypted_stream_limit_is_revalidated(monkeypatch, field):
    kms = FakeKms()
    value = payload(**{field: base64.b64encode(b"x" * 33).decode()})
    raw = seal(kms, value)
    monkeypatch.setattr(diagnostic, "MAX_DIAGNOSTIC_" + field.upper() + "_BYTES", 32)
    with pytest.raises(diagnostic.DiagnosticEnvelopeError, match="^payload-stream$"):
        unseal(kms, raw)


def test_payload_exact_and_max_plus_one_before_kms(monkeypatch):
    kms = FakeKms()
    value = payload()
    size = len(diagnostic._diagnostic_payload(value))
    monkeypatch.setattr(diagnostic, "MAX_DIAGNOSTIC_PAYLOAD_BYTES", size)
    assert unseal(kms, seal(kms, value)) == value
    kms.generated.clear()
    monkeypatch.setattr(diagnostic, "MAX_DIAGNOSTIC_PAYLOAD_BYTES", size - 1)
    with pytest.raises(diagnostic.DiagnosticEnvelopeError, match="^payload-size$"):
        seal(kms, value)
    assert not kms.generated


def test_envelope_exact_and_max_plus_one(monkeypatch):
    kms = FakeKms()
    raw = seal(kms)
    monkeypatch.setattr(diagnostic, "MAX_DIAGNOSTIC_ENVELOPE_BYTES", len(raw))
    assert unseal(kms, seal(kms)) == payload()
    monkeypatch.setattr(diagnostic, "MAX_DIAGNOSTIC_ENVELOPE_BYTES", len(raw) - 1)
    kms.decrypted.clear()
    with pytest.raises(diagnostic.DiagnosticEnvelopeError, match="^envelope-size$"):
        unseal(kms, raw)
    assert not kms.decrypted
    with pytest.raises(diagnostic.DiagnosticEnvelopeError, match="^envelope-size$"):
        seal(kms)


def test_detailed_private_stage_survives_encryption():
    kms = FakeKms()
    value = payload(stage="pulumi-preview")

    assert unseal(kms, seal(kms, value)) == value


def test_rejects_plan_envelope_transplant_and_diagnostic_as_plan():
    kms = FakeKms()
    diagnostic_raw = seal(kms)
    plan_raw = diagnostic.seal_plan(
        b"{}",
        contract=build(("operator",)),
        execution=execution(),
        generate_key=kms.generate,
    )

    with pytest.raises(diagnostic.DiagnosticEnvelopeError):
        unseal(kms, plan_raw)
    with pytest.raises(diagnostic.EnvelopeError):
        diagnostic.open_plan(
            diagnostic_raw,
            contract=build(("operator",)),
            execution=execution(),
            decrypt_key=kms.decrypt,
        )


def test_relabelled_diagnostic_without_kind_fails_plan_authentication():
    kms = FakeKms()
    envelope = json.loads(seal(kms))
    del envelope["kind"]

    with pytest.raises(diagnostic.EnvelopeError, match="authentication-failed"):
        diagnostic.open_plan(
            json.dumps(envelope, separators=(",", ":")).encode(),
            contract=build(("operator",)),
            execution=execution(),
            decrypt_key=kms.decrypt,
        )


def test_rejects_non_json_or_oversized_envelope_before_kms(monkeypatch):
    monkeypatch.setattr(diagnostic, "MAX_DIAGNOSTIC_ENVELOPE_BYTES", 1024)
    kms = FakeKms()
    with pytest.raises(diagnostic.DiagnosticEnvelopeError):
        unseal(kms, b"not-json")
    with pytest.raises(diagnostic.DiagnosticEnvelopeError):
        unseal(kms, b"x" * (diagnostic.MAX_DIAGNOSTIC_ENVELOPE_BYTES + 1))
    assert not kms.decrypted


@pytest.mark.parametrize(
    "change",
    [
        {"schema": True},
        {"kind": "operator-saved-plan-v1"},
        {"binding": {}},
        {"ciphertext": base64.b64encode(b"x" * 16).decode("ascii")},
        {"wrapped_key": base64.b64encode(b"other").decode("ascii")},
        {"nonce": base64.b64encode(b"x").decode("ascii")},
    ],
)
def test_rejects_cross_binding_type_and_ciphertext_tampering(change):
    kms = FakeKms()
    envelope = json.loads(seal(kms))
    envelope.update(change)

    with pytest.raises(diagnostic.DiagnosticEnvelopeError):
        unseal(kms, json.dumps(envelope, separators=(",", ":")).encode())


def test_rejects_foreign_kms_or_changed_execution_without_printing(capsys):
    kms = FakeKms()
    with pytest.raises(diagnostic.DiagnosticEnvelopeError):
        diagnostic.seal_diagnostic(
            payload(),
            contract=build(("operator",)),
            execution=replace(execution(), account_id="111122223333"),
            generate_key=kms.generate,
        )
    raw = seal(kms)
    with pytest.raises(diagnostic.DiagnosticEnvelopeError):
        diagnostic.open_diagnostic(
            raw,
            contract=build(("operator",)),
            execution=execution(),
            decrypt_key=lambda request: {"KeyId": "foreign", "Plaintext": b"x" * 32},
        )
    assert capsys.readouterr() == ("", "")
