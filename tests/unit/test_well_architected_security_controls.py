"""Objective direct-IAM facts must not become unearned human/SSO approval."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import _well_architected_aws_iam_access as iam  # noqa: E402
import _well_architected_security_account_evidence as attestation  # noqa: E402
import record_security_account_attestation as recording  # noqa: E402


def response(command, payload=None, error=""):
    return subprocess.CompletedProcess(
        command, 254 if error else 0, json.dumps(payload), error
    )


def test_credentialless_users_do_not_need_invented_mfa_devices():
    def runner(command, **_kwargs):
        operation = command[2]
        if operation == "get-account-summary":
            return response(
                command,
                {
                    "Users": 5,
                    "MFADevicesInUse": 3,
                    "AccountMFAEnabled": 1,
                    "AccountAccessKeysPresent": 0,
                },
            )
        if operation == "list-users":
            return response(command, [f"user-{i}" for i in range(5)])
        if operation == "list-access-keys":
            return response(command, [])
        assert operation == "get-login-profile"
        return response(command, error="An error occurred (NoSuchEntity)")

    result = iam.aws_iam_account_access(runner=runner)
    assert result["status"] == "passed"
    assert result["evidence"]["consoleUserCount"] == 0
    assert "user-" not in json.dumps(result)
    assert "securityAccountAttestation" not in result["evidence"]


@pytest.mark.parametrize("payload", [None, {}, [None], [""], ["u", "u"]])
def test_malformed_or_duplicate_user_inventory_fails(payload):
    users, blockers = iam._iam_user_names(
        runner=lambda cmd, **kw: response(cmd, payload)
    )
    assert users == [] and blockers


@pytest.mark.parametrize(
    "profile,error,devices,device_error,expected",
    [
        (None, "An error occurred (NoSuchEntity)", None, "", "no_console"),
        (None, "AccessDenied", None, "", "unknown"),
        ({}, "", None, "", "unknown"),
        ({"LoginProfile": {}}, "", None, "", "unknown"),
        ({"LoginProfile": {"UserName": "u"}}, "", {"MFADevices": []}, "", "no_mfa"),
        (
            {"LoginProfile": {"UserName": "u"}},
            "",
            {"MFADevices": [{"UserName": "u", "SerialNumber": "serial"}]},
            "",
            "mfa",
        ),
        ({"LoginProfile": {"UserName": "u"}}, "", {}, "Denied", "unknown"),
        ({"LoginProfile": {"UserName": "u"}}, "", None, "", "unknown"),
        ({"LoginProfile": {"UserName": "u"}}, "", {}, "", "unknown"),
        (
            {"LoginProfile": {"UserName": "u"}},
            "",
            {"MFADevices": [None]},
            "",
            "unknown",
        ),
        (
            {"LoginProfile": {"UserName": "u"}},
            "",
            {"MFADevices": [{"UserName": "other"}]},
            "",
            "unknown",
        ),
        (
            {"LoginProfile": {"UserName": "u"}},
            "",
            {"MFADevices": [{"UserName": "u"}]},
            "",
            "unknown",
        ),
        (
            {"LoginProfile": {"UserName": "u"}},
            "",
            {"MFADevices": [{"UserName": "u", "SerialNumber": ""}]},
            "",
            "unknown",
        ),
    ],
)
def test_console_status_requires_exact_readable_metadata(
    profile, error, devices, device_error, expected
):
    calls = []

    def runner(command, **_kwargs):
        calls.append(command[2])
        if command[2] == "get-login-profile":
            return response(command, profile, error)
        assert command[2] == "list-mfa-devices"
        return response(command, devices, device_error)

    assert iam._iam_console_user_status("u", runner=runner) == expected
    assert len(calls) <= 2


def test_console_counts_and_actual_findings_cannot_be_attested_away(monkeypatch):
    statuses = iter(["mfa", "no_mfa", "unknown", "no_console"])
    monkeypatch.setattr(iam, "_iam_console_user_status", lambda *a, **k: next(statuses))
    counts = iam._iam_console_access_counts(["a", "b", "c", "d"])
    assert counts == {
        "consoleUserCount": 2,
        "consoleUsersWithoutMfa": 1,
        "unreadableConsoleUserCount": 1,
    }
    evidence = {
        **counts,
        "accountMfaEnabled": 1,
        "accountAccessKeysPresent": 0,
        "discoveredUserCount": 4,
        "summaryUserCount": 5,
        "activeUserAccessKeyCount": 0,
        "unreadableAccessKeyUserCount": 0,
    }
    blockers = iam._iam_account_access_blockers(evidence, frozenset({"human_access"}))
    assert len(blockers) == 3
    assert any("console access lack" in item for item in blockers)


@pytest.fixture
def technical_payload():
    now = dt.datetime.now(dt.timezone.utc)
    fields = {key: 0 for key in attestation.SECURITY_ACCOUNT_ATTESTATION_ACCOUNT_FIELDS}
    return {
        "workload": "bootstrap-infrastructure",
        "owner": "platform",
        "approvedBy": "Codex",
        "reviewedAt": now.isoformat(),
        "expiresAt": (now + dt.timedelta(days=1)).isoformat(),
        "approval": "technical_review",
        "humanAccessPosture": "not_assessed",
        "activeKeyDecision": "no_active_keys",
        "permissionsBoundaryDecision": "boundary_verified",
        "evidence": ["Observed exact scoped metadata"],
        "remediationPlan": "Recheck on changes",
        "accountEvidence": fields,
    }


def test_technical_attestation_never_grants_human_access(tmp_path, technical_payload):
    path = tmp_path / "technical.json"
    path.write_text(json.dumps(technical_payload))
    _, controls, blockers = attestation._security_account_attestation_coverage(
        path, technical_payload["accountEvidence"]
    )
    assert blockers == []
    assert controls == frozenset({"active_key", "permissions_boundary"})


@pytest.mark.parametrize(
    "field,value",
    [
        ("humanAccessPosture", "approved"),
        ("activeKeyDecision", "accepted_risk"),
        ("permissionsBoundaryDecision", "approved_exemption"),
        ("approval", "approved"),
    ],
)
def test_technical_review_cannot_claim_human_or_risk_approval(
    tmp_path, technical_payload, field, value
):
    technical_payload[field] = value
    path = tmp_path / "technical.json"
    path.write_text(json.dumps(technical_payload))
    _, controls, blockers = attestation._security_account_attestation_coverage(
        path, technical_payload["accountEvidence"]
    )
    assert blockers and not controls


@pytest.mark.parametrize(
    "field,value",
    [
        ("human_access_posture", "approved"),
        ("active_key_decision", "accepted_risk"),
        ("permissions_boundary_decision", "approved_exemption"),
        ("approval_decision", "approved"),
    ],
)
def test_generator_rejects_unearned_technical_approval(field, value):
    args = argparse.Namespace(
        approval_decision="technical_review",
        human_access_posture="not_assessed",
        active_key_decision="no_active_keys",
        permissions_boundary_decision="boundary_verified",
    )
    recording._validate_attestation_choices(args)
    setattr(args, field, value)
    with pytest.raises(ValueError, match="Technical review|not_assessed"):
        recording._validate_attestation_choices(args)


@pytest.mark.parametrize("active_keys", [0, 1, None, False, -1, "0"])
def test_generator_technical_record_roundtrips_without_human_coverage(
    tmp_path, technical_payload, active_keys
):
    args = argparse.Namespace(
        workload="bootstrap-infrastructure",
        environment="test",
        reviewer="Codex technical operator",
        security_owner="Codex technical operator",
        review_date=technical_payload["reviewedAt"],
        expiry_date=technical_payload["expiresAt"],
        approval_decision="technical_review",
        human_access_posture="not_assessed",
        active_key_decision="no_active_keys",
        permissions_boundary_decision="boundary_verified",
        action=["Scoped objective metadata only; human SSO not assessed"],
    )
    report = {
        "checks": [
            {
                "name": "aws_iam_account_access",
                "status": "passed",
                "evidence": technical_payload["accountEvidence"],
            }
        ]
    }
    report["checks"][0]["evidence"]["activeUserAccessKeyCount"] = active_keys
    if type(active_keys) is not int or active_keys != 0:
        for render in (recording.structured_attestation, recording.render_attestation):
            with pytest.raises(ValueError, match="observed zero active IAM keys"):
                render(report, args)
        return
    payload = recording.structured_attestation(report, args)
    path = tmp_path / "record.json"
    path.write_text(json.dumps(payload))
    _, controls, blockers = attestation._security_account_attestation_coverage(
        path, payload["accountEvidence"]
    )
    assert blockers == []
    assert "human_access" not in controls


@pytest.mark.parametrize(
    "renderer", [recording.render_attestation, recording.structured_attestation]
)
@pytest.mark.parametrize(
    "field,value",
    [
        ("human_access_posture", "mfa_sso_verified"),
        ("active_key_decision", "accepted_risk"),
        ("permissions_boundary_decision", "approved_exemption"),
    ],
)
def test_every_attestation_format_rejects_unearned_technical_claim(
    renderer, field, value
):
    args = argparse.Namespace(
        approval_decision="technical_review",
        human_access_posture="not_assessed",
        active_key_decision="no_active_keys",
        permissions_boundary_decision="boundary_verified",
        action=["Objective metadata only"],
    )
    setattr(args, field, value)
    report = {
        "checks": [
            {
                "name": "aws_iam_account_access",
                "evidence": {"activeUserAccessKeyCount": 0},
            }
        ]
    }
    with pytest.raises(ValueError, match="Technical review"):
        renderer(report, args)
