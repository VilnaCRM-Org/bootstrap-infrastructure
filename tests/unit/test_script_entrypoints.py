"""Unit tests for repo-local Python script entrypoints."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS_DIR = PROJECT_ROOT / "scripts"


def load_script_module(monkeypatch: pytest.MonkeyPatch, module_name: str):
    """Import a script module from the repo-local scripts directory."""
    monkeypatch.syspath_prepend(str(SCRIPTS_DIR))
    importlib.invalidate_caches()
    sys.modules.pop(module_name, None)
    return importlib.import_module(module_name)


def test_script_support_helpers_cover_local_script_utilities(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Exercise the shared helper functions used by the new Python scripts."""
    module = load_script_module(monkeypatch, "_script_support")
    pulumi_dir = tmp_path / "pulumi"
    pulumi_dir.mkdir()
    (pulumi_dir / "Pulumi.dev.yaml").write_text("", encoding="utf-8")
    (pulumi_dir / "Pulumi.example.yaml").write_text("", encoding="utf-8")
    (pulumi_dir / "Pulumi.yaml").write_text("name: template\n", encoding="utf-8")

    command_result = module.run(
        [sys.executable, "-c", "print('ok')"],
        capture_output=True,
    )

    backend_dir = (tmp_path / "backend").resolve()
    module.ensure_file_backend_directory(backend_dir.as_uri())
    module.ensure_file_backend_directory("https://example.com/backend")

    assert module.repo_root("/tmp/repo/scripts/tool.py") == Path("/tmp/repo")
    assert module.split_values(None) == []
    assert module.split_values('dev, "qa env"') == ["dev", "qa env"]
    assert module.discover_stacks(pulumi_dir, None) == ["dev"]  # nosec B101
    assert module.discover_stacks(pulumi_dir, "prod staging") == ["prod", "staging"]
    assert backend_dir.is_dir()
    assert command_result.stdout == "ok\n"
    assert "import policy.pack" in "".join(module.policy_import_probe(tmp_path))


def test_find_uv_binary_prefers_env_and_supports_fallbacks(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Find uv from env, PATH, fallback, and surface a helpful error when absent."""
    module = load_script_module(monkeypatch, "_script_support")
    env_uv = tmp_path / "uv-env"
    env_uv.write_text("", encoding="utf-8")
    os.chmod(env_uv, 0o755)
    path_uv = tmp_path / "uv-path"
    path_uv.write_text("", encoding="utf-8")
    os.chmod(path_uv, 0o755)

    monkeypatch.setenv("UV_BIN", str(env_uv))
    assert module.find_uv_binary() == str(env_uv)

    missing_env_uv = tmp_path / "missing-uv"
    monkeypatch.setenv("UV_BIN", str(missing_env_uv))
    monkeypatch.setattr(module.shutil, "which", lambda name: str(path_uv))
    assert module.find_uv_binary() == str(path_uv)

    monkeypatch.delenv("UV_BIN", raising=False)
    monkeypatch.setattr(module.shutil, "which", lambda name: str(path_uv))
    assert module.find_uv_binary() == str(path_uv)

    monkeypatch.setattr(module.shutil, "which", lambda name: None)
    monkeypatch.setattr(
        module.Path, "is_file", lambda self: str(self) == "/usr/local/bin/uv"
    )
    monkeypatch.setattr(
        module.os, "access", lambda path, mode: str(path) == "/usr/local/bin/uv"
    )
    assert module.find_uv_binary() == "/usr/local/bin/uv"

    monkeypatch.setattr(module.Path, "is_file", lambda self: False)
    monkeypatch.setattr(module.os, "access", lambda path, mode: False)
    with pytest.raises(SystemExit, match="127"):
        module.find_uv_binary()
    assert "uv executable not found" in capsys.readouterr().err


def _alert_route_evidence_report(
    *,
    status: str = "passed",
    evidence: object | None = None,
    blockers: list[str] | None = None,
) -> dict[str, object]:
    return {
        "generatedAt": "2026-05-10T07:20:53.572650+00:00",
        "checks": [
            {
                "name": "aws_identity",
                "status": "passed",
                "evidence": {"account": "123456789012"},
                "blockers": [],
            },
            {
                "name": "aws_sns_alert_route",
                "status": status,
                "evidence": evidence
                if evidence is not None
                else {
                    "topicArn": (
                        "arn:aws:sns:eu-central-1:123456789012:"
                        "bootstrap-test-operations"
                    ),
                    "encrypted": True,
                    "subscriptionCount": 1,
                    "subscriptionProtocols": ["sqs"],
                    "sqsQueue": {
                        "queueArn": (
                            "arn:aws:sqs:eu-central-1:123456789012:"
                            "bootstrap-test-operations-alerts"
                        ),
                        "queueName": "bootstrap-test-operations-alerts",
                        "visibleMessages": 3,
                        "notVisibleMessages": 0,
                        "delayedMessages": 0,
                        "messageRetentionSeconds": 345600,
                        "visibilityTimeoutSeconds": 30,
                    },
                },
                "blockers": blockers or [],
            },
        ],
    }


def _production_dr_evidence_report(
    *,
    status: str = "passed",
    evidence: object | None = None,
    blockers: list[str] | None = None,
) -> dict[str, object]:
    return {
        "generatedAt": "2026-05-10T08:30:00+00:00",
        "checks": [
            {
                "name": "restore_drill_evidence",
                "status": status,
                "evidence": evidence
                if evidence is not None
                else {
                    "workload": "bootstrap-infrastructure",
                    "environment": "test",
                    "completedAt": "2026-04-27T10:00:00Z",
                    "targetRestoreLocation": (
                        "s3://awsbackup-restore-test-bootstrap-123456789012-drill"
                    ),
                    "validationResult": "passed",
                    "cleanupConfirmed": True,
                },
                "blockers": blockers or [],
            },
        ],
    }


def _security_account_evidence_report(
    *,
    status: str = "failed",
    evidence: object | None = None,
    blockers: list[str] | None = None,
    identity_evidence: object | None = None,
    include_identity: bool = True,
) -> dict[str, object]:
    checks: list[dict[str, object]] = []
    if include_identity:
        checks.append(
            {
                "name": "aws_identity",
                "status": "passed",
                "evidence": (
                    {"account": "123456789012"}
                    if identity_evidence is None
                    else identity_evidence
                ),
                "blockers": [],
            }
        )
    checks.append(
        {
            "name": "aws_iam_account_access",
            "status": status,
            "evidence": evidence
            if evidence is not None
            else {
                "accountMfaEnabled": 1,
                "accountAccessKeysPresent": 0,
                "discoveredUserCount": 4,
                "summaryUserCount": 4,
                "mfaDevicesInUse": 1,
                "mfaDeviceCount": 1,
                "activeUserAccessKeyCount": 1,
                "activeUserAccessKeyOlderThan90DaysCount": 1,
                "activeUserAccessKeyCreateDateUnknownCount": 0,
                "activeUserAccessKeyNeverUsedCount": 0,
                "activeUserAccessKeyLastUsedWithin90DaysCount": 1,
                "activeUserAccessKeyLastUsedOlderThan90DaysCount": 0,
                "activeUserAccessKeyLastUsedUnknownCount": 0,
                "inactiveUserAccessKeyCount": 0,
                "otherUserAccessKeyStatusCount": 0,
                "unreadableAccessKeyUserCount": 0,
                "unreadableAccessKeyLastUsedCount": 0,
                "usersWithActiveAccessKeys": 1,
            },
            "blockers": blockers
            if blockers is not None
            else [
                "IAM user count exceeds MFA devices in use.",
                "IAM access-key metadata reports active user access keys.",
            ],
        }
    )
    return {"generatedAt": "2026-05-10T07:52:18.485352+00:00", "checks": checks}


def _dependabot_evidence_report(
    *,
    evidence: object | None = None,
    status: str = "failed",
) -> dict[str, object]:
    return {
        "generatedAt": "2026-05-10T08:00:00+00:00",
        "checks": [
            {
                "name": "github_dependabot_alerts",
                "status": status,
                "evidence": evidence
                if evidence is not None
                else {
                    "dependencyName": "GitPython",
                    "manifestPath": "uv.lock",
                    "openAlertNumbers": [8, 4, 5, 6, 7],
                    "unexceptedOpenAlertNumbers": [8, 4, 5, 6, 7],
                    "openAlertCount": 5,
                    "unexceptedOpenAlertCount": 5,
                },
                "blockers": [
                    "Open default-branch Dependabot alerts remain for GitPython."
                ],
            },
        ],
    }


def test_record_dependabot_exception_writes_owner_review(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Render open Dependabot alert metadata into an owner exception record."""
    module = load_script_module(monkeypatch, "record_dependabot_exception")
    collector = load_script_module(monkeypatch, "collect_well_architected_evidence")
    evidence = tmp_path / "evidence.json"
    output = tmp_path / "dependabot-exception.md"
    json_output = tmp_path / "dependabot-exception.json"
    evidence.write_text(json.dumps(_dependabot_evidence_report()), encoding="utf-8")
    review_date = module.dt.datetime.now(module.dt.timezone.utc).date().isoformat()
    expiry_date = (
        (module.dt.datetime.now(module.dt.timezone.utc) + module.dt.timedelta(days=7))
        .date()
        .isoformat()
    )

    status = module.main(
        [
            "--evidence",
            str(evidence),
            "--output",
            str(output),
            "--json-output",
            str(json_output),
            "--review-date",
            review_date,
            "--reviewer",
            "Kravalg",
            "--owner",
            "security-reviewer",
            "--approval",
            "approved_exception",
            "--reason",
            "Patched lockfile is staged and waiting for default-branch merge.",
            "--remediation-plan",
            "Merge the patched lockfile or revisit exception before expiry.",
            "--expiry-date",
            expiry_date,
            "--evidence-note",
            "Security owner approved a short exception window.",
        ]
    )

    text = output.read_text(encoding="utf-8")
    structured = json.loads(json_output.read_text(encoding="utf-8"))
    blockers = collector._dependabot_exception_payload_blockers(  # noqa: SLF001
        structured,
        dependency="GitPython",
        manifest_path="uv.lock",
        blocking_alerts=[{"number": number} for number in (4, 5, 6, 7, 8)],
    )
    assert status == 0  # nosec B101
    assert f"# Dependabot Exception Review {review_date}" in text  # nosec B101
    assert "Open alert numbers" in text  # nosec B101
    assert "#4, #5, #6, #7, #8" in text  # nosec B101
    assert "credentials" in text  # nosec B101
    assert "SecretString" not in text  # nosec B101
    assert structured["dependencyName"] == "GitPython"  # nosec B101
    assert structured["manifestPath"] == "uv.lock"  # nosec B101
    assert structured["alertNumbers"] == [4, 5, 6, 7, 8]  # nosec B101
    assert structured["approval"] == "approved_exception"  # nosec B101
    assert structured["evidence"] == [  # nosec B101
        "Security owner approved a short exception window."
    ]
    assert blockers == []  # nosec B101


def test_record_dependabot_exception_json_requires_evidence_note(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Machine-readable Dependabot exceptions must carry approval evidence."""
    module = load_script_module(monkeypatch, "record_dependabot_exception")
    evidence = tmp_path / "evidence.json"
    output = tmp_path / "dependabot-exception.md"
    json_output = tmp_path / "dependabot-exception.json"
    evidence.write_text(json.dumps(_dependabot_evidence_report()), encoding="utf-8")

    status = module.main(
        [
            "--evidence",
            str(evidence),
            "--output",
            str(output),
            "--json-output",
            str(json_output),
            "--reviewer",
            "Kravalg",
            "--owner",
            "security-reviewer",
            "--approval",
            "approved",
            "--reason",
            "Patch is staged.",
            "--remediation-plan",
            "Merge patch.",
            "--expiry-date",
            "2026-07-10",
        ]
    )

    assert status == 1  # nosec B101
    assert "requires --evidence-note" in capsys.readouterr().err  # nosec B101
    assert not output.exists()  # nosec B101
    assert not json_output.exists()  # nosec B101


def test_record_dependabot_exception_json_rejects_invalid_approval(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Generated JSON should fail fast on collector-invalid approvals."""
    module = load_script_module(monkeypatch, "record_dependabot_exception")
    evidence = tmp_path / "evidence.json"
    output = tmp_path / "dependabot-exception.md"
    json_output = tmp_path / "dependabot-exception.json"
    evidence.write_text(json.dumps(_dependabot_evidence_report()), encoding="utf-8")

    status = module.main(
        [
            "--evidence",
            str(evidence),
            "--output",
            str(output),
            "--json-output",
            str(json_output),
            "--reviewer",
            "Kravalg",
            "--owner",
            "security-reviewer",
            "--approval",
            "denied",
            "--reason",
            "Patch is staged.",
            "--remediation-plan",
            "Merge patch.",
            "--expiry-date",
            "2026-07-10",
            "--evidence-note",
            "Owner rejected this exception.",
        ]
    )

    assert status == 1  # nosec B101
    assert "approval must be one of" in capsys.readouterr().err  # nosec B101
    assert not output.exists()  # nosec B101
    assert not json_output.exists()  # nosec B101


def test_record_dependabot_exception_json_requires_expiry(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Generated JSON should require the collector-required expiry timestamp."""
    module = load_script_module(monkeypatch, "record_dependabot_exception")
    evidence = tmp_path / "evidence.json"
    output = tmp_path / "dependabot-exception.md"
    json_output = tmp_path / "dependabot-exception.json"
    evidence.write_text(json.dumps(_dependabot_evidence_report()), encoding="utf-8")

    status = module.main(
        [
            "--evidence",
            str(evidence),
            "--output",
            str(output),
            "--json-output",
            str(json_output),
            "--reviewer",
            "Kravalg",
            "--owner",
            "security-reviewer",
            "--approval",
            "approved",
            "--reason",
            "Patch is staged.",
            "--remediation-plan",
            "Merge patch.",
            "--evidence-note",
            "Owner approved.",
        ]
    )

    assert status == 1  # nosec B101
    assert "requires --expiry-date" in capsys.readouterr().err  # nosec B101
    assert not output.exists()  # nosec B101
    assert not json_output.exists()  # nosec B101


def test_record_dependabot_exception_force_overwrites_with_default_notes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Force mode supports intentional rerendering and default note text."""
    module = load_script_module(monkeypatch, "record_dependabot_exception")
    evidence = tmp_path / "evidence.json"
    output = tmp_path / "dependabot-exception.md"
    evidence.write_text(json.dumps(_dependabot_evidence_report()), encoding="utf-8")
    output.write_text("existing\n", encoding="utf-8")

    status = module.main(
        [
            "--evidence",
            str(evidence),
            "--output",
            str(output),
            "--reviewer",
            "Kravalg",
            "--owner",
            "security-reviewer",
            "--approval",
            "approved",
            "--reason",
            "Patch is staged.",
            "--remediation-plan",
            "Merge patch.",
            "--force",
        ]
    )

    assert status == 0  # nosec B101
    assert "No exception evidence notes recorded." in output.read_text(  # nosec B101
        encoding="utf-8"
    )


def test_record_dependabot_exception_refuses_overwrite_without_force(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Dependabot exception records should not be overwritten accidentally."""
    module = load_script_module(monkeypatch, "record_dependabot_exception")
    evidence = tmp_path / "evidence.json"
    output = tmp_path / "dependabot-exception.md"
    evidence.write_text(json.dumps(_dependabot_evidence_report()), encoding="utf-8")
    output.write_text("existing\n", encoding="utf-8")

    status = module.main(
        [
            "--evidence",
            str(evidence),
            "--output",
            str(output),
            "--reviewer",
            "Kravalg",
            "--owner",
            "security-reviewer",
            "--approval",
            "approved",
            "--reason",
            "Patch is staged.",
            "--remediation-plan",
            "Merge patch.",
        ]
    )

    assert status == 2  # nosec B101
    assert output.read_text(encoding="utf-8") == "existing\n"
    assert "output already exists" in capsys.readouterr().err  # nosec B101


def test_record_dependabot_exception_refuses_json_overwrite_without_force(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Structured Dependabot evidence should not be overwritten accidentally."""
    module = load_script_module(monkeypatch, "record_dependabot_exception")
    evidence = tmp_path / "evidence.json"
    output = tmp_path / "dependabot-exception.md"
    json_output = tmp_path / "dependabot-exception.json"
    evidence.write_text(json.dumps(_dependabot_evidence_report()), encoding="utf-8")
    json_output.write_text('{"existing": true}\n', encoding="utf-8")

    status = module.main(
        [
            "--evidence",
            str(evidence),
            "--output",
            str(output),
            "--json-output",
            str(json_output),
            "--reviewer",
            "Kravalg",
            "--owner",
            "security-reviewer",
            "--approval",
            "approved",
            "--reason",
            "Patch is staged.",
            "--remediation-plan",
            "Merge patch.",
            "--expiry-date",
            "2026-07-10",
            "--evidence-note",
            "Owner approved.",
        ]
    )

    assert status == 2  # nosec B101
    assert not output.exists()  # nosec B101
    assert json_output.read_text(encoding="utf-8") == '{"existing": true}\n'
    assert "JSON output already exists" in capsys.readouterr().err  # nosec B101


@pytest.mark.parametrize(
    ("payload", "expected_error"),
    [
        ([], "evidence report must be a JSON object"),
        ({"checks": []}, "does not contain check"),
        (
            _dependabot_evidence_report(evidence="not structured"),
            "github_dependabot_alerts evidence must be a JSON object",
        ),
        (
            _dependabot_evidence_report(evidence={}),
            "openAlertNumbers must be a list",
        ),
        (
            _dependabot_evidence_report(evidence={"openAlertNumbers": [1, False]}),
            "openAlertNumbers must contain integers",
        ),
    ],
)
def test_record_dependabot_exception_reports_invalid_evidence(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    payload: object,
    expected_error: str,
) -> None:
    """Invalid collector evidence should block Dependabot exception records."""
    module = load_script_module(monkeypatch, "record_dependabot_exception")
    evidence = tmp_path / "evidence.json"
    output = tmp_path / "dependabot-exception.md"
    evidence.write_text(json.dumps(payload), encoding="utf-8")

    status = module.main(
        [
            "--evidence",
            str(evidence),
            "--output",
            str(output),
            "--reviewer",
            "Kravalg",
            "--owner",
            "security-reviewer",
            "--approval",
            "approved",
            "--reason",
            "Patch is staged.",
            "--remediation-plan",
            "Merge patch.",
        ]
    )

    assert status == 1  # nosec B101
    assert not output.exists()  # nosec B101
    assert expected_error in capsys.readouterr().err  # nosec B101


def test_record_dependabot_exception_json_requires_open_alerts_and_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Structured exceptions should require live alert IDs and alert metadata."""
    module = load_script_module(monkeypatch, "record_dependabot_exception")
    args = argparse.Namespace(
        workload="bootstrap-infrastructure",
        owner="security-reviewer",
        reviewer="Kravalg",
        review_date=module.dt.datetime.now(module.dt.timezone.utc).isoformat(),
        expiry_date=(
            module.dt.datetime.now(module.dt.timezone.utc) + module.dt.timedelta(days=7)
        ).isoformat(),
        approval="approved",
        reason="Patch is staged.",
        remediation_plan="Merge patch.",
        evidence_note=["Owner approved."],
    )

    with pytest.raises(ValueError, match="at least one open alert"):
        module.structured_exception(  # noqa: SLF001
            _dependabot_evidence_report(evidence={"openAlertNumbers": []}),
            args,
        )
    with pytest.raises(ValueError, match="dependencyName is required"):
        module.structured_exception(  # noqa: SLF001
            _dependabot_evidence_report(
                evidence={"openAlertNumbers": [8], "manifestPath": "uv.lock"}
            ),
            args,
        )
    with pytest.raises(ValueError, match="manifestPath is required"):
        module.structured_exception(  # noqa: SLF001
            _dependabot_evidence_report(
                evidence={"openAlertNumbers": [8], "dependencyName": "GitPython"}
            ),
            args,
        )
    report = _dependabot_evidence_report()
    report["checks"].insert(0, {"name": "other"})
    assert (
        module._check_by_name(  # noqa: SLF001  # nosec B101
            report, "github_dependabot_alerts"
        )["name"]
        == "github_dependabot_alerts"
    )
    assert module._int_list("invalid") == []  # noqa: SLF001  # nosec B101
    assert module._int_list([1, False]) == []  # noqa: SLF001  # nosec B101


def test_record_alert_route_observation_writes_monthly_review(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Render non-secret SQS route metadata into a human review artifact."""
    module = load_script_module(monkeypatch, "record_alert_route_observation")
    evidence = tmp_path / "evidence.json"
    output = tmp_path / "alert-route-observation.md"
    json_output = tmp_path / "alert-route-observation.json"
    evidence.write_text(json.dumps(_alert_route_evidence_report()), encoding="utf-8")
    review_date = module.dt.datetime.now(module.dt.timezone.utc).date().isoformat()
    expiry_date = (
        (module.dt.datetime.now(module.dt.timezone.utc) + module.dt.timedelta(days=60))
        .date()
        .isoformat()
    )

    status = module.main(
        [
            "--evidence",
            str(evidence),
            "--output",
            str(output),
            "--json-output",
            str(json_output),
            "--review-date",
            review_date,
            "--reviewer",
            "sre-reviewer",
            "--route-owner",
            "SRE",
            "--downstream-route",
            "approved queue-owner process",
            "--severity-expectations",
            "SEV2 during business hours",
            "--fallback",
            "Escalate to platform maintainers if queue depth grows.",
            "--decision",
            "accepted",
            "--expiry-date",
            expiry_date,
            "--action",
            "Open a follow-up if visible messages exceed 10.",
        ]
    )

    text = output.read_text(encoding="utf-8")
    assert status == 0  # nosec B101
    assert f"# Alert Route Observation {review_date}" in text  # nosec B101
    assert "bootstrap-test-operations-alerts" in text  # nosec B101
    assert "approved queue-owner process" in text  # nosec B101
    assert "Open a follow-up if visible messages exceed 10." in text  # nosec B101
    assert "credentials" in text  # nosec B101
    assert "SecretString" not in text  # nosec B101
    structured = json.loads(json_output.read_text(encoding="utf-8"))
    assert structured["owner"] == "SRE"  # nosec B101
    assert structured["approvedBy"] == "sre-reviewer"  # nosec B101
    assert structured["decision"] == "accepted"  # nosec B101
    assert structured["routeEvidence"]["sqsQueue"]["queueName"] == (  # nosec B101
        "bootstrap-test-operations-alerts"
    )
    assert structured["queueObservation"]["visibleMessages"] == 3  # nosec B101


def test_record_alert_route_observation_json_requires_action(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Machine-readable alert observations must include evidence text."""
    module = load_script_module(monkeypatch, "record_alert_route_observation")
    evidence = tmp_path / "evidence.json"
    output = tmp_path / "alert-route-observation.md"
    json_output = tmp_path / "alert-route-observation.json"
    evidence.write_text(json.dumps(_alert_route_evidence_report()), encoding="utf-8")

    status = module.main(
        [
            "--evidence",
            str(evidence),
            "--output",
            str(output),
            "--json-output",
            str(json_output),
            "--reviewer",
            "sre-reviewer",
            "--route-owner",
            "SRE",
            "--downstream-route",
            "approved queue-owner process",
            "--severity-expectations",
            "SEV2 during business hours",
            "--fallback",
            "Escalate to platform maintainers if queue depth grows.",
            "--decision",
            "accepted",
            "--expiry-date",
            "2026-07-09",
        ]
    )

    assert status == 1  # nosec B101
    assert "requires at least one --action" in capsys.readouterr().err  # nosec B101
    assert not output.exists()  # nosec B101
    assert not json_output.exists()  # nosec B101


def test_record_alert_route_observation_json_rejects_invalid_decision(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Generated JSON should fail fast on collector-invalid decisions."""
    module = load_script_module(monkeypatch, "record_alert_route_observation")
    evidence = tmp_path / "evidence.json"
    output = tmp_path / "alert-route-observation.md"
    json_output = tmp_path / "alert-route-observation.json"
    evidence.write_text(json.dumps(_alert_route_evidence_report()), encoding="utf-8")

    status = module.main(
        [
            "--evidence",
            str(evidence),
            "--output",
            str(output),
            "--json-output",
            str(json_output),
            "--reviewer",
            "sre-reviewer",
            "--route-owner",
            "SRE",
            "--downstream-route",
            "approved queue-owner process",
            "--severity-expectations",
            "SEV2 during business hours",
            "--fallback",
            "Escalate to platform maintainers if queue depth grows.",
            "--decision",
            "not approved",
            "--expiry-date",
            "2026-07-09",
            "--action",
            "Owner rejected this observation.",
        ]
    )

    assert status == 1  # nosec B101
    assert "decision must be one of" in capsys.readouterr().err  # nosec B101
    assert not output.exists()  # nosec B101
    assert not json_output.exists()  # nosec B101


def test_record_production_dr_owner_evidence_writes_owner_review(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Render non-secret production DR owner evidence from restore metadata."""
    module = load_script_module(monkeypatch, "record_production_dr_owner_evidence")
    evidence = tmp_path / "evidence.json"
    output = tmp_path / "production-dr-owner.md"
    json_output = tmp_path / "production-dr-owner.json"
    evidence.write_text(json.dumps(_production_dr_evidence_report()), encoding="utf-8")
    review_date = module.dt.datetime.now(module.dt.timezone.utc).date().isoformat()
    expiry_date = (
        (module.dt.datetime.now(module.dt.timezone.utc) + module.dt.timedelta(days=60))
        .date()
        .isoformat()
    )
    next_review = (
        (module.dt.datetime.now(module.dt.timezone.utc) + module.dt.timedelta(days=30))
        .date()
        .isoformat()
    )

    status = module.main(
        [
            "--evidence",
            str(evidence),
            "--output",
            str(output),
            "--json-output",
            str(json_output),
            "--review-date",
            review_date,
            "--reviewer",
            "prod-reviewer",
            "--production-owner",
            "SRE",
            "--escalation-path",
            "SRE primary, platform maintainer backup",
            "--rto-target",
            "4 hours",
            "--rpo-target",
            "24 hours",
            "--recovery-order",
            "Restore state, validate logs, resume applies",
            "--communications-plan",
            "Post owner-approved status updates in the incident channel",
            "--latest-accepted-drill",
            "2026-04-27 restore drill and 2026-05-09 tabletop accepted",
            "--next-review-date",
            next_review,
            "--evidence-retention-location",
            "docs/production-dr-owner-YYYY-MM-DD.md",
            "--approval",
            "approved",
            "--expiry-date",
            expiry_date,
            "--action",
            "Run the next restore drill before the evidence expires.",
        ]
    )

    text = output.read_text(encoding="utf-8")
    assert status == 0  # nosec B101
    assert f"# Production DR Owner Evidence {review_date}" in text  # nosec B101
    assert "Production recovery owner" in text  # nosec B101
    assert "4 hours" in text  # nosec B101
    assert "s3://awsbackup-restore-test-bootstrap" in text  # nosec B101
    assert "credentials" in text  # nosec B101
    assert "SecretAccessKey" not in text  # nosec B101
    structured = json.loads(json_output.read_text(encoding="utf-8"))
    assert structured["owner"] == "SRE"  # nosec B101
    assert structured["approval"] == "approved"  # nosec B101
    assert structured["restoreDrillEvidence"]["validationResult"] == "passed"  # nosec B101


def test_record_production_dr_owner_evidence_json_requires_action(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Machine-readable production DR evidence must include owner actions."""
    module = load_script_module(monkeypatch, "record_production_dr_owner_evidence")
    evidence = tmp_path / "evidence.json"
    output = tmp_path / "production-dr-owner.md"
    json_output = tmp_path / "production-dr-owner.json"
    evidence.write_text(json.dumps(_production_dr_evidence_report()), encoding="utf-8")

    status = module.main(
        [
            "--evidence",
            str(evidence),
            "--output",
            str(output),
            "--json-output",
            str(json_output),
            "--reviewer",
            "prod-reviewer",
            "--production-owner",
            "SRE",
            "--escalation-path",
            "SRE primary, platform maintainer backup",
            "--rto-target",
            "4 hours",
            "--rpo-target",
            "24 hours",
            "--recovery-order",
            "Restore state, validate logs, resume applies",
            "--communications-plan",
            "Post owner-approved status updates in the incident channel",
            "--latest-accepted-drill",
            "2026-04-27 restore drill and 2026-05-09 tabletop accepted",
            "--next-review-date",
            "2026-07-10",
            "--evidence-retention-location",
            "docs/production-dr-owner-YYYY-MM-DD.md",
            "--approval",
            "approved",
            "--expiry-date",
            "2026-07-10",
        ]
    )

    assert status == 1  # nosec B101
    assert "requires at least one --action" in capsys.readouterr().err  # nosec B101
    assert not output.exists()  # nosec B101
    assert not json_output.exists()  # nosec B101


def test_record_production_dr_owner_evidence_rejects_invalid_inputs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Production DR owner records should fail before writing invalid evidence."""
    module = load_script_module(monkeypatch, "record_production_dr_owner_evidence")
    valid_review = module.dt.datetime.now(module.dt.timezone.utc).isoformat()
    valid_expiry = (
        module.dt.datetime.now(module.dt.timezone.utc) + module.dt.timedelta(days=7)
    ).isoformat()
    args = argparse.Namespace(
        workload="bootstrap-infrastructure",
        environment="prod",
        production_owner="SRE",
        reviewer="prod-reviewer",
        review_date=valid_review,
        expiry_date=valid_expiry,
        rto_target="4 hours",
        rpo_target="24 hours",
        escalation_path="SRE primary",
        recovery_order="Restore state, validate logs, resume applies",
        communications_plan="Post owner-approved status updates.",
        latest_accepted_drill="2026-04-27 restore drill accepted.",
        next_review_date="2026-07-10",
        evidence_retention_location="docs/production-dr-owner.md",
        approval="approved",
        action=["Run the next drill before expiry."],
    )

    with pytest.raises(ValueError, match="must pass before production DR"):
        module.structured_owner_evidence(  # noqa: SLF001
            _production_dr_evidence_report(status="failed", blockers=["blocked"]),
            args,
        )
    with pytest.raises(ValueError, match="evidence must be a JSON object"):
        module.structured_owner_evidence(  # noqa: SLF001
            _production_dr_evidence_report(evidence="not structured"),
            args,
        )
    with pytest.raises(ValueError, match="does not contain check"):
        module._check_by_name({"checks": []}, "restore_drill_evidence")  # noqa: SLF001
    report_with_leading_check = _production_dr_evidence_report()
    report_with_leading_check["checks"].insert(0, {"name": "other"})
    assert (  # noqa: SLF001  # nosec B101
        module._check_by_name(report_with_leading_check, "restore_drill_evidence")[
            "name"
        ]
        == "restore_drill_evidence"
    )

    list_report = tmp_path / "list-report.json"
    list_report.write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError, match="must be a JSON object"):
        module._load_report(list_report)  # noqa: SLF001

    invalid_choice_args = argparse.Namespace(**{**vars(args), "approval": "denied"})
    with pytest.raises(ValueError, match="approval must be one of"):
        module.structured_owner_evidence(  # noqa: SLF001
            _production_dr_evidence_report(),
            invalid_choice_args,
        )

    missing_expiry_args = argparse.Namespace(**{**vars(args), "expiry_date": ""})
    with pytest.raises(ValueError, match="requires --expiry-date"):
        module.structured_owner_evidence(  # noqa: SLF001
            _production_dr_evidence_report(),
            missing_expiry_args,
        )

    invalid_next_review_args = argparse.Namespace(
        **{**vars(args), "next_review_date": "not-a-date"}
    )
    with pytest.raises(ValueError, match="next-review-date must be"):
        module.structured_owner_evidence(  # noqa: SLF001
            _production_dr_evidence_report(),
            invalid_next_review_args,
        )

    evidence = tmp_path / "evidence.json"
    evidence.write_text(json.dumps(_production_dr_evidence_report()), encoding="utf-8")
    output = tmp_path / "production-dr-owner.md"
    output.write_text("existing", encoding="utf-8")
    status = module.main(
        [
            "--evidence",
            str(evidence),
            "--output",
            str(output),
            "--reviewer",
            "prod-reviewer",
            "--production-owner",
            "SRE",
            "--escalation-path",
            "SRE primary",
            "--rto-target",
            "4 hours",
            "--rpo-target",
            "24 hours",
            "--recovery-order",
            "Restore state, validate logs, resume applies",
            "--communications-plan",
            "Post owner-approved status updates.",
            "--latest-accepted-drill",
            "2026-04-27 restore drill accepted.",
            "--next-review-date",
            "2026-07-10",
            "--evidence-retention-location",
            "docs/production-dr-owner.md",
            "--approval",
            "approved",
            "--action",
            "Run the next drill before expiry.",
        ]
    )
    assert status == 2  # nosec B101
    assert "output already exists" in capsys.readouterr().err  # nosec B101

    json_output = tmp_path / "production-dr-owner.json"
    json_output.write_text("existing", encoding="utf-8")
    new_output = tmp_path / "new-production-dr-owner.md"
    status = module.main(
        [
            "--evidence",
            str(evidence),
            "--output",
            str(new_output),
            "--json-output",
            str(json_output),
            "--reviewer",
            "prod-reviewer",
            "--production-owner",
            "SRE",
            "--escalation-path",
            "SRE primary",
            "--rto-target",
            "4 hours",
            "--rpo-target",
            "24 hours",
            "--recovery-order",
            "Restore state, validate logs, resume applies",
            "--communications-plan",
            "Post owner-approved status updates.",
            "--latest-accepted-drill",
            "2026-04-27 restore drill accepted.",
            "--next-review-date",
            "2026-07-10",
            "--evidence-retention-location",
            "docs/production-dr-owner.md",
            "--approval",
            "approved",
            "--expiry-date",
            valid_expiry,
            "--action",
            "Run the next drill before expiry.",
        ]
    )
    assert status == 2  # nosec B101
    assert "JSON output already exists" in capsys.readouterr().err  # nosec B101

    no_json_output = tmp_path / "production-dr-owner-no-json.md"
    status = module.main(
        [
            "--evidence",
            str(evidence),
            "--output",
            str(no_json_output),
            "--reviewer",
            "prod-reviewer",
            "--production-owner",
            "SRE",
            "--escalation-path",
            "SRE primary",
            "--rto-target",
            "4 hours",
            "--rpo-target",
            "24 hours",
            "--recovery-order",
            "Restore state, validate logs, resume applies",
            "--communications-plan",
            "Post owner-approved status updates.",
            "--latest-accepted-drill",
            "2026-04-27 restore drill accepted.",
            "--next-review-date",
            "2026-07-10",
            "--evidence-retention-location",
            "docs/production-dr-owner.md",
            "--approval",
            "approved",
            "--action",
            "Run the next drill before expiry.",
        ]
    )
    assert status == 0  # nosec B101
    assert no_json_output.exists()  # nosec B101


def test_record_alert_route_observation_json_requires_expiry(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Generated JSON should require the collector-required expiry timestamp."""
    module = load_script_module(monkeypatch, "record_alert_route_observation")
    evidence = tmp_path / "evidence.json"
    output = tmp_path / "alert-route-observation.md"
    json_output = tmp_path / "alert-route-observation.json"
    evidence.write_text(json.dumps(_alert_route_evidence_report()), encoding="utf-8")

    status = module.main(
        [
            "--evidence",
            str(evidence),
            "--output",
            str(output),
            "--json-output",
            str(json_output),
            "--reviewer",
            "sre-reviewer",
            "--route-owner",
            "SRE",
            "--downstream-route",
            "approved queue-owner process",
            "--severity-expectations",
            "SEV2 during business hours",
            "--fallback",
            "Escalate to platform maintainers if queue depth grows.",
            "--decision",
            "accepted",
            "--action",
            "Open a follow-up if visible messages exceed 10.",
        ]
    )

    assert status == 1  # nosec B101
    assert "requires --expiry-date" in capsys.readouterr().err  # nosec B101
    assert not output.exists()  # nosec B101
    assert not json_output.exists()  # nosec B101


def test_record_alert_route_observation_refuses_overwrite_without_force(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Existing monthly evidence should not be overwritten accidentally."""
    module = load_script_module(monkeypatch, "record_alert_route_observation")
    evidence = tmp_path / "evidence.json"
    output = tmp_path / "alert-route-observation.md"
    evidence.write_text(json.dumps(_alert_route_evidence_report()), encoding="utf-8")
    output.write_text("existing\n", encoding="utf-8")

    status = module.main(
        [
            "--evidence",
            str(evidence),
            "--output",
            str(output),
            "--reviewer",
            "sre-reviewer",
            "--route-owner",
            "SRE",
            "--downstream-route",
            "queue owner",
            "--severity-expectations",
            "SEV2",
            "--fallback",
            "Escalate.",
            "--decision",
            "Accepted.",
        ]
    )

    assert status == 2  # nosec B101
    assert output.read_text(encoding="utf-8") == "existing\n"
    assert "output already exists" in capsys.readouterr().err  # nosec B101


def test_record_alert_route_observation_refuses_json_overwrite_without_force(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Structured monthly evidence should not be overwritten accidentally."""
    module = load_script_module(monkeypatch, "record_alert_route_observation")
    evidence = tmp_path / "evidence.json"
    output = tmp_path / "alert-route-observation.md"
    json_output = tmp_path / "alert-route-observation.json"
    evidence.write_text(json.dumps(_alert_route_evidence_report()), encoding="utf-8")
    json_output.write_text('{"existing": true}\n', encoding="utf-8")

    status = module.main(
        [
            "--evidence",
            str(evidence),
            "--output",
            str(output),
            "--json-output",
            str(json_output),
            "--reviewer",
            "sre-reviewer",
            "--route-owner",
            "SRE",
            "--downstream-route",
            "queue owner",
            "--severity-expectations",
            "SEV2",
            "--fallback",
            "Escalate.",
            "--decision",
            "accepted",
            "--expiry-date",
            "2026-07-10",
            "--action",
            "Owner approved.",
        ]
    )

    assert status == 2  # nosec B101
    assert not output.exists()  # nosec B101
    assert json_output.read_text(encoding="utf-8") == '{"existing": true}\n'
    assert "JSON output already exists" in capsys.readouterr().err  # nosec B101


def test_record_alert_route_observation_force_overwrites_with_default_actions(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Force mode supports intentional rerendering and default action text."""
    module = load_script_module(monkeypatch, "record_alert_route_observation")
    evidence = tmp_path / "evidence.json"
    output = tmp_path / "alert-route-observation.md"
    evidence.write_text(json.dumps(_alert_route_evidence_report()), encoding="utf-8")
    output.write_text("existing\n", encoding="utf-8")

    status = module.main(
        [
            "--evidence",
            str(evidence),
            "--output",
            str(output),
            "--reviewer",
            "sre-reviewer",
            "--route-owner",
            "SRE",
            "--downstream-route",
            "queue owner",
            "--severity-expectations",
            "SEV2",
            "--fallback",
            "Escalate.",
            "--decision",
            "Accepted.",
            "--force",
        ]
    )

    text = output.read_text(encoding="utf-8")
    assert status == 0  # nosec B101
    assert "No follow-up actions recorded." in text  # nosec B101


@pytest.mark.parametrize(
    ("payload", "expected_error"),
    [
        ([], "evidence report must be a JSON object"),
        ({"checks": []}, "does not contain check"),
        (
            _alert_route_evidence_report(
                status="failed",
                blockers=["Operations SNS topic does not have an SQS subscription."],
            ),
            "aws_sns_alert_route must pass",
        ),
        (
            _alert_route_evidence_report(evidence="not structured"),
            "aws_sns_alert_route evidence must be a JSON object",
        ),
    ],
)
def test_record_alert_route_observation_reports_invalid_evidence(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    payload: object,
    expected_error: str,
) -> None:
    """Invalid or failing collector evidence should block observation records."""
    module = load_script_module(monkeypatch, "record_alert_route_observation")
    evidence = tmp_path / "evidence.json"
    output = tmp_path / "alert-route-observation.md"
    evidence.write_text(json.dumps(payload), encoding="utf-8")

    status = module.main(
        [
            "--evidence",
            str(evidence),
            "--output",
            str(output),
            "--reviewer",
            "sre-reviewer",
            "--route-owner",
            "SRE",
            "--downstream-route",
            "queue owner",
            "--severity-expectations",
            "SEV2",
            "--fallback",
            "Escalate.",
            "--decision",
            "Accepted.",
        ]
    )

    assert status == 1  # nosec B101
    assert not output.exists()  # nosec B101
    assert expected_error in capsys.readouterr().err  # nosec B101


def test_record_security_account_attestation_writes_owner_review(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Render aggregate IAM account facts into a security-owner record."""
    module = load_script_module(monkeypatch, "record_security_account_attestation")
    evidence = tmp_path / "evidence.json"
    output = tmp_path / "security-account-attestation.md"
    json_output = tmp_path / "security-account-attestation.json"
    evidence.write_text(
        json.dumps(_security_account_evidence_report()), encoding="utf-8"
    )
    review_date = module.dt.datetime.now(module.dt.timezone.utc).date().isoformat()
    expiry_date = (
        (module.dt.datetime.now(module.dt.timezone.utc) + module.dt.timedelta(days=60))
        .date()
        .isoformat()
    )

    status = module.main(
        [
            "--evidence",
            str(evidence),
            "--output",
            str(output),
            "--json-output",
            str(json_output),
            "--review-date",
            review_date,
            "--reviewer",
            "security-reviewer",
            "--security-owner",
            "security-owner",
            "--human-access-posture",
            "mfa_sso_verified",
            "--active-key-decision",
            "approved_exception",
            "--permissions-boundary-decision",
            "approved_exemption",
            "--approval-decision",
            "approved",
            "--expiry-date",
            expiry_date,
            "--action",
            "Rotate the remaining static key before expiry.",
        ]
    )

    text = output.read_text(encoding="utf-8")
    assert status == 0  # nosec B101
    assert f"# Security Account Attestation {review_date}" in text  # nosec B101
    assert "123456789012" in text  # nosec B101
    assert "Active IAM user access keys" in text  # nosec B101
    assert "Active keys older than 90 days" in text  # nosec B101
    assert "Active keys last used within 90 days" in text  # nosec B101
    assert "Unreadable access-key last-used metadata" in text  # nosec B101
    assert "approved" in text  # nosec B101
    assert "IAM user names" in text  # nosec B101
    assert "AKIA" not in text  # nosec B101
    assert "SecretAccessKey" not in text  # nosec B101
    structured = json.loads(json_output.read_text(encoding="utf-8"))
    assert structured["humanAccessPosture"] == "mfa_sso_verified"  # nosec B101
    assert structured["activeKeyDecision"] == "approved_exception"  # nosec B101
    assert structured["permissionsBoundaryDecision"] == "approved_exemption"  # nosec B101
    assert structured["approval"] == "approved"  # nosec B101
    assert structured["accountEvidence"]["activeUserAccessKeyCount"] == 1  # nosec B101


def test_record_security_account_attestation_json_requires_action(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Machine-readable attestations must carry owner evidence or remediation."""
    module = load_script_module(monkeypatch, "record_security_account_attestation")
    evidence = tmp_path / "evidence.json"
    output = tmp_path / "security-account-attestation.md"
    json_output = tmp_path / "security-account-attestation.json"
    evidence.write_text(
        json.dumps(_security_account_evidence_report()), encoding="utf-8"
    )

    status = module.main(
        [
            "--evidence",
            str(evidence),
            "--output",
            str(output),
            "--json-output",
            str(json_output),
            "--reviewer",
            "security-reviewer",
            "--security-owner",
            "security-owner",
            "--human-access-posture",
            "mfa_sso_verified",
            "--active-key-decision",
            "approved_exception",
            "--permissions-boundary-decision",
            "approved_exemption",
            "--approval-decision",
            "approved",
            "--expiry-date",
            "2026-07-10",
        ]
    )

    assert status == 1  # nosec B101
    assert "requires at least one --action" in capsys.readouterr().err  # nosec B101
    assert not output.exists()  # nosec B101
    assert not json_output.exists()  # nosec B101


def test_record_security_account_attestation_json_rejects_invalid_choices(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Generated JSON should fail fast on collector-invalid owner choices."""
    module = load_script_module(monkeypatch, "record_security_account_attestation")
    evidence = tmp_path / "evidence.json"
    output = tmp_path / "security-account-attestation.md"
    json_output = tmp_path / "security-account-attestation.json"
    evidence.write_text(
        json.dumps(_security_account_evidence_report()), encoding="utf-8"
    )

    status = module.main(
        [
            "--evidence",
            str(evidence),
            "--output",
            str(output),
            "--json-output",
            str(json_output),
            "--reviewer",
            "security-reviewer",
            "--security-owner",
            "security-owner",
            "--human-access-posture",
            "pending review",
            "--active-key-decision",
            "approved_exception",
            "--permissions-boundary-decision",
            "approved_exemption",
            "--approval-decision",
            "not approved",
            "--expiry-date",
            "2026-07-10",
            "--action",
            "Owner rejected this attestation.",
        ]
    )

    stderr = capsys.readouterr().err
    assert status == 1  # nosec B101
    assert "approval-decision must be one of" in stderr  # nosec B101
    assert "human-access-posture must be one of" in stderr  # nosec B101
    assert not output.exists()  # nosec B101
    assert not json_output.exists()  # nosec B101


def test_record_security_account_attestation_json_requires_expiry(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Generated JSON should require the collector-required expiry timestamp."""
    module = load_script_module(monkeypatch, "record_security_account_attestation")
    evidence = tmp_path / "evidence.json"
    output = tmp_path / "security-account-attestation.md"
    json_output = tmp_path / "security-account-attestation.json"
    evidence.write_text(
        json.dumps(_security_account_evidence_report()), encoding="utf-8"
    )

    status = module.main(
        [
            "--evidence",
            str(evidence),
            "--output",
            str(output),
            "--json-output",
            str(json_output),
            "--reviewer",
            "security-reviewer",
            "--security-owner",
            "security-owner",
            "--human-access-posture",
            "mfa_sso_verified",
            "--active-key-decision",
            "approved_exception",
            "--permissions-boundary-decision",
            "approved_exemption",
            "--approval-decision",
            "approved",
            "--action",
            "Rotate the remaining static key before expiry.",
        ]
    )

    assert status == 1  # nosec B101
    assert "requires --expiry-date" in capsys.readouterr().err  # nosec B101
    assert not output.exists()  # nosec B101
    assert not json_output.exists()  # nosec B101


def test_owner_evidence_generator_choices_match_collector(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Owner evidence generators should reject the same choices as the collector."""
    alert_module = load_script_module(monkeypatch, "record_alert_route_observation")
    dependabot_module = load_script_module(monkeypatch, "record_dependabot_exception")
    production_dr_module = load_script_module(
        monkeypatch, "record_production_dr_owner_evidence"
    )
    security_module = load_script_module(
        monkeypatch, "record_security_account_attestation"
    )
    collector_module = load_script_module(
        monkeypatch, "collect_well_architected_evidence"
    )

    assert alert_module.ALERT_ROUTE_ALLOWED_DECISIONS == (  # nosec B101
        collector_module.ALERT_ROUTE_ALLOWED_DECISIONS
    )
    assert dependabot_module.DEPENDABOT_EXCEPTION_ALLOWED_APPROVALS == (  # nosec B101
        collector_module.DEPENDABOT_EXCEPTION_ALLOWED_APPROVALS
    )
    assert production_dr_module.PRODUCTION_DR_OWNER_ALLOWED_APPROVALS == (  # nosec B101
        collector_module.PRODUCTION_DR_OWNER_ALLOWED_APPROVALS
    )
    assert security_module.SECURITY_ACCOUNT_ALLOWED_APPROVALS == (  # nosec B101
        collector_module.SECURITY_ACCOUNT_ALLOWED_APPROVALS
    )
    assert security_module.SECURITY_ACCOUNT_ALLOWED_HUMAN_ACCESS == (  # nosec B101
        collector_module.SECURITY_ACCOUNT_ALLOWED_HUMAN_ACCESS
    )
    assert security_module.SECURITY_ACCOUNT_ALLOWED_ACTIVE_KEY == (  # nosec B101
        collector_module.SECURITY_ACCOUNT_ALLOWED_ACTIVE_KEY
    )
    assert security_module.SECURITY_ACCOUNT_ALLOWED_BOUNDARY == (  # nosec B101
        collector_module.SECURITY_ACCOUNT_ALLOWED_BOUNDARY
    )
    assert alert_module.STRUCTURED_EVIDENCE_MAX_AGE_DAYS == (  # nosec B101
        collector_module.STRUCTURED_EVIDENCE_MAX_AGE_DAYS
    )
    assert dependabot_module.STRUCTURED_EVIDENCE_MAX_AGE_DAYS == (  # nosec B101
        collector_module.STRUCTURED_EVIDENCE_MAX_AGE_DAYS
    )
    assert production_dr_module.STRUCTURED_EVIDENCE_MAX_AGE_DAYS == (  # nosec B101
        collector_module.STRUCTURED_EVIDENCE_MAX_AGE_DAYS
    )
    assert security_module.STRUCTURED_EVIDENCE_MAX_AGE_DAYS == (  # nosec B101
        collector_module.STRUCTURED_EVIDENCE_MAX_AGE_DAYS
    )


@pytest.mark.parametrize(
    ("script_name", "label"),
    [
        ("record_alert_route_observation", "Alert-route observation"),
        ("record_dependabot_exception", "Dependabot exception"),
        ("record_production_dr_owner_evidence", "Production DR owner evidence"),
        ("record_security_account_attestation", "Security account attestation"),
    ],
)
def test_owner_evidence_generator_dates_match_collector_rules(
    monkeypatch: pytest.MonkeyPatch,
    script_name: str,
    label: str,
) -> None:
    """Generated JSON should fail fast on collector-invalid date fields."""
    module = load_script_module(monkeypatch, script_name)
    now = module.dt.datetime.now(module.dt.timezone.utc)
    valid_review = now.isoformat()
    valid_expiry = (now + module.dt.timedelta(days=7)).isoformat()

    assert (  # noqa: SLF001  # nosec B101
        module._parse_iso_date_or_timestamp("2026-04-27T10:00:00").tzinfo is not None
    )
    assert (  # noqa: SLF001  # nosec B101
        module._parse_iso_date_or_timestamp("2026-04-27T10:00:00Z").tzinfo is not None
    )

    with pytest.raises(ValueError, match="review-date must be"):
        module._validate_structured_dates(  # noqa: SLF001
            label, "not-a-date", valid_expiry
        )
    with pytest.raises(ValueError, match="future"):
        module._validate_structured_dates(  # noqa: SLF001
            label, (now + module.dt.timedelta(days=1)).isoformat(), valid_expiry
        )
    with pytest.raises(ValueError, match="older than"):
        module._validate_structured_dates(  # noqa: SLF001
            label,
            (
                now
                - module.dt.timedelta(days=module.STRUCTURED_EVIDENCE_MAX_AGE_DAYS + 1)
            ).isoformat(),
            valid_expiry,
        )
    with pytest.raises(ValueError, match="expiry-date must be"):
        module._validate_structured_dates(  # noqa: SLF001
            label, valid_review, "not-a-date"
        )
    with pytest.raises(ValueError, match="expired"):
        module._validate_structured_dates(  # noqa: SLF001
            label, valid_review, (now - module.dt.timedelta(days=1)).isoformat()
        )


def test_record_security_account_attestation_force_overwrites_without_identity(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Force mode supports rerendering and blank account metadata."""
    module = load_script_module(monkeypatch, "record_security_account_attestation")
    evidence = tmp_path / "evidence.json"
    output = tmp_path / "security-account-attestation.md"
    evidence.write_text(
        json.dumps(
            _security_account_evidence_report(
                status="passed", blockers=[], include_identity=False
            )
        ),
        encoding="utf-8",
    )
    output.write_text("existing\n", encoding="utf-8")

    status = module.main(
        [
            "--evidence",
            str(evidence),
            "--output",
            str(output),
            "--reviewer",
            "security-reviewer",
            "--security-owner",
            "security-owner",
            "--human-access-posture",
            "MFA posture accepted.",
            "--active-key-decision",
            "No active-key exception needed.",
            "--permissions-boundary-decision",
            "Boundary exemption accepted.",
            "--approval-decision",
            "Approved.",
            "--force",
        ]
    )

    text = output.read_text(encoding="utf-8")
    assert status == 0  # nosec B101
    assert "No follow-up actions recorded." in text  # nosec B101
    assert "None reported by the collector." in text  # nosec B101


def test_record_security_account_attestation_handles_unstructured_identity(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Unstructured identity metadata should not block the attestation shell."""
    module = load_script_module(monkeypatch, "record_security_account_attestation")
    evidence = tmp_path / "evidence.json"
    output = tmp_path / "security-account-attestation.md"
    evidence.write_text(
        json.dumps(_security_account_evidence_report(identity_evidence="unstructured")),
        encoding="utf-8",
    )

    status = module.main(
        [
            "--evidence",
            str(evidence),
            "--output",
            str(output),
            "--reviewer",
            "security-reviewer",
            "--security-owner",
            "security-owner",
            "--human-access-posture",
            "MFA posture accepted.",
            "--active-key-decision",
            "Exception accepted.",
            "--permissions-boundary-decision",
            "Boundary exemption accepted.",
            "--approval-decision",
            "Approved.",
        ]
    )

    assert status == 0  # nosec B101
    assert "| AWS account |  |" in output.read_text(encoding="utf-8")  # nosec B101


def test_record_security_account_attestation_refuses_overwrite_without_force(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Security attestations should not be overwritten accidentally."""
    module = load_script_module(monkeypatch, "record_security_account_attestation")
    evidence = tmp_path / "evidence.json"
    output = tmp_path / "security-account-attestation.md"
    evidence.write_text(
        json.dumps(_security_account_evidence_report()), encoding="utf-8"
    )
    output.write_text("existing\n", encoding="utf-8")

    status = module.main(
        [
            "--evidence",
            str(evidence),
            "--output",
            str(output),
            "--reviewer",
            "security-reviewer",
            "--security-owner",
            "security-owner",
            "--human-access-posture",
            "MFA posture accepted.",
            "--active-key-decision",
            "Exception accepted.",
            "--permissions-boundary-decision",
            "Boundary exemption accepted.",
            "--approval-decision",
            "Approved.",
        ]
    )

    assert status == 2  # nosec B101
    assert output.read_text(encoding="utf-8") == "existing\n"
    assert "output already exists" in capsys.readouterr().err  # nosec B101


def test_record_security_account_attestation_refuses_json_overwrite_without_force(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Structured security attestations should not be overwritten accidentally."""
    module = load_script_module(monkeypatch, "record_security_account_attestation")
    evidence = tmp_path / "evidence.json"
    output = tmp_path / "security-account-attestation.md"
    json_output = tmp_path / "security-account-attestation.json"
    evidence.write_text(
        json.dumps(_security_account_evidence_report()), encoding="utf-8"
    )
    json_output.write_text('{"existing": true}\n', encoding="utf-8")

    status = module.main(
        [
            "--evidence",
            str(evidence),
            "--output",
            str(output),
            "--json-output",
            str(json_output),
            "--reviewer",
            "security-reviewer",
            "--security-owner",
            "security-owner",
            "--human-access-posture",
            "mfa_sso_verified",
            "--active-key-decision",
            "approved_exception",
            "--permissions-boundary-decision",
            "approved_exemption",
            "--approval-decision",
            "approved",
            "--expiry-date",
            "2026-07-10",
            "--action",
            "Owner approved.",
        ]
    )

    assert status == 2  # nosec B101
    assert not output.exists()  # nosec B101
    assert json_output.read_text(encoding="utf-8") == '{"existing": true}\n'
    assert "JSON output already exists" in capsys.readouterr().err  # nosec B101


@pytest.mark.parametrize(
    ("raw_payload", "expected_error"),
    [
        ("[]", "evidence report must be a JSON object"),
        (json.dumps({"checks": []}), "does not contain check"),
        (
            json.dumps(_security_account_evidence_report(evidence="not structured")),
            "aws_iam_account_access evidence must be a JSON object",
        ),
        ("{", "Expecting property name enclosed in double quotes"),
    ],
)
def test_record_security_account_attestation_reports_invalid_evidence(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    raw_payload: str,
    expected_error: str,
) -> None:
    """Invalid collector evidence should block security attestation records."""
    module = load_script_module(monkeypatch, "record_security_account_attestation")
    evidence = tmp_path / "evidence.json"
    output = tmp_path / "security-account-attestation.md"
    evidence.write_text(raw_payload, encoding="utf-8")

    status = module.main(
        [
            "--evidence",
            str(evidence),
            "--output",
            str(output),
            "--reviewer",
            "security-reviewer",
            "--security-owner",
            "security-owner",
            "--human-access-posture",
            "MFA posture accepted.",
            "--active-key-decision",
            "Exception accepted.",
            "--permissions-boundary-decision",
            "Boundary exemption accepted.",
            "--approval-decision",
            "Approved.",
        ]
    )

    assert status == 1  # nosec B101
    assert not output.exists()  # nosec B101
    assert expected_error in capsys.readouterr().err  # nosec B101


def _well_architected_question_toc() -> dict[str, object]:
    """Return a compact AWS Well-Architected TOC fixture with all question IDs."""
    counts = {
        "OPS": 11,
        "SEC": 11,
        "REL": 13,
        "PERF": 5,
        "COST": 11,
        "SUS": 6,
    }
    nodes = []
    for prefix, count in counts.items():
        for number in range(1, count + 1):
            separator = "." if prefix != "SUS" else ""
            nodes.append(
                {
                    "title": f"{prefix} {number}{separator} Question {number}?",
                    "href": f"{prefix.lower()}-{number:02d}.html",
                }
            )
    return {
        "contents": [
            {
                "title": "Appendix",
                "contents": [
                    "ignored non-object node",
                    {"title": "Ignored branch", "contents": "not a list"},
                    *nodes,
                ],
            }
        ]
    }


def _well_architected_question_evidence() -> dict[str, object]:
    """Return structured question evidence aligned with the TOC fixture."""
    pillar_by_prefix = {
        "OPS": "Operational Excellence",
        "SEC": "Security",
        "REL": "Reliability",
        "PERF": "Performance Efficiency",
        "COST": "Cost Optimization",
        "SUS": "Sustainability",
    }
    counts = {
        "OPS": 11,
        "SEC": 11,
        "REL": 13,
        "PERF": 5,
        "COST": 11,
        "SUS": 6,
    }
    scores = [
        {
            "id": f"{prefix}{number}",
            "pillar": pillar,
            "score": 5,
            "status": "passed",
            "rationale": "Fixture evidence.",
            "primaryBlocker": "",
        }
        for prefix, pillar in pillar_by_prefix.items()
        for number in range(1, counts[prefix] + 1)
    ]
    scores[0]["score"] = 4
    scores[0]["status"] = "unresolved"
    scores[0]["evidenceRefs"] = ["issue:#26"]
    return {
        "workload": "bootstrap-infrastructure",
        "owner": "platform-maintainers",
        "reviewedAt": "2026-05-10T08:23:23Z",
        "questionCount": len(scores),
        "unresolvedQuestionCount": 1,
        "unresolvedQuestionIds": ["OPS1"],
        "pillarUnresolvedQuestionCounts": {
            "Operational Excellence": 1,
            "Security": 0,
            "Reliability": 0,
            "Performance Efficiency": 0,
            "Cost Optimization": 0,
            "Sustainability": 0,
        },
        "questionScoreAverages": {
            "Operational Excellence": 4.91,
            "Security": 5.0,
            "Reliability": 5.0,
            "Performance Efficiency": 5.0,
            "Cost Optimization": 5.0,
            "Sustainability": 5.0,
        },
        "evidenceLocation": "specs/question-matrix.md",
        "frameworkSourceVerification": {
            "checkedAt": "2026-05-10T08:00:00Z",
            "source": "AWS Well-Architected Framework latest public documentation",
            "questionCounts": {
                "Operational Excellence": 11,
                "Security": 11,
                "Reliability": 13,
                "Performance Efficiency": 5,
                "Cost Optimization": 11,
                "Sustainability": 6,
            },
            "sourceUrls": [
                "https://docs.aws.amazon.com/wellarchitected/latest/framework/toc-contents.json",
                "https://docs.aws.amazon.com/wellarchitected/latest/framework/ops-01.html",
            ],
        },
        "questionScores": scores,
    }


def _well_architected_question_markdown() -> str:
    """Return a Markdown question matrix aligned with the TOC fixture."""
    prefixes = (
        ("Operational Excellence", "OPS", 11),
        ("Security", "SEC", 11),
        ("Reliability", "REL", 13),
        ("Performance Efficiency", "PERF", 5),
        ("Cost Optimization", "COST", 11),
        ("Sustainability", "SUS", 6),
    )
    lines = ["# AWS Well-Architected Question Matrix", ""]
    for pillar, prefix, count in prefixes:
        lines.extend(
            [
                f"## {pillar}",
                "",
                "| ID | Question | Evidence | Gap | Target |",
                "| --- | --- | --- | --- | --- |",
            ]
        )
        for number in range(1, count + 1):
            lines.append(f"| {prefix}{number} | Q{number}? | E. | G. | T. |")
        lines.append("")
    return "\n".join(lines)


def test_verify_well_architected_questions_accepts_matching_toc(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Compare local question evidence with an AWS TOC-shaped fixture."""
    module = load_script_module(monkeypatch, "verify_well_architected_questions")
    evidence = tmp_path / "question-matrix-evidence.json"
    matrix = tmp_path / "question-matrix.md"
    toc = tmp_path / "toc.json"
    output = tmp_path / "question-verification.json"
    evidence.write_text(
        json.dumps(_well_architected_question_evidence()), encoding="utf-8"
    )
    matrix.write_text(_well_architected_question_markdown(), encoding="utf-8")
    toc.write_text(json.dumps(_well_architected_question_toc()), encoding="utf-8")

    status = module.main(
        [
            "--question-matrix-evidence",
            str(evidence),
            "--question-matrix",
            str(matrix),
            "--toc-json",
            str(toc),
            "--output",
            str(output),
        ]
    )

    report = json.loads(output.read_text(encoding="utf-8"))
    assert status == 0  # nosec B101
    assert report["status"] == "passed"  # nosec B101
    assert report["checkedAt"].endswith("Z")  # nosec B101
    assert report["awsQuestionCount"] == 57  # nosec B101
    assert report["markdownQuestionCount"] == 57  # nosec B101
    assert report["awsPillarQuestionCounts"]["Sustainability"] == 6  # nosec B101
    assert report["expectedUnresolvedQuestionIds"] == ["OPS1"]  # nosec B101
    assert report["evidenceUnresolvedQuestionIds"] == ["OPS1"]  # nosec B101
    assert report["expectedQuestionScoreAverages"]["Operational Excellence"] == 4.91  # nosec B101
    assert report["blockers"] == []  # nosec B101


def test_verify_well_architected_questions_rejects_gaps_and_bad_scores(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Surface matrix coverage and score problems as non-zero verification."""
    module = load_script_module(monkeypatch, "verify_well_architected_questions")
    evidence_payload = _well_architected_question_evidence()
    scores = evidence_payload["questionScores"]
    assert isinstance(scores, list)  # nosec B101
    scores.pop()
    scores[0]["score"] = 6
    scores[0]["status"] = "unresolved"
    scores[0]["evidenceRefs"] = []
    evidence = tmp_path / "question-matrix-evidence.json"
    matrix = tmp_path / "question-matrix.md"
    toc = tmp_path / "toc.json"
    evidence.write_text(json.dumps(evidence_payload), encoding="utf-8")
    matrix.write_text(_well_architected_question_markdown(), encoding="utf-8")
    toc.write_text(json.dumps(_well_architected_question_toc()), encoding="utf-8")

    status = module.main(
        [
            "--question-matrix-evidence",
            str(evidence),
            "--question-matrix",
            str(matrix),
            "--toc-json",
            str(toc),
        ]
    )

    report = json.loads(capsys.readouterr().out)
    assert status == 1  # nosec B101
    assert report["status"] == "failed"  # nosec B101
    assert report["missingQuestionIds"] == ["SUS6"]  # nosec B101
    assert report["invalidScoreQuestionIds"] == ["OPS1"]  # nosec B101
    assert report["missingEvidenceRefQuestionIds"] == ["OPS1"]  # nosec B101
    assert "SUS6" in " ".join(report["blockers"])  # nosec B101
    assert "evidenceRefs" in " ".join(report["blockers"])  # nosec B101


def test_verify_well_architected_questions_rejects_markdown_matrix_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The reviewer-facing Markdown matrix must cover the same AWS rows."""
    module = load_script_module(monkeypatch, "verify_well_architected_questions")
    markdown = _well_architected_question_markdown()
    markdown = markdown.replace("| SUS6 |", "| OPS99 |", 1)
    markdown = markdown.replace(
        "## Security",
        "## Operational Excellence",
        1,
    )
    markdown += "\n| OPS1 | Duplicate? | Evidence. | Gap. | Target. |\n"

    report = module.verify_question_matrix(
        evidence=_well_architected_question_evidence(),
        toc=_well_architected_question_toc(),
        toc_source="fixture",
        question_matrix_markdown=markdown,
    )

    blockers = " ".join(report["blockers"])
    assert report["status"] == "failed"  # nosec B101
    assert report["missingMarkdownQuestionIds"] == ["SUS6"]  # nosec B101
    assert report["extraMarkdownQuestionIds"] == ["OPS99"]  # nosec B101
    assert report["duplicateMarkdownQuestionIds"] == ["OPS1"]  # nosec B101
    assert "SEC1" in report["markdownPillarMismatchQuestionIds"]  # nosec B101
    assert "Markdown" in blockers  # nosec B101
    assert "sections" in blockers  # nosec B101
    assert module.extract_markdown_questions(  # nosec B101
        "\n".join(
            [
                "## Operational Excellence",
                "| OPS1 | Q? | E. | G. | T. |",
                "## Claim Gate",
                "| OPS2 | Q? | E. | G. | T. |",
            ]
        )
    ) == [
        {"id": "OPS1", "pillar": "Operational Excellence"},
        {"id": "OPS2", "pillar": ""},
    ]


def test_verify_well_architected_questions_rejects_score_status_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A 5/5 claim must keep score and pass/unresolved status aligned."""
    module = load_script_module(monkeypatch, "verify_well_architected_questions")
    evidence = _well_architected_question_evidence()
    scores = evidence["questionScores"]
    assert isinstance(scores, list)  # nosec B101
    assert isinstance(scores[0], dict)  # nosec B101
    assert isinstance(scores[1], dict)  # nosec B101
    scores[0]["score"] = 5
    scores[1]["score"] = 4
    scores[1]["status"] = "passed"

    report = module.verify_question_matrix(
        evidence=evidence,
        toc=_well_architected_question_toc(),
        toc_source="fixture",
    )

    assert report["status"] == "failed"  # nosec B101
    assert report["scoreStatusMismatchQuestionIds"] == ["OPS1", "OPS2"]  # nosec B101
    assert "passed entries must score 5" in " ".join(report["blockers"])  # nosec B101


def test_verify_well_architected_questions_rejects_score_summary_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Structured summary fields must agree with the individual score rows."""
    module = load_script_module(monkeypatch, "verify_well_architected_questions")
    evidence = _well_architected_question_evidence()
    evidence["unresolvedQuestionCount"] = 0
    evidence["unresolvedQuestionIds"] = ["SEC1"]
    evidence["pillarUnresolvedQuestionCounts"] = {
        "Operational Excellence": 0,
        "Security": 1,
        "Reliability": 0,
        "Performance Efficiency": 0,
        "Cost Optimization": 0,
        "Sustainability": 0,
    }
    evidence["questionScoreAverages"] = {
        "Operational Excellence": 5.0,
        "Security": 4.91,
        "Reliability": 5.0,
        "Performance Efficiency": 5.0,
        "Cost Optimization": 5.0,
        "Sustainability": 5.0,
    }

    report = module.verify_question_matrix(
        evidence=evidence,
        toc=_well_architected_question_toc(),
        toc_source="fixture",
    )

    blockers = " ".join(report["blockers"])
    assert report["status"] == "failed"  # nosec B101
    assert report["expectedUnresolvedQuestionCount"] == 1  # nosec B101
    assert report["evidenceUnresolvedQuestionCount"] == 0  # nosec B101
    assert report["expectedUnresolvedQuestionIds"] == ["OPS1"]  # nosec B101
    assert report["evidenceUnresolvedQuestionIds"] == ["SEC1"]  # nosec B101
    assert "unresolvedQuestionCount" in blockers  # nosec B101
    assert "unresolvedQuestionIds" in blockers  # nosec B101
    assert "pillarUnresolvedQuestionCounts" in blockers  # nosec B101
    assert "questionScoreAverages" in blockers  # nosec B101
    assert "OPS1" in blockers  # nosec B101
    assert module._question_id_sort_key("OPSX") == (0, 0, "OPSX")  # noqa: SLF001  # nosec B101
    assert module._question_id_sort_key("WA99") == (6, 0, "WA99")  # noqa: SLF001  # nosec B101
    assert module._aws_pillar_for_question_id(1, {}) is None  # noqa: SLF001  # nosec B101
    assert module._valid_question_score(True) is None  # noqa: SLF001  # nosec B101
    assert module._valid_question_score("5") is None  # noqa: SLF001  # nosec B101
    assert module._valid_question_score(6) is None  # noqa: SLF001  # nosec B101
    assert module._string_list(["OPS1", 2]) is None  # noqa: SLF001  # nosec B101
    assert module._string_key_number_map({1: 5}) is None  # noqa: SLF001  # nosec B101
    assert (  # noqa: SLF001  # nosec B101
        module._string_key_number_map({"Security": True}) is None
    )
    assert module._string_key_number_map({"Security": "5"}) is None  # noqa: SLF001  # nosec B101
    assert module._string_key_int_map({1: 5}) is None  # noqa: SLF001  # nosec B101
    assert module._string_key_int_map({"Security": False}) is None  # noqa: SLF001  # nosec B101
    assert module._string_key_int_map({"Security": 5.0}) is None  # noqa: SLF001  # nosec B101
    assert (  # noqa: SLF001  # nosec B101
        module._expected_pillar_unresolved_question_counts(
            [{"id": "WA99", "status": "unresolved"}, {"id": 1, "status": "unresolved"}],
            {"OPS1": "Operational Excellence"},
        )
        == {
            "Operational Excellence": 0,
            "Security": 0,
            "Reliability": 0,
            "Performance Efficiency": 0,
            "Cost Optimization": 0,
            "Sustainability": 0,
        }
    )
    assert (  # noqa: SLF001  # nosec B101
        module._expected_pillar_question_score_averages(
            [
                {"id": "OPS1", "score": 5},
                {"id": "SEC1", "score": True},
                {"id": "REL1", "score": 6},
                {"id": 1, "score": 5},
            ],
            {
                "OPS1": "Operational Excellence",
                "SEC1": "Security",
                "REL1": "Reliability",
            },
        )
        == {}
    )


def test_verify_well_architected_questions_rejects_invalid_status_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Question status values must be from the collector-compatible enum."""
    module = load_script_module(monkeypatch, "verify_well_architected_questions")
    evidence = _well_architected_question_evidence()
    scores = evidence["questionScores"]
    assert isinstance(scores, list)  # nosec B101
    assert isinstance(scores[0], dict)  # nosec B101
    scores[0]["status"] = "waived"

    report = module.verify_question_matrix(
        evidence=evidence,
        toc=_well_architected_question_toc(),
        toc_source="fixture",
    )

    assert report["status"] == "failed"  # nosec B101
    assert report["invalidStatusQuestionIds"] == ["OPS1"]  # nosec B101
    assert "statuses must be one of" in " ".join(report["blockers"])  # nosec B101


def test_verify_well_architected_questions_reports_duplicates_and_extra_ids(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch duplicated AWS/source IDs, extra evidence IDs, and bad metadata."""
    module = load_script_module(monkeypatch, "verify_well_architected_questions")
    evidence = _well_architected_question_evidence()
    scores = evidence["questionScores"]
    assert isinstance(scores, list)  # nosec B101
    duplicate = dict(scores[0])
    extra = dict(scores[1])
    extra["id"] = "OPS99"
    extra["score"] = True
    scores.extend([duplicate, extra])
    evidence["questionCount"] = 999
    evidence["frameworkSourceVerification"] = "missing"
    toc = _well_architected_question_toc()
    contents = toc["contents"]
    assert isinstance(contents, list)  # nosec B101
    appendix = contents[0]
    assert isinstance(appendix, dict)  # nosec B101
    nodes = appendix["contents"]
    assert isinstance(nodes, list)  # nosec B101
    nodes.append({"title": "OPS 1. Duplicate question?", "href": "ops-01.html"})

    report = module.verify_question_matrix(
        evidence=evidence,
        toc=toc,
        toc_source="fixture",
    )

    blockers = " ".join(report["blockers"])
    assert report["status"] == "failed"  # nosec B101
    assert report["duplicateAwsQuestionIds"] == ["OPS1"]  # nosec B101
    assert report["duplicateEvidenceQuestionIds"] == ["OPS1"]  # nosec B101
    assert report["extraQuestionIds"] == ["OPS99"]  # nosec B101
    assert report["invalidScoreQuestionIds"] == ["OPS99"]  # nosec B101
    assert "questionCount" in blockers  # nosec B101
    assert "questionCounts" in blockers  # nosec B101

    no_scores_report = module.verify_question_matrix(
        evidence={
            "questionCount": 57,
            "frameworkSourceVerification": {
                "questionCounts": {
                    "Operational Excellence": 11,
                    "Security": 11,
                    "Reliability": 13,
                    "Performance Efficiency": 5,
                    "Cost Optimization": 11,
                    "Sustainability": 6,
                }
            },
            "questionScores": "not a list",
        },
        toc=_well_architected_question_toc(),
        toc_source="fixture",
    )
    assert no_scores_report["status"] == "failed"  # nosec B101
    assert len(no_scores_report["missingQuestionIds"]) == 57  # nosec B101


def test_verify_well_architected_questions_rejects_pillar_swaps(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch per-question pillar drift even when pillar counts still match."""
    module = load_script_module(monkeypatch, "verify_well_architected_questions")
    evidence = _well_architected_question_evidence()
    scores = evidence["questionScores"]
    assert isinstance(scores, list)  # nosec B101
    ops1 = next(score for score in scores if score["id"] == "OPS1")
    sec1 = next(score for score in scores if score["id"] == "SEC1")
    ops1["pillar"], sec1["pillar"] = sec1["pillar"], ops1["pillar"]

    report = module.verify_question_matrix(
        evidence=evidence,
        toc=_well_architected_question_toc(),
        toc_source="fixture",
    )

    assert report["status"] == "failed"  # nosec B101
    assert report["pillarMismatchQuestionIds"] == ["OPS1", "SEC1"]  # nosec B101
    assert (  # nosec B101
        report["evidencePillarQuestionCounts"] == report["awsPillarQuestionCounts"]
    )
    assert "pillar values" in " ".join(report["blockers"])  # nosec B101
    assert module._pillar_mismatch_ids([{"id": 1}], {}) == []  # noqa: SLF001  # nosec B101


def test_verify_well_architected_questions_fetches_toc_and_reports_errors(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Cover live-fetch plumbing with a fake response and error rendering."""
    module = load_script_module(monkeypatch, "verify_well_architected_questions")
    evidence = tmp_path / "question-matrix-evidence.json"
    matrix = tmp_path / "question-matrix.md"
    evidence.write_text(
        json.dumps(_well_architected_question_evidence()), encoding="utf-8"
    )
    matrix.write_text(_well_architected_question_markdown(), encoding="utf-8")

    class FakeResponse(io.StringIO):
        def __enter__(self):
            return self

        def __exit__(self, *args: object) -> None:
            self.close()

    monkeypatch.setattr(
        module,
        "urlopen",
        lambda url, timeout: FakeResponse(json.dumps(_well_architected_question_toc())),
    )
    assert (
        module.main(
            [
                "--question-matrix-evidence",
                str(evidence),
                "--question-matrix",
                str(matrix),
            ]
        )
        == 0
    )
    assert '"status": "passed"' in capsys.readouterr().out

    monkeypatch.setattr(module, "urlopen", lambda url, timeout: FakeResponse("[]"))
    assert (
        module.main(
            [
                "--question-matrix-evidence",
                str(evidence),
                "--question-matrix",
                str(matrix),
            ]
        )
        == 2
    )
    assert "AWS Well-Architected TOC must be a JSON object" in capsys.readouterr().err

    invalid_evidence = tmp_path / "invalid-question-matrix-evidence.json"
    invalid_evidence.write_text("[]", encoding="utf-8")
    assert module.main(["--question-matrix-evidence", str(invalid_evidence)]) == 2
    assert "must contain a JSON object" in capsys.readouterr().err


def test_doctor_main_reports_missing_and_ready_states(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Cover prerequisite detection for the repo doctor command."""
    module = load_script_module(monkeypatch, "doctor")
    assert module._version([sys.executable, "-c", "print('version')"]) == "version"

    monkeypatch.setattr(module.shutil, "which", lambda name: None)
    assert module.main() == 1
    assert "docker: missing" in capsys.readouterr().err

    monkeypatch.setattr(module.shutil, "which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr(
        module,
        "_version",
        lambda command: (_ for _ in ()).throw(
            subprocess.CalledProcessError(1, command)
        ),
    )
    assert module.main() == 1
    assert "docker: missing or not installed" in capsys.readouterr().err

    env_file = tmp_path / ".env"
    env_file.write_text("KEY=value\n", encoding="utf-8")
    monkeypatch.setenv("COMPOSE_ENV_FILE", str(env_file))
    monkeypatch.setenv("COMPOSE_SERVICE", "pulumi")
    monkeypatch.setenv("PULUMI_DIR", str(tmp_path / "missing"))
    monkeypatch.setattr(
        module,
        "_version",
        lambda command: (
            (_ for _ in ()).throw(subprocess.CalledProcessError(1, command))
            if "--short" in command
            else "Docker version 1.0.0"
        ),
    )
    assert module.main() == 1
    assert "docker compose: missing" in capsys.readouterr().err

    monkeypatch.setattr(
        module,
        "_version",
        lambda command: "2.0.0" if "--short" in command else "Docker version 1.0.0",
    )
    assert module.main() == 1
    assert "pulumi directory missing" in capsys.readouterr().err

    pulumi_dir = tmp_path / "pulumi"
    pulumi_dir.mkdir()
    monkeypatch.setenv("PULUMI_DIR", str(pulumi_dir))
    assert module.main() == 0
    output = capsys.readouterr().out
    assert "effective env file:" in output
    assert "env file present: yes" in output

    monkeypatch.setenv("COMPOSE_ENV_FILE", str(tmp_path / "absent.env"))
    assert module.main() == 1
    assert "env file present: no" in capsys.readouterr().err


def test_configure_github_repository_controls_payloads(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Build the GitHub admin-control payloads without applying them."""
    module = load_script_module(monkeypatch, "configure_github_repository_controls")
    existing_pull_request_rule = {
        "type": "pull_request",
        "parameters": {"required_approving_review_count": 2},
    }
    existing_code_quality_rule = {
        "type": "code_quality",
        "parameters": {"severity": "errors"},
    }
    existing_code_scanning_rule = {
        "type": "code_scanning",
        "parameters": {
            "code_scanning_tools": [
                {
                    "alerts_threshold": "errors",
                    "security_alerts_threshold": "high_or_higher",
                    "tool": "CodeQL",
                }
            ]
        },
    }

    payload = module.ruleset_payload(
        [
            existing_pull_request_rule,
            existing_code_quality_rule,
            existing_code_scanning_rule,
            {"type": "ignored_rule"},
        ]
    )
    rules = {rule["type"]: rule for rule in payload["rules"]}
    contexts = [
        check["context"]
        for check in rules["required_status_checks"]["parameters"][
            "required_status_checks"
        ]
    ]

    assert contexts == list(module.REQUIRED_STATUS_CHECKS)  # nosec B101
    assert rules["pull_request"] == existing_pull_request_rule  # nosec B101
    assert rules["code_quality"] == existing_code_quality_rule  # nosec B101
    assert rules["code_scanning"] == existing_code_scanning_rule  # nosec B101
    assert module.prod_environment_payload(9444106) == {  # nosec B101
        "wait_timer": 0,
        "prevent_self_review": True,
        "reviewers": [{"type": "User", "id": 9444106}],
        "deployment_branch_policy": {
            "protected_branches": True,
            "custom_branch_policies": False,
        },
    }

    monkeypatch.setattr(module, "_main_ruleset", lambda _repo: None)
    monkeypatch.setattr(module, "_github_user_id", lambda _reviewer: 9444106)
    assert (  # nosec B101
        module.main(["--repo", "VilnaCRM-Org/bootstrap-infrastructure"]) == 0
    )
    rendered = json.loads(capsys.readouterr().out)
    assert rendered["prodEnvironment"]["reviewers"][0]["id"] == 9444106  # nosec B101
    assert rendered["prodEnvironmentReviewerLogin"] == "Kravalg"  # nosec B101

    assert (  # nosec B101
        module.main(["--repo", "VilnaCRM-Org/bootstrap-infrastructure", "--dry-run"])
        == 0
    )
    dry_run_rendered = json.loads(capsys.readouterr().out)
    assert (  # nosec B101
        dry_run_rendered["prodEnvironment"]["reviewers"][0]["id"] == 9444106
    )
    assert dry_run_rendered["prodEnvironmentReviewerLogin"] == "Kravalg"  # nosec B101

    with pytest.raises(SystemExit):
        module.main(["--repo", "example/repo", "--apply", "--dry-run"])
    with pytest.raises(SystemExit):
        module.main(["--repo", "example/repo", "--apply", "--verify-only"])
    with pytest.raises(SystemExit):
        module.main(["--repo", "example/repo", "--dry-run", "--verify-only"])


def test_configure_github_repository_controls_verification_helpers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify applied GitHub controls before reporting admin success."""
    module = load_script_module(monkeypatch, "configure_github_repository_controls")
    ruleset = module.ruleset_payload()
    environment = {
        "prevent_self_review": True,
        "deployment_branch_policy": {
            "protected_branches": True,
            "custom_branch_policies": False,
        },
        "protection_rules": [
            {
                "type": "required_reviewers",
                "reviewers": [
                    {
                        "type": "User",
                        "reviewer": {"id": 9444106, "login": "Kravalg"},
                    }
                ],
            }
        ],
    }

    assert module._ruleset_verification_blockers(ruleset) == []  # noqa: SLF001  # nosec B101
    assert (
        module._prod_environment_verification_blockers(  # noqa: SLF001  # nosec B101
            environment, 9444106
        )
        == []
    )
    assert module._environment_reviewer_ids(  # noqa: SLF001  # nosec B101
        {"reviewers": [{"type": "User", "id": 9444106}]}
    ) == {9444106}
    assert (
        module._environment_reviewer_ids(  # noqa: SLF001  # nosec B101
            {
                "reviewers": ["invalid", {"type": "Team", "id": 1}],
                "protection_rules": [
                    "invalid",
                    {"reviewers": "invalid"},
                    {"reviewers": [{"type": "User", "reviewer": {"login": "missing"}}]},
                ],
            }
        )
        == set()
    )
    assert module._required_status_contexts({"rules": "invalid"}) == set()  # noqa: SLF001  # nosec B101
    assert module._required_status_contexts(  # noqa: SLF001  # nosec B101
        {
            "rules": [
                "invalid",
                {"type": "required_status_checks", "parameters": "invalid"},
                {
                    "type": "required_status_checks",
                    "parameters": {"required_status_checks": "invalid"},
                },
                {
                    "type": "required_status_checks",
                    "parameters": {
                        "required_status_checks": ["invalid", {}, {"name": "Unit"}]
                    },
                },
            ]
        }
    ) == {"Unit"}
    assert not module._ruleset_has_pull_request_reviews(  # noqa: SLF001  # nosec B101
        {"rules": "invalid"}
    )
    assert not module._ruleset_has_pull_request_reviews(  # noqa: SLF001  # nosec B101
        {"rules": [{"type": "pull_request", "parameters": "invalid"}]}
    )

    bad_ruleset = {"rules": [{"type": "deletion"}]}
    ruleset_blockers = module._ruleset_verification_blockers(  # noqa: SLF001
        bad_ruleset
    )
    assert "missing required status checks" in ruleset_blockers[0]  # nosec B101
    assert "pull request reviews" in ruleset_blockers[1]  # nosec B101
    environment_blockers = module._prod_environment_verification_blockers(  # noqa: SLF001
        {
            "prevent_self_review": False,
            "deployment_branch_policy": {
                "protected_branches": False,
                "custom_branch_policies": True,
            },
            "protection_rules": [],
        },
        9444106,
    )
    assert "prevent self-review" in environment_blockers[0]  # nosec B101
    assert "protected branches" in environment_blockers[1]  # nosec B101
    assert "configured reviewer" in environment_blockers[2]  # nosec B101
    missing_policy_blockers = module._prod_environment_verification_blockers(  # noqa: SLF001
        {"prevent_self_review": True, "protection_rules": []},
        9444106,
    )
    assert "branch policy" in missing_policy_blockers[0]  # nosec B101
    assert module._ruleset_verification_blockers(None) == [  # noqa: SLF001  # nosec B101
        "Active main branch ruleset was not found after apply."
    ]
    assert module._prod_environment_verification_blockers(  # noqa: SLF001  # nosec B101
        None, 9444106
    ) == ["Production environment was not readable after apply."]

    monkeypatch.setattr(module, "_main_ruleset", lambda _repo: ruleset)
    monkeypatch.setattr(
        module,
        "_run_gh_api",
        lambda _args, **_kwargs: environment,
    )
    assert module._verify_applied_controls(  # noqa: SLF001  # nosec B101
        "example/repo", 9444106
    ) == {
        "requiredStatusChecks": sorted(module.REQUIRED_STATUS_CHECKS),
        "prodReviewerId": 9444106,
        "prodEnvironment": "prod",
    }

    monkeypatch.setattr(module, "_main_ruleset", lambda _repo: bad_ruleset)
    with pytest.raises(RuntimeError, match="missing required status checks"):
        module._verify_applied_controls("example/repo", 9444106)  # noqa: SLF001

    def fail_environment_read(_args, **_kwargs):
        raise RuntimeError("gh: Not Found")

    monkeypatch.setattr(module, "_run_gh_api", fail_environment_read)
    with pytest.raises(RuntimeError) as exc_info:
        module._verify_applied_controls("example/repo", 9444106)  # noqa: SLF001
    combined_error = str(exc_info.value)
    assert "missing required status checks" in combined_error  # nosec B101
    assert "gh: Not Found" in combined_error  # nosec B101

    monkeypatch.setattr(module, "_main_ruleset", lambda _repo: ruleset)
    monkeypatch.setattr(module, "_run_gh_api", lambda _args, **_kwargs: [])
    with pytest.raises(RuntimeError, match="not readable"):
        module._verify_applied_controls("example/repo", 9444106)  # noqa: SLF001


def test_configure_github_repository_controls_verify_only(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Verify existing GitHub controls without applying writes or requiring admin."""
    module = load_script_module(monkeypatch, "configure_github_repository_controls")
    verifications: list[tuple[str, int]] = []

    monkeypatch.setattr(module, "_github_user_id", lambda _reviewer: 9444106)
    monkeypatch.setattr(
        module,
        "_repo_admin_allowed",
        lambda _repo: (_ for _ in ()).throw(AssertionError("admin checked")),
    )
    monkeypatch.setattr(
        module,
        "_main_ruleset",
        lambda _repo: (_ for _ in ()).throw(AssertionError("ruleset read")),
    )
    monkeypatch.setattr(
        module,
        "_verify_applied_controls",
        lambda repo, reviewer_id: (
            verifications.append((repo, reviewer_id))
            or {"prodEnvironment": "prod", "prodReviewerId": reviewer_id}
        ),
    )

    assert (  # nosec B101
        module.configure("example/repo", "Kravalg", apply=False, verify_only=True) == 0
    )
    rendered = json.loads(capsys.readouterr().out)
    assert rendered == {  # nosec B101
        "verification": {"prodEnvironment": "prod", "prodReviewerId": 9444106}
    }

    assert (  # nosec B101
        module.main(["--repo", "example/repo", "--verify-only"]) == 0
    )
    rendered = json.loads(capsys.readouterr().out)
    assert rendered["verification"]["prodReviewerId"] == 9444106  # nosec B101
    assert verifications == [  # nosec B101
        ("example/repo", 9444106),
        ("example/repo", 9444106),
    ]


def test_required_status_check_contract_matches_collector_and_docs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Keep the branch-protection helper, collector, and docs in sync."""
    controls_module = load_script_module(
        monkeypatch, "configure_github_repository_controls"
    )
    collector_module = load_script_module(
        monkeypatch, "collect_well_architected_evidence"
    )
    guardrails_doc = (PROJECT_ROOT / "docs/ci-guardrails.md").read_text(
        encoding="utf-8"
    )
    quality_gates_doc = (PROJECT_ROOT / "docs/ci-quality-gates.md").read_text(
        encoding="utf-8"
    )
    operating_evidence_doc = (
        PROJECT_ROOT / "docs/well-architected-operating-evidence.md"
    ).read_text(encoding="utf-8")
    implementation_readiness_report = (
        PROJECT_ROOT
        / "specs"
        / "issue-17-well-architected-5-of-5"
        / "implementation-readiness-report.md"
    ).read_text(encoding="utf-8")
    external_control_path = (
        PROJECT_ROOT
        / "specs"
        / "issue-17-well-architected-5-of-5"
        / "external-control-evidence-2026-05-09.json"
    )
    external_control_evidence = json.loads(
        external_control_path.read_text(encoding="utf-8")
    )
    required_checks_section = guardrails_doc.split("## Required PR checks", 1)[1].split(
        "### Same-repo privileged check contract", 1
    )[0]
    documented_checks = [
        line.split("`", 2)[1]
        for line in required_checks_section.splitlines()
        if line.startswith("| `")
    ]
    quality_required_checks_section = quality_gates_doc.split(
        "## PR-blocking checks", 1
    )[1].split("## Scheduled quality monitoring", 1)[0]
    quality_documented_checks = [
        line.split("`", 2)[1]
        for line in quality_required_checks_section.splitlines()
        if line.startswith("| `")
    ]

    assert controls_module.REQUIRED_STATUS_CHECKS == (  # nosec B101
        collector_module.DEFAULT_REQUIRED_STATUS_CHECKS
    )
    assert documented_checks == list(  # nosec B101
        collector_module.DEFAULT_REQUIRED_STATUS_CHECKS
    )
    assert quality_documented_checks == list(  # nosec B101
        collector_module.DEFAULT_REQUIRED_STATUS_CHECKS
    )
    required_check_text = (
        ", ".join(collector_module.DEFAULT_REQUIRED_STATUS_CHECKS[:-1])
        + f", and {collector_module.DEFAULT_REQUIRED_STATUS_CHECKS[-1]}"
    )
    branch_protection_control = next(
        control
        for control in external_control_evidence["controls"]
        if control["id"] == "branch_protection"
    )
    production_approval_control = next(
        control
        for control in external_control_evidence["controls"]
        if control["id"] == "production_approval"
    )
    unresolved_controls = [
        control
        for control in external_control_evidence["controls"]
        if control.get("status") != "passed"
    ]
    assert (  # noqa: SLF001  # nosec B101
        collector_module._unresolved_control_ids_from_controls(
            external_control_evidence["controls"]
        )
        == external_control_evidence["unresolvedControlIds"]
    )
    assert all(  # nosec B101
        collector_module._non_empty_string_list(control.get("evidence"))  # noqa: SLF001
        for control in external_control_evidence["controls"]
    )
    assert all(  # nosec B101
        isinstance(control.get("unresolvedReason"), str)
        and control["unresolvedReason"].strip()
        for control in unresolved_controls
    )
    assert branch_protection_control["unresolvedReason"] == (  # nosec B101
        "Admin-owned ruleset must require the documented status checks: "
        f"{required_check_text}."
    )
    for control in (branch_protection_control, production_approval_control):
        evidence_text = " ".join(control["evidence"])
        assert "--dry-run" in evidence_text  # nosec B101
        assert "--verify-only" in evidence_text  # nosec B101
        assert "--apply" in evidence_text  # nosec B101
    assert (  # nosec B101
        f"GitHub ruleset 13906584 requires {required_check_text}." in guardrails_doc
    )
    assert (  # nosec B101
        f"Active `main` ruleset requires {required_check_text}."
        in operating_evidence_doc
    )
    normalized_readiness_report = " ".join(implementation_readiness_report.split())
    assert (  # nosec B101
        f"active `main` ruleset requires {required_check_text}."
        in normalized_readiness_report
    )


def test_well_architected_question_source_contract_matches_docs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Keep the official AWS TOC source contract visible in audit docs."""
    collector_module = load_script_module(
        monkeypatch, "collect_well_architected_evidence"
    )
    toc_url = collector_module.AWS_WELL_ARCHITECTED_TOC_URL
    issue_dir = PROJECT_ROOT / "specs" / "issue-17-well-architected-5-of-5"
    question_evidence = json.loads(
        (issue_dir / "question-matrix-evidence-2026-05-09.json").read_text(
            encoding="utf-8"
        )
    )
    source_verification = question_evidence["frameworkSourceVerification"]

    assert toc_url in source_verification["sourceUrls"]  # nosec B101
    assert (  # noqa: SLF001  # nosec B101
        collector_module._question_matrix_source_verification_blockers(
            question_evidence
        )
        == []
    )
    for relative_path in (
        "completion-audit-2026-05-10.md",
        "implementation-readiness-report.md",
        "well-architected-review.md",
    ):
        assert toc_url in (issue_dir / relative_path).read_text(  # nosec B101
            encoding="utf-8"
        )


def test_configure_github_repository_controls_api_helpers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cover gh api parsing, ruleset lookup, and reviewer resolution paths."""
    module = load_script_module(monkeypatch, "configure_github_repository_controls")
    calls: list[tuple[list[str], str | None]] = []
    responses = [
        '{"ok": true}',
        "",
        '"scalar"',
        '[{"name":"other"},{"name":"main","target":"branch","id":123}]',
        '{"id":123,"rules":[{"type":"deletion"}]}',
        '{"not":"a-list"}',
        '["invalid", {"name":"main","target":"branch","id":"not-int"}]',
        '{"id":9444106}',
        "{}",
        "[]",
        '{"permissions":{"admin":true}}',
        '{"permissions":{"admin":false}}',
        '{"permissions":{}}',
    ]

    def fake_run(command, input=None, check=None, capture_output=None, text=None):
        calls.append((command, input))
        return subprocess.CompletedProcess(command, 0, stdout=responses.pop(0))

    monkeypatch.setattr(module.subprocess, "run", fake_run)

    assert module._run_gh_api(["repos/example/repo"]) == {"ok": True}  # nosec B101
    assert (  # nosec B101
        module._run_gh_api(["repos/example/repo"], input_payload={"x": 1}) == {}
    )
    assert module._run_gh_api(["repos/example/repo"]) == {}  # nosec B101
    assert module._main_ruleset("example/repo") == {  # nosec B101
        "id": 123,
        "rules": [{"type": "deletion"}],
    }
    assert module._main_ruleset("example/repo") is None  # nosec B101
    assert module._main_ruleset("example/repo") is None  # nosec B101
    assert module._github_user_id("Kravalg") == 9444106  # nosec B101
    with pytest.raises(ValueError, match="Could not resolve"):
        module._github_user_id("missing")
    assert module._repo_admin_allowed("example/repo") is False  # nosec B101  # noqa: SLF001
    assert module._repo_admin_allowed("example/repo") is True  # nosec B101  # noqa: SLF001
    assert module._repo_admin_allowed("example/repo") is False  # nosec B101  # noqa: SLF001
    assert module._repo_admin_allowed("example/repo") is False  # nosec B101  # noqa: SLF001
    assert calls[1][1] == '{"x": 1}'  # nosec B101

    def failing_run(command, input=None, check=None, capture_output=None, text=None):
        return subprocess.CompletedProcess(command, 1, stdout="", stderr="denied")

    monkeypatch.setattr(module.subprocess, "run", failing_run)
    with pytest.raises(RuntimeError, match="denied"):
        module._run_gh_api(["repos/example/repo"])


def test_configure_github_repository_controls_apply_paths(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Apply existing and new ruleset paths through gh api wrappers."""
    module = load_script_module(monkeypatch, "configure_github_repository_controls")
    calls: list[tuple[list[str], dict]] = []
    verifications: list[tuple[str, int]] = []
    existing = {"id": 123, "rules": "invalid"}

    monkeypatch.setattr(module, "_repo_admin_allowed", lambda _repo: True)
    monkeypatch.setattr(module, "_github_user_id", lambda _reviewer: 9444106)
    monkeypatch.setattr(
        module,
        "_verify_applied_controls",
        lambda repo, reviewer_id: (
            verifications.append((repo, reviewer_id)) or {"verified": True}
        ),
    )

    def fake_run_gh_api(args, *, input_payload=None):
        calls.append((list(args), dict(input_payload or {})))
        return {}

    monkeypatch.setattr(module, "_run_gh_api", fake_run_gh_api)
    monkeypatch.setattr(module, "_main_ruleset", lambda _repo: existing)

    assert module.configure("example/repo", "Kravalg", apply=True) == 0  # nosec B101
    assert calls[0][0] == [  # nosec B101
        "repos/example/repo/rulesets/123",
        "--method",
        "PUT",
    ]
    assert calls[1][0] == [  # nosec B101
        "repos/example/repo/environments/prod",
        "--method",
        "PUT",
    ]
    rendered = json.loads(capsys.readouterr().out)
    assert rendered["prodEnvironment"]["reviewers"][0]["id"] == 9444106  # nosec B101
    assert rendered["verification"] == {"verified": True}  # nosec B101
    assert verifications == [("example/repo", 9444106)]  # nosec B101

    calls.clear()
    verifications.clear()
    monkeypatch.setattr(module, "_main_ruleset", lambda _repo: None)
    assert module.configure("example/repo", "Kravalg", apply=True) == 0  # nosec B101
    assert calls[0][0] == ["repos/example/repo/rulesets", "--method", "POST"]  # nosec B101
    assert verifications == [("example/repo", 9444106)]  # nosec B101


def test_configure_github_repository_controls_apply_requires_admin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fail before mutating repository controls when the token is not an admin."""
    module = load_script_module(monkeypatch, "configure_github_repository_controls")
    calls: list[list[str]] = []

    monkeypatch.setattr(module, "_repo_admin_allowed", lambda _repo: False)
    monkeypatch.setattr(
        module,
        "_main_ruleset",
        lambda _repo: (_ for _ in ()).throw(AssertionError("ruleset read")),
    )
    monkeypatch.setattr(
        module,
        "_github_user_id",
        lambda _reviewer: (_ for _ in ()).throw(AssertionError("reviewer read")),
    )

    def fake_run_gh_api(args, *, input_payload=None):
        calls.append(list(args))
        return {}

    monkeypatch.setattr(module, "_run_gh_api", fake_run_gh_api)

    with pytest.raises(RuntimeError, match="repository admin rights"):
        module.configure("example/repo", "Kravalg", apply=True)
    assert calls == []  # nosec B101


def test_configure_github_repository_controls_main_reports_errors(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Return a non-zero exit when GitHub rejects the admin update."""
    module = load_script_module(monkeypatch, "configure_github_repository_controls")

    def fail_configure(*_args, **_kwargs):
        raise RuntimeError("admin required")

    monkeypatch.setattr(module, "configure", fail_configure)

    assert module.main(["--repo", "example/repo", "--apply"]) == 1  # nosec B101
    assert "error:" in capsys.readouterr().err  # nosec B101


def test_prepare_docker_context_main_bootstraps_and_rejects_invalid_env(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Create the local Docker context safely and reject invalid .env paths."""
    module = load_script_module(monkeypatch, "prepare_docker_context")
    home_dir = tmp_path / "home"
    repo_dir = tmp_path / "repo"
    home_dir.mkdir()
    repo_dir.mkdir()
    monkeypatch.setenv("HOME", str(home_dir))
    monkeypatch.chdir(repo_dir)

    aws_marker = home_dir / ".aws"
    aws_target = tmp_path / "aws-target"
    aws_target.mkdir()
    aws_marker.symlink_to(aws_target, target_is_directory=True)
    assert module.main() == 1
    assert "~/.aws must be a regular directory" in capsys.readouterr().err
    aws_marker.unlink()

    aws_marker.write_text("not-a-directory\n", encoding="utf-8")
    assert module.main() == 1
    assert "~/.aws must be a regular directory" in capsys.readouterr().err
    aws_marker.unlink()

    assert module.main() == 1
    assert ".env.empty not found" in capsys.readouterr().err

    (repo_dir / ".env.empty").write_text("KEY=value\n", encoding="utf-8")
    target_env = tmp_path / "target.env"
    target_env.write_text("TARGET=value\n", encoding="utf-8")
    (repo_dir / ".env").symlink_to(target_env)
    assert module.main() == 1
    assert ".env must be a regular file" in capsys.readouterr().err
    (repo_dir / ".env").unlink()

    missing_env_target = tmp_path / "missing.env"
    (repo_dir / ".env").symlink_to(missing_env_target)
    assert module.main() == 1
    assert ".env must be a regular file" in capsys.readouterr().err
    (repo_dir / ".env").unlink()

    backend_target = tmp_path / "backend-target"
    backend_target.mkdir()
    (repo_dir / ".pulumi-backend").symlink_to(backend_target, target_is_directory=True)
    assert module.main() == 1
    assert ".pulumi-backend must be a regular directory" in capsys.readouterr().err
    (repo_dir / ".pulumi-backend").unlink()

    assert module.main() == 0
    assert (home_dir / ".aws").is_dir()
    assert (repo_dir / ".env").read_text(encoding="utf-8") == "KEY=value\n"
    assert (repo_dir / ".pulumi-backend").is_dir()
    (repo_dir / ".env").write_text("LOCAL=value\n", encoding="utf-8")
    assert module.main() == 0
    assert (repo_dir / ".env").read_text(encoding="utf-8") == "LOCAL=value\n"


def test_prepare_docker_context_helpers_reject_non_directories(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Exercise helper guards that reject symlinks and non-directory paths."""
    module = load_script_module(monkeypatch, "prepare_docker_context")
    regular_dir = tmp_path / "regular-dir"
    regular_dir.mkdir()
    symlink_dir = tmp_path / "symlink-dir"
    symlink_dir.symlink_to(regular_dir, target_is_directory=True)
    plain_file = tmp_path / "plain-file"
    plain_file.write_text("x\n", encoding="utf-8")

    assert module._is_regular_directory_path(regular_dir, "regular-dir") is True
    assert module._is_regular_directory_path(symlink_dir, "symlink-dir") is False

    with pytest.raises(NotADirectoryError):
        module._ensure_dir(symlink_dir, 0o700)
    with pytest.raises(NotADirectoryError):
        module._ensure_dir(plain_file, 0o700)


def test_prepare_policy_pack_helpers_and_main_paths(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Cover policy-pack bootstrap success and failure paths."""
    module = load_script_module(monkeypatch, "prepare_policy_pack")
    policy_dir = tmp_path / "policy"
    policy_dir.mkdir()
    policy_link = policy_dir / ".venv"
    policy_link.mkdir()
    with pytest.raises(SystemExit, match="1"):
        module._link_policy_venv(tmp_path / "shared-venv", policy_link)
    assert "must be a symlink" in capsys.readouterr().err
    policy_link.rmdir()

    monkeypatch.setattr(
        module.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0),
    )
    assert module._imports_available(tmp_path / "python", tmp_path) is True
    monkeypatch.setattr(
        module.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 1),
    )
    assert module._imports_available(tmp_path / "python", tmp_path) is False

    repo_dir = tmp_path / "repo"
    repo_policy_dir = repo_dir / "policy"
    repo_policy_dir.mkdir(parents=True)
    policy_venv = tmp_path / "policy-venv"
    policy_python = policy_venv / "bin" / "python"
    policy_python.parent.mkdir(parents=True)
    policy_python.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
    os.chmod(policy_python, 0o755)
    monkeypatch.setattr(module, "repo_root", lambda _: repo_dir)
    monkeypatch.setenv("POLICY_VENV", str(policy_venv))

    assert module.main() == 1
    assert "policy requirements file not found" in capsys.readouterr().err

    requirements_file = repo_policy_dir / "requirements.txt"
    requirements_file.write_text("pulumi-policy\n", encoding="utf-8")
    policy_python.unlink()
    assert module.main() == 1
    assert "policy interpreter not found" in capsys.readouterr().err

    policy_python.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
    os.chmod(policy_python, 0o755)
    run_calls: list[list[str]] = []
    availability = iter([False, True])
    monkeypatch.setattr(module, "_imports_available", lambda *args: next(availability))
    monkeypatch.setattr(
        module,
        "run",
        lambda command, **kwargs: (
            run_calls.append(command) or subprocess.CompletedProcess(command, 0)
        ),
    )
    assert module.main() == 0
    assert run_calls == [["uv", "sync", "--frozen", "--all-groups"]]
    assert (repo_policy_dir / ".venv").is_symlink()

    run_calls.clear()
    monkeypatch.setattr(module, "_imports_available", lambda *args: True)
    assert module.main() == 0
    assert run_calls == []

    monkeypatch.setattr(module, "_imports_available", lambda *args: False)
    assert module.main() == 1
    assert "shared policy interpreter is missing" in capsys.readouterr().err


def test_validate_repository_catalogs_main_validates_default_catalogs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Validate committed repository catalog files against schema and loader rules."""
    module = load_script_module(monkeypatch, "validate_repository_catalogs")
    repo_dir = tmp_path / "repo"
    pulumi_dir = repo_dir / "pulumi"
    pulumi_dir.mkdir(parents=True)
    schema_path = pulumi_dir / "repositories.schema.json"
    schema_path.write_text(
        (PROJECT_ROOT / "pulumi" / "repositories.schema.json").read_text(
            encoding="utf-8"
        ),
        encoding="utf-8",
    )
    catalog_path = pulumi_dir / "repositories.example.json"
    catalog_path.write_text(
        json.dumps(
            {
                "$schema": "./repositories.schema.json",
                "repositories": [
                    {
                        "name": "user-service-infrastructure",
                        "defaultBranch": "main",
                        "project": "user-service",
                        "owner": "team-user-service",
                        "lifecycleState": "active",
                        "lastReviewed": "2026-04-27",
                        "expectedEnvironments": 2,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(module, "ROOT_DIR", repo_dir)

    assert module.repository_catalog_paths(repo_dir) == [catalog_path]  # nosec B101
    assert module.validate_catalogs(  # nosec B101
        [catalog_path], schema_path
    ) == [catalog_path]
    assert module.catalog_fanout_report(catalog_path, schema_path) == {  # nosec B101
        "backupPlans": 1,
        "backupSelections": 2,
        "backupVaults": 1,
        "budgets": 1,
        "cloudTrailTrails": 1,
        "configDeliveryChannels": 1,
        "configRecorders": 1,
        "costAllocationTags": 0,
        "costAnomalyMonitors": 1,
        "costAnomalySubscriptions": 1,
        "ecrRepositories": 1,
        "environmentInstances": 2,
        "eventRules": 4,
        "guardDutyDetectors": 1,
        "iamRoles": 7,
        "kmsKeys": 3,
        "oidcProviders": 1,
        "repositories": 1,
        "s3Buckets": 8,
        "securityHubAccounts": 1,
        "snsSubscriptions": 1,
        "snsTopics": 1,
        "sqsQueues": 1,
    }
    assert module._fanout_threshold_report(  # nosec B101
        {"s3Buckets": 6, "kmsKeys": 3},
        {"s3Buckets": 10, "kmsKeys": 2},
    ) == {
        "kmsKeys": {
            "current": 3,
            "max": 2,
            "overBy": 1,
            "remaining": 0,
            "status": "exceeded",
        },
        "s3Buckets": {
            "current": 6,
            "max": 10,
            "overBy": 0,
            "remaining": 4,
            "status": "ok",
        },
    }
    assert module.main([]) == 0  # nosec B101
    assert module.main(["--fanout-report"]) == 0  # nosec B101
    assert module.main(["--fanout-report", "--max-s3-buckets", "1"]) == 1  # nosec B101
    assert module.main(["--fanout-report", "--max-budgets", "0"]) == 1  # nosec B101

    captured = capsys.readouterr()
    output = captured.out
    assert f"validated repository catalog: {catalog_path}" in output  # nosec B101
    assert "repository fanout estimate" in output  # nosec B101
    assert "repository fanout thresholds" in output  # nosec B101
    assert '"current": 8' in output  # nosec B101
    assert '"remaining": 192' in output  # nosec B101
    assert "s3Buckets fanout" in captured.err  # nosec B101
    assert "budgets fanout" in captured.err  # nosec B101
    assert "cloudTrailTrails" in output  # nosec B101
    assert "guardDutyDetectors" in output  # nosec B101


def test_validate_repository_catalogs_reports_schema_errors(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Schema failures should identify the invalid catalog path."""
    module = load_script_module(monkeypatch, "validate_repository_catalogs")
    catalog_path = tmp_path / "repositories.json"
    catalog_path.write_text(
        json.dumps({"repositories": [{"name": 123}]}),
        encoding="utf-8",
    )
    schema_path = PROJECT_ROOT / "pulumi" / "repositories.schema.json"

    assert module._json_pointer(["repositories", 0, "name"]) == (  # nosec B101
        "$.repositories[0].name"
    )
    assert module.main(["--schema", str(schema_path), str(catalog_path)]) == 1  # nosec B101

    error_output = capsys.readouterr().err
    assert str(catalog_path) in error_output  # nosec B101
    assert "$.repositories[0]" in error_output  # nosec B101


def test_validate_repository_catalogs_reports_semantic_errors(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Loader-level checks should still catch schema-valid duplicate names."""
    module = load_script_module(monkeypatch, "validate_repository_catalogs")
    catalog_path = tmp_path / "repositories.json"
    catalog_path.write_text(
        json.dumps({"repositories": ["Repo", "repo"]}),
        encoding="utf-8",
    )
    schema_path = PROJECT_ROOT / "pulumi" / "repositories.schema.json"

    with pytest.raises(ValueError, match="must be unique"):
        module.validate_catalog(catalog_path, schema_path)

    catalog_path.write_text(
        json.dumps(
            {
                "repositories": [
                    {
                        "name": "repo",
                        "lifecycleState": "unknown",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="lifecycleState"):
        module.validate_catalog(catalog_path, schema_path)


def test_validate_repository_catalogs_semantic_helpers_reject_bad_inputs(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Cover semantic guardrails that usually sit behind schema validation."""
    module = load_script_module(monkeypatch, "validate_repository_catalogs")

    assert module._repository_name({"name": " repo "}) == "repo"  # nosec B101
    module._validate_repository_mapping({"name": "repo"})

    with pytest.raises(ValueError, match="blank value"):
        module._required_non_blank_string(" ", "blank value")
    with pytest.raises(ValueError, match="string or an object"):
        module._repository_name(123)
    with pytest.raises(ValueError, match="must be a list"):
        module._validate_loader_semantics({"repositories": "repo"})
    with pytest.raises(ValueError, match="lastReviewed"):
        module._validate_repository_mapping(
            {"name": "repo", "lastReviewed": "27-04-2026"}
        )
    with pytest.raises(ValueError, match="lastReviewed"):
        module._validate_repository_mapping(
            {"name": "repo", "lastReviewed": "20260427"}
        )
    with pytest.raises(ValueError, match="lastReviewed"):
        module._validate_repository_mapping(
            {"name": "repo", "lastReviewed": "2026-02-30"}
        )
    with pytest.raises(ValueError, match="lifecycleState"):
        module._validate_repository_mapping(
            {"name": "repo", "lifecycleState": "unknown"}
        )
    with pytest.raises(ValueError, match="expectedEnvironments"):
        module._validate_repository_mapping({"name": "repo", "expectedEnvironments": 0})
    with pytest.raises(ValueError, match="expectedEnvironments"):
        module._validate_repository_mapping(
            {"name": "repo", "expectedEnvironments": True}
        )
    with pytest.raises(ValueError, match="must be a list"):
        module.estimate_fanout({"repositories": "repo"})
    assert (  # nosec B101
        module.estimate_fanout({"repositories": ["repo"]})["environmentInstances"] == 2
    )
    assert (  # nosec B101
        module.estimate_fanout(
            {"repositories": [{"name": "repo", "expectedEnvironments": "2"}]}
        )["environmentInstances"]
        == 2
    )

    monkeypatch.setattr(module, "validate_catalog", lambda *_args: None)
    monkeypatch.setattr(module, "_load_json", lambda _path: [])
    with pytest.raises(ValueError, match="must be an object"):
        module.catalog_fanout_report(
            tmp_path / "repositories.json",
            tmp_path / "schema.json",
        )


def test_validate_repository_catalogs_handles_empty_and_invalid_inputs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The CLI should fail clearly when no catalogs or malformed JSON are present."""
    module = load_script_module(monkeypatch, "validate_repository_catalogs")
    repo_dir = tmp_path / "repo"
    (repo_dir / "pulumi").mkdir(parents=True)
    monkeypatch.setattr(module, "ROOT_DIR", repo_dir)

    assert module.main([]) == 1  # nosec B101
    assert "no repository catalog JSON files found" in capsys.readouterr().err  # nosec B101

    schema_path = PROJECT_ROOT / "pulumi" / "repositories.schema.json"
    bad_catalog = tmp_path / "repositories.bad.json"
    bad_catalog.write_text("{not-json", encoding="utf-8")

    assert module.main(["--schema", str(schema_path), str(bad_catalog)]) == 1  # nosec B101
    assert "Expecting property name" in capsys.readouterr().err  # nosec B101

    invalid_schema = tmp_path / "repositories.schema.json"
    invalid_schema.write_text(json.dumps({"type": 123}), encoding="utf-8")
    valid_catalog = tmp_path / "repositories.json"
    valid_catalog.write_text(
        json.dumps({"repositories": ["user-service-infrastructure"]}),
        encoding="utf-8",
    )

    assert module.main(["--schema", str(invalid_schema), str(valid_catalog)]) == 1  # nosec B101
    error_output = capsys.readouterr().err
    assert str(invalid_schema) in error_output  # nosec B101
    assert "invalid repository catalog schema" in error_output  # nosec B101


def test_publish_pulumi_preview_summary_main_handles_backend_and_summary_paths(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Run the preview summary wrapper across its guarded execution paths."""
    module = load_script_module(monkeypatch, "publish_pulumi_preview_summary")
    repo_dir = tmp_path / "repo"
    preview_dir = repo_dir / ".artifacts" / "pulumi-preview"
    preview_dir.mkdir(parents=True)
    monkeypatch.setattr(module, "repo_root", lambda _: repo_dir)

    monkeypatch.setenv("PULUMI_REQUIRE_SHARED_BACKEND", "true")
    monkeypatch.delenv("PULUMI_BACKEND_URL", raising=False)
    assert module.main() == 1
    assert "privileged previews require a non-file" in capsys.readouterr().err

    run_calls: list[tuple[list[str], Path | None, dict[str, str]]] = []

    def fake_run(command, **kwargs):
        run_calls.append((command, kwargs.get("cwd"), kwargs["env"]))
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(module, "run", fake_run)
    monkeypatch.setenv("PULUMI_REQUIRE_SHARED_BACKEND", "false")
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    assert module.main() == 0
    assert run_calls[-1][0] == ["make", "test-preview"]
    assert run_calls[-1][1] == repo_dir
    assert run_calls[-1][2]["PULUMI_BACKEND_URL"] == "file:///workspace/.pulumi-backend"

    monkeypatch.setenv("PULUMI_BACKEND_URL", "")
    assert module.main() == 0
    assert run_calls[-1][2]["PULUMI_BACKEND_URL"] == "file:///workspace/.pulumi-backend"

    monkeypatch.setenv("PULUMI_BACKEND_URL", "s3://configured-backend")
    assert module.main() == 0
    assert run_calls[-1][2]["PULUMI_BACKEND_URL"] == "s3://configured-backend"

    monkeypatch.setenv("PULUMI_REQUIRE_SHARED_BACKEND", "true")
    monkeypatch.setenv("PULUMI_BACKEND_URL", "s3://shared-backend")
    monkeypatch.delenv("PULUMI_SECRETS_PROVIDER", raising=False)
    assert module.main() == 1  # nosec B101
    assert "privileged previews require an awskms://" in capsys.readouterr().err  # nosec B101

    monkeypatch.setenv(
        "PULUMI_SECRETS_PROVIDER",
        "awskms://alias/bootstrap-preview?region=eu-central-1",
    )
    assert module.main() == 0
    assert run_calls[-1][2]["PULUMI_BACKEND_URL"] == "s3://shared-backend"

    preview_summary = preview_dir / "summary.md"
    preview_summary.write_text("preview summary\n", encoding="utf-8")
    github_summary = tmp_path / "github-summary.md"
    github_summary.write_text("existing\n", encoding="utf-8")
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(github_summary))
    assert module.main() == 0
    assert github_summary.read_text(encoding="utf-8") == "existing\npreview summary\n"

    preview_summary.unlink()
    assert module.main() == 0
    assert "without a rendered summary artifact" in github_summary.read_text(
        encoding="utf-8"
    )


def test_report_maintainability_trends_main_handles_git_and_wily_paths(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Cover skipped and successful maintainability-report generation."""
    module = load_script_module(monkeypatch, "report_maintainability_trends")
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    monkeypatch.setattr(module, "repo_root", lambda _: repo_dir)
    monkeypatch.setenv("ROOT_DIR", str(repo_dir))
    monkeypatch.setenv("QUALITY_ARTIFACT_DIR", "reports")
    monkeypatch.setenv("WILY_TARGETS", "pulumi,policy")

    skip_calls: list[list[str]] = []

    def fake_skip_run(command, **kwargs):
        skip_calls.append(command)
        if command[:2] == ["git", "rev-parse"]:
            return subprocess.CompletedProcess(command, 1)
        if command[:4] == ["uv", "run", "radon", "mi"]:
            return subprocess.CompletedProcess(
                command, 0, stdout="pulumi/app.py - A (100.00)\n"
            )
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(module, "run", fake_skip_run)
    assert module.main() == 0
    skip_report = repo_dir / "reports" / "wily-rank.txt"
    skip_report_text = skip_report.read_text(encoding="utf-8")
    assert "Wily maintainability report skipped" in skip_report_text
    assert "Current maintainability snapshot from radon" in skip_report_text
    assert "pulumi/app.py - A (100.00)" in skip_report_text
    assert any(command[:4] == ["uv", "run", "radon", "mi"] for command in skip_calls)

    calls: list[list[str]] = []
    rank_stdout = "ranked output\n"
    cache_dir = repo_dir / "reports" / "wily-cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    (cache_dir / "stale.txt").write_text("stale\n", encoding="utf-8")

    def fake_run(command, **kwargs):
        calls.append(command)
        if command[:3] == ["git", "rev-parse", "--is-inside-work-tree"]:
            return subprocess.CompletedProcess(command, 0)
        if command[:3] == ["git", "rev-parse", "--verify"]:
            return subprocess.CompletedProcess(command, 0)
        if "rank" in command:
            return subprocess.CompletedProcess(command, 0, stdout=rank_stdout)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(module, "run", fake_run)
    assert module.main() == 0
    monkeypatch.setenv("QUALITY_ARTIFACT_DIR", str(tmp_path / "absolute-reports"))
    assert module.main() == 0
    assert not cache_dir.joinpath("stale.txt").exists()
    assert (repo_dir / "reports" / "wily-rank.txt").read_text(
        encoding="utf-8"
    ) == rank_stdout
    assert any(
        command[:3] == ["uv", "run", "wily"] and "build" in command for command in calls
    )
    assert any(
        command[:3] == ["uv", "run", "wily"] and "rank" in command for command in calls
    )

    symlink_reports_dir = repo_dir / "symlink-reports"
    symlink_reports_dir.mkdir(parents=True, exist_ok=True)
    symlink_cache_target = tmp_path / "symlink-target"
    symlink_cache_target.write_text("stale\n", encoding="utf-8")
    symlink_cache_dir = symlink_reports_dir / "wily-cache"
    symlink_cache_dir.symlink_to(symlink_cache_target)
    monkeypatch.setenv("QUALITY_ARTIFACT_DIR", str(symlink_reports_dir))
    calls.clear()
    assert module.main() == 0
    assert not symlink_cache_dir.exists()


def test_report_maintainability_trends_snapshot_fallback_records_radon_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Keep fallback maintainability evidence useful when radon cannot run."""
    module = load_script_module(monkeypatch, "report_maintainability_trends")
    report_path = tmp_path / "wily-rank.txt"

    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(
            command,
            1,
            stdout="partial output\n",
            stderr="radon failed\n",
        )

    monkeypatch.setattr(module, "run", fake_run)
    module._write_current_snapshot_report(
        root_dir=tmp_path,
        wily_report=report_path,
        wily_targets=["pulumi"],
        reason="history unavailable",
    )

    report_text = report_path.read_text(encoding="utf-8")
    assert "Radon current snapshot unavailable" in report_text
    assert "partial output" in report_text
    assert "radon failed" in report_text

    def fake_empty_failure(command, **kwargs):
        return subprocess.CompletedProcess(command, 1, stdout="", stderr="")

    empty_report_path = tmp_path / "empty-wily-rank.txt"
    monkeypatch.setattr(module, "run", fake_empty_failure)
    module._write_current_snapshot_report(
        root_dir=tmp_path,
        wily_report=empty_report_path,
        wily_targets=["pulumi"],
        reason="history unavailable",
    )

    empty_report_text = empty_report_path.read_text(encoding="utf-8")
    assert "Radon current snapshot unavailable" in empty_report_text
    assert "stdout:" not in empty_report_text
    assert "stderr:" not in empty_report_text


def test_run_mutation_tests_main_uses_configurable_paths_and_runner(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Build the coverage and mutmut commands from the configured environment."""
    module = load_script_module(monkeypatch, "run_mutation_tests")
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    coverage_file = repo_dir / ".coverage.old"
    coverage_file.write_text("stale\n", encoding="utf-8")
    coverage_config = repo_dir / ".coveragerc"
    coverage_config.write_text("[run]\nbranch = True\n", encoding="utf-8")
    (repo_dir / ".coverage-dir").mkdir()
    monkeypatch.setattr(module, "repo_root", lambda _: repo_dir)
    monkeypatch.setattr(module, "find_uv_binary", lambda: "uv")
    monkeypatch.setenv("MUTATION_PATHS", "pulumi/app,scripts")
    monkeypatch.setenv(
        "MUTATION_TEST_TARGETS",
        "tests/unit/test_environment_component.py tests/unit/test_guardrails.py",
    )
    monkeypatch.setenv("MUTATION_TESTS_DIR", "tests/unit")
    monkeypatch.setenv("MUTATION_COVERAGE_TARGETS", "tests/unit/test_guardrails.py")
    monkeypatch.setenv("MUTATION_TEST_TIME_MULTIPLIER", "4")
    monkeypatch.setenv(
        "MUTATION_RUNNER", "uv run pytest -q tests/unit/test_guardrails.py"
    )

    calls: list[list[str]] = []
    monkeypatch.setattr(
        module,
        "run",
        lambda command, **kwargs: (
            calls.append(command) or subprocess.CompletedProcess(command, 0)
        ),
    )

    assert module.main() == 0
    assert not coverage_file.exists()
    assert coverage_config.exists()
    assert calls[0] == [
        "uv",
        "run",
        "pytest",
        "-q",
        "--cov=pulumi/app",
        "--cov=scripts",
        "--cov-branch",
        "--cov-report=",
        "tests/unit/test_guardrails.py",
    ]
    assert calls[1] == [
        "uv",
        "run",
        "mutmut",
        "run",
        "--paths-to-mutate",
        "pulumi/app scripts",
        "--runner",
        "uv run pytest -q tests/unit/test_guardrails.py",
        "--tests-dir",
        "tests/unit",
        "--test-time-multiplier",
        "4",
        "--use-coverage",
    ]


def test_run_pulumi_drift_check_main_handles_skip_and_success_paths(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Validate shared-backend drift orchestration without touching real cloud state."""
    module = load_script_module(monkeypatch, "run_pulumi_drift_check")
    repo_dir = tmp_path / "repo"
    monkeypatch.setattr(module, "repo_root", lambda _: repo_dir)

    assert module.main() == 1
    assert "does not exist" in capsys.readouterr().err

    pulumi_dir = repo_dir / "pulumi"
    pulumi_dir.mkdir(parents=True)
    policy_dir = repo_dir / "policy"
    policy_dir.mkdir()
    monkeypatch.setenv("PULUMI_BACKEND_URL", "file:///workspace/.pulumi-backend")
    assert module.main() == 0
    assert "Skipping drift detection" in capsys.readouterr().out

    calls: list[list[str]] = []
    monkeypatch.setattr(
        module,
        "run",
        lambda command, **kwargs: (
            calls.append(command) or subprocess.CompletedProcess(command, 0)
        ),
    )
    monkeypatch.setenv("PULUMI_BACKEND_URL", "s3://shared-backend")
    monkeypatch.setattr(module, "discover_stacks", lambda *args: [])
    assert module.main() == 1
    assert "no Pulumi stacks configured for drift detection" in capsys.readouterr().err
    assert calls == []

    calls.clear()
    monkeypatch.setattr(module, "discover_stacks", lambda *args: ["dev"])
    assert module.main() == 0  # nosec B101
    assert calls[0][0] == sys.executable  # nosec B101
    expected_login_command = [
        "pulumi",
        "-C",
        str(pulumi_dir),
        "login",
        "--non-interactive",
    ]
    assert calls[1][:5] == expected_login_command  # nosec B101
    assert calls[2][3:6] == ["stack", "select", "dev"]  # nosec B101
    assert "--expect-no-changes" in calls[3]  # nosec B101

    calls.clear()
    relative_repo_dir = repo_dir / "nested"
    relative_repo_dir.mkdir()
    monkeypatch.setattr(module, "repo_root", lambda _: relative_repo_dir)
    (relative_repo_dir / "relative-pulumi").mkdir()
    (relative_repo_dir / "relative-policy").mkdir()
    monkeypatch.setenv("PULUMI_DIR", "relative-pulumi")
    monkeypatch.setenv("POLICY_PACK_DIR", "relative-policy")
    assert module.main() == 0  # nosec B101
    relative_login_command = [
        "pulumi",
        "-C",
        str((relative_repo_dir / "relative-pulumi").resolve()),
        "login",
        "--non-interactive",
    ]
    assert calls[1][:5] == relative_login_command  # nosec B101
    assert calls[3][-1] == str((relative_repo_dir / "relative-policy").resolve())  # nosec B101


def test_run_pulumi_preview_main_handles_empty_and_successful_runs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Validate preview orchestration and summary generation for file backends."""
    module = load_script_module(monkeypatch, "run_pulumi_preview")
    repo_dir = tmp_path / "repo"
    pulumi_dir = repo_dir / "pulumi"
    policy_dir = repo_dir / "policy"
    preview_dir = repo_dir / ".artifacts" / "pulumi-preview"
    preview_dir.mkdir(parents=True)
    pulumi_dir.mkdir()
    policy_dir.mkdir()
    (preview_dir / "stale.json").write_text("{}", encoding="utf-8")
    (preview_dir / "summary.md").write_text("old summary\n", encoding="utf-8")
    monkeypatch.setattr(module, "repo_root", lambda _: repo_dir)
    monkeypatch.delenv("PULUMI_BACKEND_URL", raising=False)
    monkeypatch.setenv(
        "PULUMI_SECRETS_PROVIDER",
        "awskms://alias/bootstrap-preview?region=eu-central-1",
    )

    precheck_calls: list[list[str]] = []
    monkeypatch.setattr(
        module,
        "run",
        lambda command, **kwargs: (
            precheck_calls.append(command)
            or subprocess.CompletedProcess(command, 0, stdout="")
        ),
    )
    monkeypatch.setattr(module, "discover_stacks", lambda *args: [])
    assert module.main() == 1
    assert "no Pulumi stack configs found" in capsys.readouterr().err

    run_calls: list[tuple[list[str], dict[str, str], object | None]] = []

    def fake_run(command, **kwargs):
        env = kwargs.get("env", {})
        stdout = kwargs.get("stdout")
        run_calls.append((command, env, stdout))
        if command[0] == "pulumi" and command[3:6] == ["stack", "select", "dev"]:
            return subprocess.CompletedProcess(command, 1, stderr="missing stack\n")
        if command[0] == "pulumi" and command[3:6] == ["stack", "select", "qa/staging"]:
            return subprocess.CompletedProcess(command, 1, stderr="missing stack\n")
        if command[0] == "pulumi" and "preview" in command and stdout is not None:
            stdout.write('{"changeSummary": {"create": 1}, "steps": []}')
            stdout.flush()
            return subprocess.CompletedProcess(command, 0)
        if command[:3] == ["uv", "--project", str(repo_dir)]:
            preview_path = Path(command[-1])
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=f"### Pulumi Preview: {preview_path.stem}\n\n",
            )
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(module, "discover_stacks", lambda *args: ["dev", "qa/staging"])
    monkeypatch.setattr(module, "run", fake_run)
    assert module.main() == 0

    dev_stem = module._safe_preview_artifact_stem("dev")
    staging_stem = module._safe_preview_artifact_stem("qa/staging")
    output = capsys.readouterr().out
    assert f"Pulumi Preview: {dev_stem}" in output
    assert f"Pulumi Preview: {staging_stem}" in output
    assert not (preview_dir / "stale.json").exists()
    assert (preview_dir / f"{dev_stem}.json").is_file()
    assert (preview_dir / f"{staging_stem}.json").is_file()
    assert (repo_dir / ".pulumi-backend").is_dir()
    backend_url = (repo_dir / ".pulumi-backend").resolve().as_uri()
    assert any(
        env.get("PULUMI_BACKEND_URL") == backend_url
        and env.get("PULUMI_SECRETS_PROVIDER")
        == "awskms://alias/bootstrap-preview?region=eu-central-1"
        for _, env, _ in run_calls
    )
    assert any(
        len(command) > 1 and "prepare_policy_pack.py" in str(command[1])
        for command, _, _ in run_calls
    )
    login_called = any(
        command[:5] == ["pulumi", "-C", str(pulumi_dir), "login", "--non-interactive"]
        for command, _, _ in run_calls
    )
    assert login_called  # nosec B101
    initialized_dev = any(
        command[3:10]
        == [
            "stack",
            "init",
            "dev",
            "--non-interactive",
            "--secrets-provider",
            "awskms://alias/bootstrap-preview?region=eu-central-1",
        ]
        for command, _, _ in run_calls
    )
    assert initialized_dev  # nosec B101


def test_run_pulumi_preview_artifact_stems_add_a_hash_to_avoid_collisions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Different raw stack names must not collapse into the same artifact stem."""
    module = load_script_module(monkeypatch, "run_pulumi_preview")

    slash_stack = module._safe_preview_artifact_stem("org/prod")
    underscore_stack = module._safe_preview_artifact_stem("org_prod")

    assert slash_stack.startswith("org_prod-")
    assert underscore_stack.startswith("org_prod-")
    assert slash_stack != underscore_stack


def test_run_pulumi_command_builds_expected_pulumi_invocations(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Keep the generic Pulumi command helper explicit and argument-safe."""
    module = load_script_module(monkeypatch, "run_pulumi_command")
    pulumi_dir = tmp_path / "pulumi"
    policy_dir = tmp_path / "policy"
    plan_path = tmp_path / "plan"
    context = module.CommandContext(
        root_dir=tmp_path,
        env={},
        pulumi_dir=pulumi_dir,
        policy_pack_dir=policy_dir,
        plan_dir=tmp_path / "plans",
        preview_artifact_dir=tmp_path / "previews",
        backend_url="file:///tmp/backend",
        secrets_provider="awskms://alias/example?region=eu-central-1",
    )

    configured_stacks = module._configured_stack_names(
        "preview", pulumi_dir, {"PULUMI_STACK": "test"}
    )
    assert configured_stacks == ["test"]  # nosec B101
    drift_stacks = module._configured_stack_names(
        "drift", pulumi_dir, {"PULUMI_DRIFT_STACKS": "prod"}
    )
    assert drift_stacks == ["prod"]  # nosec B101
    assert module._validate_secrets_provider("not-kms") == 1  # nosec B101
    assert module._validate_secrets_provider("") == 1  # nosec B101
    assert (  # nosec B101
        module._validate_secrets_provider("awskms://alias/example") is None
    )
    assert module._uses_file_backend("file:///tmp/backend") is True  # nosec B101
    assert module._uses_file_backend("s3://bucket/state") is False  # nosec B101

    expected_preview_command = [
        "pulumi",
        "-C",
        str(pulumi_dir),
        "preview",
        "--stack",
        "test",
        "--non-interactive",
        "--policy-pack",
        str(policy_dir),
    ]
    preview_command = module._pulumi_command(
        context, module.StackCommand("preview", "test")
    )
    assert preview_command == expected_preview_command  # nosec B101
    assert "--save-plan" in module._pulumi_command(  # nosec B101
        context, module.StackCommand("plan", "test", plan_path=plan_path)
    )
    assert "--plan" in module._pulumi_command(  # nosec B101
        context, module.StackCommand("up-plan", "test", plan_path=plan_path)
    )
    drift_command = module._pulumi_command(
        context, module.StackCommand("drift", "test")
    )
    up_command = module._pulumi_command(context, module.StackCommand("up", "test"))
    refresh_command = module._pulumi_command(
        context, module.StackCommand("refresh", "test")
    )
    destroy_command = module._pulumi_command(
        context, module.StackCommand("destroy", "test")
    )
    assert "--yes" in up_command  # nosec B101
    assert "--yes" in refresh_command  # nosec B101
    assert "--expect-no-changes" in drift_command  # nosec B101
    assert "--yes" in destroy_command  # nosec B101

    with pytest.raises(ValueError, match="plan command requires"):
        module._pulumi_command(context, module.StackCommand("plan", "test"))
    with pytest.raises(ValueError, match="up-plan command requires"):
        module._pulumi_command(context, module.StackCommand("up-plan", "test"))
    with pytest.raises(ValueError, match="unsupported"):
        module._pulumi_command(context, module.StackCommand("unknown", "test"))


def test_run_pulumi_command_prefers_configured_stack_lists(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Multi-stack commands should not be masked by Make's default PULUMI_STACK."""
    module = load_script_module(monkeypatch, "run_pulumi_command")
    pulumi_dir = tmp_path / "pulumi"
    pulumi_dir.mkdir()

    preview_stacks = module._configured_stack_names(
        "preview",
        pulumi_dir,
        {"PULUMI_STACK": "default", "PULUMI_PREVIEW_STACKS": "test prod/eu"},
    )
    drift_stacks = module._configured_stack_names(
        "drift",
        pulumi_dir,
        {"PULUMI_STACK": "default", "PULUMI_DRIFT_STACKS": "prod"},
    )
    up_plan_stacks = module._configured_stack_names(
        "up-plan",
        pulumi_dir,
        {"PULUMI_STACK": "default", "PULUMI_PREVIEW_STACKS": "test prod/eu"},
    )

    assert preview_stacks == ["test", "prod/eu"]  # nosec B101
    assert drift_stacks == ["prod"]  # nosec B101
    assert up_plan_stacks == ["test", "prod/eu"]  # nosec B101


def test_run_pulumi_command_safe_artifact_stem_handles_empty_sanitized_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Artifact names should still be stable when no stack characters are safe."""
    module = load_script_module(monkeypatch, "run_pulumi_command")

    stem = module._safe_artifact_stem("")

    assert stem.startswith("stack-")  # nosec B101
    assert len(stem) == len("stack-") + 8  # nosec B101


def test_collect_well_architected_evidence_success_path(  # noqa: C901
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Metadata evidence collector should score proven controls without secrets."""
    module = load_script_module(monkeypatch, "collect_well_architected_evidence")
    reviewed_at = module.dt.datetime.now(module.dt.timezone.utc).isoformat()
    restore_evidence = tmp_path / "restore-drill.json"
    restore_evidence.write_text(
        json.dumps(
            {
                "workload": "bootstrap-infrastructure",
                "environment": "test",
                "completedAt": "2026-04-27T10:00:00Z",
                "sourceRecoveryPointArn": (
                    "arn:aws:backup:us-east-1:123456789012:recovery-point:test"
                ),
                "targetRestoreLocation": "s3://awsbackup-restore-test-bootstrap-123456789012-drill",
                "validationResult": "passed",
                "cleanupConfirmed": True,
            }
        ),
        encoding="utf-8",
    )
    question_matrix_evidence = tmp_path / "question-matrix.json"
    question_matrix_evidence.write_text(
        json.dumps(
            {
                "workload": "bootstrap-infrastructure",
                "owner": "platform",
                "reviewedAt": reviewed_at,
                "questionCount": 57,
                "unresolvedQuestionCount": 0,
                "unresolvedQuestionIds": [],
                "questionScoreAverages": {
                    pillar: 5.0
                    for pillar in module.EXPECTED_WELL_ARCHITECTED_QUESTION_COUNTS
                },
                "pillarUnresolvedQuestionCounts": {
                    pillar: 0
                    for pillar in module.EXPECTED_WELL_ARCHITECTED_QUESTION_COUNTS
                },
                "questionScores": [
                    {
                        "id": question_id,
                        "pillar": (
                            module.EXPECTED_WELL_ARCHITECTED_QUESTION_PILLAR_BY_ID[
                                question_id
                            ]
                        ),
                        "score": 5,
                        "status": "passed",
                    }
                    for question_id in module.EXPECTED_WELL_ARCHITECTED_QUESTION_IDS
                ],
                "frameworkSourceVerification": {
                    "checkedAt": reviewed_at,
                    "source": (
                        "AWS Well-Architected Framework latest public documentation"
                    ),
                    "questionCounts": module.EXPECTED_WELL_ARCHITECTED_QUESTION_COUNTS,
                    "sourceUrls": [
                        "https://docs.aws.amazon.com/wellarchitected/latest/framework/toc-contents.json",
                        "https://docs.aws.amazon.com/wellarchitected/latest/framework/ops-01.html",
                    ],
                },
                "evidenceLocation": (
                    "specs/issue-17-well-architected-5-of-5/question-matrix.md"
                ),
            }
        ),
        encoding="utf-8",
    )
    external_control_evidence = tmp_path / "external-controls.json"
    external_control_evidence.write_text(
        json.dumps(
            {
                "workload": "bootstrap-infrastructure",
                "owner": "platform",
                "reviewedAt": reviewed_at,
                "controlCount": 8,
                "unresolvedControlCount": 0,
                "unresolvedControlIds": [],
                "controls": [
                    {
                        "id": "alert_route",
                        "status": "passed",
                        "evidence": ["SNS route verified."],
                    },
                    {
                        "id": "backup_restore",
                        "status": "passed",
                        "evidence": ["Restore drill verified."],
                    },
                    {
                        "id": "branch_protection",
                        "status": "passed",
                        "evidence": ["Required checks verified."],
                    },
                    {
                        "id": "finops",
                        "status": "passed",
                        "evidence": ["Budget and anomaly route verified."],
                    },
                    {
                        "id": "production_approval",
                        "status": "passed",
                        "evidence": ["Protected prod environment verified."],
                    },
                    {
                        "id": "quota_headroom",
                        "status": "passed",
                        "evidence": ["Quota headroom verified."],
                    },
                    {
                        "id": "security_account_controls",
                        "status": "passed",
                        "evidence": ["Security-owner attestation verified."],
                    },
                    {
                        "id": "sustainability_governance",
                        "status": "passed",
                        "evidence": ["Sustainability review verified."],
                    },
                ],
                "evidenceLocation": "internal-control-ledger",
                "fallbackPlan": "Block final score claims until evidence is refreshed.",
            }
        ),
        encoding="utf-8",
    )

    def runner(command, **_kwargs):  # noqa: C901
        command_text = " ".join(command)
        payload: object
        if command[:4] == ["git", "-C", str(PROJECT_ROOT), "rev-parse"]:
            return subprocess.CompletedProcess(command, 0, "abc123\n", "")
        if command[:4] == ["git", "-C", str(PROJECT_ROOT), "status"]:
            return subprocess.CompletedProcess(command, 0, "", "")
        if command[:3] == ["gh", "pr", "view"]:
            payload = {
                "mergeStateStatus": "CLEAN",
                "reviewDecision": "APPROVED",
                "headRefOid": "abc123",
                "headRefName": "feature",
                "statusCheckRollup": [
                    {
                        "__typename": "CheckRun",
                        "name": "Unit",
                        "status": "COMPLETED",
                        "conclusion": "SUCCESS",
                    },
                    {
                        "__typename": "CheckRun",
                        "name": "Preview (Unprivileged)",
                        "status": "COMPLETED",
                        "conclusion": "SKIPPED",
                    },
                    {
                        "__typename": "CheckRun",
                        "name": "Evidence (Unprivileged)",
                        "status": "COMPLETED",
                        "conclusion": "SKIPPED",
                    },
                    {
                        "__typename": "StatusContext",
                        "context": "qlty check",
                        "state": "SUCCESS",
                    },
                ],
            }
        elif command[:3] == ["gh", "api", "graphql"]:
            payload = {
                "data": {
                    "repository": {
                        "pullRequest": {
                            "reviewThreads": {
                                "nodes": [{"isResolved": True}, {"isResolved": True}]
                            }
                        }
                    }
                }
            }
        elif command[:2] == ["gh", "api"] and "/dependabot/alerts?" in command[-1]:
            payload = []
        elif command[:2] == ["gh", "api"] and command[-1].endswith(
            "/environments/prod"
        ):
            payload = {
                "name": "prod",
                "protection_rules": [
                    {
                        "type": "required_reviewers",
                        "prevent_self_review": True,
                        "reviewers": [
                            {
                                "type": "User",
                                "reviewer": {"login": "Kravalg"},
                            }
                        ],
                    }
                ],
                "deployment_branch_policy": {
                    "protected_branches": True,
                    "custom_branch_policies": False,
                },
            }
        elif command[:2] == ["gh", "api"]:
            payload = {
                "required_status_checks": {"contexts": ["Unit"]},
                "required_pull_request_reviews": {"required_approving_review_count": 1},
                "enforce_admins": {"enabled": True},
            }
        elif command[:3] == ["aws", "sts", "get-caller-identity"]:
            payload = {"Account": "123456789012", "Arn": "arn:aws:iam::123:user/test"}
        elif command[:3] == ["aws", "iam", "get-account-summary"]:
            payload = {
                "AccountAccessKeysPresent": 0,
                "AccountMFAEnabled": 1,
                "MFADevices": 1,
                "MFADevicesInUse": 1,
                "Users": 1,
            }
        elif command[:3] == ["aws", "iam", "list-users"]:
            payload = ["automation"]
        elif command[:3] == ["aws", "iam", "list-access-keys"]:
            payload = []
        elif command[:3] == ["aws", "budgets", "describe-budgets"]:
            payload = 1
        elif command[:3] == ["aws", "ce", "get-anomaly-monitors"]:
            payload = 1
        elif command[:3] == ["aws", "sns", "get-topic-attributes"]:
            payload = "arn:aws:kms:us-east-1:123456789012:key/topic"
        elif command[:3] == ["aws", "sns", "list-subscriptions-by-topic"]:
            payload = [
                {
                    "Protocol": "sqs",
                    "Endpoint": (
                        "arn:aws:sqs:us-east-1:123456789012:"
                        "bootstrap-test-operations-alerts"
                    ),
                }
            ]
        elif command[:3] == ["aws", "sqs", "get-queue-url"]:
            payload = (
                "https://sqs.us-east-1.amazonaws.com/123456789012/"
                "bootstrap-test-operations-alerts"
            )
        elif command[:3] == ["aws", "sqs", "get-queue-attributes"]:
            payload = {
                "ApproximateNumberOfMessages": "0",
                "ApproximateNumberOfMessagesNotVisible": "0",
                "ApproximateNumberOfMessagesDelayed": "0",
                "MessageRetentionPeriod": "345600",
                "VisibilityTimeout": "30",
            }
        elif command[:3] == ["aws", "cloudtrail", "get-trail"]:
            payload = {
                "Name": "bootstrap-test-management-events",
                "IsMultiRegionTrail": True,
                "IncludeGlobalServiceEvents": True,
                "LogFileValidationEnabled": True,
                "KmsKeyId": "arn:aws:kms:us-east-1:123456789012:key/cloudtrail",
            }
        elif command[:3] == ["aws", "cloudtrail", "get-trail-status"]:
            payload = {
                "IsLogging": True,
                "LatestDeliveryTime": "2026-04-27T10:00:00Z",
            }
        elif command[:3] == ["aws", "cloudtrail", "get-event-selectors"]:
            payload = [{"IncludeManagementEvents": True, "ReadWriteType": "All"}]
        elif command[:3] == ["aws", "backup", "list-restore-jobs"]:
            payload = ["COMPLETED"]
        else:  # pragma: no cover - fail fast if the command contract changes.
            raise AssertionError(command_text)
        return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")

    args = module.build_parser().parse_args(
        [
            "--repo",
            "VilnaCRM-Org/bootstrap-infrastructure",
            "--pr",
            "22",
            "--aws-account-id",
            "123456789012",
            "--operations-topic-arn",
            "arn:aws:sns:us-east-1:123456789012:bootstrap-test-operations",
            "--operations-cloudtrail-name",
            "bootstrap-test-management-events",
            "--restore-drill-evidence",
            str(restore_evidence),
            "--question-matrix-evidence",
            str(question_matrix_evidence),
            "--external-control-evidence",
            str(external_control_evidence),
            "--required-status-check",
            "Unit",
            "--root-dir",
            str(PROJECT_ROOT),
        ]
    )
    report = module.collect_evidence(args, runner=runner)

    assert report["blockers"] == []  # nosec B101
    assert report["scoreBlockers"] == []  # nosec B101
    assert report["proxyPillarScores"] == report["pillarScores"]  # nosec B101
    assert all(score == 5 for score in report["pillarScores"].values())  # nosec B101
    assert {check["status"] for check in report["checks"]} == {"passed"}  # nosec B101
    checks = {check["name"]: check for check in report["checks"]}
    question_evidence = checks["question_matrix_evidence"]["evidence"]
    assert question_evidence["unresolvedQuestionIds"] == []  # nosec B101
    assert question_evidence["questionScoreAverages"]["Security"] == 5.0  # nosec B101
    assert (  # nosec B101
        question_evidence["pillarUnresolvedQuestionCounts"]["Security"] == 0
    )
    assert question_evidence["unresolvedQuestionEvidenceRefCount"] == 0  # nosec B101
    assert question_evidence["unresolvedQuestionEvidenceRefIds"] == []  # nosec B101
    assert (  # nosec B101
        question_evidence["frameworkSourceVerification"]["questionCounts"]
        == module.EXPECTED_WELL_ARCHITECTED_QUESTION_COUNTS
    )
    assert (  # nosec B101
        question_evidence["frameworkSourceVerification"]["sourceUrlCount"] == 2
    )
    assert (  # nosec B101
        checks["external_control_evidence"]["evidence"].get("unresolvedControlIds")
        is None
    )
    assert (  # nosec B101
        checks["aws_sns_alert_route"]["evidence"]["sqsQueue"]["queueName"]
        == "bootstrap-test-operations-alerts"
    )
    assert (  # nosec B101
        checks["aws_sns_alert_route"]["evidence"]["sqsQueue"]["messageRetentionSeconds"]
        == 345600
    )
    assert checks["aws_iam_account_access"]["evidence"] == {  # nosec B101
        "accountAccessKeysPresent": 0,
        "accountMfaEnabled": 1,
        "activeUserAccessKeyCreateDateUnknownCount": 0,
        "activeUserAccessKeyCount": 0,
        "activeUserAccessKeyLastUsedOlderThan90DaysCount": 0,
        "activeUserAccessKeyLastUsedUnknownCount": 0,
        "activeUserAccessKeyLastUsedWithin90DaysCount": 0,
        "activeUserAccessKeyNeverUsedCount": 0,
        "activeUserAccessKeyOlderThan90DaysCount": 0,
        "discoveredUserCount": 1,
        "inactiveUserAccessKeyCount": 0,
        "mfaDeviceCount": 1,
        "mfaDevicesInUse": 1,
        "otherUserAccessKeyStatusCount": 0,
        "summaryUserCount": 1,
        "unreadableAccessKeyLastUsedCount": 0,
        "unreadableAccessKeyUserCount": 0,
        "usersWithActiveAccessKeys": 0,
    }


def test_collect_well_architected_evidence_reports_failed_controls(  # noqa: C901
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Collector should keep blockers explicit when metadata is insufficient."""
    module = load_script_module(monkeypatch, "collect_well_architected_evidence")

    def runner(command, **_kwargs):  # noqa: C901
        if command[0] == "git" and command[3:5] == ["rev-parse", "HEAD"]:
            return subprocess.CompletedProcess(command, 0, "local123\n", "")
        if command[0] == "git" and command[3] == "status":
            return subprocess.CompletedProcess(command, 0, " M file.py\n", "")
        if command[:3] == ["gh", "pr", "view"]:
            payload = {
                "mergeStateStatus": "DIRTY",
                "reviewDecision": "REVIEW_REQUIRED",
                "headRefOid": "abc123",
                "headRefName": "feature",
                "statusCheckRollup": [
                    {
                        "__typename": "CheckRun",
                        "name": "Unit",
                        "status": "IN_PROGRESS",
                        "conclusion": "",
                    },
                    {
                        "__typename": "StatusContext",
                        "context": "qlty check",
                        "state": "ERROR",
                    },
                    {"__typename": "Unknown", "name": "mystery"},
                ],
            }
        elif command[:3] == ["gh", "api", "graphql"]:
            payload = {
                "data": {
                    "repository": {
                        "pullRequest": {
                            "reviewThreads": {
                                "nodes": [{"isResolved": False}, {"isResolved": True}]
                            }
                        }
                    }
                }
            }
        elif command[:2] == ["gh", "api"] and "/dependabot/alerts?" in command[-1]:
            payload = [
                {
                    "number": 8,
                    "state": "open",
                    "dependency": {
                        "package": {"name": "GitPython"},
                        "manifest_path": "uv.lock",
                    },
                    "security_advisory": {"severity": "high"},
                    "security_vulnerability": {
                        "first_patched_version": {"identifier": "3.1.50"}
                    },
                }
            ]
        elif command[:2] == ["gh", "api"] and command[-1].endswith(
            "/environments/prod"
        ):
            return subprocess.CompletedProcess(command, 1, "", "not found")
        elif command[:2] == ["gh", "api"]:
            payload = {
                "required_status_checks": {"contexts": []},
                "enforce_admins": {"enabled": False},
            }
        elif command[:3] == ["aws", "sts", "get-caller-identity"]:
            payload = {"Account": "123456789012", "Arn": "arn:aws:iam::123:user/test"}
        elif command[:3] == ["aws", "iam", "get-account-summary"]:
            payload = {
                "AccountAccessKeysPresent": 1,
                "AccountMFAEnabled": 0,
                "MFADevices": 0,
                "MFADevicesInUse": 0,
                "Users": 2,
            }
        elif command[:3] == ["aws", "iam", "list-users"]:
            payload = ["automation", "maintainer"]
        elif command[:3] == ["aws", "iam", "list-access-keys"] and (
            command[command.index("--user-name") + 1] == "maintainer"
        ):
            return subprocess.CompletedProcess(command, 1, "", "denied")
        elif command[:3] == ["aws", "iam", "list-access-keys"]:
            payload = ["Active", "Inactive", "Unexpected"]
        elif command[:3] == ["aws", "budgets", "describe-budgets"]:
            payload = 0
        elif command[:3] == ["aws", "ce", "get-anomaly-monitors"]:
            payload = 0
        elif command[:3] == ["aws", "sns", "get-topic-attributes"]:
            payload = None
        elif command[:3] == ["aws", "sns", "list-subscriptions-by-topic"]:
            payload = []
        elif command[:3] == ["aws", "cloudtrail", "get-trail"]:
            payload = {
                "Name": "bootstrap-test-management-events",
                "IsMultiRegionTrail": False,
                "IncludeGlobalServiceEvents": False,
                "LogFileValidationEnabled": False,
                "KmsKeyId": None,
            }
        elif command[:3] == ["aws", "cloudtrail", "get-trail-status"]:
            payload = {"IsLogging": False}
        elif command[:3] == ["aws", "cloudtrail", "get-event-selectors"]:
            payload = []
        elif command[:3] == ["aws", "backup", "list-restore-jobs"]:
            payload = []
        else:  # pragma: no cover - fail fast if the command contract changes.
            raise AssertionError(command)
        return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")

    args = module.build_parser().parse_args(
        [
            "--repo",
            "VilnaCRM-Org/bootstrap-infrastructure",
            "--pr",
            "22",
            "--operations-topic-arn",
            "arn:aws:sns:us-east-1:123456789012:bootstrap-test-operations",
            "--operations-cloudtrail-name",
            "bootstrap-test-management-events",
            "--root-dir",
            str(PROJECT_ROOT),
        ]
    )
    report = module.collect_evidence(args, runner=runner)
    statuses = {check["name"]: check["status"] for check in report["checks"]}

    assert statuses["github_pr_checks"] == "failed"  # nosec B101
    assert statuses["github_pr_local_state"] == "failed"  # nosec B101
    assert statuses["github_review_threads"] == "failed"  # nosec B101
    assert statuses["github_branch_protection"] == "failed"  # nosec B101
    assert statuses["github_dependabot_alerts"] == "failed"  # nosec B101
    assert statuses["github_production_environment"] == "failed"  # nosec B101
    assert statuses["aws_iam_account_access"] == "failed"  # nosec B101
    assert statuses["aws_cost_controls"] == "failed"  # nosec B101
    assert statuses["aws_sns_alert_route"] == "failed"  # nosec B101
    assert statuses["aws_cloudtrail_management_events"] == "failed"  # nosec B101
    assert statuses["aws_restore_jobs"] == "failed"  # nosec B101
    assert statuses["restore_drill_evidence"] == "missing"  # nosec B101
    assert report["scoreBlockers"]  # nosec B101
    assert max(report["pillarScores"].values()) <= 4  # nosec B101
    assert report["blockers"]  # nosec B101


def test_github_pr_checks_accepts_covered_codeql_aggregate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Aggregate CodeQL is okay when concrete CodeQL checks pass."""
    module = load_script_module(monkeypatch, "collect_well_architected_evidence")

    def runner(command, **_kwargs):
        assert command[:3] == ["gh", "pr", "view"]  # nosec B101
        payload = {
            "mergeStateStatus": "BLOCKED",
            "mergeable": "MERGEABLE",
            "reviewDecision": "APPROVED",
            "headRefOid": "abc123",
            "statusCheckRollup": [
                {
                    "__typename": "CheckRun",
                    "name": "CodeQL",
                    "status": "COMPLETED",
                    "conclusion": "NEUTRAL",
                },
                {
                    "__typename": "CheckRun",
                    "name": "CodeQL (actions)",
                    "status": "COMPLETED",
                    "conclusion": "SUCCESS",
                },
                {
                    "__typename": "CheckRun",
                    "name": "CodeQL (python)",
                    "status": "COMPLETED",
                    "conclusion": "SUCCESS",
                },
            ],
        }
        return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")

    check = module.github_pr_checks("org/repo", 1, runner=runner)

    assert check["status"] == "passed"  # nosec B101
    assert check["evidence"]["nonPassingCheckCount"] == 0  # nosec B101
    assert check["evidence"]["mergeStateStatus"] == "BLOCKED"  # nosec B101
    assert check["evidence"]["mergeable"] == "MERGEABLE"  # nosec B101


def test_github_pr_checks_requires_concrete_codeql_checks_for_aggregate_allowance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Aggregate CodeQL still fails without all concrete CodeQL checks."""
    module = load_script_module(monkeypatch, "collect_well_architected_evidence")

    def runner(command, **_kwargs):
        assert command[:3] == ["gh", "pr", "view"]  # nosec B101
        payload = {
            "mergeStateStatus": "CLEAN",
            "reviewDecision": "APPROVED",
            "headRefOid": "abc123",
            "statusCheckRollup": [
                {
                    "__typename": "CheckRun",
                    "name": "CodeQL",
                    "status": "COMPLETED",
                    "conclusion": "NEUTRAL",
                },
                {
                    "__typename": "CheckRun",
                    "name": "CodeQL (actions)",
                    "status": "COMPLETED",
                    "conclusion": "SUCCESS",
                },
            ],
        }
        return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")

    check = module.github_pr_checks("org/repo", 1, runner=runner)

    assert check["status"] == "failed"  # nosec B101
    assert check["evidence"]["nonPassingCheckCount"] == 1  # nosec B101
    assert check["blockers"] == [  # nosec B101
        "Non-passing check contexts: CodeQL."
    ]


def test_score_blockers_distinguish_failed_and_missing_gates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Score blockers should say if readiness evidence is absent or failing."""
    module = load_script_module(monkeypatch, "collect_well_architected_evidence")

    blockers = module.score_blockers(
        [
            {"name": "question_matrix_evidence", "status": "failed"},
            {"name": "external_control_evidence", "status": "missing"},
        ]
    )

    assert blockers == [  # nosec B101
        (
            "question_matrix_evidence must pass before proxy readiness scores "
            "can be treated as final Well-Architected scores."
        ),
        (
            "external_control_evidence is required before proxy readiness scores "
            "can be treated as final Well-Architected scores."
        ),
    ]


def test_collect_well_architected_evidence_unknown_and_missing_paths(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Unknown command results and missing inputs should be represented safely."""
    module = load_script_module(monkeypatch, "collect_well_architected_evidence")

    def failing_runner(command, **_kwargs):
        return subprocess.CompletedProcess(command, 1, "", "not available")

    invalid_ok, invalid_payload, invalid_error = module._run_json(  # noqa: SLF001
        ["tool"],
        runner=lambda command, **_kwargs: subprocess.CompletedProcess(
            command, 0, "not-json", ""
        ),
    )
    assert invalid_ok is False  # nosec B101
    assert invalid_payload is None  # nosec B101
    assert "invalid JSON output" in invalid_error  # nosec B101
    assert module._account_id_from_identity({"evidence": "unknown"}) == ""  # noqa: SLF001
    assert module._all_blockers([{"blockers": "unknown"}]) == []  # noqa: SLF001
    assert module._pr_head_oid([]) == ""  # noqa: SLF001
    assert module.github_pr_checks("org/repo", None)["status"] == "missing"
    assert (
        module.github_pr_local_state("org/repo", None, tmp_path)["status"] == "missing"
    )
    assert module.github_review_threads("org/repo", None)["status"] == "missing"
    assert module.aws_sns_alert_route(None)["status"] == "missing"
    assert module.aws_cloudtrail_management_events(None)["status"] == "missing"
    assert module.github_pr_checks("org/repo", 1, runner=failing_runner)["status"] == (
        "unknown"
    )
    assert (
        module.github_pr_local_state("org/repo", 1, tmp_path, runner=failing_runner)[
            "status"
        ]
        == "failed"
    )
    assert (
        module.github_review_threads("org/repo", 1, runner=failing_runner)["status"]
        == "unknown"
    )
    assert (
        module.github_branch_protection("org/repo", "main", runner=failing_runner)[
            "status"
        ]
        == "unknown"
    )
    assert (
        module.github_dependabot_alerts("org/repo", runner=failing_runner)["status"]
        == "unknown"
    )
    assert module.aws_identity(runner=failing_runner)["status"] == "unknown"
    assert module.aws_iam_account_access(runner=failing_runner)["status"] == "unknown"
    assert module.aws_cost_controls(None, runner=failing_runner)["status"] == "unknown"
    assert (
        module.aws_cost_controls("123456789012", runner=failing_runner)["status"]
        == "failed"
    )
    assert module.aws_sns_alert_route("arn:topic", runner=failing_runner)["status"] == (
        "failed"
    )
    null_subscription_result = module.aws_sns_alert_route(
        "arn:topic",
        runner=lambda command, **_kwargs: subprocess.CompletedProcess(
            command,
            0,
            json.dumps(
                {"KmsMasterKeyId": "alias/bootstrap"}
                if command[:3] == ["aws", "sns", "get-topic-attributes"]
                else None
            ),
            "",
        ),
    )
    assert null_subscription_result["status"] == "failed"  # nosec B101
    assert null_subscription_result["evidence"]["subscriptionProtocols"] == []  # nosec B101
    legacy_subscription_result = module.aws_sns_alert_route(
        "arn:topic",
        runner=lambda command, **_kwargs: subprocess.CompletedProcess(
            command,
            0,
            json.dumps(
                "alias/bootstrap"
                if command[:3] == ["aws", "sns", "get-topic-attributes"]
                else ["sqs"]
            ),
            "",
        ),
    )
    assert legacy_subscription_result["status"] == "failed"  # nosec B101
    assert "derive SQS queue name" in " ".join(  # nosec B101
        legacy_subscription_result["blockers"]
    )
    assert (
        module.aws_cloudtrail_management_events(
            "bootstrap-test-management-events", runner=failing_runner
        )["status"]
        == "failed"
    )
    assert module.aws_restore_jobs(90, runner=failing_runner)["status"] == "unknown"
    assert module.restore_drill_evidence(None)["status"] == "missing"
    assert module.restore_drill_evidence(tmp_path / "missing.json")["status"] == (
        "failed"
    )
    missing_fanout_args = module.build_parser().parse_args(
        ["--root-dir", str(tmp_path)]
    )
    (tmp_path / "pulumi").mkdir()
    low_threshold_args = module.build_parser().parse_args(
        ["--root-dir", str(PROJECT_ROOT), "--max-s3-buckets", "0"]
    )
    malformed_restore_evidence = tmp_path / "malformed-restore.json"
    malformed_restore_evidence.write_text("{", encoding="utf-8")
    assert module.restore_drill_evidence(malformed_restore_evidence)["status"] == (
        "failed"
    )
    list_restore_evidence = tmp_path / "list-restore.json"
    list_restore_evidence.write_text("[]", encoding="utf-8")
    assert module.restore_drill_evidence(list_restore_evidence)["status"] == "failed"
    invalid_restore_evidence = tmp_path / "restore.json"
    invalid_restore_evidence.write_text(
        json.dumps({"workload": "other", "cleanupConfirmed": False}),
        encoding="utf-8",
    )
    invalid_restore = module.restore_drill_evidence(invalid_restore_evidence)
    assert invalid_restore["status"] == "failed"  # nosec B101
    assert "bootstrap-infrastructure" in " ".join(invalid_restore["blockers"])  # nosec B101
    valid_restore_evidence = tmp_path / "valid-restore.json"
    valid_restore_evidence.write_text(
        json.dumps(
            {
                "workload": "bootstrap-infrastructure",
                "environment": "test",
                "completedAt": "2026-04-27T10:00:00Z",
                "sourceRecoveryPointArn": (
                    "arn:aws:backup:us-east-1:123456789012:recovery-point:test"
                ),
                "targetRestoreLocation": (
                    "s3://awsbackup-restore-test-bootstrap-123456789012-drill"
                ),
                "validationResult": "passed",
                "cleanupConfirmed": True,
            }
        ),
        encoding="utf-8",
    )
    production_owner_evidence = tmp_path / "production-dr-owner.json"
    production_owner_evidence.write_text(
        json.dumps(
            {
                "workload": "bootstrap-infrastructure",
                "environment": "prod",
                "owner": "SRE",
                "approvedBy": "prod-reviewer",
                "reviewedAt": module.dt.datetime.now(
                    module.dt.timezone.utc
                ).isoformat(),
                "expiresAt": (
                    module.dt.datetime.now(module.dt.timezone.utc)
                    + module.dt.timedelta(days=30)
                ).isoformat(),
                "rtoTarget": "4 hours",
                "rpoTarget": "24 hours",
                "escalationPath": "SRE primary, platform maintainer backup",
                "recoveryOrder": "Restore state, validate logs, resume applies",
                "communicationsPlan": "Post owner-approved status updates.",
                "latestAcceptedDrill": "2026-04-27 restore drill accepted.",
                "nextReviewDate": (
                    module.dt.datetime.now(module.dt.timezone.utc)
                    + module.dt.timedelta(days=20)
                )
                .date()
                .isoformat(),
                "evidenceRetentionLocation": "docs/production-dr-owner.md",
                "approval": "approved",
                "evidence": ["Production owner reviewed the DR target."],
                "remediationPlan": "Run the next drill before expiry.",
                "restoreDrillEvidence": {
                    "workload": "bootstrap-infrastructure",
                    "environment": "test",
                    "completedAt": "2026-04-27T10:00:00Z",
                    "targetRestoreLocation": (
                        "s3://awsbackup-restore-test-bootstrap-123456789012-drill"
                    ),
                    "validationResult": "passed",
                    "cleanupConfirmed": True,
                },
            }
        ),
        encoding="utf-8",
    )
    owner_covered_restore = module.restore_drill_evidence(
        valid_restore_evidence,
        production_dr_owner_evidence=production_owner_evidence,
    )
    assert owner_covered_restore["status"] == "passed"  # nosec B101
    owner_summary = owner_covered_restore["evidence"]["productionDrOwnerEvidence"]
    assert owner_summary["owner"] == "SRE"  # nosec B101
    assert owner_summary["approval"] == "approved"  # nosec B101
    legacy_args = module.build_parser().parse_args(
        [
            "--question-matrix-evidence-confirmed",
            "--external-control-evidence-confirmed",
        ]
    )
    assert module.question_matrix_evidence(legacy_args)["status"] == "missing"
    legacy_blockers = module.question_matrix_evidence(legacy_args)["blockers"]
    assert "boolean" in " ".join(legacy_blockers)
    malformed_structured = tmp_path / "malformed-structured.json"
    malformed_structured.write_text("{", encoding="utf-8")
    malformed_args = module.build_parser().parse_args(
        ["--question-matrix-evidence", str(malformed_structured)]
    )
    assert module.question_matrix_evidence(malformed_args)["status"] == "failed"
    invalid_question_matrix = tmp_path / "invalid-question-matrix.json"
    invalid_question_matrix.write_text(
        json.dumps(
            {
                "workload": "bootstrap-infrastructure",
                "owner": "platform",
                "reviewedAt": module.dt.datetime.now(
                    module.dt.timezone.utc
                ).isoformat(),
                "questionCount": 2,
                "unresolvedQuestionCount": 2,
                "questionScores": [
                    {
                        "id": "OPS1",
                        "status": "resolved",
                        "score": 6,
                        "evidenceRefs": [],
                    },
                    "not-an-object",
                ],
                "frameworkSourceVerification": {
                    "checkedAt": module.dt.datetime.now(
                        module.dt.timezone.utc
                    ).isoformat(),
                    "source": (
                        "AWS Well-Architected Framework latest public documentation"
                    ),
                    "questionCounts": module.EXPECTED_WELL_ARCHITECTED_QUESTION_COUNTS,
                    "sourceUrls": [
                        "https://docs.aws.amazon.com/wellarchitected/latest/framework/ops-01.html"
                    ],
                },
                "evidenceLocation": "ledger",
            }
        ),
        encoding="utf-8",
    )
    invalid_question_args = module.build_parser().parse_args(
        ["--question-matrix-evidence", str(invalid_question_matrix)]
    )
    invalid_question_check = module.question_matrix_evidence(invalid_question_args)
    invalid_question_text = " ".join(invalid_question_check["blockers"])
    assert invalid_question_check["status"] == "failed"  # nosec B101
    assert "entries must be objects" in invalid_question_text  # nosec B101
    assert "questionCount" in invalid_question_text  # nosec B101
    assert "unresolvedQuestionCount" in invalid_question_text  # nosec B101
    assert "integers from 1 to 5" in invalid_question_text  # nosec B101
    assert "statuses must be one of" in invalid_question_text  # nosec B101
    assert "evidenceRefs" in invalid_question_text  # nosec B101
    missing_structured_args = module.build_parser().parse_args(
        ["--external-control-evidence", str(tmp_path / "missing-structured.json")]
    )
    assert module.external_control_evidence(missing_structured_args)["status"] == (
        "failed"
    )
    list_structured = tmp_path / "list-structured.json"
    list_structured.write_text("[]", encoding="utf-8")
    list_args = module.build_parser().parse_args(
        ["--external-control-evidence", str(list_structured)]
    )
    assert module.external_control_evidence(list_args)["status"] == "failed"
    incomplete_external = tmp_path / "incomplete-external.json"
    incomplete_external.write_text(
        json.dumps(
            {
                "workload": "bootstrap-infrastructure",
                "owner": "platform",
                "reviewedAt": module.dt.datetime.now(
                    module.dt.timezone.utc
                ).isoformat(),
                "controlCount": 8,
                "unresolvedControlCount": 0,
                "controls": [{"id": "alert_route", "status": "passed"}],
                "evidenceLocation": "ledger",
                "fallbackPlan": "block",
            }
        ),
        encoding="utf-8",
    )
    incomplete_external_args = module.build_parser().parse_args(
        ["--external-control-evidence", str(incomplete_external)]
    )
    incomplete_external_check = module.external_control_evidence(
        incomplete_external_args
    )
    assert incomplete_external_check["status"] == "failed"  # nosec B101
    assert "branch_protection" in " ".join(  # nosec B101
        incomplete_external_check["blockers"]
    )
    assert "non-empty evidence" in " ".join(  # nosec B101
        incomplete_external_check["blockers"]
    )
    strict_external_blockers = module._structured_evidence_control_blockers(  # noqa: SLF001
        {
            "controlCount": 2,
            "unresolvedControlCount": 0,
            "controls": [
                {"id": "branch_protection", "status": "passed", "evidence": []},
                {"id": "alert_route", "status": "blocked"},
                {
                    "id": "backup_restore",
                    "status": "unresolved",
                    "unresolvedReason": "Restore owner evidence is pending.",
                },
            ],
        },
        ("branch_protection", "alert_route", "backup_restore"),
    )
    strict_external_text = " ".join(strict_external_blockers)
    assert "controlCount" in strict_external_text  # nosec B101
    assert "unresolvedControlCount" in strict_external_text  # nosec B101
    assert "statuses must be one of" in strict_external_text  # nosec B101
    assert "non-empty evidence" in strict_external_text  # nosec B101
    assert "unresolvedReason" in strict_external_text  # nosec B101
    external_id_blockers = module._structured_evidence_control_blockers(  # noqa: SLF001
        {
            "controlCount": 5,
            "unresolvedControlCount": 0,
            "controls": [
                {
                    "id": "branch_protection",
                    "status": "passed",
                    "evidence": ["Ruleset verified."],
                },
                {
                    "id": "alert_route",
                    "status": "passed",
                    "evidence": ["Alert route verified."],
                },
                {
                    "id": "alert_route",
                    "status": "passed",
                    "evidence": ["Duplicate row."],
                },
                {
                    "id": "unexpected",
                    "status": "passed",
                    "evidence": ["Unexpected row."],
                },
                {"status": "passed", "evidence": ["Missing ID."]},
            ],
        },
        ("branch_protection", "alert_route"),
    )
    external_id_text = " ".join(external_id_blockers)
    assert "non-empty string IDs" in external_id_text  # nosec B101
    assert "duplicate controls: alert_route" in external_id_text  # nosec B101
    assert "unknown controls: unexpected" in external_id_text  # nosec B101
    non_count_external_blockers = module._structured_evidence_control_blockers(  # noqa: SLF001
        {
            "controlCount": "2",
            "unresolvedControlCount": "1",
            "controls": [
                {
                    "id": "branch_protection",
                    "status": "passed",
                    "evidence": ["Ruleset verified."],
                },
                {
                    "id": "alert_route",
                    "status": "unresolved",
                    "evidence": ["Monthly observation owner is assigned."],
                    "unresolvedReason": "Monthly observation history is pending.",
                },
            ],
        },
        ("branch_protection", "alert_route"),
    )
    assert non_count_external_blockers == []  # nosec B101
    external_summary_blockers = module._structured_evidence_control_blockers(  # noqa: SLF001
        {
            "controlCount": 2,
            "unresolvedControlCount": 1,
            "unresolvedControlIds": ["branch_protection"],
            "controls": [
                {
                    "id": "branch_protection",
                    "status": "passed",
                    "evidence": ["Ruleset verified."],
                },
                {
                    "id": "alert_route",
                    "status": "unresolved",
                    "evidence": ["Monthly observation owner is assigned."],
                    "unresolvedReason": "Monthly observation history is pending.",
                },
            ],
        },
        ("branch_protection", "alert_route"),
    )
    external_summary_text = " ".join(external_summary_blockers)
    assert "unresolvedControlIds" in external_summary_text  # nosec B101
    assert "alert_route" in external_summary_text  # nosec B101
    assert "list of strings" in " ".join(  # noqa: SLF001  # nosec B101
        module._external_control_unresolved_id_blockers(
            {"unresolvedControlIds": [1]},
            [],
        )
    )
    assert (  # noqa: SLF001  # nosec B101
        module._external_control_unresolved_id_blockers(
            {"unresolvedControlIds": []},
            [],
        )
        == []
    )
    valid_source_blockers = module._question_matrix_source_verification_blockers(  # noqa: SLF001
        {
            "frameworkSourceVerification": {
                "checkedAt": module.dt.datetime.now(module.dt.timezone.utc).isoformat(),
                "source": "AWS Well-Architected Framework latest public documentation",
                "questionCounts": module.EXPECTED_WELL_ARCHITECTED_QUESTION_COUNTS,
                "sourceUrls": [
                    "https://docs.aws.amazon.com/wellarchitected/latest/framework/toc-contents.json",
                    "https://docs.aws.amazon.com/wellarchitected/latest/framework/ops-01.html",
                ],
            }
        }
    )
    assert valid_source_blockers == []  # nosec B101
    invalid_source_blockers = module._question_matrix_source_verification_blockers(  # noqa: SLF001
        {
            "frameworkSourceVerification": {
                "checkedAt": "2025-01-01",
                "source": "",
                "questionCounts": {"Security": 11},
                "sourceUrls": [],
            }
        }
    )
    invalid_source_text = " ".join(invalid_source_blockers)
    assert "older than" in invalid_source_text  # nosec B101
    assert "source is required" in invalid_source_text  # nosec B101
    assert "questionCounts" in invalid_source_text  # nosec B101
    assert "sourceUrls" in invalid_source_text  # nosec B101
    missing_toc_blockers = module._question_matrix_source_verification_blockers(  # noqa: SLF001
        {
            "frameworkSourceVerification": {
                "checkedAt": module.dt.datetime.now(module.dt.timezone.utc).isoformat(),
                "source": "AWS Well-Architected Framework latest public documentation",
                "questionCounts": module.EXPECTED_WELL_ARCHITECTED_QUESTION_COUNTS,
                "sourceUrls": [
                    "https://docs.aws.amazon.com/wellarchitected/latest/framework/ops-01.html"
                ],
            }
        }
    )
    assert module.AWS_WELL_ARCHITECTED_TOC_URL in " ".join(  # nosec B101
        missing_toc_blockers
    )
    assert module._framework_source_verification_summary({}) == {}  # noqa: SLF001
    assert (  # noqa: SLF001  # nosec B101
        module._framework_source_verification_summary(
            {
                "frameworkSourceVerification": {
                    "checkedAt": 123,
                    "source": ["unexpected"],
                    "questionCounts": {"Security": True},
                    "sourceUrls": ["https://docs.aws.amazon.com/", 1],
                }
            }
        )
        == {}
    )
    stale_structured = tmp_path / "stale-structured.json"
    stale_structured.write_text(
        json.dumps(
            {
                "workload": "bootstrap-infrastructure",
                "owner": "platform",
                "reviewedAt": "2025-01-01",
                "questionCount": 1,
                "unresolvedQuestionCount": 2,
                "questionScores": [
                    {
                        "id": "OPS1",
                        "status": "unresolved",
                        "score": 3,
                        "evidenceRefs": ["issue:#26"],
                    }
                ],
                "evidenceLocation": "spec",
            }
        ),
        encoding="utf-8",
    )
    stale_args = module.build_parser().parse_args(
        ["--question-matrix-evidence", str(stale_structured)]
    )
    stale_question_matrix = module.question_matrix_evidence(stale_args)
    assert stale_question_matrix["status"] == "failed"  # nosec B101
    assert "older than" in " ".join(stale_question_matrix["blockers"])  # nosec B101
    future_blockers = module._structured_evidence_freshness_blockers(  # noqa: SLF001
        {
            "reviewedAt": (
                module.dt.datetime.now(module.dt.timezone.utc)
                + module.dt.timedelta(days=1)
            ).isoformat()
        },
        "Future evidence",
    )
    assert "future" in future_blockers[0]  # nosec B101
    invalid_blockers = module._structured_evidence_freshness_blockers(  # noqa: SLF001
        {"reviewedAt": 123},
        "Invalid evidence",
    )
    assert "ISO-8601" in invalid_blockers[0]  # nosec B101
    unresolved_payload = module._structured_evidence_payload(  # noqa: SLF001
        {
            "workload": "bootstrap-infrastructure",
            "owner": "platform",
            "reviewedAt": "2026-04-27T10:00:00Z",
            "controlCount": 2,
            "unresolvedControlCount": 1,
            "controls": [
                {"id": "alert_route", "status": "passed"},
                {"id": "branch_protection", "status": "unresolved"},
            ],
            "evidenceLocation": "ledger",
        },
        "controlCount",
        "unresolvedControlCount",
    )
    assert unresolved_payload["unresolvedControlIds"] == [  # nosec B101
        "branch_protection"
    ]
    assert module._string_list(["OPS1", 2]) is None  # noqa: SLF001  # nosec B101
    assert (  # noqa: SLF001  # nosec B101
        module._string_key_number_map({"Security": True}) is None
    )
    assert module._string_key_number_map({"Security": "5"}) is None  # noqa: SLF001  # nosec B101
    assert module._string_key_int_map({"Security": False}) is None  # noqa: SLF001  # nosec B101
    assert module._string_key_int_map({"Security": 5.0}) is None  # noqa: SLF001  # nosec B101
    assert module._unresolved_question_evidence_ref_ids({}) is None  # noqa: SLF001  # nosec B101
    assert module._question_matrix_score_blockers(  # noqa: SLF001  # nosec B101
        {"questionScores": "missing"}
    ) == ["Question-matrix evidence questionScores must be a list."]
    assert module._valid_structured_status("passed")  # noqa: SLF001  # nosec B101
    assert not module._valid_structured_status("passed ")  # noqa: SLF001  # nosec B101
    assert not module._valid_structured_status("passsed")  # noqa: SLF001  # nosec B101
    assert module._allowed_status_text() == "passed, unresolved"  # noqa: SLF001  # nosec B101
    assert "OPS1, OPS2" in " ".join(  # noqa: SLF001  # nosec B101
        module._question_matrix_score_status_blockers(
            [
                {"id": "OPS1", "score": 4, "status": "passed"},
                {"id": "OPS2", "score": 5, "status": "unresolved"},
            ]
        )
    )
    assert (  # noqa: SLF001  # nosec B101
        module._question_matrix_score_count_blockers(
            {"questionCount": "1", "unresolvedQuestionCount": "0"},
            [],
        )
        == []
    )
    assert module._parse_reviewed_at("not-a-date") is None  # noqa: SLF001
    assert (  # nosec B101
        module._parse_reviewed_at("2026-04-27T10:00:00").tzinfo  # noqa: SLF001
        is not None
    )
    assert (
        module.repository_fanout_evidence(tmp_path, missing_fanout_args)["status"]
        == "missing"
    )
    evidence_catalog_paths = module._evidence_repository_catalog_paths(PROJECT_ROOT)  # noqa: SLF001
    assert [path.name for path in evidence_catalog_paths] == [  # nosec B101
        "repositories.bootstrap.json"
    ]
    assert (
        module.repository_fanout_evidence(
            PROJECT_ROOT,
            module.build_parser().parse_args(["--root-dir", str(PROJECT_ROOT)]),
        )["status"]
        == "passed"
    )
    assert (
        module.repository_fanout_evidence(PROJECT_ROOT, low_threshold_args)["status"]
        == "failed"
    )
    monkeypatch.setattr(
        module,
        "_evidence_repository_catalog_paths",
        lambda root_dir: [root_dir / "pulumi" / "repositories.example.json"],
    )
    monkeypatch.setattr(
        module,
        "catalog_fanout_report",
        lambda *_args: (_ for _ in ()).throw(ValueError("invalid catalog")),
    )
    invalid_fanout = module.repository_fanout_evidence(
        PROJECT_ROOT,
        module.build_parser().parse_args(["--root-dir", str(PROJECT_ROOT)]),
    )
    assert invalid_fanout["status"] == "failed"  # nosec B101
    assert invalid_fanout["evidence"]["reports"][0]["error"] == "invalid catalog"  # nosec B101


def test_collect_well_architected_evidence_rejects_question_id_gaps(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Require exact Well-Architected question IDs in score evidence."""
    module = load_script_module(monkeypatch, "collect_well_architected_evidence")
    evidence_payload = _well_architected_question_evidence()
    now = module.dt.datetime.now(module.dt.timezone.utc).isoformat()
    evidence_payload["reviewedAt"] = now
    source_verification = evidence_payload["frameworkSourceVerification"]
    assert isinstance(source_verification, dict)  # nosec B101
    source_verification["checkedAt"] = now
    scores = evidence_payload["questionScores"]
    assert isinstance(scores, list)  # nosec B101
    for score in scores:
        assert isinstance(score, dict)  # nosec B101
        score["status"] = "passed"
        score["score"] = 5
        score.pop("evidenceRefs", None)
    scores.pop()
    scores.append(dict(scores[0]))
    unknown_score = dict(scores[1])
    unknown_score["id"] = "WA99"
    scores.append(unknown_score)
    evidence_payload["questionCount"] = len(scores)
    evidence_payload["unresolvedQuestionCount"] = 0
    evidence = tmp_path / "question-matrix-evidence.json"
    evidence.write_text(json.dumps(evidence_payload), encoding="utf-8")

    args = module.build_parser().parse_args(
        ["--question-matrix-evidence", str(evidence)]
    )
    check = module.question_matrix_evidence(args)
    blockers = " ".join(check["blockers"])

    assert check["status"] == "failed"  # nosec B101
    assert "duplicate question IDs: OPS1" in blockers  # nosec B101
    assert "missing question IDs: SUS6" in blockers  # nosec B101
    assert "unknown question IDs: WA99" in blockers  # nosec B101


def test_collect_well_architected_evidence_rejects_question_pillar_drift(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Question score row pillars must agree with AWS question IDs."""
    module = load_script_module(monkeypatch, "collect_well_architected_evidence")
    evidence_payload = _well_architected_question_evidence()
    now = module.dt.datetime.now(module.dt.timezone.utc).isoformat()
    evidence_payload["reviewedAt"] = now
    source_verification = evidence_payload["frameworkSourceVerification"]
    assert isinstance(source_verification, dict)  # nosec B101
    source_verification["checkedAt"] = now
    scores = evidence_payload["questionScores"]
    assert isinstance(scores, list)  # nosec B101
    for score in scores:
        assert isinstance(score, dict)  # nosec B101
        score["status"] = "passed"
        score["score"] = 5
        score.pop("evidenceRefs", None)
    scores[0]["pillar"] = "Security"
    evidence = tmp_path / "question-matrix-evidence.json"
    evidence.write_text(json.dumps(evidence_payload), encoding="utf-8")

    args = module.build_parser().parse_args(
        ["--question-matrix-evidence", str(evidence)]
    )
    check = module.question_matrix_evidence(args)
    blockers = " ".join(check["blockers"])

    assert check["status"] == "failed"  # nosec B101
    assert "pillar values" in blockers  # nosec B101
    assert "OPS1" in blockers  # nosec B101


def test_collect_well_architected_evidence_rejects_score_summary_drift(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Question score summaries must agree with the individual score rows."""
    module = load_script_module(monkeypatch, "collect_well_architected_evidence")
    evidence_payload = _well_architected_question_evidence()
    now = module.dt.datetime.now(module.dt.timezone.utc).isoformat()
    evidence_payload["reviewedAt"] = now
    evidence_payload["unresolvedQuestionCount"] = 1
    evidence_payload["unresolvedQuestionIds"] = ["SEC1"]
    evidence_payload["pillarUnresolvedQuestionCounts"] = {
        pillar: 0 for pillar in module.EXPECTED_WELL_ARCHITECTED_QUESTION_COUNTS
    }
    evidence_payload["questionScoreAverages"] = {
        pillar: 5.0 for pillar in module.EXPECTED_WELL_ARCHITECTED_QUESTION_COUNTS
    }
    source_verification = evidence_payload["frameworkSourceVerification"]
    assert isinstance(source_verification, dict)  # nosec B101
    source_verification["checkedAt"] = now
    scores = evidence_payload["questionScores"]
    assert isinstance(scores, list)  # nosec B101
    assert isinstance(scores[0], dict)  # nosec B101
    scores[0]["score"] = 3
    evidence = tmp_path / "question-matrix-evidence.json"
    evidence.write_text(json.dumps(evidence_payload), encoding="utf-8")

    args = module.build_parser().parse_args(
        ["--question-matrix-evidence", str(evidence)]
    )
    check = module.question_matrix_evidence(args)
    blockers = " ".join(check["blockers"])

    assert check["status"] == "failed"  # nosec B101
    assert "unresolvedQuestionIds" in blockers  # nosec B101
    assert "OPS1" in blockers  # nosec B101
    assert "pillarUnresolvedQuestionCounts" in blockers  # nosec B101
    assert "questionScoreAverages" in blockers  # nosec B101
    assert "list of strings" in " ".join(  # noqa: SLF001  # nosec B101
        module._question_matrix_unresolved_id_blockers(
            {"unresolvedQuestionIds": [1]},
            [],
        )
    )
    assert "integer map" in " ".join(  # noqa: SLF001  # nosec B101
        module._question_matrix_pillar_unresolved_blockers(
            {"pillarUnresolvedQuestionCounts": {"Security": "1"}},
            [],
        )
    )
    assert "numeric map" in " ".join(  # noqa: SLF001  # nosec B101
        module._question_matrix_average_blockers(
            {"questionScoreAverages": {"Security": True}},
            [],
        )
    )
    unknown_unresolved_counts = (  # noqa: SLF001
        module._expected_pillar_unresolved_question_counts(
            [{"id": "WA99", "status": "unresolved"}]
        )
    )
    assert set(unknown_unresolved_counts) == set(  # nosec B101
        module.EXPECTED_WELL_ARCHITECTED_QUESTION_COUNTS
    )
    assert all(count == 0 for count in unknown_unresolved_counts.values())  # nosec B101
    assert (  # noqa: SLF001  # nosec B101
        module._expected_pillar_question_score_averages(
            [{"id": "OPS1", "score": 6}, {"id": "WA99", "score": 5}]
        )
        == {}
    )


def test_sns_alert_route_records_sqs_queue_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SNS route evidence should include non-secret SQS queue attributes."""
    module = load_script_module(monkeypatch, "collect_well_architected_evidence")

    def runner(command, **_kwargs):
        if command[:3] == ["aws", "sns", "get-topic-attributes"]:
            payload: object = "alias/bootstrap"
        elif command[:3] == ["aws", "sns", "list-subscriptions-by-topic"]:
            payload = [
                "email",
                {"Protocol": "lambda", "Endpoint": 123},
                {"Protocol": "sqs"},
                1,
                {},
                "malformed",
                {
                    "Protocol": "sqs",
                    "Endpoint": (
                        "arn:aws:sqs:eu-central-1:123456789012:"
                        "bootstrap-test-operations-alerts"
                    ),
                },
            ]
        elif command[:3] == ["aws", "sqs", "get-queue-url"]:
            payload = (
                "https://sqs.eu-central-1.amazonaws.com/123456789012/"
                "bootstrap-test-operations-alerts"
            )
        elif command[:3] == ["aws", "sqs", "get-queue-attributes"]:
            payload = {
                "ApproximateNumberOfMessages": 2,
                "ApproximateNumberOfMessagesNotVisible": "0",
                "ApproximateNumberOfMessagesDelayed": "bad",
                "MessageRetentionPeriod": "345600",
                "VisibilityTimeout": "30",
            }
        else:  # pragma: no cover - fail fast if the command contract changes.
            raise AssertionError(command)
        return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")

    evidence = module.aws_sns_alert_route("arn:topic", runner=runner)

    assert evidence["status"] == "passed"  # nosec B101
    assert evidence["evidence"]["subscriptionCount"] == 5  # nosec B101
    assert evidence["evidence"]["subscriptionProtocols"] == [  # nosec B101
        "email",
        "lambda",
        "malformed",
        "sqs",
    ]
    queue = evidence["evidence"]["sqsQueue"]
    assert queue["queueName"] == "bootstrap-test-operations-alerts"  # nosec B101
    assert queue["visibleMessages"] == 2  # nosec B101
    assert queue["delayedMessages"] is None  # nosec B101
    assert queue["messageRetentionSeconds"] == 345600  # nosec B101


def test_sns_alert_route_accepts_observation_evidence(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Current SRE observation evidence should attach to alert-route metadata."""
    module = load_script_module(monkeypatch, "collect_well_architected_evidence")

    def runner(command, **_kwargs):
        if command[:3] == ["aws", "sns", "get-topic-attributes"]:
            payload: object = "alias/bootstrap"
        elif command[:3] == ["aws", "sns", "list-subscriptions-by-topic"]:
            payload = [
                {
                    "Protocol": "sqs",
                    "Endpoint": (
                        "arn:aws:sqs:eu-central-1:123456789012:"
                        "bootstrap-test-operations-alerts"
                    ),
                }
            ]
        elif command[:3] == ["aws", "sqs", "get-queue-url"]:
            payload = (
                "https://sqs.eu-central-1.amazonaws.com/123456789012/"
                "bootstrap-test-operations-alerts"
            )
        elif command[:3] == ["aws", "sqs", "get-queue-attributes"]:
            payload = {
                "ApproximateNumberOfMessages": "2",
                "ApproximateNumberOfMessagesNotVisible": "0",
                "ApproximateNumberOfMessagesDelayed": "0",
                "MessageRetentionPeriod": "345600",
                "VisibilityTimeout": "30",
            }
        else:  # pragma: no cover - fail fast if the command contract changes.
            raise AssertionError(command)
        return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")

    route_evidence = {
        "topicArn": "arn:topic",
        "encrypted": True,
        "subscriptionCount": 1,
        "subscriptionProtocols": ["sqs"],
        "sqsQueue": {
            "queueArn": (
                "arn:aws:sqs:eu-central-1:123456789012:bootstrap-test-operations-alerts"
            ),
            "queueName": "bootstrap-test-operations-alerts",
            "messageRetentionSeconds": 345600,
            "visibilityTimeoutSeconds": 30,
        },
    }
    observation = {
        "workload": "bootstrap-infrastructure",
        "environment": "test",
        "owner": "SRE",
        "approvedBy": "sre-reviewer",
        "reviewedAt": module.dt.datetime.now(module.dt.timezone.utc).isoformat(),
        "expiresAt": (
            module.dt.datetime.now(module.dt.timezone.utc)
            + module.dt.timedelta(days=30)
        ).isoformat(),
        "downstreamRoute": "approved queue-owner process",
        "severityExpectations": "SEV2 during business hours",
        "fallback": "Escalate to platform maintainers.",
        "decision": "accepted",
        "evidence": ["SRE reviewed the queue-owner process."],
        "remediationPlan": "Review queue consumption monthly.",
        "routeEvidence": route_evidence,
    }
    observation_path = tmp_path / "alert-route-observation.json"
    observation_path.write_text(json.dumps(observation), encoding="utf-8")

    evidence = module.aws_sns_alert_route(
        "arn:topic",
        observation_evidence=observation_path,
        runner=runner,
    )

    assert evidence["status"] == "passed"  # nosec B101
    assert evidence["blockers"] == []  # nosec B101
    summary = evidence["evidence"]["alertRouteObservation"]
    assert summary["owner"] == "SRE"  # nosec B101
    assert summary["decision"] == "accepted"  # nosec B101
    assert "approved queue-owner process" in json.dumps(evidence)  # nosec B101


def test_sns_alert_route_rejects_bad_observation_evidence(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Alert-route observation evidence must be current, exact, and approved."""
    module = load_script_module(monkeypatch, "collect_well_architected_evidence")
    route_evidence = {
        "topicArn": "arn:topic",
        "encrypted": True,
        "subscriptionCount": 1,
        "subscriptionProtocols": ["sqs"],
        "sqsQueue": {
            "queueArn": "arn:aws:sqs:eu-central-1:123456789012:queue",
            "queueName": "queue",
            "messageRetentionSeconds": 345600,
            "visibilityTimeoutSeconds": 30,
        },
    }
    payload = {
        "workload": "bootstrap-infrastructure",
        "environment": "test",
        "owner": "SRE",
        "approvedBy": "sre-reviewer",
        "reviewedAt": module.dt.datetime.now(module.dt.timezone.utc).isoformat(),
        "expiresAt": "not-a-date",
        "downstreamRoute": "approved queue-owner process",
        "severityExpectations": "SEV2 during business hours",
        "fallback": "Escalate to platform maintainers.",
        "decision": "rejected",
        "evidence": [],
        "remediationPlan": "",
        "routeEvidence": {
            **route_evidence,
            "subscriptionCount": 0,
            "sqsQueue": {**route_evidence["sqsQueue"], "queueName": "old-queue"},
        },
    }
    path = tmp_path / "bad-alert-route-observation.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    summary, blockers = module._alert_route_observation_coverage(  # noqa: SLF001
        path,
        route_evidence,
    )

    blocker_text = " ".join(blockers)
    assert summary["path"] == str(path)  # nosec B101
    assert "decision must be one of" in blocker_text  # nosec B101
    assert "evidence must include non-empty" in blocker_text  # nosec B101
    assert "remediationPlan must be non-empty" in blocker_text  # nosec B101
    assert "expiresAt must be ISO-8601" in blocker_text  # nosec B101
    assert "subscriptionCount" in blocker_text  # nosec B101
    assert "sqsQueue.queueName" in blocker_text  # nosec B101

    non_object_path = tmp_path / "non-object-route.json"
    non_object_payload = {**payload, "routeEvidence": []}
    non_object_path.write_text(json.dumps(non_object_payload), encoding="utf-8")
    _, non_object_blockers = module._alert_route_observation_coverage(  # noqa: SLF001
        non_object_path,
        route_evidence,
    )
    assert "routeEvidence must be an object" in " ".join(non_object_blockers)  # nosec B101

    expired_path = tmp_path / "expired-route.json"
    expired_payload = {
        **payload,
        "decision": "accepted",
        "evidence": ["SRE reviewed the route."],
        "remediationPlan": "Review queue consumption monthly.",
        "expiresAt": (
            module.dt.datetime.now(module.dt.timezone.utc) - module.dt.timedelta(days=1)
        ).isoformat(),
        "routeEvidence": {**route_evidence, "sqsQueue": []},
    }
    expired_path.write_text(json.dumps(expired_payload), encoding="utf-8")
    _, expired_blockers = module._alert_route_observation_coverage(  # noqa: SLF001
        expired_path,
        route_evidence,
    )
    expired_text = " ".join(expired_blockers)
    assert "evidence is expired" in expired_text  # nosec B101
    assert "routeEvidence.sqsQueue must be an object" in expired_text  # nosec B101

    missing_live_queue_path = tmp_path / "missing-live-queue.json"
    missing_live_queue_payload = {
        **payload,
        "decision": "accepted",
        "evidence": ["SRE reviewed the route."],
        "remediationPlan": "Review queue consumption monthly.",
        "expiresAt": (
            module.dt.datetime.now(module.dt.timezone.utc)
            + module.dt.timedelta(days=30)
        ).isoformat(),
        "routeEvidence": route_evidence,
    }
    missing_live_queue_path.write_text(
        json.dumps(missing_live_queue_payload),
        encoding="utf-8",
    )
    _, missing_live_queue_blockers = module._alert_route_observation_coverage(  # noqa: SLF001
        missing_live_queue_path,
        {key: value for key, value in route_evidence.items() if key != "sqsQueue"},
    )
    assert "fields: sqsQueue" in " ".join(missing_live_queue_blockers)  # nosec B101


def test_restore_drill_rejects_bad_production_dr_owner_evidence(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Production DR owner evidence must be current, complete, and restore-bound."""
    module = load_script_module(monkeypatch, "collect_well_architected_evidence")
    restore_evidence = {
        "workload": "bootstrap-infrastructure",
        "environment": "test",
        "completedAt": "2026-04-27T10:00:00Z",
        "targetRestoreLocation": "s3://awsbackup-restore-test-bootstrap-drill",
        "validationResult": "passed",
        "cleanupConfirmed": True,
    }
    payload = {
        "workload": "bootstrap-infrastructure",
        "environment": "prod",
        "owner": "SRE",
        "approvedBy": "prod-reviewer",
        "reviewedAt": module.dt.datetime.now(module.dt.timezone.utc).isoformat(),
        "expiresAt": "not-a-date",
        "rtoTarget": "",
        "rpoTarget": "24 hours",
        "escalationPath": "SRE primary",
        "recoveryOrder": "Restore state, validate logs, resume applies",
        "communicationsPlan": "Post owner-approved status updates.",
        "latestAcceptedDrill": "2026-04-27 restore drill accepted.",
        "nextReviewDate": "not-a-date",
        "evidenceRetentionLocation": "docs/production-dr-owner.md",
        "approval": "unknown",
        "evidence": [],
        "remediationPlan": "",
        "restoreDrillEvidence": {
            **restore_evidence,
            "targetRestoreLocation": "s3://stale-target",
        },
    }
    path = tmp_path / "bad-production-dr-owner.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    summary, blockers = module._production_dr_owner_coverage(  # noqa: SLF001
        path,
        restore_evidence,
    )

    blocker_text = " ".join(blockers)
    assert summary["path"] == str(path)  # nosec B101
    assert "approval must be one of" in blocker_text  # nosec B101
    assert "rtoTarget must be non-empty" in blocker_text  # nosec B101
    assert "nextReviewDate must be ISO-8601" in blocker_text  # nosec B101
    assert "evidence must include non-empty" in blocker_text  # nosec B101
    assert "remediationPlan must be non-empty" in blocker_text  # nosec B101
    assert "restoreDrillEvidence does not match" in blocker_text  # nosec B101

    expired_path = tmp_path / "expired-production-dr-owner.json"
    expired_payload = {
        **payload,
        "approval": "approved",
        "rtoTarget": "4 hours",
        "evidence": ["Production owner reviewed the target."],
        "remediationPlan": "Run the next drill before expiry.",
        "nextReviewDate": "2026-07-10",
        "expiresAt": (
            module.dt.datetime.now(module.dt.timezone.utc) - module.dt.timedelta(days=1)
        ).isoformat(),
    }
    expired_path.write_text(json.dumps(expired_payload), encoding="utf-8")
    _, expired_blockers = module._production_dr_owner_coverage(  # noqa: SLF001
        expired_path,
        restore_evidence,
    )
    assert "evidence is expired" in " ".join(expired_blockers)  # nosec B101

    non_object_restore_path = tmp_path / "non-object-production-dr-owner.json"
    non_object_restore_payload = {
        **expired_payload,
        "expiresAt": (
            module.dt.datetime.now(module.dt.timezone.utc)
            + module.dt.timedelta(days=30)
        ).isoformat(),
        "restoreDrillEvidence": [],
    }
    non_object_restore_path.write_text(
        json.dumps(non_object_restore_payload),
        encoding="utf-8",
    )
    _, non_object_restore_blockers = module._production_dr_owner_coverage(  # noqa: SLF001
        non_object_restore_path,
        restore_evidence,
    )
    assert "restoreDrillEvidence must be an object" in " ".join(  # nosec B101
        non_object_restore_blockers
    )


def test_sns_alert_route_reports_sqs_metadata_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SNS route evidence should fail when SQS queue metadata is unreadable."""
    module = load_script_module(monkeypatch, "collect_well_architected_evidence")

    def queue_url_runner(command, **_kwargs):
        if command[:3] == ["aws", "sns", "get-topic-attributes"]:
            return subprocess.CompletedProcess(command, 0, json.dumps("alias/key"), "")
        if command[:3] == ["aws", "sns", "list-subscriptions-by-topic"]:
            return subprocess.CompletedProcess(
                command,
                0,
                json.dumps(
                    [
                        {
                            "Protocol": "sqs",
                            "Endpoint": (
                                "arn:aws:sqs:eu-central-1:123456789012:"
                                "bootstrap-test-operations-alerts"
                            ),
                        }
                    ]
                ),
                "",
            )
        return subprocess.CompletedProcess(command, 1, "", "denied")

    queue_url_evidence = module.aws_sns_alert_route(
        "arn:topic",
        runner=queue_url_runner,
    )

    assert queue_url_evidence["status"] == "failed"  # nosec B101
    assert "SQS queue URL" in " ".join(queue_url_evidence["blockers"])  # nosec B101

    def attributes_runner(command, **_kwargs):
        if command[:3] == ["aws", "sns", "get-topic-attributes"]:
            payload: object = "alias/key"
        elif command[:3] == ["aws", "sns", "list-subscriptions-by-topic"]:
            payload = [
                {
                    "Protocol": "sqs",
                    "Endpoint": (
                        "arn:aws:sqs:eu-central-1:123456789012:"
                        "bootstrap-test-operations-alerts"
                    ),
                }
            ]
        elif command[:3] == ["aws", "sqs", "get-queue-url"]:
            payload = "https://sqs.eu-central-1.amazonaws.com/123456789012/queue"
        else:
            return subprocess.CompletedProcess(command, 1, "", "denied")
        return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")

    attributes_evidence = module.aws_sns_alert_route(
        "arn:topic",
        runner=attributes_runner,
    )

    assert attributes_evidence["status"] == "failed"  # nosec B101
    assert "SQS queue attributes" in " ".join(  # nosec B101
        attributes_evidence["blockers"]
    )
    assert module._sns_subscription_items(None) == []  # noqa: SLF001  # nosec B101
    assert (  # noqa: SLF001  # nosec B101
        module._queue_name_from_sqs_arn("arn:aws:sns:bad") == ""
    )
    assert (  # noqa: SLF001  # nosec B101
        module._queue_name_from_sqs_arn("arn:aws:sns:eu:1:name") == ""
    )
    assert (  # noqa: SLF001  # nosec B101
        module._queue_name_from_sqs_arn("arn:aws:sqs:eu:1:") == ""
    )
    assert module._metadata_int(True) is None  # noqa: SLF001  # nosec B101
    assert module._metadata_int(None) is None  # noqa: SLF001  # nosec B101
    assert module._metadata_int("not-an-int") is None  # noqa: SLF001  # nosec B101
    assert module._metadata_int(["1"]) is None  # noqa: SLF001  # nosec B101


def test_collect_well_architected_evidence_reports_dependabot_alerts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Dependabot evidence should fail on open high-impact default-branch alerts."""
    module = load_script_module(monkeypatch, "collect_well_architected_evidence")

    def runner(command, **_kwargs):
        assert command[:2] == ["gh", "api"]  # nosec B101
        assert "/dependabot/alerts?" in command[-1]  # nosec B101
        payload = [
            {
                "number": 8,
                "state": "open",
                "dependency": {
                    "package": {"name": "GitPython"},
                    "manifest_path": "uv.lock",
                },
                "security_advisory": {"severity": "high"},
                "security_vulnerability": {
                    "first_patched_version": {"identifier": "3.1.50"}
                },
            },
            {
                "number": 4,
                "state": "open",
                "dependency": {
                    "package": {"name": "GitPython"},
                    "manifest_path": "uv.lock",
                },
                "security_advisory": {"severity": "critical"},
                "security_vulnerability": {
                    "first_patched_version": {"identifier": "3.1.47"}
                },
            },
            {
                "number": 9,
                "state": "open",
                "dependency": {
                    "package": {"name": "GitPython"},
                    "manifest_path": "uv.lock",
                },
                "security_advisory": {"severity": "low"},
                "security_vulnerability": {},
            },
            {
                "number": 10,
                "state": "open",
                "dependency": {
                    "package": {"name": "GitPython"},
                    "manifest_path": "pyproject.toml",
                },
                "security_advisory": {"severity": "high"},
                "security_vulnerability": {},
            },
            {
                "number": 11,
                "state": "fixed",
                "dependency": {
                    "package": {"name": "GitPython"},
                    "manifest_path": "uv.lock",
                },
                "security_advisory": {"severity": "high"},
                "security_vulnerability": {},
            },
            "malformed",
        ]
        return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")

    evidence = module.github_dependabot_alerts(
        "VilnaCRM-Org/bootstrap-infrastructure",
        runner=runner,
    )

    assert evidence["status"] == "failed"  # nosec B101
    assert evidence["evidence"]["matchingOpenAlertCount"] == 3  # nosec B101
    assert evidence["evidence"]["openAlertCount"] == 2  # nosec B101
    assert evidence["evidence"]["openAlertNumbers"] == [4, 8]  # nosec B101
    assert evidence["evidence"]["alerts"][0]["firstPatchedVersion"] == "3.1.47"  # nosec B101
    assert "GitPython in uv.lock: #4, #8" in evidence["blockers"][0]  # nosec B101
    assert module._dependabot_alert_blockers(  # noqa: SLF001  # nosec B101
        dependency="GitPython",
        manifest_path="uv.lock",
        open_alert_numbers=[],
        open_alert_count=2,
    ) == [
        "Open default-branch Dependabot alerts remain for "
        "GitPython in uv.lock: 2 alert(s)."
    ]


def test_collect_well_architected_evidence_accepts_dependabot_exception(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Owner-approved exception evidence can cover exact open alert numbers."""
    module = load_script_module(monkeypatch, "collect_well_architected_evidence")
    exception_path = tmp_path / "dependabot-exception.json"
    exception_path.write_text(
        json.dumps(
            {
                "workload": "bootstrap-infrastructure",
                "owner": "security-reviewer",
                "approvedBy": "Kravalg",
                "reviewedAt": module.dt.datetime.now(
                    module.dt.timezone.utc
                ).isoformat(),
                "expiresAt": (
                    module.dt.datetime.now(module.dt.timezone.utc)
                    + module.dt.timedelta(days=7)
                ).isoformat(),
                "dependencyName": "GitPython",
                "manifestPath": "uv.lock",
                "alertNumbers": [8, 4],
                "approval": "approved",
                "reason": "Patched lockfile is staged; alerts close after merge.",
                "remediationPlan": "Merge patched lockfile or revisit exception.",
                "evidence": ["Security owner approved a short exception window."],
            }
        ),
        encoding="utf-8",
    )

    def runner(command, **_kwargs):
        assert command[:2] == ["gh", "api"]  # nosec B101
        payload = [
            {
                "number": 8,
                "state": "open",
                "dependency": {
                    "package": {"name": "GitPython"},
                    "manifest_path": "uv.lock",
                },
                "security_advisory": {"severity": "high"},
                "security_vulnerability": {
                    "first_patched_version": {"identifier": "3.1.50"}
                },
            },
            {
                "number": 4,
                "state": "open",
                "dependency": {
                    "package": {"name": "GitPython"},
                    "manifest_path": "uv.lock",
                },
                "security_advisory": {"severity": "critical"},
                "security_vulnerability": {
                    "first_patched_version": {"identifier": "3.1.47"}
                },
            },
        ]
        return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")

    evidence = module.github_dependabot_alerts(
        "VilnaCRM-Org/bootstrap-infrastructure",
        exception_evidence=exception_path,
        runner=runner,
    )

    assert evidence["status"] == "passed"  # nosec B101
    assert evidence["blockers"] == []  # nosec B101
    assert evidence["evidence"]["openAlertNumbers"] == [4, 8]  # nosec B101
    assert evidence["evidence"]["unexceptedOpenAlertCount"] == 0  # nosec B101
    assert evidence["evidence"]["exceptedOpenAlertNumbers"] == [4, 8]  # nosec B101
    assert (  # nosec B101
        evidence["evidence"]["exceptionEvidence"]["approvedBy"] == "Kravalg"
    )


def test_collect_well_architected_evidence_rejects_bad_dependabot_exception(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Exception evidence should be strict and scoped to live alert metadata."""
    module = load_script_module(monkeypatch, "collect_well_architected_evidence")
    exception_path = tmp_path / "bad-dependabot-exception.json"
    exception_path.write_text(
        json.dumps(
            {
                "workload": "bootstrap-infrastructure",
                "owner": "security-reviewer",
                "approvedBy": "Kravalg",
                "reviewedAt": module.dt.datetime.now(
                    module.dt.timezone.utc
                ).isoformat(),
                "expiresAt": "not-a-date",
                "dependencyName": "OtherPackage",
                "manifestPath": "pyproject.toml",
                "alertNumbers": [7, 9],
                "approval": "denied",
                "reason": "Not approved.",
                "remediationPlan": "None.",
                "evidence": [],
            }
        ),
        encoding="utf-8",
    )

    def runner(command, **_kwargs):
        payload = [
            {
                "number": 8,
                "state": "open",
                "dependency": {
                    "package": {"name": "GitPython"},
                    "manifest_path": "uv.lock",
                },
                "security_advisory": {"severity": "high"},
                "security_vulnerability": {
                    "first_patched_version": {"identifier": "3.1.50"}
                },
            }
        ]
        return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")

    evidence = module.github_dependabot_alerts(
        "VilnaCRM-Org/bootstrap-infrastructure",
        exception_evidence=exception_path,
        runner=runner,
    )

    blocker_text = " ".join(evidence["blockers"])
    assert evidence["status"] == "failed"  # nosec B101
    assert "dependencyName" in blocker_text  # nosec B101
    assert "manifestPath" in blocker_text  # nosec B101
    assert "approval" in blocker_text  # nosec B101
    assert "non-empty evidence" in blocker_text  # nosec B101
    assert "expiresAt" in blocker_text  # nosec B101
    assert "#8" in blocker_text  # nosec B101
    assert "#7" in blocker_text  # nosec B101
    assert "GitPython in uv.lock: #8" in blocker_text  # nosec B101

    expired_blockers = module._dependabot_exception_payload_blockers(  # noqa: SLF001
        {
            "dependencyName": "GitPython",
            "manifestPath": "uv.lock",
            "approval": "approved",
            "evidence": ["Owner approved."],
            "expiresAt": (
                module.dt.datetime.now(module.dt.timezone.utc)
                - module.dt.timedelta(days=1)
            ).isoformat(),
            "alertNumbers": [8],
        },
        dependency="GitPython",
        manifest_path="uv.lock",
        blocking_alerts=[{"number": 8}],
    )
    assert "expired" in " ".join(expired_blockers)  # nosec B101

    unnumbered_blockers = module._dependabot_exception_payload_blockers(  # noqa: SLF001
        {
            "dependencyName": "GitPython",
            "manifestPath": "uv.lock",
            "approval": "accepted_risk",
            "evidence": ["Owner approved."],
            "expiresAt": (
                module.dt.datetime.now(module.dt.timezone.utc)
                + module.dt.timedelta(days=1)
            ).isoformat(),
            "alertNumbers": [],
        },
        dependency="GitPython",
        manifest_path="uv.lock",
        blocking_alerts=[{"number": "unknown"}],
    )
    assert "without GitHub alert numbers" in " ".join(  # nosec B101
        unnumbered_blockers
    )
    assert (  # noqa: SLF001  # nosec B101
        module._dependabot_exception_alert_number_blockers(
            {"alertNumbers": []},
            [],
        )
        == []
    )
    assert (  # noqa: SLF001  # nosec B101
        module._dependabot_exception_alert_numbers({"alertNumbers": "all"}) == []
    )
    assert (  # noqa: SLF001  # nosec B101
        module._dependabot_exception_alert_numbers({"alertNumbers": [1, False]}) == []
    )


def test_collect_well_architected_evidence_reads_ruleset_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Rulesets should provide branch evidence when classic protection is absent."""
    module = load_script_module(monkeypatch, "collect_well_architected_evidence")

    def runner(command, **_kwargs):
        command_path = command[-1]
        if command_path.endswith("/protection"):
            return subprocess.CompletedProcess(command, 1, "", "not found")
        if command_path.endswith("/rulesets"):
            payload = [
                {"id": 1},
                {"id": 2},
                {"id": 3},
                {"name": "missing id"},
                "malformed",
            ]
            return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")
        if command_path.endswith("/rulesets/1"):
            payload = {
                "name": "main",
                "target": "branch",
                "enforcement": "active",
                "rules": [
                    {
                        "type": "required_status_checks",
                        "parameters": {
                            "required_status_checks": [
                                {"context": "Unit"},
                                {"context": "Policy"},
                            ]
                        },
                    },
                    {"type": "pull_request", "parameters": {}},
                ],
            }
            return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")
        if command_path.endswith("/rulesets/2"):
            return subprocess.CompletedProcess(command, 1, "", "denied")
        if command_path.endswith("/rulesets/3"):
            payload = {
                "name": "tag rules",
                "target": "tag",
                "enforcement": "active",
                "rules": [{"type": "pull_request", "parameters": {}}],
            }
            return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")
        raise AssertionError(command)  # pragma: no cover

    evidence = module.github_branch_protection(
        "VilnaCRM-Org/bootstrap-infrastructure",
        "main",
        expected_required_status_checks=("Unit", "Policy"),
        runner=runner,
    )

    assert evidence["status"] == "passed"  # nosec B101
    assert evidence["evidence"]["classicProtectionReadable"] is False  # nosec B101
    assert evidence["evidence"]["activeRulesetCount"] == 1  # nosec B101
    assert evidence["evidence"]["requiredStatusCheckCount"] == 2  # nosec B101
    assert evidence["evidence"]["requiresPullRequestReviews"] is True  # nosec B101
    assert (  # nosec B101
        module._ruleset_has_pull_request_reviews(  # noqa: SLF001
            [
                {
                    "target": "branch",
                    "enforcement": "active",
                    "rules": [{"type": "required_status_checks"}],
                },
                {
                    "target": "tag",
                    "enforcement": "active",
                    "rules": [{"type": "pull_request"}],
                },
                {
                    "target": "branch",
                    "enforcement": "evaluate",
                    "rules": [{"type": "pull_request"}],
                },
            ]
        )
        is False
    )


def test_collect_well_architected_evidence_reads_production_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Production environment evidence should require protected approvals."""
    module = load_script_module(monkeypatch, "collect_well_architected_evidence")

    payload = {
        "name": "prod",
        "protection_rules": [
            {"type": "wait_timer", "wait_timer": 0},
            {
                "type": "required_reviewers",
                "prevent_self_review": False,
                "reviewers": "unexpected-shape",
            },
            {
                "type": "required_reviewers",
                "prevent_self_review": True,
                "reviewers": [
                    {"type": "User", "reviewer": {"login": "Kravalg"}},
                    {"type": "Team", "reviewer": {"login": "platform-admins"}},
                ],
            },
        ],
        "deployment_branch_policy": {
            "protected_branches": True,
            "custom_branch_policies": False,
        },
    }

    evidence = module.github_production_environment(
        "VilnaCRM-Org/bootstrap-infrastructure",
        "prod",
        "Kravalg",
        runner=lambda command, **_kwargs: subprocess.CompletedProcess(
            command, 0, json.dumps(payload), ""
        ),
    )

    assert evidence["status"] == "passed"  # nosec B101
    assert evidence["evidence"]["requiredReviewerCount"] == 2  # nosec B101
    assert evidence["evidence"]["requiredReviewerLogins"] == [  # nosec B101
        "Kravalg",
        "platform-admins",
    ]
    assert evidence["evidence"]["preventSelfReview"] is True  # nosec B101
    assert evidence["evidence"]["protectedBranchesOnly"] is True  # nosec B101


def test_collect_well_architected_evidence_reports_production_environment_gaps(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Production environment gaps should be explicit blocker text."""
    module = load_script_module(monkeypatch, "collect_well_architected_evidence")

    missing = module.github_production_environment(
        "VilnaCRM-Org/bootstrap-infrastructure",
        "prod",
        runner=lambda command, **_kwargs: subprocess.CompletedProcess(
            command, 1, "", "not found"
        ),
    )
    assert missing["status"] == "failed"  # nosec B101
    assert missing["evidence"]["readable"] is False  # nosec B101

    no_reviewers_payload = {
        "name": "prod",
        "prevent_self_review": True,
        "protection_rules": [],
        "deployment_branch_policy": {
            "protected_branches": True,
            "custom_branch_policies": False,
        },
    }
    no_reviewers = module.github_production_environment(
        "VilnaCRM-Org/bootstrap-infrastructure",
        "prod",
        "Kravalg",
        runner=lambda command, **_kwargs: subprocess.CompletedProcess(
            command, 0, json.dumps(no_reviewers_payload), ""
        ),
    )
    assert no_reviewers["status"] == "failed"  # nosec B101
    assert "does not require reviewers" in " ".join(  # nosec B101
        no_reviewers["blockers"]
    )

    no_shape_payload = {
        "name": "prod",
        "prevent_self_review": True,
        "deployment_branch_policy": {
            "protected_branches": True,
            "custom_branch_policies": False,
        },
    }
    no_shape = module.github_production_environment(
        "VilnaCRM-Org/bootstrap-infrastructure",
        "prod",
        "Kravalg",
        runner=lambda command, **_kwargs: subprocess.CompletedProcess(
            command, 0, json.dumps(no_shape_payload), ""
        ),
    )
    assert no_shape["status"] == "failed"  # nosec B101
    assert no_shape["evidence"]["requiredReviewerCount"] == 0  # nosec B101

    weak_payload = {
        "name": "prod",
        "reviewers": [
            {"type": "User", "login": "pixelTM"},
            {"type": "Team"},
            "unexpected-shape",
        ],
        "deployment_branch_policy": {
            "protected_branches": False,
            "custom_branch_policies": True,
        },
    }
    weak = module.github_production_environment(
        "VilnaCRM-Org/bootstrap-infrastructure",
        "prod",
        "Kravalg",
        runner=lambda command, **_kwargs: subprocess.CompletedProcess(
            command, 0, json.dumps(weak_payload), ""
        ),
    )

    assert weak["status"] == "failed"  # nosec B101
    blockers = " ".join(weak["blockers"])
    assert "Kravalg" in blockers  # nosec B101
    assert "self-review" in blockers  # nosec B101
    assert "protected branches" in blockers  # nosec B101


def test_collect_well_architected_evidence_reads_iam_access_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """IAM access evidence should stay aggregate and avoid key or user output."""
    module = load_script_module(monkeypatch, "collect_well_architected_evidence")
    old_timestamp = (
        module.dt.datetime.now(module.dt.timezone.utc) - module.dt.timedelta(days=120)
    ).isoformat()
    recent_timestamp = (
        module.dt.datetime.now(module.dt.timezone.utc) - module.dt.timedelta(days=1)
    ).isoformat()

    def runner(command, **_kwargs):
        if command[:3] == ["aws", "iam", "get-account-summary"]:
            payload = {
                "AccountAccessKeysPresent": 1,
                "AccountMFAEnabled": 0,
                "MFADevices": 1,
                "MFADevicesInUse": 1,
                "Users": 3,
            }
            return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")
        if command[:3] == ["aws", "iam", "list-users"]:
            return subprocess.CompletedProcess(
                command, 0, json.dumps(["automation", "maintainer", "auditor"]), ""
            )
        if command[:3] == ["aws", "iam", "list-access-keys"] and (
            command[command.index("--user-name") + 1] == "auditor"
        ):
            return subprocess.CompletedProcess(command, 1, "", "denied")
        if command[:3] == ["aws", "iam", "list-access-keys"]:
            user_name = command[command.index("--user-name") + 1]
            active_key_id = f"{user_name}-active-key"
            return subprocess.CompletedProcess(
                command,
                0,
                json.dumps(
                    [
                        {
                            "AccessKeyId": active_key_id,
                            "CreateDate": (
                                old_timestamp
                                if user_name == "automation"
                                else recent_timestamp
                            ),
                            "Status": "Active",
                        },
                        {
                            "AccessKeyId": f"{user_name}-inactive-key",
                            "CreateDate": old_timestamp,
                            "Status": "Inactive",
                        },
                        {
                            "AccessKeyId": f"{user_name}-unknown-key",
                            "CreateDate": old_timestamp,
                            "Status": "Other",
                        },
                    ]
                ),
                "",
            )
        if command[:3] == ["aws", "iam", "get-access-key-last-used"]:
            key_id = command[command.index("--access-key-id") + 1]
            payload = (
                {"LastUsedDate": old_timestamp}
                if key_id == "automation-active-key"
                else {"LastUsedDate": recent_timestamp}
            )
            return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")
        raise AssertionError(command)  # pragma: no cover

    evidence = module.aws_iam_account_access(runner=runner)

    assert evidence["status"] == "failed"  # nosec B101
    assert evidence["evidence"] == {  # nosec B101
        "accountAccessKeysPresent": 1,
        "accountMfaEnabled": 0,
        "activeUserAccessKeyCreateDateUnknownCount": 0,
        "activeUserAccessKeyCount": 2,
        "activeUserAccessKeyLastUsedOlderThan90DaysCount": 1,
        "activeUserAccessKeyLastUsedUnknownCount": 0,
        "activeUserAccessKeyLastUsedWithin90DaysCount": 1,
        "activeUserAccessKeyNeverUsedCount": 0,
        "activeUserAccessKeyOlderThan90DaysCount": 1,
        "discoveredUserCount": 3,
        "inactiveUserAccessKeyCount": 2,
        "mfaDeviceCount": 1,
        "mfaDevicesInUse": 1,
        "otherUserAccessKeyStatusCount": 2,
        "summaryUserCount": 3,
        "unreadableAccessKeyLastUsedCount": 0,
        "unreadableAccessKeyUserCount": 1,
        "usersWithActiveAccessKeys": 2,
    }
    blockers = " ".join(evidence["blockers"])
    assert "root/account MFA" in blockers  # nosec B101
    assert "root account access keys" in blockers  # nosec B101
    assert "active user access keys" in blockers  # nosec B101
    assert "one or more IAM users" in blockers  # nosec B101
    assert "automation" not in blockers  # nosec B101
    assert "maintainer" not in blockers  # nosec B101


def test_collect_well_architected_evidence_accepts_security_attestation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Current owner attestation should cover human and active-key IAM blockers."""
    module = load_script_module(monkeypatch, "collect_well_architected_evidence")
    old_timestamp = (
        module.dt.datetime.now(module.dt.timezone.utc) - module.dt.timedelta(days=120)
    ).isoformat()
    recent_timestamp = (
        module.dt.datetime.now(module.dt.timezone.utc) - module.dt.timedelta(days=1)
    ).isoformat()

    def runner(command, **_kwargs):
        if command[:3] == ["aws", "iam", "get-account-summary"]:
            payload = {
                "AccountAccessKeysPresent": 0,
                "AccountMFAEnabled": 1,
                "MFADevices": 1,
                "MFADevicesInUse": 1,
                "Users": 2,
            }
            return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")
        if command[:3] == ["aws", "iam", "list-users"]:
            return subprocess.CompletedProcess(
                command, 0, json.dumps(["automation", "maintainer"]), ""
            )
        if command[:3] == ["aws", "iam", "list-access-keys"]:
            user_name = command[command.index("--user-name") + 1]
            payload = (
                [
                    {
                        "AccessKeyId": "automation-active-key",
                        "CreateDate": old_timestamp,
                        "Status": "Active",
                    }
                ]
                if user_name == "automation"
                else []
            )
            return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")
        if command[:3] == ["aws", "iam", "get-access-key-last-used"]:
            return subprocess.CompletedProcess(
                command, 0, json.dumps({"LastUsedDate": recent_timestamp}), ""
            )
        raise AssertionError(command)  # pragma: no cover

    base = module.aws_iam_account_access(runner=runner)
    assert base["status"] == "failed"  # nosec B101
    attestation = {
        "workload": "bootstrap-infrastructure",
        "owner": "security-reviewer",
        "approvedBy": "security-owner",
        "reviewedAt": module.dt.datetime.now(module.dt.timezone.utc).isoformat(),
        "expiresAt": (
            module.dt.datetime.now(module.dt.timezone.utc)
            + module.dt.timedelta(days=30)
        ).isoformat(),
        "humanAccessPosture": "mfa_sso_verified",
        "activeKeyDecision": "approved_exception",
        "permissionsBoundaryDecision": "approved_exemption",
        "approval": "approved",
        "evidence": ["Security owner reviewed aggregate IAM posture."],
        "remediationPlan": "Rotate the remaining static key before expiry.",
        "accountEvidence": base["evidence"],
    }
    attestation_path = tmp_path / "security-account-attestation.json"
    attestation_path.write_text(json.dumps(attestation), encoding="utf-8")

    covered = module.aws_iam_account_access(
        attestation_evidence=attestation_path,
        runner=runner,
    )

    assert covered["status"] == "passed"  # nosec B101
    assert covered["blockers"] == []  # nosec B101
    summary = covered["evidence"]["securityAccountAttestation"]
    assert summary["approvedBy"] == "security-owner"  # nosec B101
    assert summary["activeKeyDecision"] == "approved_exception"  # nosec B101
    assert "automation" not in json.dumps(covered)  # nosec B101
    assert "automation-active-key" not in json.dumps(covered)  # nosec B101


def test_collect_well_architected_evidence_rejects_bad_security_attestation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Security attestation evidence must be current, exact, and approved."""
    module = load_script_module(monkeypatch, "collect_well_architected_evidence")
    account_evidence = {
        "accountAccessKeysPresent": 0,
        "accountMfaEnabled": 1,
        "activeUserAccessKeyCreateDateUnknownCount": 0,
        "activeUserAccessKeyCount": 1,
        "activeUserAccessKeyLastUsedOlderThan90DaysCount": 0,
        "activeUserAccessKeyLastUsedUnknownCount": 0,
        "activeUserAccessKeyLastUsedWithin90DaysCount": 1,
        "activeUserAccessKeyNeverUsedCount": 0,
        "activeUserAccessKeyOlderThan90DaysCount": 1,
        "discoveredUserCount": 2,
        "inactiveUserAccessKeyCount": 0,
        "mfaDeviceCount": 1,
        "mfaDevicesInUse": 1,
        "otherUserAccessKeyStatusCount": 0,
        "summaryUserCount": 2,
        "unreadableAccessKeyLastUsedCount": 0,
        "unreadableAccessKeyUserCount": 0,
        "usersWithActiveAccessKeys": 1,
    }
    payload = {
        "workload": "bootstrap-infrastructure",
        "owner": "security-reviewer",
        "approvedBy": "security-owner",
        "reviewedAt": module.dt.datetime.now(module.dt.timezone.utc).isoformat(),
        "expiresAt": "not-a-date",
        "humanAccessPosture": "unknown",
        "activeKeyDecision": "no_active_keys",
        "permissionsBoundaryDecision": "unknown",
        "approval": "unknown",
        "evidence": [],
        "remediationPlan": "",
        "accountEvidence": {**account_evidence, "activeUserAccessKeyCount": 0},
    }
    path = tmp_path / "bad-security-account-attestation.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    summary, controls, blockers = module._security_account_attestation_coverage(  # noqa: SLF001
        path,
        account_evidence,
    )

    blocker_text = " ".join(blockers)
    assert summary["path"] == str(path)  # nosec B101
    assert controls == frozenset()  # nosec B101
    assert "approval must be one of" in blocker_text  # nosec B101
    assert "humanAccessPosture must be one of" in blocker_text  # nosec B101
    assert "no_active_keys" in blocker_text  # nosec B101
    assert "expiresAt must be ISO-8601" in blocker_text  # nosec B101
    assert "accountEvidence does not match" in blocker_text  # nosec B101
    assert module._security_account_attestation_expiry_blockers(  # noqa: SLF001  # nosec B101
        "2025-01-01T00:00:00Z"
    ) == ["Security account attestation evidence is expired."]
    assert module._security_account_attestation_account_blockers(  # noqa: SLF001  # nosec B101
        {"accountEvidence": "not-an-object"},
        account_evidence,
    ) == ["Security account attestation accountEvidence must be an object."]


def test_collect_well_architected_evidence_handles_iam_key_metadata_gaps(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """IAM key edge cases should be counted without exposing identifiers."""
    module = load_script_module(monkeypatch, "collect_well_architected_evidence")
    counts = {
        "active": 0,
        "inactive": 0,
        "other": 0,
        "usersWithActive": 0,
        "unreadableUsers": 0,
        "activeOlderThan90Days": 0,
        "activeCreateDateUnknown": 0,
        "activeNeverUsed": 0,
        "activeLastUsedWithin90Days": 0,
        "activeLastUsedOlderThan90Days": 0,
        "activeLastUsedUnknown": 0,
        "unreadableAccessKeyLastUsed": 0,
    }

    def denied_runner(command, **_kwargs):
        assert command[:3] == ["aws", "iam", "get-access-key-last-used"]  # nosec B101
        return subprocess.CompletedProcess(command, 1, "", "denied")

    def never_used_runner(command, **_kwargs):
        assert command[:3] == ["aws", "iam", "get-access-key-last-used"]  # nosec B101
        return subprocess.CompletedProcess(command, 0, json.dumps({}), "")

    module._record_active_access_key_last_used(  # noqa: SLF001
        "denied-key", counts, runner=denied_runner
    )
    module._record_active_access_key_last_used(  # noqa: SLF001
        "never-used-key", counts, runner=never_used_runner
    )
    module._record_active_access_key_age("not-a-timestamp", counts)  # noqa: SLF001

    assert counts["unreadableAccessKeyLastUsed"] == 1  # nosec B101
    assert counts["activeNeverUsed"] == 1  # nosec B101
    assert counts["activeCreateDateUnknown"] == 1  # nosec B101
    assert module._parse_aws_timestamp("2026-05-10T10:00:00") is not None  # noqa: SLF001
    assert module._parse_aws_timestamp("not-a-timestamp") is None  # noqa: SLF001


def test_collect_well_architected_evidence_reports_iam_user_query_gaps(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Malformed IAM user metadata should block without exposing raw output."""
    module = load_script_module(monkeypatch, "collect_well_architected_evidence")

    def runner(command, **_kwargs):
        if command[:3] == ["aws", "iam", "get-account-summary"]:
            payload = {
                "AccountAccessKeysPresent": 0,
                "AccountMFAEnabled": 1,
                "MFADevices": True,
                "MFADevicesInUse": 0,
                "Users": 0,
            }
            return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")
        if command[:3] == ["aws", "iam", "list-users"]:
            return subprocess.CompletedProcess(
                command, 0, json.dumps({"bad": True}), ""
            )
        raise AssertionError(command)  # pragma: no cover

    evidence = module.aws_iam_account_access(runner=runner)

    assert evidence["status"] == "failed"  # nosec B101
    assert evidence["evidence"]["mfaDeviceCount"] == 0  # nosec B101
    assert "Unable to query IAM users" in " ".join(evidence["blockers"])  # nosec B101


def test_collect_well_architected_evidence_paginates_review_threads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Review thread collection should follow cursors and surface bad pagination."""
    module = load_script_module(monkeypatch, "collect_well_architected_evidence")
    calls: list[list[str]] = []

    def runner(command, **_kwargs):
        calls.append(command)
        after_arg = next(
            (argument for argument in command if argument.startswith("after=")),
            None,
        )
        payload = {
            "data": {
                "repository": {
                    "pullRequest": {
                        "reviewThreads": {
                            "nodes": [{"isResolved": after_arg is None}],
                            "pageInfo": {
                                "hasNextPage": after_arg is None,
                                "endCursor": "cursor-1",
                            },
                        }
                    }
                }
            }
        }
        return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")

    evidence = module.github_review_threads(
        "VilnaCRM-Org/bootstrap-infrastructure",
        22,
        runner=runner,
    )

    assert evidence["status"] == "failed"  # nosec B101
    assert evidence["evidence"]["threadCount"] == 2  # nosec B101
    assert evidence["evidence"]["unresolvedThreadCount"] == 1  # nosec B101
    assert evidence["evidence"]["blockingThreadCount"] == 1  # nosec B101
    assert any("after=cursor-1" in command for command in calls)  # nosec B101

    def outdated_thread_runner(command, **_kwargs):
        payload = {
            "data": {
                "repository": {
                    "pullRequest": {
                        "reviewThreads": {
                            "nodes": [
                                {"isResolved": False, "isOutdated": True},
                                {"isResolved": True, "isOutdated": False},
                            ],
                            "pageInfo": {"hasNextPage": False, "endCursor": None},
                        }
                    }
                }
            }
        }
        return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")

    outdated_evidence = module.github_review_threads(
        "VilnaCRM-Org/bootstrap-infrastructure",
        22,
        runner=outdated_thread_runner,
    )

    assert outdated_evidence["status"] == "passed"  # nosec B101
    assert outdated_evidence["evidence"]["unresolvedThreadCount"] == 1  # nosec B101
    assert outdated_evidence["evidence"]["outdatedUnresolvedThreadCount"] == 1  # nosec B101
    assert outdated_evidence["evidence"]["blockingThreadCount"] == 0  # nosec B101

    def missing_cursor_runner(command, **_kwargs):
        payload = {
            "data": {
                "repository": {
                    "pullRequest": {
                        "reviewThreads": {
                            "nodes": [],
                            "pageInfo": {"hasNextPage": True},
                        }
                    }
                }
            }
        }
        return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")

    missing_cursor = module.github_review_threads(
        "VilnaCRM-Org/bootstrap-infrastructure",
        22,
        runner=missing_cursor_runner,
    )

    assert missing_cursor["status"] == "unknown"  # nosec B101
    assert "pagination did not return a cursor" in missing_cursor["blockers"][0]  # nosec B101

    def endless_runner(command, **_kwargs):
        payload = {
            "data": {
                "repository": {
                    "pullRequest": {
                        "reviewThreads": {
                            "nodes": [],
                            "pageInfo": {
                                "hasNextPage": True,
                                "endCursor": "cursor-loop",
                            },
                        }
                    }
                }
            }
        }
        return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")

    endless = module.github_review_threads(
        "VilnaCRM-Org/bootstrap-infrastructure",
        22,
        runner=endless_runner,
    )

    assert endless["status"] == "unknown"  # nosec B101
    assert "exceeded 20 pages" in endless["blockers"][0]  # nosec B101


@pytest.mark.parametrize(
    "payload",
    [
        {"data": None},
        {"data": {"repository": None}},
        {"data": {"repository": {"pullRequest": None}}},
        {"data": {"repository": {"pullRequest": {"reviewThreads": None}}}},
        {
            "data": {
                "repository": {
                    "pullRequest": {"reviewThreads": {"nodes": None, "pageInfo": None}}
                }
            }
        },
    ],
)
def test_collect_well_architected_evidence_handles_null_review_thread_leaves(
    monkeypatch: pytest.MonkeyPatch,
    payload: dict[str, object],
) -> None:
    """Review thread parsing should tolerate nullable GraphQL leaves."""
    module = load_script_module(monkeypatch, "collect_well_architected_evidence")

    assert module._review_threads_page(payload) == ([], {})  # nosec B101  # noqa: SLF001


def test_collect_well_architected_evidence_reports_missing_required_checks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Branch evidence should name required contexts absent from protection."""
    module = load_script_module(monkeypatch, "collect_well_architected_evidence")

    def runner(command, **_kwargs):
        command_path = command[-1]
        if command_path.endswith("/protection"):
            payload = {
                "required_status_checks": {"contexts": ["Preview"]},
                "required_pull_request_reviews": {"required_approving_review_count": 1},
                "enforce_admins": {"enabled": True},
            }
            return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")
        if command_path.endswith("/rulesets"):
            return subprocess.CompletedProcess(command, 0, "[]", "")
        raise AssertionError(command)  # pragma: no cover

    evidence = module.github_branch_protection(
        "VilnaCRM-Org/bootstrap-infrastructure",
        "main",
        expected_required_status_checks=("Preview", "IAM Validation"),
        runner=runner,
    )

    assert evidence["status"] == "failed"  # nosec B101
    assert evidence["evidence"]["requiredStatusChecks"] == ["Preview"]  # nosec B101
    assert evidence["evidence"]["missingRequiredStatusChecks"] == [  # nosec B101
        "IAM Validation"
    ]
    assert "IAM Validation" in evidence["blockers"][0]  # nosec B101


def test_collect_well_architected_evidence_main_writes_report(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """CLI wrapper should write evidence reports and signal blockers."""
    module = load_script_module(monkeypatch, "collect_well_architected_evidence")
    output_path = tmp_path / "evidence.json"
    markdown_path = tmp_path / "evidence.md"

    monkeypatch.setattr(
        module,
        "collect_evidence",
        lambda _args: {
            "generatedAt": "2026-05-10T06:31:06Z",
            "repo": "VilnaCRM-Org/bootstrap-infrastructure",
            "pr": 22,
            "branch": "main",
            "checks": [
                {
                    "name": "github_pr_checks",
                    "status": "passed",
                    "blockers": [],
                },
            ],
            "pillarScores": {"Security": 5.0},
            "proxyPillarScores": {"Security": 5.0},
            "scoreBlockers": [],
            "blockers": [],
        },
    )
    assert (
        module.main(
            ["--output", str(output_path), "--markdown-output", str(markdown_path)]
        )
        == 0
    )
    assert json.loads(output_path.read_text(encoding="utf-8"))["blockers"] == []
    markdown = markdown_path.read_text(encoding="utf-8")
    assert "# Well-Architected Evidence Report" in markdown  # nosec B101
    assert "| Security | 5.0 |" in markdown  # nosec B101
    assert "| github_pr_checks | passed | None |" in markdown  # nosec B101
    assert '"blockers": []' in capsys.readouterr().out
    blocked_markdown = module.render_markdown_report(
        {
            "generatedAt": "2026-05-10T06:31:06Z",
            "repo": "org/repo",
            "pr": None,
            "branch": "main",
            "checks": [
                "ignored",
                {
                    "name": None,
                    "status": "failed",
                    "blockers": ["blocked | escaped"],
                },
            ],
            "pillarScores": {},
            "proxyPillarScores": {"Custom | Pillar": 3},
            "scoreBlockers": ["score | blocker"],
            "blockers": ["plain | blocker"],
        }
    )
    assert "## Score Blockers" in blocked_markdown  # nosec B101
    assert "- score \\| blocker" in blocked_markdown  # nosec B101
    assert "- plain \\| blocker" in blocked_markdown  # nosec B101
    assert "| None reported | - |" in blocked_markdown  # nosec B101
    assert "| Custom \\| Pillar | 3 |" in blocked_markdown  # nosec B101
    assert "| - | failed | blocked \\| escaped |" in blocked_markdown  # nosec B101
    assert module._markdown_checks("invalid") == []  # noqa: SLF001  # nosec B101
    assert module._markdown_string_entries("invalid") == []  # noqa: SLF001  # nosec B101

    monkeypatch.setattr(
        module,
        "collect_evidence",
        lambda _args: {
            "checks": [],
            "pillarScores": {},
            "blockers": ["missing evidence"],
        },
    )
    assert module.main([]) == 1
    assert "missing evidence" in capsys.readouterr().out


def test_run_pulumi_command_branch_helpers_return_select_failures(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Cover helper branches that short-circuit before invoking Pulumi."""
    module = load_script_module(monkeypatch, "run_pulumi_command")
    repo_dir = tmp_path / "repo"
    pulumi_dir = repo_dir / "pulumi"
    policy_dir = repo_dir / "policy"
    plan_dir = repo_dir / ".artifacts" / "pulumi-plan"
    preview_dir = repo_dir / ".artifacts" / "pulumi-preview"
    pulumi_dir.mkdir(parents=True)
    policy_dir.mkdir()
    plan_dir.mkdir(parents=True)
    preview_dir.mkdir(parents=True)
    context = module.CommandContext(
        root_dir=repo_dir,
        env={},
        pulumi_dir=pulumi_dir,
        policy_pack_dir=policy_dir,
        plan_dir=plan_dir,
        preview_artifact_dir=preview_dir,
        backend_url="file:///tmp/backend",
        secrets_provider="awskms://alias/example?region=eu-central-1",
    )

    default_plan = module._selected_plan_path(context, None, "test")
    assert default_plan == module._plan_file(plan_dir, "test")  # nosec B101

    monkeypatch.setattr(module, "_select_or_init_stack", lambda *args: 7)
    assert module._run_plan_command(context, ["test"]) == 7  # nosec B101

    monkeypatch.setattr(module, "_select_or_init_stack", lambda *args: 9)
    assert module._run_up_plan_command(context, ["test"]) == 9  # nosec B101


def test_run_pulumi_command_validates_plan_manifest_error_paths(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Reject saved plans with stale or mismatched manifest evidence."""
    module = load_script_module(monkeypatch, "run_pulumi_command")
    repo_dir = tmp_path / "repo"
    pulumi_dir = repo_dir / "pulumi"
    policy_dir = repo_dir / "policy"
    plan_dir = repo_dir / ".artifacts" / "pulumi-plan"
    preview_dir = repo_dir / ".artifacts" / "pulumi-preview"
    pulumi_dir.mkdir(parents=True)
    policy_dir.mkdir()
    plan_dir.mkdir(parents=True)
    preview_dir.mkdir(parents=True)
    plan_file = plan_dir / "test.plan"
    other_plan = plan_dir / "other.plan"
    plan_file.write_text("plan", encoding="utf-8")
    other_plan.write_text("other", encoding="utf-8")
    context = module.CommandContext(
        root_dir=repo_dir,
        env={"PULUMI_PLAN_NOW_EPOCH": "1000", "PULUMI_EXPECTED_SHA": "sha-a"},
        pulumi_dir=pulumi_dir,
        policy_pack_dir=policy_dir,
        plan_dir=plan_dir,
        preview_artifact_dir=preview_dir,
        backend_url="file:///tmp/backend",
        secrets_provider="awskms://alias/example?region=eu-central-1",
    )

    assert module._load_plan_manifest(context) is None  # nosec B101
    assert "manifest not found" in capsys.readouterr().err  # nosec B101

    valid_entry = {
        "stack": "test",
        "planFile": ".artifacts/pulumi-plan/test.plan",
        "planSha256": hashlib.sha256(b"plan").hexdigest(),
    }
    valid_manifest = {
        "schemaVersion": 1,
        "createdAtEpoch": 1000,
        "commitSha": "sha-a",
        "backendUrl": "file:///tmp/backend",
        "stacks": [
            {"stack": "skip", "planFile": "unused", "planSha256": "unused"},
            valid_entry,
        ],
    }
    assert (  # nosec B101
        module._validate_plan_manifest(context, valid_manifest, "test", plan_file)
        is None
    )

    bad_schema = {**valid_manifest, "schemaVersion": 2}
    assert module._validate_plan_manifest(context, bad_schema, "test", plan_file) == 1
    context.env["PULUMI_PLAN_MAX_AGE_SECONDS"] = "10"
    stale = {**valid_manifest, "createdAtEpoch": 0}
    assert module._validate_plan_manifest(context, stale, "test", plan_file) == 1
    context.env.pop("PULUMI_PLAN_MAX_AGE_SECONDS")
    wrong_sha = {**valid_manifest, "commitSha": "sha-b"}
    assert module._validate_plan_manifest(context, wrong_sha, "test", plan_file) == 1
    wrong_backend = {**valid_manifest, "backendUrl": "s3://other"}
    assert (  # nosec B101
        module._validate_plan_manifest(context, wrong_backend, "test", plan_file) == 1
    )
    missing_stack = {**valid_manifest, "stacks": []}
    assert (  # nosec B101
        module._validate_plan_manifest(context, missing_stack, "test", plan_file) == 1
    )
    wrong_plan_path = {
        **valid_manifest,
        "stacks": [{**valid_entry, "planFile": ".artifacts/pulumi-plan/other.plan"}],
    }
    assert (  # nosec B101
        module._validate_plan_manifest(context, wrong_plan_path, "test", plan_file) == 1
    )
    wrong_hash = {
        **valid_manifest,
        "stacks": [{**valid_entry, "planSha256": hashlib.sha256(b"bad").hexdigest()}],
    }
    assert module._validate_plan_manifest(context, wrong_hash, "test", plan_file) == 1
    assert "hash does not match" in capsys.readouterr().err  # nosec B101


def test_run_pulumi_command_requires_manifest_before_saved_plan_apply(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A saved plan cannot be applied without its manifest."""
    module = load_script_module(monkeypatch, "run_pulumi_command")
    repo_dir = tmp_path / "repo"
    plan_dir = repo_dir / ".artifacts" / "pulumi-plan"
    plan_dir.mkdir(parents=True)
    plan_file = plan_dir / f"{module._safe_artifact_stem('test')}.plan"
    plan_file.write_text("plan", encoding="utf-8")
    context = module.CommandContext(
        root_dir=repo_dir,
        env={},
        pulumi_dir=repo_dir / "pulumi",
        policy_pack_dir=repo_dir / "policy",
        plan_dir=plan_dir,
        preview_artifact_dir=repo_dir / ".artifacts" / "pulumi-preview",
        backend_url="file:///tmp/backend",
        secrets_provider="awskms://alias/example?region=eu-central-1",
        runner=lambda command, **kwargs: subprocess.CompletedProcess(command, 0),
    )

    assert module._run_up_plan_command(context, ["test"]) == 1  # nosec B101
    assert "manifest not found" in capsys.readouterr().err  # nosec B101

    (plan_dir / "manifest.json").write_text(
        json.dumps({"schemaVersion": 2, "stacks": []}),
        encoding="utf-8",
    )
    assert module._run_up_plan_command(context, ["test"]) == 1  # nosec B101
    assert "unsupported" in capsys.readouterr().err  # nosec B101


def test_run_pulumi_command_reuses_manifest_for_multiple_plan_applications(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Multi-stack apply should load one manifest and validate every plan."""
    module = load_script_module(monkeypatch, "run_pulumi_command")
    repo_dir = tmp_path / "repo"
    plan_dir = repo_dir / ".artifacts" / "pulumi-plan"
    plan_dir.mkdir(parents=True)
    context = module.CommandContext(
        root_dir=repo_dir,
        env={"PULUMI_PLAN_NOW_EPOCH": "1000"},
        pulumi_dir=repo_dir / "pulumi",
        policy_pack_dir=repo_dir / "policy",
        plan_dir=plan_dir,
        preview_artifact_dir=repo_dir / ".artifacts" / "pulumi-preview",
        backend_url="file:///tmp/backend",
        secrets_provider="awskms://alias/example?region=eu-central-1",
        runner=lambda command, **kwargs: subprocess.CompletedProcess(command, 0),
    )
    stacks = ["test", "prod"]
    entries = []
    for stack in stacks:
        plan_file = module._plan_file(plan_dir, stack)
        plan_file.write_text(f"plan-{stack}", encoding="utf-8")
        entries.append(
            {
                "stack": stack,
                "planFile": f".artifacts/pulumi-plan/{plan_file.name}",
                "planSha256": hashlib.sha256(f"plan-{stack}".encode()).hexdigest(),
            }
        )
    (plan_dir / "manifest.json").write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "createdAtEpoch": 1000,
                "commitSha": "",
                "backendUrl": "file:///tmp/backend",
                "stacks": entries,
            }
        ),
        encoding="utf-8",
    )

    assert module._run_up_plan_command(context, stacks) == 0  # nosec B101


def test_run_pulumi_command_plan_fails_when_saved_plan_is_missing(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The plan command must not publish a manifest without a real saved plan."""
    module = load_script_module(monkeypatch, "run_pulumi_command")
    repo_dir = tmp_path / "repo"
    pulumi_dir = repo_dir / "pulumi"
    policy_dir = repo_dir / "policy"
    pulumi_dir.mkdir(parents=True)
    policy_dir.mkdir()
    context = module.CommandContext(
        root_dir=repo_dir,
        env={},
        pulumi_dir=pulumi_dir,
        policy_pack_dir=policy_dir,
        plan_dir=repo_dir / ".artifacts" / "pulumi-plan",
        preview_artifact_dir=repo_dir / ".artifacts" / "pulumi-preview",
        backend_url="file:///tmp/backend",
        secrets_provider="awskms://alias/example?region=eu-central-1",
        runner=lambda command, **kwargs: subprocess.CompletedProcess(command, 0),
    )

    assert module._run_plan_command(context, ["test"]) == 1  # nosec B101
    assert "plan file not created" in capsys.readouterr().err  # nosec B101


def test_select_or_init_stack_requires_file_backend_secrets_provider(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """File-backed stack initialization should fail before init without a provider."""
    module = load_script_module(monkeypatch, "run_pulumi_command")
    repo_dir = tmp_path / "repo"
    pulumi_dir = repo_dir / "pulumi"
    pulumi_dir.mkdir(parents=True)

    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(command, 1, stderr="missing stack\n")

    context = module.CommandContext(
        root_dir=repo_dir,
        env={},
        pulumi_dir=pulumi_dir,
        policy_pack_dir=repo_dir / "policy",
        plan_dir=repo_dir / ".artifacts" / "pulumi-plan",
        preview_artifact_dir=repo_dir / ".artifacts" / "pulumi-preview",
        backend_url="file:///tmp/backend",
        secrets_provider="",
        runner=fake_run,
    )

    assert module._select_or_init_stack(context, "test") == 1  # nosec B101
    assert "set PULUMI_SECRETS_PROVIDER" in capsys.readouterr().err  # nosec B101


def test_run_pulumi_command_plan_handles_multiple_configured_stacks(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A configured stack list should create one saved plan per stack."""
    module = load_script_module(monkeypatch, "run_pulumi_command")
    repo_dir = tmp_path / "repo"
    pulumi_dir = repo_dir / "pulumi"
    policy_dir = repo_dir / "policy"
    output_file = repo_dir / "github-output.txt"
    preview_dir = repo_dir / ".artifacts" / "pulumi-preview"
    pulumi_dir.mkdir(parents=True)
    policy_dir.mkdir()
    preview_dir.mkdir(parents=True)
    (preview_dir / "stale.json").write_text("{}", encoding="utf-8")
    (preview_dir / "summary.md").write_text("old summary\n", encoding="utf-8")
    monkeypatch.setattr(module, "repo_root", lambda _: repo_dir)
    monkeypatch.setenv("PULUMI_STACK", "default")
    monkeypatch.setenv("PULUMI_PREVIEW_STACKS", "test prod/eu")
    monkeypatch.setenv(
        "PULUMI_SECRETS_PROVIDER",
        "awskms://alias/bootstrap-preview?region=eu-central-1",
    )
    monkeypatch.setenv("GITHUB_OUTPUT", str(output_file))

    calls: list[list[str]] = []

    def fake_run(command, **kwargs):
        calls.append(command)
        if command[0] == "pulumi" and command[3:6] == ["stack", "select", "test"]:
            return subprocess.CompletedProcess(command, 1, stderr="missing test\n")
        if command[0] == "pulumi" and command[3:6] == [
            "stack",
            "select",
            "prod/eu",
        ]:
            return subprocess.CompletedProcess(command, 1, stderr="missing prod\n")
        if command[0] == "pulumi" and command[3] == "preview":
            stdout = kwargs.get("stdout")
            if stdout is not None:
                stdout.write('{"changeSummary": {"create": 1}, "steps": []}')
            if "--save-plan" in command:
                plan_path = Path(command[command.index("--save-plan") + 1])
                plan_path.write_text(
                    f"plan for {command[command.index('--stack') + 1]}",
                    encoding="utf-8",
                )
            return subprocess.CompletedProcess(command, 0)
        if command[:3] == ["uv", "--project", str(repo_dir)]:
            return subprocess.CompletedProcess(
                command, 0, stdout=f"summary for {Path(command[-1]).stem}\n"
            )
        return subprocess.CompletedProcess(command, 0, stdout="")

    monkeypatch.setattr(module, "run", fake_run)
    assert module.main(["plan"]) == 0  # nosec B101

    test_stem = module._safe_artifact_stem("test")
    prod_stem = module._safe_artifact_stem("prod/eu")
    output = capsys.readouterr().out
    output_values = output_file.read_text(encoding="utf-8")
    assert f"summary for {test_stem}" in output  # nosec B101
    assert f"summary for {prod_stem}" in output  # nosec B101
    assert f"{test_stem}.plan" in output_values  # nosec B101
    assert f"{prod_stem}.plan" in output_values  # nosec B101
    assert "plan_manifest=" in output_values  # nosec B101
    assert "old summary" not in output  # nosec B101
    assert not (preview_dir / "stale.json").exists()  # nosec B101
    manifest = json.loads(
        (repo_dir / ".artifacts/pulumi-plan/manifest.json").read_text()
    )
    assert manifest["schemaVersion"] == 1  # nosec B101
    assert manifest["backendUrl"].startswith("file://")  # nosec B101
    assert [entry["stack"] for entry in manifest["stacks"]] == [  # nosec B101
        "test",
        "prod/eu",
    ]
    initialized_prod = any(
        command[3:10]
        == [
            "stack",
            "init",
            "prod/eu",
            "--non-interactive",
            "--secrets-provider",
            "awskms://alias/bootstrap-preview?region=eu-central-1",
        ]
        for command in calls
    )
    assert initialized_prod  # nosec B101


def test_run_pulumi_command_handles_error_paths_and_plan_application(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Cover stack-safety failures and saved-plan application."""
    module = load_script_module(monkeypatch, "run_pulumi_command")
    repo_dir = tmp_path / "repo"
    pulumi_dir = repo_dir / "pulumi"
    policy_dir = repo_dir / "policy"
    plan_dir = repo_dir / ".artifacts" / "pulumi-plan"
    pulumi_dir.mkdir(parents=True)
    policy_dir.mkdir()
    plan_dir.mkdir(parents=True)
    monkeypatch.setattr(module, "repo_root", lambda _: repo_dir)

    monkeypatch.setenv("PULUMI_SECRETS_PROVIDER", "local")
    assert module.main(["preview"]) == 1  # nosec B101
    assert "awskms://" in capsys.readouterr().err  # nosec B101

    monkeypatch.setenv(
        "PULUMI_SECRETS_PROVIDER", "awskms://alias/example?region=eu-central-1"
    )
    monkeypatch.setattr(module, "discover_stacks", lambda *args: [])
    assert module.main(["preview"]) == 1  # nosec B101
    assert "set PULUMI_STACK" in capsys.readouterr().err  # nosec B101

    def shared_run(command, **kwargs):
        if command[0] == "pulumi" and command[3:6] == ["stack", "select", "test"]:
            return subprocess.CompletedProcess(command, 255, stderr="missing\n")
        return subprocess.CompletedProcess(command, 0, stdout="")

    monkeypatch.setattr(module, "discover_stacks", lambda *args: ["test"])
    monkeypatch.setattr(module, "run", shared_run)
    monkeypatch.setenv("PULUMI_BACKEND_URL", "s3://shared-state")
    assert module.main(["refresh"]) == 255  # nosec B101
    assert "shared backend stack test does not exist" in capsys.readouterr().err  # nosec B101

    def missing_provider_run(command, **kwargs):
        if command[0] == "pulumi" and command[3:6] == ["stack", "select", "test"]:
            return subprocess.CompletedProcess(command, 1, stderr="")
        return subprocess.CompletedProcess(command, 0, stdout="")

    monkeypatch.setattr(module, "run", missing_provider_run)
    monkeypatch.setenv("PULUMI_BACKEND_URL", "file:///tmp/backend")
    monkeypatch.delenv("PULUMI_SECRETS_PROVIDER", raising=False)
    module._emit_stderr("")
    assert module.main(["refresh"]) == 1  # nosec B101
    assert "PULUMI_SECRETS_PROVIDER must be set" in capsys.readouterr().err  # nosec B101

    def init_failure_run(command, **kwargs):
        if command[0] == "pulumi" and command[3:6] == ["stack", "select", "test"]:
            return subprocess.CompletedProcess(command, 1, stderr="")
        if command[0] == "pulumi" and command[3:6] == ["stack", "init", "test"]:
            return subprocess.CompletedProcess(command, 42, stderr="kms denied\n")
        return subprocess.CompletedProcess(command, 0, stdout="")

    monkeypatch.setattr(module, "run", init_failure_run)
    monkeypatch.setenv(
        "PULUMI_SECRETS_PROVIDER", "awskms://alias/example?region=eu-central-1"
    )
    assert module.main(["refresh"]) == 42  # nosec B101
    assert "kms denied" in capsys.readouterr().err  # nosec B101

    def ok_run(command, **kwargs):
        return subprocess.CompletedProcess(command, 0, stdout="")

    monkeypatch.setattr(module, "run", ok_run)
    monkeypatch.setenv("PULUMI_BACKEND_URL", "file:///tmp/backend")
    monkeypatch.setenv("PULUMI_PLAN_FILE", str(plan_dir / "single.plan"))
    monkeypatch.setattr(module, "discover_stacks", lambda *args: ["test", "prod"])
    assert module.main(["up-plan"]) == 1  # nosec B101
    assert "single selected stack" in capsys.readouterr().err  # nosec B101

    monkeypatch.setattr(module, "discover_stacks", lambda *args: ["test"])
    assert module.main(["up-plan"]) == 1  # nosec B101
    assert "Pulumi plan file not found" in capsys.readouterr().err  # nosec B101

    selected_plan = plan_dir / "single.plan"
    selected_plan.write_text("plan", encoding="utf-8")
    monkeypatch.setenv("PULUMI_PLAN_NOW_EPOCH", "1000")
    (plan_dir / "manifest.json").write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "createdAtEpoch": 1000,
                "commitSha": "",
                "backendUrl": "file:///tmp/backend",
                "stacks": [
                    {
                        "stack": "test",
                        "planFile": ".artifacts/pulumi-plan/single.plan",
                        "planSha256": hashlib.sha256(b"plan").hexdigest(),
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    applied: list[list[str]] = []

    def apply_run(command, **kwargs):
        applied.append(command)
        return subprocess.CompletedProcess(command, 0, stdout="")

    monkeypatch.setattr(module, "run", apply_run)
    assert module.main(["up-plan"]) == 0  # nosec B101
    applied_selected_plan = any(
        "--plan" in command and str(selected_plan) in command for command in applied
    )
    assert applied_selected_plan  # nosec B101

    single_output = repo_dir / "single-output.txt"
    module._write_plan_outputs(
        str(single_output), [selected_plan], plan_dir, plan_dir / "manifest.json"
    )
    assert f"plan_file={selected_plan}" in single_output.read_text(encoding="utf-8")  # nosec B101


def test_run_pulumi_command_runs_generic_and_plan_without_github_output(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Cover non-plan command dispatch and plan summaries without GitHub outputs."""
    module = load_script_module(monkeypatch, "run_pulumi_command")
    repo_dir = tmp_path / "repo"
    pulumi_dir = repo_dir / "pulumi"
    policy_dir = repo_dir / "policy"
    pulumi_dir.mkdir(parents=True)
    policy_dir.mkdir()
    monkeypatch.setattr(module, "repo_root", lambda _: repo_dir)
    monkeypatch.setenv("PULUMI_STACK", "test")
    monkeypatch.setenv(
        "PULUMI_SECRETS_PROVIDER", "awskms://alias/example?region=eu-central-1"
    )
    monkeypatch.delenv("GITHUB_OUTPUT", raising=False)

    calls: list[list[str]] = []

    def fake_run(command, **kwargs):
        calls.append(command)
        if command[0] == "pulumi" and command[3] == "preview":
            stdout = kwargs.get("stdout")
            if stdout is not None:
                stdout.write('{"changeSummary": {}, "steps": []}')
            if "--save-plan" in command:
                plan_path = Path(command[command.index("--save-plan") + 1])
                plan_path.write_text("plan", encoding="utf-8")
            return subprocess.CompletedProcess(command, 0)
        if command[:3] == ["uv", "--project", str(repo_dir)]:
            return subprocess.CompletedProcess(command, 0, stdout="summary\n")
        return subprocess.CompletedProcess(command, 0, stdout="")

    monkeypatch.setattr(module, "run", fake_run)
    assert module.main(["preview"]) == 0  # nosec B101
    preview_called = any(
        len(command) > 3 and command[3] == "preview" for command in calls
    )
    assert preview_called  # nosec B101

    calls.clear()
    assert module.main(["plan"]) == 0  # nosec B101
    assert "summary" in capsys.readouterr().out  # nosec B101
    assert all("plan_files<<EOF" not in str(command) for command in calls)  # nosec B101


def test_select_stack_for_preview_returns_none_for_existing_stack(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Existing stacks should bypass the create-with-provider flow entirely."""
    module = load_script_module(monkeypatch, "run_pulumi_preview")
    pulumi_dir = tmp_path / "pulumi"
    pulumi_dir.mkdir()
    calls: list[list[str]] = []

    def fake_run(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, stdout="")

    monkeypatch.setattr(module, "run", fake_run)
    result = module._select_stack_for_preview(
        pulumi_dir,
        "dev",
        env={"PULUMI_BACKEND_URL": "file:///tmp/backend"},
        uses_file_backend=True,
        secrets_provider="awskms://alias/example?region=eu-central-1",
    )

    assert result is None, (  # nosec B101
        f"expected existing stack select to return None, got {result}"
    )
    expected_calls = [
        [
            "pulumi",
            "-C",
            str(pulumi_dir),
            "stack",
            "select",
            "dev",
            "--non-interactive",
        ]
    ]
    assert calls == expected_calls, f"unexpected stack select calls: {calls!r}"  # nosec B101


def test_run_pulumi_preview_main_keeps_shared_backends_read_only(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Fail fast instead of creating typo stacks in shared preview backends."""
    module = load_script_module(monkeypatch, "run_pulumi_preview")
    repo_dir = tmp_path / "repo"
    pulumi_dir = repo_dir / "pulumi"
    policy_dir = repo_dir / "policy"
    preview_dir = repo_dir / ".artifacts" / "pulumi-preview"
    preview_dir.mkdir(parents=True)
    pulumi_dir.mkdir()
    policy_dir.mkdir()
    monkeypatch.setattr(module, "repo_root", lambda _: repo_dir)
    monkeypatch.setenv("PULUMI_BACKEND_URL", "s3://shared-backend")
    monkeypatch.setattr(module, "discover_stacks", lambda *args: ["missing-stack"])

    run_calls: list[tuple[list[str], dict[str, str]]] = []

    def fake_run(command, **kwargs):
        env = kwargs.get("env", {})
        run_calls.append((command, env))
        if command[0] == "pulumi" and command[3:6] == [
            "stack",
            "select",
            "missing-stack",
        ]:
            return subprocess.CompletedProcess(
                command,
                255,
                stderr="error: no stack named missing-stack found\n",
            )
        return subprocess.CompletedProcess(command, 0, stdout="")

    monkeypatch.setattr(module, "run", fake_run)
    assert module.main() == 255  # nosec B101

    error_output = capsys.readouterr().err
    assert "shared-backend previews will not create missing stacks" in error_output  # nosec B101
    assert "no stack named missing-stack found" in error_output  # nosec B101
    selected_missing_stack = any(
        command[3:7] == ["stack", "select", "missing-stack", "--non-interactive"]
        for command, _ in run_calls
    )
    created_stack = any("--create" in command for command, _ in run_calls)
    assert selected_missing_stack  # nosec B101
    assert not created_stack  # nosec B101


def test_run_pulumi_preview_main_returns_file_backend_select_failures(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Require an explicit KMS secrets provider before creating file-backed stacks."""
    module = load_script_module(monkeypatch, "run_pulumi_preview")
    repo_dir = tmp_path / "repo"
    pulumi_dir = repo_dir / "pulumi"
    policy_dir = repo_dir / "policy"
    preview_dir = repo_dir / ".artifacts" / "pulumi-preview"
    preview_dir.mkdir(parents=True)
    pulumi_dir.mkdir()
    policy_dir.mkdir()
    monkeypatch.setattr(module, "repo_root", lambda _: repo_dir)
    monkeypatch.delenv("PULUMI_BACKEND_URL", raising=False)
    monkeypatch.delenv("PULUMI_SECRETS_PROVIDER", raising=False)
    monkeypatch.setattr(module, "discover_stacks", lambda *args: ["dev"])

    run_calls: list[list[str]] = []

    def fake_run(command, **kwargs):
        run_calls.append(command)
        if command[0] == "pulumi" and command[3:6] == ["stack", "select", "dev"]:
            return subprocess.CompletedProcess(
                command,
                1,
                stderr="error: no stack named dev found\n",
            )
        return subprocess.CompletedProcess(command, 0, stdout="")

    monkeypatch.setattr(module, "run", fake_run)
    assert module.main() == 1  # nosec B101

    error_output = capsys.readouterr().err
    assert "file-backed previews require PULUMI_SECRETS_PROVIDER" in error_output  # nosec B101
    assert "shared-backend previews will not create missing stacks" not in error_output  # nosec B101
    selected_dev_stack = any(
        command[3:7] == ["stack", "select", "dev", "--non-interactive"]
        for command in run_calls
    )
    assert selected_dev_stack  # nosec B101


def test_select_stack_for_preview_surfaces_stack_init_failures(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Propagate init failures after a missing file-backed stack selection."""
    module = load_script_module(monkeypatch, "run_pulumi_preview")
    pulumi_dir = tmp_path / "pulumi"
    pulumi_dir.mkdir()

    def fake_run(command, **kwargs):
        if command[0] == "pulumi" and command[3:6] == ["stack", "select", "dev"]:
            return subprocess.CompletedProcess(
                command,
                1,
                stderr="error: no stack named dev found\n",
            )
        if command[0] == "pulumi" and command[3:6] == ["stack", "init", "dev"]:
            return subprocess.CompletedProcess(
                command,
                255,
                stderr="error: access denied to KMS key\n",
            )
        return subprocess.CompletedProcess(command, 0, stdout="")

    monkeypatch.setattr(module, "run", fake_run)
    result = module._select_stack_for_preview(
        pulumi_dir,
        "dev",
        env={"PULUMI_BACKEND_URL": "file:///tmp/backend"},
        uses_file_backend=True,
        secrets_provider="awskms://alias/example?region=eu-central-1",
    )

    assert result == 255
    assert "access denied to KMS key" in capsys.readouterr().err


def test_select_stack_for_preview_handles_empty_stderr_error_paths(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Cover the stderr-free branches for shared, missing-provider, and init errors."""
    module = load_script_module(monkeypatch, "run_pulumi_preview")
    pulumi_dir = tmp_path / "pulumi"
    pulumi_dir.mkdir()

    def shared_run(command, **kwargs):
        if command[0] == "pulumi" and command[3:6] == ["stack", "select", "dev"]:
            return subprocess.CompletedProcess(command, 1, stderr="")
        return subprocess.CompletedProcess(command, 0, stdout="")

    monkeypatch.setattr(module, "run", shared_run)
    assert (
        module._select_stack_for_preview(
            pulumi_dir,
            "dev",
            env={"PULUMI_BACKEND_URL": "s3://shared-backend"},
            uses_file_backend=False,
            secrets_provider="awskms://alias/example?region=eu-central-1",
        )
        == 1
    )

    def missing_provider_run(command, **kwargs):
        if command[0] == "pulumi" and command[3:6] == ["stack", "select", "dev"]:
            return subprocess.CompletedProcess(command, 1, stderr="")
        return subprocess.CompletedProcess(command, 0, stdout="")

    monkeypatch.setattr(module, "run", missing_provider_run)
    assert (
        module._select_stack_for_preview(
            pulumi_dir,
            "dev",
            env={"PULUMI_BACKEND_URL": "file:///tmp/backend"},
            uses_file_backend=True,
            secrets_provider="",
        )
        == 1
    )

    def init_failure_run(command, **kwargs):
        if command[0] == "pulumi" and command[3:6] == ["stack", "select", "dev"]:
            return subprocess.CompletedProcess(command, 1, stderr="")
        if command[0] == "pulumi" and command[3:6] == ["stack", "init", "dev"]:
            return subprocess.CompletedProcess(command, 1, stderr="")
        return subprocess.CompletedProcess(command, 0, stdout="")

    monkeypatch.setattr(module, "run", init_failure_run)
    assert (
        module._select_stack_for_preview(
            pulumi_dir,
            "dev",
            env={"PULUMI_BACKEND_URL": "file:///tmp/backend"},
            uses_file_backend=True,
            secrets_provider="awskms://alias/example?region=eu-central-1",
        )
        == 1
    )
