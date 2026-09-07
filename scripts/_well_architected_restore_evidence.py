from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
from typing import Any

import _well_architected_recording as _recording
import _well_architected_structured_evidence as _structured_evidence
from _script_support import run
from _well_architected_evidence_common import (
    OptionalOwnerEvidenceSpec,
    Runner,
    _check,
    _non_empty_text,
    _normalized_text,
    _optional_owner_evidence_coverage,
    _run_json,
)

PRODUCTION_DR_OWNER_REQUIRED_FIELDS = _recording.PRODUCTION_DR_OWNER_REQUIRED_FIELDS
PRODUCTION_DR_OWNER_RESTORE_FIELDS = _recording.PRODUCTION_DR_OWNER_RESTORE_FIELDS
PRODUCTION_DR_OWNER_TEXT_FIELDS = _recording.PRODUCTION_DR_OWNER_TEXT_FIELDS
PRODUCTION_DR_OWNER_ALLOWED_APPROVALS = _recording.PRODUCTION_DR_OWNER_ALLOWED_APPROVALS
PRODUCTION_DR_OWNER_SUMMARY_FIELDS = _recording.PRODUCTION_DR_OWNER_SUMMARY_FIELDS
RESTORE_DRILL_REQUIRED_FIELDS = (
    "workload",
    "environment",
    "completedAt",
    "sourceRecoveryPointArn",
    "targetRestoreLocation",
    "validationResult",
    "cleanupConfirmed",
)
_parse_reviewed_at = _structured_evidence._parse_reviewed_at
_read_required_structured_evidence = (
    _structured_evidence._read_required_structured_evidence
)
_structured_evidence_mismatch_blockers = (
    _structured_evidence._structured_evidence_mismatch_blockers
)
_non_empty_string_list = _structured_evidence._non_empty_string_list


def aws_restore_jobs(days: int, *, runner: Runner = run) -> dict[str, object]:
    """Collect recent AWS Backup restore-job status counts as account context."""
    created_after = (
        dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    ok, statuses, error = _run_json(
        [
            "aws",
            "backup",
            "list-restore-jobs",
            "--by-created-after",
            created_after,
            "--query",
            "RestoreJobs[].Status",
            "--output",
            "json",
        ],
        runner=runner,
    )
    if not ok or not isinstance(statuses, list):
        return _check("aws_restore_jobs", status="unknown", blockers=[error])
    status_counts = {status: statuses.count(status) for status in sorted(set(statuses))}
    completed = status_counts.get("COMPLETED", 0)
    return _check(
        "aws_restore_jobs",
        status="passed" if completed else "failed",
        evidence={"windowDays": days, "statusCounts": status_counts},
        blockers=(
            [f"No completed AWS Backup restore jobs found in the last {days} days."]
            if not completed
            else []
        ),
    )


def _read_restore_drill_payload(
    evidence_path: Path,
) -> tuple[dict[str, Any], list[str]]:
    """Read and parse a restore-drill evidence payload."""
    try:
        payload = json.loads(evidence_path.read_text(encoding="utf-8"))
    except OSError as exc:
        return {}, [f"Unable to read restore-drill evidence: {exc}"]
    except json.JSONDecodeError as exc:
        return {}, [f"Restore-drill evidence is not valid JSON: {exc.msg}"]
    if not isinstance(payload, dict):
        return {}, ["Restore-drill evidence must be a JSON object."]
    return payload, []


def _restore_drill_payload_blockers(payload: dict[str, Any]) -> list[str]:
    """Return blockers for workload-scoped restore-drill evidence."""
    blockers: list[str] = [
        f"Restore-drill evidence is missing required field: {field}"
        for field in RESTORE_DRILL_REQUIRED_FIELDS
        if not payload.get(field)
    ]

    if payload.get("workload") != "bootstrap-infrastructure":
        blockers.append(
            "Restore-drill evidence must be scoped to the bootstrap-infrastructure "
            "workload."
        )
    if payload.get("validationResult") != "passed":
        blockers.append("Restore-drill evidence validationResult must be passed.")
    if payload.get("cleanupConfirmed") is not True:
        blockers.append("Restore-drill evidence must confirm cleanup.")

    return blockers


def _restore_drill_evidence_payload(payload: dict[str, Any]) -> dict[str, object]:
    """Return the non-secret restore-drill evidence fields."""
    return {
        "workload": payload.get("workload"),
        "environment": payload.get("environment"),
        "completedAt": payload.get("completedAt"),
        "targetRestoreLocation": payload.get("targetRestoreLocation"),
        "validationResult": payload.get("validationResult"),
        "cleanupConfirmed": payload.get("cleanupConfirmed") is True,
    }


def restore_drill_evidence(
    evidence_path: Path | None,
    production_dr_owner_evidence: Path | None = None,
) -> dict[str, object]:
    """Validate a workload-scoped restore-drill evidence record."""
    if evidence_path is None:
        return _check(
            "restore_drill_evidence",
            status="missing",
            blockers=[
                "RESTORE_DRILL_EVIDENCE path is required for workload-scoped "
                "restore evidence."
            ],
        )

    payload, read_blockers = _read_restore_drill_payload(evidence_path)
    restore_evidence = _restore_drill_evidence_payload(payload)
    owner_summary, owner_blockers = _production_dr_owner_coverage(
        production_dr_owner_evidence,
        restore_evidence,
    )
    blockers = [
        *read_blockers,
        *_restore_drill_payload_blockers(payload),
        *owner_blockers,
    ]
    evidence = restore_evidence
    if owner_summary:
        evidence["productionDrOwnerEvidence"] = owner_summary
    return _check(
        "restore_drill_evidence",
        status="passed" if not blockers else "failed",
        evidence=evidence,
        blockers=blockers,
    )


def _production_dr_owner_coverage(
    evidence_path: Path | None,
    restore_evidence: dict[str, object],
) -> tuple[dict[str, object], list[str]]:
    """Return approved production DR owner metadata for restore evidence."""
    return _optional_owner_evidence_coverage(
        evidence_path,
        spec=PRODUCTION_DR_OWNER_SPEC,
        live_evidence=restore_evidence,
    )


def _production_dr_owner_payload_blockers(
    payload: dict[str, Any],
    restore_evidence: dict[str, object],
) -> list[str]:
    """Return blockers for production DR owner evidence."""
    blockers: list[str] = []
    approval = _normalized_text(payload.get("approval"))
    if approval not in PRODUCTION_DR_OWNER_ALLOWED_APPROVALS:
        allowed = ", ".join(sorted(PRODUCTION_DR_OWNER_ALLOWED_APPROVALS))
        blockers.append(
            f"Production DR owner evidence approval must be one of: {allowed}."
        )
    for field in PRODUCTION_DR_OWNER_TEXT_FIELDS:
        if not _non_empty_text(payload.get(field)):
            blockers.append(f"Production DR owner evidence {field} must be non-empty.")
    if _parse_reviewed_at(payload.get("nextReviewDate")) is None:
        blockers.append("Production DR owner evidence nextReviewDate must be ISO-8601.")
    if not _non_empty_string_list(payload.get("evidence")):
        blockers.append(
            "Production DR owner evidence must include non-empty evidence strings."
        )
    if not _non_empty_text(payload.get("remediationPlan")):
        blockers.append(
            "Production DR owner evidence remediationPlan must be non-empty."
        )
    blockers.extend(_production_dr_owner_expiry_blockers(payload.get("expiresAt")))
    blockers.extend(_production_dr_owner_restore_blockers(payload, restore_evidence))
    return blockers


def _production_dr_owner_expiry_blockers(expires_at_value: object) -> list[str]:
    """Return blockers for production DR owner evidence expiry."""
    expires_at = _parse_reviewed_at(expires_at_value)
    if expires_at is None:
        return ["Production DR owner evidence expiresAt must be ISO-8601."]
    now = dt.datetime.now(dt.timezone.utc)
    if expires_at <= now:
        return ["Production DR owner evidence is expired."]
    return []


def _production_dr_owner_restore_blockers(
    payload: dict[str, Any],
    restore_evidence: dict[str, object],
) -> list[str]:
    """Return blockers when production DR evidence references stale restore data."""
    return _structured_evidence_mismatch_blockers(
        payload.get("restoreDrillEvidence"),
        restore_evidence,
        PRODUCTION_DR_OWNER_RESTORE_FIELDS,
        object_error=(
            "Production DR owner evidence restoreDrillEvidence must be an object."
        ),
        mismatch_message=(
            "Production DR owner evidence restoreDrillEvidence does not match current "
            "restore evidence fields"
        ),
    )


def _production_dr_owner_summary(
    evidence_path: Path,
    payload: dict[str, Any],
) -> dict[str, object]:
    """Return non-secret production DR owner evidence metadata."""
    return {
        "path": str(evidence_path),
        **{
            field: str(payload.get(field) or "")
            for field in PRODUCTION_DR_OWNER_SUMMARY_FIELDS
        },
    }


PRODUCTION_DR_OWNER_SPEC = OptionalOwnerEvidenceSpec(
    label="Production DR owner evidence",
    required_fields=PRODUCTION_DR_OWNER_REQUIRED_FIELDS,
    payload_blockers=_production_dr_owner_payload_blockers,
    summary=_production_dr_owner_summary,
    # Policy validity uses its mandatory expiry; live restore health stays separate.
    max_review_age_days=None,
)
