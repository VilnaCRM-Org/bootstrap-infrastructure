#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any, cast

PRODUCTION_DR_OWNER_ALLOWED_APPROVALS = frozenset(
    {"approved", "approved_exception", "accepted_risk"}
)
PRODUCTION_DR_OWNER_RESTORE_FIELDS = (
    "workload",
    "environment",
    "completedAt",
    "targetRestoreLocation",
    "validationResult",
    "cleanupConfirmed",
)
STRUCTURED_EVIDENCE_MAX_AGE_DAYS = 30


def _load_report(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("evidence report must be a JSON object")
    return payload


def _check_by_name(report: dict[str, Any], name: str) -> dict[str, Any]:
    for item in report.get("checks", []):
        check = cast("dict[str, Any]", item)
        if check.get("name") == name:
            return check
    raise ValueError(f"evidence report does not contain check {name!r}")


def _restore_drill_evidence(report: dict[str, Any]) -> dict[str, Any]:
    check = _check_by_name(report, "restore_drill_evidence")
    if check.get("status") != "passed":
        blockers = ", ".join(str(item) for item in check.get("blockers", []))
        detail = f": {blockers}" if blockers else ""
        raise ValueError(
            f"restore_drill_evidence must pass before production DR evidence{detail}"
        )
    evidence = check.get("evidence")
    if not isinstance(evidence, dict):
        raise ValueError("restore_drill_evidence evidence must be a JSON object")
    return evidence


def _markdown_cell(value: object) -> str:
    return str(value).replace("\n", " ").replace("|", "\\|")


def _table(rows: Sequence[tuple[str, object]]) -> str:
    lines = ["| Field | Value |", "| --- | --- |"]
    lines.extend(
        f"| {_markdown_cell(key)} | {_markdown_cell(value)} |" for key, value in rows
    )
    return "\n".join(lines)


def render_owner_evidence(report: dict[str, Any], args: argparse.Namespace) -> str:
    restore = _restore_drill_evidence(report)
    actions = args.action or ["No follow-up actions recorded."]
    action_lines = "\n".join(f"- {_markdown_cell(action)}" for action in actions)

    return "\n".join(
        [
            f"# Production DR Owner Evidence {args.review_date}",
            "",
            "This production DR owner record is generated from metadata-only "
            "Well-Architected collector output and completed with production-owner "
            "review fields. Do not add credentials, secret values, private incident "
            "notes, customer data, screenshots containing private identities, or "
            "raw account exports.",
            "",
            "## Review Metadata",
            "",
            _table(
                [
                    ("Workload", args.workload),
                    ("Environment", args.environment),
                    ("Review date", args.review_date),
                    ("Reviewer", args.reviewer),
                    ("Production recovery owner", args.production_owner),
                    ("Escalation path", args.escalation_path),
                    ("RTO target", args.rto_target),
                    ("RPO target", args.rpo_target),
                    ("Recovery order", args.recovery_order),
                    ("Communications expectations", args.communications_plan),
                    ("Latest accepted drill", args.latest_accepted_drill),
                    ("Next review or drill date", args.next_review_date),
                    ("Evidence retention location", args.evidence_retention_location),
                    ("Approval decision", args.approval),
                    ("Evidence expiry", args.expiry_date or "Not specified"),
                    ("Evidence source generated at", report.get("generatedAt", "")),
                ]
            ),
            "",
            "## Collector Restore Evidence",
            "",
            _table(
                [
                    ("Restore workload", restore.get("workload", "")),
                    ("Restore environment", restore.get("environment", "")),
                    ("Completed at", restore.get("completedAt", "")),
                    (
                        "Target restore location",
                        restore.get("targetRestoreLocation", ""),
                    ),
                    ("Validation result", restore.get("validationResult", "")),
                    ("Cleanup confirmed", restore.get("cleanupConfirmed", "")),
                ]
            ),
            "",
            "## Follow-Up Actions",
            "",
            action_lines,
            "",
        ]
    )


def structured_owner_evidence(
    report: dict[str, Any], args: argparse.Namespace
) -> dict[str, object]:
    """Return machine-readable, non-secret production DR owner evidence."""
    restore = _restore_drill_evidence(report)
    if not args.action:
        raise ValueError(
            "structured production DR owner evidence requires at least one --action"
        )
    _validate_choice(
        "Production DR owner evidence approval",
        args.approval,
        PRODUCTION_DR_OWNER_ALLOWED_APPROVALS,
    )
    _validate_structured_dates(
        "Production DR owner evidence", args.review_date, args.expiry_date
    )
    _validate_iso_date(
        "Production DR owner evidence next-review-date",
        args.next_review_date,
    )
    actions = args.action
    return {
        "workload": args.workload,
        "environment": args.environment,
        "owner": args.production_owner,
        "approvedBy": args.reviewer,
        "reviewedAt": args.review_date,
        "expiresAt": args.expiry_date,
        "rtoTarget": args.rto_target,
        "rpoTarget": args.rpo_target,
        "escalationPath": args.escalation_path,
        "recoveryOrder": args.recovery_order,
        "communicationsPlan": args.communications_plan,
        "latestAcceptedDrill": args.latest_accepted_drill,
        "nextReviewDate": args.next_review_date,
        "evidenceRetentionLocation": args.evidence_retention_location,
        "approval": args.approval,
        "evidence": actions,
        "remediationPlan": " ".join(actions),
        "restoreDrillEvidence": {
            field: restore.get(field) for field in PRODUCTION_DR_OWNER_RESTORE_FIELDS
        },
    }


def _validate_choice(field: str, value: str, allowed_values: frozenset[str]) -> None:
    normalized = value.strip().lower()
    if normalized in allowed_values:
        return
    allowed = ", ".join(sorted(allowed_values))
    raise ValueError(f"{field} must be one of: {allowed}.")


def _validate_structured_dates(
    label: str, reviewed_at_value: str, expires_at_value: str
) -> None:
    reviewed_at = _parse_iso_date_or_timestamp(reviewed_at_value)
    if reviewed_at is None:
        raise ValueError(f"{label} review-date must be an ISO-8601 date or timestamp.")
    now = dt.datetime.now(dt.timezone.utc)
    if reviewed_at > now + dt.timedelta(minutes=5):
        raise ValueError(f"{label} review-date is in the future.")
    if now - reviewed_at > dt.timedelta(days=STRUCTURED_EVIDENCE_MAX_AGE_DAYS):
        raise ValueError(
            f"{label} review-date is older than "
            f"{STRUCTURED_EVIDENCE_MAX_AGE_DAYS} days."
        )
    if not expires_at_value.strip():
        raise ValueError(f"{label} JSON output requires --expiry-date.")
    expires_at = _parse_iso_date_or_timestamp(expires_at_value)
    if expires_at is None:
        raise ValueError(f"{label} expiry-date must be an ISO-8601 date or timestamp.")
    if expires_at <= now:
        raise ValueError(f"{label} expiry-date is expired.")


def _validate_iso_date(label: str, value: str) -> None:
    if _parse_iso_date_or_timestamp(value) is None:
        raise ValueError(f"{label} must be an ISO-8601 date or timestamp.")


def _parse_iso_date_or_timestamp(value: str) -> dt.datetime | None:
    """Parse an ISO date or timestamp into an aware UTC datetime."""
    try:
        if "T" not in value:
            parsed_date = dt.date.fromisoformat(value)
            return dt.datetime.combine(
                parsed_date,
                dt.time.min,
                tzinfo=dt.timezone.utc,
            )
        parsed_datetime = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed_datetime.tzinfo is None:
        return parsed_datetime.replace(tzinfo=dt.timezone.utc)
    return parsed_datetime.astimezone(dt.timezone.utc)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Render non-secret production DR owner evidence from "
            "Well-Architected collector restore evidence."
        )
    )
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--json-output", type=Path)
    parser.add_argument(
        "--review-date", default=dt.datetime.now(dt.timezone.utc).date().isoformat()
    )
    parser.add_argument("--workload", default="bootstrap-infrastructure")
    parser.add_argument("--environment", default="prod")
    parser.add_argument("--reviewer", required=True)
    parser.add_argument("--production-owner", required=True)
    parser.add_argument("--escalation-path", required=True)
    parser.add_argument("--rto-target", required=True)
    parser.add_argument("--rpo-target", required=True)
    parser.add_argument("--recovery-order", required=True)
    parser.add_argument("--communications-plan", required=True)
    parser.add_argument("--latest-accepted-drill", required=True)
    parser.add_argument("--next-review-date", required=True)
    parser.add_argument("--evidence-retention-location", required=True)
    parser.add_argument("--approval", required=True)
    parser.add_argument("--expiry-date", default="")
    parser.add_argument("--action", action="append", default=[])
    parser.add_argument("--force", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.output.exists() and not args.force:
        print(f"error: output already exists: {args.output}", file=sys.stderr)
        return 2
    if args.json_output and args.json_output.exists() and not args.force:
        print(f"error: JSON output already exists: {args.json_output}", file=sys.stderr)
        return 2

    try:
        report = _load_report(args.evidence)
        markdown = render_owner_evidence(report, args)
        json_payload = (
            structured_owner_evidence(report, args) if args.json_output else None
        )
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(markdown, encoding="utf-8")
    if args.json_output:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(
            f"{json.dumps(json_payload, indent=2, sort_keys=True)}\n",
            encoding="utf-8",
        )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
