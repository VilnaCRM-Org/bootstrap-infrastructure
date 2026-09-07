#!/usr/bin/env python3
from __future__ import annotations

import argparse
from collections.abc import Sequence
from typing import Any

import _well_architected_recording as _recording

dt = _recording.dt
PRODUCTION_DR_OWNER_ALLOWED_APPROVALS = _recording.PRODUCTION_DR_OWNER_ALLOWED_APPROVALS
PRODUCTION_DR_OWNER_RESTORE_FIELDS = _recording.PRODUCTION_DR_OWNER_RESTORE_FIELDS
STRUCTURED_EVIDENCE_MAX_AGE_DAYS = _recording.STRUCTURED_EVIDENCE_MAX_AGE_DAYS
_load_report = _recording.load_report
_check_by_name = _recording.check_by_name
_markdown_cell = _recording.markdown_cell
_markdown_list = _recording.markdown_list
_table = _recording.markdown_table
_parse_iso_date_or_timestamp = _recording.parse_iso_date_or_timestamp
_validate_choice = _recording.validate_choice
_validate_structured_dates = _recording.validate_structured_dates


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


def render_owner_evidence(report: dict[str, Any], args: argparse.Namespace) -> str:
    restore = _restore_drill_evidence(report)
    action_lines = _markdown_list(args.action, "No follow-up actions recorded.")

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
        "Production DR owner evidence",
        args.review_date,
        args.expiry_date,
        max_review_age_days=None,
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


def _validate_iso_date(label: str, value: str) -> None:
    if _parse_iso_date_or_timestamp(value) is None:
        raise ValueError(f"{label} must be an ISO-8601 date or timestamp.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Render non-secret production DR owner evidence from "
            "Well-Architected collector restore evidence."
        )
    )
    _recording.add_recording_output_arguments(
        parser, include_environment=True, environment_default="prod"
    )
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
    return _recording.run_recording_cli(
        build_parser(),
        argv,
        render_markdown=render_owner_evidence,
        render_json=structured_owner_evidence,
    )


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
