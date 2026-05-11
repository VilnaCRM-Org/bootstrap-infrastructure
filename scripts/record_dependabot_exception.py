#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any, cast

DEPENDABOT_EXCEPTION_ALLOWED_APPROVALS = frozenset(
    {"approved", "approved_exception", "accepted_risk"}
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


def _dependabot_alert_check(
    report: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    check = _check_by_name(report, "github_dependabot_alerts")
    evidence = check.get("evidence")
    if not isinstance(evidence, dict):
        raise ValueError("github_dependabot_alerts evidence must be a JSON object")
    return check, evidence


def _markdown_cell(value: object) -> str:
    return str(value).replace("\n", " ").replace("|", "\\|")


def _table(rows: Sequence[tuple[str, object]]) -> str:
    lines = ["| Field | Value |", "| --- | --- |"]
    lines.extend(
        f"| {_markdown_cell(key)} | {_markdown_cell(value)} |" for key, value in rows
    )
    return "\n".join(lines)


def _alert_number_text(numbers: Sequence[int]) -> str:
    return ", ".join(f"#{number}" for number in numbers)


def _open_alert_numbers(evidence: dict[str, Any]) -> list[int]:
    values = evidence.get("openAlertNumbers")
    if not isinstance(values, list):
        raise ValueError("github_dependabot_alerts openAlertNumbers must be a list")
    numbers: list[int] = []
    for value in values:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(
                "github_dependabot_alerts openAlertNumbers must contain integers"
            )
        numbers.append(value)
    return sorted(numbers)


def _required_text(field: str, value: object) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"github_dependabot_alerts {field} is required")
    return text


def render_exception(report: dict[str, Any], args: argparse.Namespace) -> str:
    check, evidence = _dependabot_alert_check(report)
    alert_numbers = _open_alert_numbers(evidence)
    notes = args.evidence_note or ["No exception evidence notes recorded."]
    note_lines = "\n".join(f"- {_markdown_cell(note)}" for note in notes)

    return "\n".join(
        [
            f"# Dependabot Exception Review {args.review_date}",
            "",
            "This exception record is generated from metadata-only Well-Architected "
            "collector output and completed with security-owner review fields. Do "
            "not add credentials, exploit details, private incident notes, tokens, "
            "or raw dependency reports.",
            "",
            "## Review Metadata",
            "",
            _table(
                [
                    ("Workload", args.workload),
                    ("Review date", args.review_date),
                    ("Reviewer", args.reviewer),
                    ("Owner", args.owner),
                    ("Approval", args.approval),
                    ("Reason", args.reason),
                    ("Remediation plan", args.remediation_plan),
                    ("Evidence expiry", args.expiry_date or "Not specified"),
                    ("Evidence source generated at", report.get("generatedAt", "")),
                ]
            ),
            "",
            "## Collector Alert Evidence",
            "",
            _table(
                [
                    ("Collector check status", check.get("status", "")),
                    ("Dependency", evidence.get("dependencyName", "")),
                    ("Manifest path", evidence.get("manifestPath", "")),
                    ("Open alert numbers", _alert_number_text(alert_numbers)),
                    (
                        "Unexcepted open alert numbers",
                        _alert_number_text(
                            _int_list(evidence.get("unexceptedOpenAlertNumbers"))
                        ),
                    ),
                    ("Open alert count", evidence.get("openAlertCount", "")),
                    (
                        "Unexcepted open alert count",
                        evidence.get("unexceptedOpenAlertCount", ""),
                    ),
                ]
            ),
            "",
            "## Evidence Notes",
            "",
            note_lines,
            "",
        ]
    )


def structured_exception(
    report: dict[str, Any], args: argparse.Namespace
) -> dict[str, object]:
    """Return machine-readable, non-secret Dependabot exception evidence."""
    _check, evidence = _dependabot_alert_check(report)
    alert_numbers = _open_alert_numbers(evidence)
    if not alert_numbers:
        raise ValueError(
            "structured Dependabot exception requires at least one open alert number"
        )
    if not args.evidence_note:
        raise ValueError("structured Dependabot exception requires --evidence-note")
    _validate_choice(args.approval)
    _validate_structured_dates(
        "Dependabot exception", args.review_date, args.expiry_date
    )
    return {
        "workload": args.workload,
        "owner": args.owner,
        "approvedBy": args.reviewer,
        "reviewedAt": args.review_date,
        "expiresAt": args.expiry_date,
        "dependencyName": _required_text(
            "dependencyName", evidence.get("dependencyName")
        ),
        "manifestPath": _required_text("manifestPath", evidence.get("manifestPath")),
        "alertNumbers": alert_numbers,
        "approval": args.approval,
        "reason": args.reason,
        "remediationPlan": args.remediation_plan,
        "evidence": args.evidence_note,
    }


def _int_list(value: object) -> list[int]:
    if not isinstance(value, list):
        return []
    numbers: list[int] = []
    for item in value:
        if isinstance(item, bool) or not isinstance(item, int):
            return []
        numbers.append(item)
    return sorted(numbers)


def _validate_choice(value: str) -> None:
    """Reject structured evidence choices the collector would later reject."""
    normalized = value.strip().lower()
    if normalized in DEPENDABOT_EXCEPTION_ALLOWED_APPROVALS:
        return
    allowed = ", ".join(sorted(DEPENDABOT_EXCEPTION_ALLOWED_APPROVALS))
    raise ValueError(f"Dependabot exception approval must be one of: {allowed}.")


def _validate_structured_dates(
    label: str, reviewed_at_value: str, expires_at_value: str
) -> None:
    """Reject structured evidence dates the collector would later reject."""
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
            "Render a non-secret Dependabot exception review from "
            "Well-Architected collector evidence."
        )
    )
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--json-output", type=Path)
    parser.add_argument(
        "--review-date", default=dt.datetime.now(dt.timezone.utc).date().isoformat()
    )
    parser.add_argument("--workload", default="bootstrap-infrastructure")
    parser.add_argument("--reviewer", required=True)
    parser.add_argument("--owner", required=True)
    parser.add_argument("--approval", required=True)
    parser.add_argument("--reason", required=True)
    parser.add_argument("--remediation-plan", required=True)
    parser.add_argument("--expiry-date", default="")
    parser.add_argument("--evidence-note", action="append", default=[])
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
        markdown = render_exception(report, args)
        json_payload = structured_exception(report, args) if args.json_output else None
    except (OSError, ValueError) as exc:
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
