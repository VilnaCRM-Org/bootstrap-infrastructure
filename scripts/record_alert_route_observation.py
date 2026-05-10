#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any, cast

ALERT_ROUTE_OBSERVATION_ROUTE_FIELDS = (
    "topicArn",
    "encrypted",
    "subscriptionCount",
    "subscriptionProtocols",
)
ALERT_ROUTE_OBSERVATION_QUEUE_FIELDS = (
    "queueArn",
    "queueName",
    "messageRetentionSeconds",
    "visibilityTimeoutSeconds",
)
ALERT_ROUTE_OBSERVATION_QUEUE_OBSERVATION_FIELDS = (
    "visibleMessages",
    "notVisibleMessages",
    "delayedMessages",
)
ALERT_ROUTE_ALLOWED_DECISIONS = frozenset(
    {"accepted", "approved", "approved_exception", "accepted_risk"}
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


def _passed_route_evidence(report: dict[str, Any]) -> dict[str, Any]:
    check = _check_by_name(report, "aws_sns_alert_route")
    if check.get("status") != "passed":
        blockers = ", ".join(str(item) for item in check.get("blockers", []))
        detail = f": {blockers}" if blockers else ""
        raise ValueError(f"aws_sns_alert_route must pass before observation{detail}")
    evidence = check.get("evidence")
    if not isinstance(evidence, dict):
        raise ValueError("aws_sns_alert_route evidence must be a JSON object")
    return evidence


def _markdown_cell(value: object) -> str:
    return str(value).replace("\n", " ").replace("|", "\\|")


def _table(rows: Sequence[tuple[str, object]]) -> str:
    lines = ["| Field | Value |", "| --- | --- |"]
    lines.extend(
        f"| {_markdown_cell(key)} | {_markdown_cell(value)} |" for key, value in rows
    )
    return "\n".join(lines)


def render_observation(report: dict[str, Any], args: argparse.Namespace) -> str:
    route = _passed_route_evidence(report)
    queue = cast("dict[str, Any]", route.get("sqsQueue", {}))
    protocols = ", ".join(str(item) for item in route.get("subscriptionProtocols", []))
    actions = args.action or ["No follow-up actions recorded."]
    action_lines = "\n".join(f"- {_markdown_cell(action)}" for action in actions)

    return "\n".join(
        [
            f"# Alert Route Observation {args.review_date}",
            "",
            "This monthly observation record is generated from the metadata-only "
            "Well-Architected collector output and completed with human review "
            "fields. Do not add alert payloads, stack exports, credentials, "
            "tokens, private incident notes, or access-key material.",
            "",
            "## Review Metadata",
            "",
            _table(
                [
                    ("Workload", args.workload),
                    ("Environment", args.environment),
                    ("Review date", args.review_date),
                    ("Reviewer", args.reviewer),
                    ("Route owner", args.route_owner),
                    ("Downstream route", args.downstream_route),
                    ("Severity expectations", args.severity_expectations),
                    ("Fallback behavior", args.fallback),
                    ("Review decision", args.decision),
                    ("Evidence source generated at", report.get("generatedAt", "")),
                ]
            ),
            "",
            "## Collector Route Evidence",
            "",
            _table(
                [
                    ("SNS topic ARN", route.get("topicArn", "")),
                    ("Encrypted", route.get("encrypted", "")),
                    ("Subscription count", route.get("subscriptionCount", "")),
                    ("Subscription protocols", protocols),
                ]
            ),
            "",
            "## Queue Observation",
            "",
            _table(
                [
                    ("Queue name", queue.get("queueName", "")),
                    ("Queue ARN", queue.get("queueArn", "")),
                    ("Visible messages", queue.get("visibleMessages", "")),
                    ("Not visible messages", queue.get("notVisibleMessages", "")),
                    ("Delayed messages", queue.get("delayedMessages", "")),
                    ("Retention seconds", queue.get("messageRetentionSeconds", "")),
                    (
                        "Visibility timeout seconds",
                        queue.get("visibilityTimeoutSeconds", ""),
                    ),
                ]
            ),
            "",
            "## Follow-Up Actions",
            "",
            action_lines,
            "",
        ]
    )


def structured_observation(
    report: dict[str, Any], args: argparse.Namespace
) -> dict[str, object]:
    """Return machine-readable, non-secret alert-route observation evidence."""
    route = _passed_route_evidence(report)
    if not args.action:
        raise ValueError(
            "structured alert-route observation requires at least one --action"
        )
    _validate_choice(
        "Alert-route observation decision",
        args.decision,
        ALERT_ROUTE_ALLOWED_DECISIONS,
    )
    _validate_structured_dates(
        "Alert-route observation", args.review_date, args.expiry_date
    )
    actions = args.action
    return {
        "workload": args.workload,
        "environment": args.environment,
        "owner": args.route_owner,
        "approvedBy": args.reviewer,
        "reviewedAt": args.review_date,
        "expiresAt": args.expiry_date,
        "downstreamRoute": args.downstream_route,
        "severityExpectations": args.severity_expectations,
        "fallback": args.fallback,
        "decision": args.decision,
        "evidence": actions,
        "remediationPlan": " ".join(actions),
        "routeEvidence": _structured_route_evidence(route),
        "queueObservation": _queue_observation(route),
    }


def _structured_route_evidence(route: dict[str, Any]) -> dict[str, object]:
    """Return stable route fields that the collector can compare later."""
    queue = cast("dict[str, Any]", route.get("sqsQueue", {}))
    return {
        **{field: route.get(field) for field in ALERT_ROUTE_OBSERVATION_ROUTE_FIELDS},
        "sqsQueue": {
            field: queue.get(field) for field in ALERT_ROUTE_OBSERVATION_QUEUE_FIELDS
        },
    }


def _queue_observation(route: dict[str, Any]) -> dict[str, object]:
    """Return volatile queue-depth fields as observation-only metadata."""
    queue = cast("dict[str, Any]", route.get("sqsQueue", {}))
    return {
        field: queue.get(field)
        for field in ALERT_ROUTE_OBSERVATION_QUEUE_OBSERVATION_FIELDS
    }


def _validate_choice(field: str, value: str, allowed_values: frozenset[str]) -> None:
    """Reject structured evidence choices the collector would later reject."""
    normalized = value.strip().lower()
    if normalized in allowed_values:
        return
    allowed = ", ".join(sorted(allowed_values))
    raise ValueError(f"{field} must be one of: {allowed}.")


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
            "Render a non-secret monthly alert-route observation from "
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
    parser.add_argument("--environment", default="test")
    parser.add_argument("--reviewer", required=True)
    parser.add_argument("--route-owner", required=True)
    parser.add_argument("--downstream-route", required=True)
    parser.add_argument("--severity-expectations", required=True)
    parser.add_argument("--fallback", required=True)
    parser.add_argument("--decision", required=True)
    parser.add_argument("--expiry-date", default="")
    parser.add_argument("--action", action="append", default=[])
    parser.add_argument("--force", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.output.exists() and not args.force:
        print(f"error: output already exists: {args.output}", file=sys.stderr)
        return 2

    try:
        report = _load_report(args.evidence)
        markdown = render_observation(report, args)
        json_payload = (
            structured_observation(report, args) if args.json_output else None
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
