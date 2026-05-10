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
