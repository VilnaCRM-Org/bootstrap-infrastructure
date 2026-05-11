#!/usr/bin/env python3
from __future__ import annotations

import argparse
from collections.abc import Sequence
from typing import Any, cast

import _well_architected_recording as _recording

dt = _recording.dt
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
STRUCTURED_EVIDENCE_MAX_AGE_DAYS = _recording.STRUCTURED_EVIDENCE_MAX_AGE_DAYS
_load_report = _recording.load_report
_check_by_name = _recording.check_by_name
_markdown_cell = _recording.markdown_cell
_markdown_list = _recording.markdown_list
_table = _recording.markdown_table
_parse_iso_date_or_timestamp = _recording.parse_iso_date_or_timestamp
_validate_choice = _recording.validate_choice
_validate_structured_dates = _recording.validate_structured_dates


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


def render_observation(report: dict[str, Any], args: argparse.Namespace) -> str:
    route = _passed_route_evidence(report)
    queue = cast(dict[str, Any], route.get("sqsQueue", {}))
    protocols = ", ".join(str(item) for item in route.get("subscriptionProtocols", []))
    action_lines = _markdown_list(args.action, "No follow-up actions recorded.")

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
    queue = cast(dict[str, Any], route.get("sqsQueue", {}))
    return {
        **{field: route.get(field) for field in ALERT_ROUTE_OBSERVATION_ROUTE_FIELDS},
        "sqsQueue": {
            field: queue.get(field) for field in ALERT_ROUTE_OBSERVATION_QUEUE_FIELDS
        },
    }


def _queue_observation(route: dict[str, Any]) -> dict[str, object]:
    """Return volatile queue-depth fields as observation-only metadata."""
    queue = cast(dict[str, Any], route.get("sqsQueue", {}))
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
    _recording.add_recording_output_arguments(parser, include_environment=True)
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
    return _recording.run_recording_cli(
        build_parser(),
        argv,
        render_markdown=render_observation,
        render_json=structured_observation,
    )


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
