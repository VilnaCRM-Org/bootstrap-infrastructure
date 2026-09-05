#!/usr/bin/env python3
"""Render sanitized operations-alert issues and stable duplicate fingerprints."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

FINGERPRINT_VERSION = 2


@dataclass(frozen=True)
class IssueContext:
    """Non-secret metadata shared by the rendered GitHub issue body."""

    queue_name: str
    account_id: str
    region: str
    fingerprint: str


def load_json(value: object) -> dict[str, Any]:
    """Return a JSON object from a nested SNS/SQS string field."""
    if isinstance(value, dict):
        return {str(key): item for key, item in value.items()}
    if not isinstance(value, str) or not value:
        return {}
    try:
        loaded = json.loads(value)
    except json.JSONDecodeError:
        return {}
    if isinstance(loaded, dict):
        return {str(key): item for key, item in loaded.items()}
    return {}


def safe_value(value: object) -> str:
    """Return one sanitized metadata field for GitHub issue text."""
    if value in (None, ""):
        return "unknown"
    return str(value).replace("`", "'").replace("\n", " ")[:200]


def event_from_message(
    message: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Extract SNS and EventBridge metadata from one SQS message."""
    sns = load_json(message.get("Body"))
    return sns, load_json(sns.get("Message"))


def alert_messages(alerts: dict[str, Any]) -> list[dict[str, Any]]:
    """Return only well-formed SQS message objects from an alert batch."""
    messages = alerts.get("Messages")
    if not isinstance(messages, list):
        return []
    return [message for message in messages if isinstance(message, dict)]


def message_fields(message: dict[str, Any]) -> dict[str, object]:
    """Return sanitized field names and values for one alert occurrence."""
    sns, event = event_from_message(message)
    attributes = message.get("Attributes")
    attributes = attributes if isinstance(attributes, dict) else {}
    return {
        "sqsMessageId": message.get("MessageId"),
        "snsMessageId": sns.get("MessageId"),
        "sentTimestamp": attributes.get("SentTimestamp"),
        "eventSource": event.get("source"),
        "detailType": event.get("detail-type"),
        "eventTime": event.get("time") or sns.get("Timestamp"),
    }


_VOLATILE_DETAIL_KEYS = frozenset(
    {
        "backupJobId",
        "copyJobId",
        "eventID",
        "eventId",
        "eventTime",
        "id",
        "recoveryPointArn",
        "requestID",
        "requestId",
        "restoreJobId",
        "time",
        "x-amz-request-id",
        "xAmzRequestId",
    }
)


def stable_detail(value: object) -> object:
    """Return EventBridge detail content without per-occurrence metadata."""
    if isinstance(value, dict):
        return {
            str(key): stable_detail(item)
            for key, item in sorted(value.items())
            if str(key) not in _VOLATILE_DETAIL_KEYS
        }
    if isinstance(value, list):
        return [stable_detail(item) for item in value]
    if isinstance(value, str | int | float | bool) or value is None:
        return value
    return safe_value(value)


def canonical_json(value: object) -> str:
    """Return deterministic compact JSON for fingerprint material."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def fingerprint_parts(message: dict[str, Any]) -> tuple[str, ...]:
    """Return stable non-secret fields that identify one alert stream."""
    _, event = event_from_message(message)
    detail = event.get("detail")
    detail = detail if isinstance(detail, dict) else {}
    return tuple(
        canonical_json(value)
        for value in (
            event.get("source"),
            event.get("detail-type"),
            detail.get("state"),
            detail.get("backupVaultName"),
            detail.get("backupPlanId"),
            detail.get("backupRuleId"),
            detail.get("resourceArn"),
            canonical_json(stable_detail(detail)),
            canonical_json(stable_detail(event.get("resources"))),
        )
    )


def message_fingerprint(message: dict[str, Any]) -> str:
    """Return the stable fingerprint for one alert stream."""
    digest_input = canonical_json(
        {"version": FINGERPRINT_VERSION, "parts": fingerprint_parts(message)}
    ).encode("utf-8")
    return hashlib.sha256(digest_input).hexdigest()[:24]


def alert_groups(alerts: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """Return alert messages grouped by stable per-stream fingerprint."""
    groups: dict[str, list[dict[str, Any]]] = {}
    for message in alert_messages(alerts):
        groups.setdefault(message_fingerprint(message), []).append(message)
    return [
        (fingerprint, {"Messages": messages})
        for fingerprint, messages in sorted(groups.items())
    ]


def grouped_alerts_payload(alerts: dict[str, Any]) -> dict[str, object]:
    """Return a JSON-serializable grouped alert manifest."""
    return {
        "fingerprintVersion": FINGERPRINT_VERSION,
        "groups": [
            {
                "fingerprint": fingerprint,
                "messageCount": len(group["Messages"]),
                "alerts": group,
            }
            for fingerprint, group in alert_groups(alerts)
        ],
    }


def alerts_fingerprint(alerts: dict[str, Any]) -> str:
    """Return a stable aggregate fingerprint for the current alert batch."""
    messages = alert_messages(alerts)
    if not messages:
        return "empty"
    unique_parts = sorted({message_fingerprint(message) for message in messages})
    if len(unique_parts) == 1:
        return unique_parts[0]
    digest_input = "\n".join(unique_parts).encode("utf-8")
    return hashlib.sha256(digest_input).hexdigest()[:24]


def render_issue_body(
    alerts: dict[str, Any],
    context: IssueContext,
) -> str:
    """Render a sanitized GitHub issue body for alert triage."""
    messages = alert_messages(alerts)
    lines = [
        f"<!-- operations-alert:fingerprint={context.fingerprint} -->",
        f"The operations alert queue contains {len(messages)} message(s).",
        "",
        (
            "This issue intentionally records sanitized metadata only. Use the "
            "message IDs, event source, detail type, event time, CloudTrail, and "
            "linked runbooks for investigation; do not paste raw alert payloads, "
            "stack exports, credentials, tokens, or private incident notes."
        ),
        "",
        f"Queue: <code>{safe_value(context.queue_name)}</code>",
        f"AWS account: <code>{safe_value(context.account_id)}</code>",
        f"AWS region: <code>{safe_value(context.region)}</code>",
        "",
        "Messages:",
    ]
    # Bound display size even when metadata uses four-byte Unicode characters.
    displayed = messages[:10]
    for message in displayed:
        rendered = ", ".join(
            f"{name}: `{safe_value(value)}`"
            for name, value in message_fields(message).items()
        )
        lines.append(f"- {rendered}")
    if len(messages) > len(displayed):
        lines.append(
            f"- {len(messages) - len(displayed)} additional occurrences omitted; "
            "not all message IDs are displayed in this issue."
        )
    lines.append("")
    return "\n".join(lines)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Render sanitized operations alert issue content."
    )
    parser.add_argument("--alerts-json", required=True)
    parser.add_argument("--queue-name", required=True)
    parser.add_argument("--account-id", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--body-file", required=True)
    parser.add_argument("--fingerprint-file", required=True)
    parser.add_argument("--groups-file")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        with Path(args.alerts_json).open(encoding="utf-8") as alerts_file:
            loaded_alerts = json.load(alerts_file)
    except (OSError, json.JSONDecodeError, TypeError) as exc:
        print(
            f"error: {args.alerts_json} must contain a JSON object: {exc}",
            file=sys.stderr,
        )
        return 1
    if not isinstance(loaded_alerts, dict):
        print(
            f"error: {args.alerts_json} must contain a JSON object.",
            file=sys.stderr,
        )
        return 1
    alerts = {str(key): item for key, item in loaded_alerts.items()}
    fingerprint = alerts_fingerprint(alerts)
    if args.groups_file:
        Path(args.groups_file).write_text(
            f"{json.dumps(grouped_alerts_payload(alerts), sort_keys=True)}\n",
            encoding="utf-8",
        )
    Path(args.body_file).write_text(
        render_issue_body(
            alerts,
            IssueContext(
                queue_name=args.queue_name,
                account_id=args.account_id,
                region=args.region,
                fingerprint=fingerprint,
            ),
        ),
        encoding="utf-8",
    )
    Path(args.fingerprint_file).write_text(f"{fingerprint}\n", encoding="utf-8")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
