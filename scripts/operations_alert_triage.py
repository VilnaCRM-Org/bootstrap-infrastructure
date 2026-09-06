#!/usr/bin/env python3
"""Render sanitized operations-alert issues and stable duplicate fingerprints."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

FINGERPRINT_VERSION = 2
BACKUP_JOB_TYPES = {
    "Backup Job State Change": "backupJobId",
    "Copy Job State Change": "copyJobId",
    "Restore Job State Change": "restoreJobId",
}


@dataclass(frozen=True)
class IssueContext:
    """Non-secret metadata shared by the rendered GitHub issue body."""

    queue_name: str
    account_id: str
    region: str
    fingerprint: str


def _nonempty_text(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip()) and value.isprintable()


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError("Duplicate JSON fields")
    return result


def _reject_nonfinite(_value: str) -> None:
    raise ValueError("Non-finite JSON numbers are not supported")


def _event_time_valid(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).tzinfo is not None
    except ValueError:
        return False


def _strict_event_from_message(
    message: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Reject malformed or duplicate fields before choosing a dispatch path."""
    sns = json.loads(
        message["Body"],
        object_pairs_hook=_unique_object,
        parse_constant=_reject_nonfinite,
    )
    if not isinstance(sns, dict):
        raise ValueError("SNS envelope must be an object")
    event = json.loads(
        sns["Message"],
        object_pairs_hook=_unique_object,
        parse_constant=_reject_nonfinite,
    )
    if not isinstance(event, dict):
        raise ValueError("Event envelope must be an object")
    # Validate recursive fingerprint processing before acknowledgment.
    stable_detail(event)
    return sns, event


def _backup_envelope_valid(
    message: dict[str, Any],
    sns: dict[str, Any],
    event: dict[str, Any],
    context: IssueContext,
    topic: str,
) -> bool:
    return all(
        (
            sns.get("Type") == "Notification",
            sns.get("TopicArn") == topic,
            event.get("account") == context.account_id,
            event.get("region") == context.region,
            _event_time_valid(event.get("time")),
            *(
                _nonempty_text(value)
                for value in (
                    message.get("MessageId"),
                    message.get("ReceiptHandle"),
                    sns.get("MessageId"),
                    event.get("id"),
                    event.get("time"),
                )
            ),
        )
    )


def _backup_state(detail: dict[str, Any]) -> tuple[str | None, str]:
    states = [detail[key] for key in ("state", "status") if key in detail]
    if not states or any(not isinstance(state, str) for state in states):
        return None, "invalid_backup_state"
    if len(set(states)) != 1:
        return None, "conflicting_backup_state"
    return states[0], ""


def _backup_detail_disposition(detail: dict[str, Any]) -> tuple[str, str]:
    state, error = _backup_state(detail)
    if state is None:
        return "quarantine", error
    message = detail.get("statusMessage")
    if "StatusMessage" in detail or (
        message is not None and not isinstance(message, str)
    ):
        return "quarantine", "invalid_backup_status_message"
    if state in {"FAILED", "ABORTED", "EXPIRED"}:
        return "actionable", "backup_terminal_failure"
    if state != "COMPLETED":
        return "quarantine", "unexpected_backup_state"
    if message is None or message == "":
        return "benign", "backup_completed_without_warning"
    return "actionable", "backup_completed_with_warning"


def message_disposition(
    message: dict[str, Any], context: IssueContext, topic: str
) -> tuple[str, str]:
    """Validate known Backup events before permitting any benign acknowledgment."""
    try:
        sns, event = _strict_event_from_message(message)
    except (ValueError, TypeError, KeyError, RecursionError):
        return "quarantine", "invalid_alert_envelope"
    kind = event.get("detail-type")
    if event.get("source") != "aws.backup":
        return "actionable", "existing_alert"
    if not isinstance(kind, str):
        return "quarantine", "invalid_backup_type"
    if kind not in BACKUP_JOB_TYPES:
        return "actionable", "existing_alert"
    if not _backup_envelope_valid(message, sns, event, context, topic):
        return "quarantine", "invalid_backup_envelope"
    detail = event.get("detail")
    if not isinstance(detail, dict) or not _nonempty_text(
        detail.get(BACKUP_JOB_TYPES[kind])
    ):
        return "quarantine", "invalid_backup_job"
    return _backup_detail_disposition(detail)


def classified_alerts(
    alerts: dict[str, Any], context: IssueContext, topic: str
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Return actionable alerts, private ack allowlist and payload-free audit."""
    prefix = f"arn:aws:sns:{context.region}:{context.account_id}:"
    if not topic.startswith(prefix) or not _nonempty_text(topic[len(prefix) :]):
        raise ValueError("Expected topic must match the trusted account and region")
    actionable: list[dict[str, Any]] = []
    acknowledgments: list[dict[str, str]] = []
    records: list[dict[str, str]] = []
    receipt_counts = Counter(
        str(message.get("ReceiptHandle")) for message in alert_messages(alerts)
    )
    for message in alert_messages(alerts):
        disposition, reason = message_disposition(message, context, topic)
        receipt = message.get("ReceiptHandle")
        if not _nonempty_text(receipt):
            disposition, reason = "quarantine", "invalid_receipt"
        elif receipt_counts[str(receipt)] != 1:
            disposition, reason = "quarantine", "duplicate_receipt"
        if disposition == "actionable":
            actionable.append(message)
        if disposition != "quarantine":
            acknowledgments.append({"ReceiptHandle": str(receipt)})
        records.append(
            {
                "messageSha256": hashlib.sha256(
                    canonical_json(message).encode()
                ).hexdigest(),
                "disposition": disposition,
                "reason": reason,
            }
        )
    return (
        {"Messages": actionable},
        {"Messages": acknowledgments},
        {"schemaVersion": 1, "records": records},
    )


def load_json(value: object) -> dict[str, Any]:
    """Return a JSON object from a nested SNS/SQS string field."""
    if isinstance(value, dict):
        return {str(key): item for key, item in value.items()}
    if not isinstance(value, str) or not value:
        return {}
    try:
        loaded = json.loads(value, parse_constant=_reject_nonfinite)
    except (ValueError, RecursionError):
        return {}
    if isinstance(loaded, dict):
        return {str(key): item for key, item in loaded.items()}
    return {}


def safe_value(value: object) -> str:
    """Return one sanitized metadata field for GitHub issue text."""
    if not isinstance(value, str | int | float | bool) or value == "":
        return "unknown"
    text = str(value).replace("`", "'").replace("\n", " ")
    sanitized = "".join(character for character in text if character.isprintable())[
        :200
    ]
    return sanitized if sanitized.strip() else "unknown"


def event_from_message(
    message: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Extract SNS and EventBridge metadata from one SQS message."""
    sns = load_json(message.get("Body"))
    return sns, load_json(sns.get("Message"))


def alert_messages(alerts: dict[str, Any]) -> list[dict[str, Any]]:
    """Reject a malformed batch rather than silently discard its messages."""
    messages = alerts.get("Messages", [])
    if not isinstance(messages, list) or any(
        not isinstance(message, dict) for message in messages
    ):
        raise ValueError("Messages must be a list of JSON objects")
    return messages


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
            "resources" in event,
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
        f"Canonical fingerprint: <code>{safe_value(context.fingerprint)}</code>",
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
    parser.add_argument("--acknowledgments-file")
    parser.add_argument("--audit-file")
    parser.add_argument("--topic-arn")
    return parser


def _prepare_classification(
    alerts: dict[str, Any], args: argparse.Namespace
) -> dict[str, Any]:
    options = (args.acknowledgments_file, args.audit_file, args.topic_arn)
    if not any(options):
        return alerts
    if not all(options):
        raise ValueError(
            "Classification requires acknowledgment, audit and topic inputs"
        )
    actionable, acknowledgments, audit = classified_alerts(
        alerts,
        IssueContext(args.queue_name, args.account_id, args.region, ""),
        args.topic_arn,
    )
    descriptor = os.open(
        args.acknowledgments_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600
    )
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        os.fchmod(output.fileno(), 0o600)
        json.dump(acknowledgments, output, sort_keys=True)
    Path(args.audit_file).write_text(
        json.dumps(audit, sort_keys=True), encoding="utf-8"
    )
    return actionable


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        with Path(args.alerts_json).open(encoding="utf-8") as alerts_file:
            loaded_alerts = json.load(
                alerts_file,
                object_pairs_hook=_unique_object,
                parse_constant=_reject_nonfinite,
            )
    except (OSError, ValueError, TypeError, RecursionError) as exc:
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
    try:
        # Validate the complete batch before creating artifacts.
        alert_messages(alerts)
        alerts = _prepare_classification(alerts, args)
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
    except (OSError, ValueError, TypeError, RecursionError):
        print("error: alert processing or artifact write failed.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
