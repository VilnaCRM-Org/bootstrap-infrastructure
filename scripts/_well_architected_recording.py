from __future__ import annotations

import datetime as dt
import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

JsonObject = dict[str, Any]
STRUCTURED_EVIDENCE_MAX_AGE_DAYS = 30


def load_report(path: Path) -> JsonObject:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("evidence report must be a JSON object")
    return payload


def check_by_name(report: JsonObject, name: str) -> JsonObject:
    for item in report.get("checks", []):
        if isinstance(item, dict) and item.get("name") == name:
            return item
    raise ValueError(f"evidence report does not contain check {name!r}")


def markdown_cell(value: object) -> str:
    return str(value).replace("\n", " ").replace("|", "\\|")


def markdown_table(rows: Sequence[tuple[str, object]]) -> str:
    lines = ["| Field | Value |", "| --- | --- |"]
    lines.extend(
        f"| {markdown_cell(key)} | {markdown_cell(value)} |" for key, value in rows
    )
    return "\n".join(lines)


def validate_choice(field: str, value: str, allowed_values: frozenset[str]) -> None:
    normalized = value.strip().lower()
    if normalized in allowed_values:
        return
    allowed = ", ".join(sorted(allowed_values))
    raise ValueError(f"{field} must be one of: {allowed}.")


def validate_structured_dates(
    label: str, reviewed_at_value: str, expires_at_value: str
) -> None:
    reviewed_at = parse_iso_date_or_timestamp(reviewed_at_value)
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
    expires_at = parse_iso_date_or_timestamp(expires_at_value)
    if expires_at is None:
        raise ValueError(f"{label} expiry-date must be an ISO-8601 date or timestamp.")
    if expires_at <= now:
        raise ValueError(f"{label} expiry-date is expired.")


def parse_iso_date_or_timestamp(value: str) -> dt.datetime | None:
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
