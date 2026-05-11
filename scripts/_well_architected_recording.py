from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

JsonObject = dict[str, Any]
MarkdownRenderer = Callable[[JsonObject, argparse.Namespace], str]
JsonRenderer = Callable[[JsonObject, argparse.Namespace], object]
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


def markdown_list(values: Sequence[str], default: str) -> str:
    """Return a Markdown bullet list with a default item when values are empty."""
    items = values or [default]
    return "\n".join(f"- {markdown_cell(item)}" for item in items)


def default_review_date() -> str:
    """Return the current UTC date for owner evidence records."""
    return dt.datetime.now(dt.timezone.utc).date().isoformat()


def add_recording_output_arguments(
    parser: argparse.ArgumentParser,
    *,
    include_environment: bool,
    environment_default: str = "test",
) -> None:
    """Add common evidence input and report output arguments to a parser."""
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--json-output", type=Path)
    parser.add_argument("--review-date", default=default_review_date())
    parser.add_argument("--workload", default="bootstrap-infrastructure")
    if include_environment:
        parser.add_argument("--environment", default=environment_default)


def output_exists_error(
    output: Path, json_output: Path | None, *, force: bool
) -> str | None:
    """Return an overwrite error message for report outputs, if any."""
    if output.exists() and not force:
        return f"output already exists: {output}"
    if json_output is not None and json_output.exists() and not force:
        return f"JSON output already exists: {json_output}"
    return None


def write_recording_outputs(
    output: Path,
    markdown: str,
    *,
    json_output: Path | None = None,
    json_payload: object | None = None,
) -> None:
    """Write owner evidence Markdown and optional JSON payload outputs."""
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(markdown, encoding="utf-8")
    if json_output is None:
        return
    json_output.parent.mkdir(parents=True, exist_ok=True)
    json_output.write_text(
        f"{json.dumps(json_payload, indent=2, sort_keys=True)}\n",
        encoding="utf-8",
    )


def run_recording_cli(
    parser: argparse.ArgumentParser,
    argv: Sequence[str] | None,
    *,
    render_markdown: MarkdownRenderer,
    render_json: JsonRenderer,
) -> int:
    """Run the common owner evidence load, render, and write command flow."""
    args = parser.parse_args(argv)
    overwrite_error = output_exists_error(
        args.output, args.json_output, force=args.force
    )
    if overwrite_error:
        print(f"error: {overwrite_error}", file=sys.stderr)
        return 2

    try:
        report = load_report(args.evidence)
        markdown = render_markdown(report, args)
        json_payload = render_json(report, args) if args.json_output else None
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    write_recording_outputs(
        args.output,
        markdown,
        json_output=args.json_output,
        json_payload=json_payload,
    )
    return 0


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
