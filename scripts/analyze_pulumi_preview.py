#!/usr/bin/env python3
"""Analyze Pulumi preview JSON and block destructive changes to critical resources."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

CRITICAL_RESOURCE_PREFIXES = (
    "aws:ec2/eip:",
    "aws:ec2/internetGateway:",
    "aws:ec2/natGateway:",
    "aws:ec2/networkAcl:",
    "aws:ec2/routeTable:",
    "aws:ec2/securityGroup:",
    "aws:ec2/subnet:",
    "aws:ec2/vpc:",
    "aws:eks/",
    "aws:iam/",
    "aws:kms/key:Key",
    "aws:rds/",
    "aws:route53/",
    "aws:s3/bucket:Bucket",
    "aws:secretsmanager/",
)
DESTRUCTIVE_OPERATIONS = {
    "delete",
    "delete-replaced",
    "discard-replaced",
    "replace",
    "create-replacement",
}


@dataclass(frozen=True)
class PreviewStep:
    """Preview step metadata used by the destructive diff gate."""

    op: str
    resource_type: str
    urn: str


def _resource_type(step: dict[str, Any]) -> str:
    old_state = step.get("oldState")
    old_type = old_state.get("type") if isinstance(old_state, dict) else None
    if isinstance(old_type, str):
        return old_type

    new_state = step.get("newState")
    new_type = new_state.get("type") if isinstance(new_state, dict) else None
    if isinstance(new_type, str):
        return new_type

    return "unknown"


def load_preview(path: Path) -> dict[str, Any]:
    """Load a Pulumi preview JSON document from disk."""
    with path.open(encoding="utf-8") as handle:
        loaded = json.load(handle)
    if not isinstance(loaded, dict):
        raise ValueError("Pulumi preview JSON must decode into an object.")
    return loaded


def extract_preview_steps(preview: dict[str, Any]) -> list[PreviewStep]:
    """Normalize preview steps into a typed list."""
    raw_steps = preview.get("steps")
    if not isinstance(raw_steps, list):
        return []

    steps: list[PreviewStep] = []
    for raw_step in raw_steps:
        if not isinstance(raw_step, dict):
            continue
        op = raw_step.get("op")
        urn = raw_step.get("urn")
        if not isinstance(op, str) or not isinstance(urn, str):
            continue
        steps.append(
            PreviewStep(op=op, resource_type=_resource_type(raw_step), urn=urn)
        )
    return steps


def is_destructive_operation(op: str) -> bool:
    """Return True when the preview operation deletes or replaces resources."""
    return op in DESTRUCTIVE_OPERATIONS


def is_critical_resource_type(resource_type: str) -> bool:
    """Return True when a resource type is considered high-risk."""
    return any(
        resource_type.startswith(prefix) for prefix in CRITICAL_RESOURCE_PREFIXES
    )


def destructive_critical_steps(steps: list[PreviewStep]) -> list[PreviewStep]:
    """Return destructive changes that affect critical infrastructure resources."""
    return [
        step
        for step in steps
        if is_destructive_operation(step.op)
        and is_critical_resource_type(step.resource_type)
    ]


def render_markdown_summary(
    preview: dict[str, Any],
    dangerous_steps: list[PreviewStep],
    *,
    override_enabled: bool,
) -> str:
    """Render a markdown summary for CI logs and step summaries."""
    lines = ["## Pulumi Preview Summary", ""]

    change_summary = preview.get("changeSummary")
    if isinstance(change_summary, dict) and change_summary:
        lines.append("### Change Summary")
        lines.append("")
        for action, count in sorted(change_summary.items()):
            lines.append(f"- `{action}`: `{count}`")
        lines.append("")

    if dangerous_steps:
        label = "override enabled" if override_enabled else "blocked"
        lines.append(f"### Destructive Diff Gate: {label}")
        lines.append("")
        lines.append(
            "The preview includes deletes or replacements for critical resource types."
        )
        lines.append("")
        for step in dangerous_steps:
            lines.append(f"- `{step.op}` `{step.resource_type}` `{step.urn}`")
        lines.append("")
    else:
        lines.append("### Destructive Diff Gate")
        lines.append("")
        lines.append(
            "No destructive changes were detected for critical resource types."
        )
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--preview-file",
        required=True,
        type=Path,
        help="Path to the Pulumi preview JSON file.",
    )
    parser.add_argument(
        "--summary-file",
        type=Path,
        help="Optional markdown summary output path.",
    )
    parser.add_argument(
        "--allow-destructive-override",
        action="store_true",
        help="Allow destructive changes after recording them in the summary.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint."""
    args = _parse_args(list(argv or sys.argv[1:]))
    preview = load_preview(args.preview_file)
    steps = extract_preview_steps(preview)
    dangerous_steps = destructive_critical_steps(steps)
    summary = render_markdown_summary(
        preview,
        dangerous_steps,
        override_enabled=args.allow_destructive_override,
    )

    sys.stdout.write(summary)
    if args.summary_file is not None:
        args.summary_file.write_text(summary, encoding="utf-8")

    if dangerous_steps and not args.allow_destructive_override:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
