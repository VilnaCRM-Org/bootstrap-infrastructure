from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Any


def render_markdown_report(
    report: Mapping[str, Any], pillar_order: Iterable[str] = ()
) -> str:
    """Render the human-readable Well-Architected evidence report."""
    lines = [
        "# Well-Architected Evidence Report",
        "",
        f"- Generated: `{markdown_value(report.get('generatedAt'))}`",
        f"- Repository: `{markdown_value(report.get('repo'))}`",
        f"- Pull request: `{markdown_value(report.get('pr'))}`",
        f"- Branch: `{markdown_value(report.get('branch'))}`",
        "",
        "## Final Pillar Scores",
        "",
        "| Pillar | Score |",
        "| --- | ---: |",
    ]
    lines.extend(score_table_rows(report.get("pillarScores"), pillar_order))
    lines.extend(
        [
            "",
            "## Proxy Readiness Scores",
            "",
            "| Pillar | Score |",
            "| --- | ---: |",
        ]
    )
    lines.extend(score_table_rows(report.get("proxyPillarScores"), pillar_order))
    lines.extend(
        [
            "",
            "## Check Results",
            "",
            "| Check | Status | Blockers |",
            "| --- | --- | --- |",
        ]
    )
    for check in markdown_checks(report.get("checks")):
        lines.append(
            "| "
            f"{markdown_cell(check['name'])} | "
            f"{markdown_cell(check['status'])} | "
            f"{markdown_cell(check['blockers'])} |"
        )

    score_blockers = markdown_string_entries(report.get("scoreBlockers"))
    if score_blockers:
        lines.extend(["", "## Score Blockers", ""])
        lines.extend(f"- {markdown_text(blocker)}" for blocker in score_blockers)

    blockers = markdown_string_entries(report.get("blockers"))
    if blockers:
        lines.extend(["", "## Blockers", ""])
        lines.extend(f"- {markdown_text(blocker)}" for blocker in blockers)
    else:
        lines.extend(["", "## Blockers", "", "No blockers reported."])

    return "\n".join(lines) + "\n"


def score_table_rows(value: object, pillar_order: Iterable[str] = ()) -> list[str]:
    """Return Markdown table rows for a pillar score mapping."""
    if not isinstance(value, Mapping) or not value:
        return ["| None reported | - |"]
    rows = []
    ordered_pillars = tuple(pillar_order)
    for pillar in ordered_pillars:
        if pillar in value:
            rows.append(f"| {markdown_cell(pillar)} | {markdown_cell(value[pillar])} |")
    for pillar, score in value.items():
        if pillar not in ordered_pillars:
            rows.append(f"| {markdown_cell(pillar)} | {markdown_cell(score)} |")
    return rows


def markdown_checks(value: object) -> list[dict[str, str]]:
    """Return check rows safe for Markdown rendering."""
    if not isinstance(value, list):
        return []
    rows = []
    for item in value:
        if not isinstance(item, Mapping):
            continue
        blockers = markdown_string_entries(item.get("blockers"))
        rows.append(
            {
                "name": markdown_value(item.get("name")),
                "status": markdown_value(item.get("status")),
                "blockers": "<br>".join(blockers) if blockers else "None",
            }
        )
    return rows


def markdown_string_entries(value: object) -> list[str]:
    """Return string entries from a JSON-like list."""
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def markdown_value(value: object) -> str:
    """Return a compact string value for Markdown reports."""
    if value is None:
        return "-"
    return str(value)


def markdown_cell(value: object) -> str:
    """Escape a value for use in a Markdown table cell."""
    return markdown_text(markdown_value(value)).replace("\n", " ")


def markdown_text(value: str) -> str:
    """Escape Markdown table separators without hiding evidence text."""
    return value.replace("|", "\\|")


def all_blockers(checks: Sequence[Mapping[str, object]]) -> list[str]:
    """Return every string blocker from normalized checks."""
    blockers: list[str] = []
    for check in checks:
        check_blockers = check.get("blockers", [])
        if not isinstance(check_blockers, list):
            continue
        blockers.extend(
            blocker for blocker in check_blockers if isinstance(blocker, str)
        )
    return blockers
