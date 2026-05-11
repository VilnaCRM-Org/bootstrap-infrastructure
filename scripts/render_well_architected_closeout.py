#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any, cast

DEFAULT_EVIDENCE = Path(".artifacts/well-architected/evidence.json")
DEFAULT_QUESTION_VERIFICATION = Path(
    ".artifacts/well-architected/question-verification.json"
)
DEFAULT_OUTPUT = Path(".artifacts/well-architected/owner-closeout-bundle.md")


def _load_json_object(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return payload


def _iter_checks(report: dict[str, Any]) -> list[dict[str, Any]]:
    checks = report.get("checks", [])
    if not isinstance(checks, list):
        return []
    return [cast("dict[str, Any]", item) for item in checks if isinstance(item, dict)]


def _check_evidence(
    checks_by_name: dict[str, dict[str, Any]], check_name: str
) -> dict[str, Any]:
    evidence = checks_by_name.get(check_name, {}).get("evidence", {})
    if not isinstance(evidence, dict):
        return {}
    return evidence


def _string_entries(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value]


def _markdown_cell(value: object) -> str:
    return str(value).replace("\n", " ").replace("|", "\\|")


def _comma_list(values: Sequence[object]) -> str:
    entries = [str(value) for value in values]
    if not entries:
        return "None"
    return ", ".join(entries)


def _table(rows: Sequence[tuple[str, object]]) -> str:
    lines = ["| Field | Value |", "| --- | --- |"]
    lines.extend(
        f"| {_markdown_cell(key)} | {_markdown_cell(value)} |" for key, value in rows
    )
    return "\n".join(lines)


def _collector_command(pr_number: object, topic_arn: object, trail_name: object) -> str:
    """Return the final collector command with required evidence inputs visible."""
    entries = [
        ("PR_NUMBER", pr_number),
        ("OPERATIONS_TOPIC_ARN", topic_arn),
        ("OPERATIONS_CLOUDTRAIL_NAME", trail_name),
        ("RESTORE_DRILL_EVIDENCE", "<path>"),
        ("QUESTION_MATRIX_EVIDENCE", "<path>"),
        ("EXTERNAL_CONTROL_EVIDENCE", "<path>"),
    ]
    prefix = " ".join(f"{key}={value}" for key, value in entries if value)
    return f"{prefix} make report-well-architected-evidence"


def render_closeout_bundle(
    evidence_report: dict[str, Any], question_verification: dict[str, Any]
) -> str:
    """Render a non-secret owner/admin handoff from local verification artifacts."""
    checks = _iter_checks(evidence_report)
    checks_by_name = {str(check.get("name", "")): check for check in checks}
    pr_checks = _check_evidence(checks_by_name, "github_pr_checks")
    local_state = _check_evidence(checks_by_name, "github_pr_local_state")
    review_threads = _check_evidence(checks_by_name, "github_review_threads")
    alert_route = _check_evidence(checks_by_name, "aws_sns_alert_route")
    cloudtrail = _check_evidence(checks_by_name, "aws_cloudtrail_management_events")
    external_controls = _check_evidence(checks_by_name, "external_control_evidence")

    failed_checks = [check for check in checks if check.get("status") != "passed"]
    failed_check_rows = [
        (
            str(check.get("name", "")),
            str(check.get("status", "")),
            _comma_list(_string_entries(check.get("blockers"))),
        )
        for check in failed_checks
    ] or [("None", "passed", "None")]
    unresolved_questions = _string_entries(
        question_verification.get("evidenceUnresolvedQuestionIds")
    )
    unresolved_controls = _string_entries(external_controls.get("unresolvedControlIds"))
    repo = str(evidence_report.get("repo", ""))
    repo_arg = f" --repo {repo}" if repo else ""
    pr_head = pr_checks.get("headRefOid", "")
    final_collector_command = _collector_command(
        evidence_report.get("pr", ""),
        alert_route.get("topicArn", ""),
        cloudtrail.get("trailName", ""),
    )

    lines = [
        "# Owner Closeout Bundle",
        "",
        "This bundle is generated from metadata-only Well-Architected evidence. "
        "Keep owner decisions, approvals, and evidence references non-secret.",
        "",
        "## Source Artifacts",
        "",
        _table(
            [
                ("Collector generated at", evidence_report.get("generatedAt", "")),
                (
                    "Question verifier checked at",
                    question_verification.get("checkedAt", ""),
                ),
                (
                    "AWS Well-Architected source",
                    question_verification.get("tocSource", ""),
                ),
                ("Repository", repo),
                ("Pull request", evidence_report.get("pr", "")),
                ("Branch", evidence_report.get("branch", "")),
            ]
        ),
        "",
        "## Pull Request State",
        "",
        _table(
            [
                ("PR head SHA", pr_head),
                ("Local head SHA", local_state.get("localHead", "")),
                ("Dirty file count", local_state.get("dirtyFileCount", "")),
                ("Hosted check count", pr_checks.get("checkCount", "")),
                (
                    "Non-passing hosted checks",
                    pr_checks.get("nonPassingCheckCount", ""),
                ),
                ("Review decision", pr_checks.get("reviewDecision", "")),
                ("Merge state", pr_checks.get("mergeStateStatus", "")),
                ("Mergeable", pr_checks.get("mergeable", "")),
                ("Review thread count", review_threads.get("threadCount", "")),
                (
                    "Unresolved review threads",
                    review_threads.get("unresolvedThreadCount", ""),
                ),
                (
                    "Advisory unresolved review threads",
                    review_threads.get("advisoryUnresolvedThreadCount", ""),
                ),
                (
                    "Blocking review threads",
                    review_threads.get("blockingThreadCount", ""),
                ),
                (
                    "Outdated unresolved review threads",
                    review_threads.get("outdatedUnresolvedThreadCount", ""),
                ),
            ]
        ),
        "",
        "## Remaining Collector Gates",
        "",
        "| Check | Status | Blockers |",
        "| --- | --- | --- |",
    ]
    lines.extend(
        f"| {_markdown_cell(name)} | {_markdown_cell(status)} | "
        f"{_markdown_cell(blockers)} |"
        for name, status, blockers in failed_check_rows
    )
    lines.extend(
        [
            "",
            "## Remaining AWS Questions",
            "",
            _table(
                [
                    (
                        "Unresolved question count",
                        question_verification.get(
                            "evidenceUnresolvedQuestionCount", ""
                        ),
                    ),
                    ("Unresolved question IDs", _comma_list(unresolved_questions)),
                    (
                        "Evidence row count",
                        question_verification.get("evidenceQuestionCount", ""),
                    ),
                    (
                        "Markdown row count",
                        question_verification.get("markdownQuestionCount", ""),
                    ),
                ]
            ),
            "",
            "## External Owner Controls",
            "",
            _table(
                [
                    (
                        "Unresolved control count",
                        external_controls.get("unresolvedControlCount", ""),
                    ),
                    ("Unresolved control IDs", _comma_list(unresolved_controls)),
                ]
            ),
            "",
            "## Required Owner Actions",
            "",
            "### Reviewer",
            "",
            "- Review and approve the latest PR head SHA after checking the current "
            f"diff and hosted checks: `{pr_head}`.",
            "- Do not rely on approvals from earlier commits when GitHub reports an "
            "empty review decision.",
            "",
            "### Repository Admin",
            "",
            "- Apply and verify repository controls with "
            f"`scripts/configure_github_repository_controls.py{repo_arg} --apply`, "
            "then "
            f"`scripts/configure_github_repository_controls.py{repo_arg} "
            "--verify-only`.",
            "- Confirm `main` requires all PR checks and the `prod` environment "
            "requires an independent reviewer.",
            "",
            "### Security Owner",
            "",
            "- Generate security account evidence with "
            "`make report-security-account-attestation`.",
            "- Re-run `SECURITY_ACCOUNT_ATTESTATION_EVIDENCE=<path> "
            "make report-well-architected-evidence`.",
            "",
            "### Vulnerability Owner",
            "",
            "- Prefer merging the approved dependency-only Dependabot remediation PR.",
            "- If remediation cannot merge immediately, generate a short exception "
            "with `make report-dependabot-exception` and re-run "
            "`DEPENDABOT_EXCEPTION_EVIDENCE=<path> "
            "make report-well-architected-evidence`.",
            "",
            "### SRE Owner",
            "",
            "- Generate monthly downstream alert-route evidence with "
            "`make report-alert-route-observation`.",
            "- Re-run `ALERT_ROUTE_OBSERVATION_EVIDENCE=<path> "
            "make report-well-architected-evidence`.",
            "",
            "### Production DR Owner",
            "",
            "- Generate production recovery-owner evidence with "
            "`make report-production-dr-owner-evidence`.",
            "- Re-run `PRODUCTION_DR_OWNER_EVIDENCE=<path> "
            "make report-well-architected-evidence`.",
            "",
            "## Final Verification",
            "",
            "- `make verify-well-architected-questions`",
            f"- `{final_collector_command}`",
            "",
        ]
    )
    return "\n".join(lines)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Render a non-secret Well-Architected owner closeout bundle."
    )
    parser.add_argument("--evidence", type=Path, default=DEFAULT_EVIDENCE)
    parser.add_argument(
        "--question-verification", type=Path, default=DEFAULT_QUESTION_VERIFICATION
    )
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        evidence_report = _load_json_object(args.evidence)
        question_verification = _load_json_object(args.question_verification)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        render_closeout_bundle(evidence_report, question_verification),
        encoding="utf-8",
    )
    print(args.output)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
