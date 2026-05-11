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


def _score_summary(scores: object) -> str:
    if not isinstance(scores, dict) or not scores:
        return "None"
    return ", ".join(f"{pillar}: {score}" for pillar, score in scores.items())


def _score_scale_summary(score_scale: object) -> str:
    if isinstance(score_scale, str) and score_scale.strip():
        return score_scale
    if not isinstance(score_scale, dict) or not score_scale:
        return "None"

    def sort_key(item: tuple[object, object]) -> tuple[int, str]:
        key = str(item[0])
        if key.isdecimal():
            return (0, f"{int(key):02d}")
        return (1, key)

    entries = [
        f"{key}: {value}"
        for key, value in sorted(score_scale.items(), key=sort_key)
        if str(key).strip() and str(value).strip()
    ]
    if not entries:
        return "None"
    return "; ".join(entries)


def _collector_command(pr_number: object, topic_arn: object, trail_name: object) -> str:
    """Return the final collector command with closure evidence inputs visible."""
    entries = [
        ("PR_NUMBER", pr_number),
        ("OPERATIONS_TOPIC_ARN", topic_arn),
        ("OPERATIONS_CLOUDTRAIL_NAME", trail_name),
        ("RESTORE_DRILL_EVIDENCE", "<path>"),
        ("QUESTION_MATRIX_EVIDENCE", "<path>"),
        ("EXTERNAL_CONTROL_EVIDENCE", "<path>"),
        ("DEPENDABOT_EXCEPTION_EVIDENCE", "<path-if-needed>"),
        ("ALERT_ROUTE_OBSERVATION_EVIDENCE", "<path-if-needed>"),
        ("SECURITY_ACCOUNT_ATTESTATION_EVIDENCE", "<path-if-needed>"),
        ("PRODUCTION_DR_OWNER_EVIDENCE", "<path-if-needed>"),
    ]
    prefix = " ".join(f"{key}={value}" for key, value in entries if value)
    return f"{prefix} make report-well-architected-evidence"


def _shell_template(assignments: Sequence[tuple[str, str]], make_target: str) -> str:
    """Return a copy-pasteable non-secret shell template for owner evidence."""
    lines = ["```bash"]
    lines.extend(f"{key}='{value}' \\" for key, value in assignments)
    lines.append(f"make {make_target}")
    lines.append("```")
    return "\n".join(lines)


def _github_variable_template(repo: str) -> str:
    """Return GitHub Actions variable commands for hosted owner evidence."""
    repo_arg = f" --repo {repo}" if repo else ""
    variables = [
        (
            "DEPENDABOT_EXCEPTION_EVIDENCE",
            "<path-to-dependabot-exception.json>",
        ),
        (
            "ALERT_ROUTE_OBSERVATION_EVIDENCE",
            "<path-to-alert-route-observation.json>",
        ),
        (
            "SECURITY_ACCOUNT_ATTESTATION_EVIDENCE",
            "<path-to-security-account-attestation.json>",
        ),
        (
            "PRODUCTION_DR_OWNER_EVIDENCE",
            "<path-to-production-dr-owner.json>",
        ),
    ]
    lines = ["```bash"]
    lines.extend(
        f"gh variable set {name}{repo_arg} --body '{value}'"
        for name, value in variables
    )
    lines.append("```")
    return "\n".join(lines)


def _goal_status(
    failed_check_names: Sequence[str],
    unresolved_questions: Sequence[str],
    unresolved_controls: Sequence[str],
    score_blockers: Sequence[str],
) -> str:
    if (
        failed_check_names
        or unresolved_questions
        or unresolved_controls
        or score_blockers
    ):
        return "Not achieved"
    return "Achieved"


def _failed_check_rows(
    failed_checks: Sequence[dict[str, Any]],
) -> list[tuple[str, str, str]]:
    return [
        (
            str(check.get("name", "")),
            str(check.get("status", "")),
            _comma_list(_string_entries(check.get("blockers"))),
        )
        for check in failed_checks
    ] or [("None", "passed", "None")]


def _objective_audit_lines(
    evidence_report: dict[str, Any],
    score_blockers: Sequence[str],
    goal_status: str,
) -> list[str]:
    return [
        "## Objective Audit",
        "",
        _table(
            [
                (
                    "Success criteria",
                    "All AWS Well-Architected questions checked, PR and project code "
                    "checked, 1-5 scores assigned, and every question plus external "
                    "condition honestly at 5/5.",
                ),
                ("Current result", goal_status),
                (
                    "Current final scores",
                    _score_summary(evidence_report.get("pillarScores")),
                ),
                (
                    "Proxy scores",
                    _score_summary(evidence_report.get("proxyPillarScores")),
                ),
                ("Score blockers", _comma_list(score_blockers)),
            ]
        ),
        "",
    ]


def _prompt_checklist_lines(
    question_verification: dict[str, Any],
    pr_checks: dict[str, Any],
    local_state: dict[str, Any],
    question_matrix: dict[str, Any],
    pr_head: object,
    unresolved_questions: Sequence[str],
    failed_check_names: Sequence[str],
    goal_status: str,
    evidence_report: dict[str, Any],
) -> list[str]:
    changed_top_level = _comma_list(
        _string_entries(pr_checks.get("changedFileTopLevelPaths"))
    )
    score_scale = _score_scale_summary(question_matrix.get("scoreScale"))
    return [
        "## Prompt-To-Artifact Checklist",
        "",
        "| Requirement | Artifact evidence | Coverage | Current result |",
        "| --- | --- | --- | --- |",
        (
            "| Check all AWS Well-Architected Framework questions | "
            f"`{question_verification.get('tocSource', '')}`; "
            f"{question_verification.get('evidenceQuestionCount', '')} evidence rows; "
            f"{question_verification.get('markdownQuestionCount', '')} Markdown rows | "
            "Verifier compares structured evidence and reviewer Markdown with the "
            "AWS public TOC | "
            f"{question_verification.get('status', '') or 'verified'}; unresolved: "
            f"{_comma_list(unresolved_questions)} |"
        ),
        (
            "| Check PR code and whole project code | "
            f"PR head `{pr_head}`; hosted checks "
            f"{pr_checks.get('checkCount', '')}; non-passing hosted checks "
            f"{pr_checks.get('nonPassingCheckCount', '')}; local dirty files "
            f"{local_state.get('dirtyFileCount', '')}; changed files "
            f"{pr_checks.get('changedFileCount', '')}; changed top-level paths "
            f"{changed_top_level} | "
            "Hosted PR gates, changed-file metadata, and local evidence state cover "
            "the reviewed branch; repository-owned tests still need to stay green "
            "after every new push | "
            f"merge state {pr_checks.get('mergeStateStatus', '')}; review decision "
            f"{pr_checks.get('reviewDecision', '') or 'empty'} |"
        ),
        (
            "| Put scores from 1 to 5 | "
            f"Question score scale `{score_scale}`; "
            f"{question_matrix.get('questionScoreCount', '')} question score rows; "
            "collector `pillarScores`, `proxyPillarScores`, and score blockers | "
            "Question rows carry 1-5 scores; final pillar scores are capped by "
            "failed readiness gates; proxy scores are not accepted as final | "
            f"{_score_summary(evidence_report.get('pillarScores'))} |"
        ),
        (
            "| Work until PR is 5/5 for all questions and conditions | "
            "Collector failed gates, unresolved AWS questions, unresolved external "
            "controls, and score blockers | "
            "Completion requires no failed collector gates, no unresolved questions, "
            "no unresolved external controls, no score blockers, and current PR "
            "approval | "
            f"{goal_status}; failed gates: {_comma_list(failed_check_names)} |"
        ),
        "",
    ]


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
    question_matrix = _check_evidence(checks_by_name, "question_matrix_evidence")
    external_controls = _check_evidence(checks_by_name, "external_control_evidence")

    failed_checks = [check for check in checks if check.get("status") != "passed"]
    failed_check_rows = _failed_check_rows(failed_checks)
    unresolved_questions = _string_entries(
        question_verification.get("evidenceUnresolvedQuestionIds")
    )
    unresolved_controls = _string_entries(external_controls.get("unresolvedControlIds"))
    failed_check_names = [str(check.get("name", "")) for check in failed_checks]
    score_blockers = _string_entries(evidence_report.get("scoreBlockers"))
    goal_status = _goal_status(
        failed_check_names, unresolved_questions, unresolved_controls, score_blockers
    )
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
        *_objective_audit_lines(evidence_report, score_blockers, goal_status),
        *_prompt_checklist_lines(
            question_verification,
            pr_checks,
            local_state,
            question_matrix,
            pr_head,
            unresolved_questions,
            failed_check_names,
            goal_status,
            evidence_report,
        ),
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
                ("Changed file count", pr_checks.get("changedFileCount", "")),
                (
                    "Changed top-level paths",
                    _comma_list(
                        _string_entries(pr_checks.get("changedFileTopLevelPaths"))
                    ),
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
                        "Question score scale",
                        _score_scale_summary(question_matrix.get("scoreScale")),
                    ),
                    (
                        "Question score rows",
                        question_matrix.get("questionScoreCount", ""),
                    ),
                    (
                        "Question score averages",
                        _score_summary(question_matrix.get("questionScoreAverages")),
                    ),
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
            "- After real owner evidence JSON paths exist, set the non-secret "
            "repository Actions variables for hosted evidence runs. Leave any "
            "variable unset until its owner evidence exists.",
            "",
            _github_variable_template(repo),
            "",
            "### Security Owner",
            "",
            "- Generate security account evidence with "
            "`make report-security-account-attestation`.",
            "",
            _shell_template(
                [
                    (
                        "SECURITY_ACCOUNT_ATTESTATION_OUTPUT",
                        ".artifacts/well-architected/security-account-attestation.md",
                    ),
                    (
                        "SECURITY_ACCOUNT_ATTESTATION_JSON_OUTPUT",
                        ".artifacts/well-architected/security-account-attestation.json",
                    ),
                    ("SECURITY_ACCOUNT_REVIEWER", "<reviewer-login>"),
                    ("SECURITY_ACCOUNT_OWNER", "<security-owner-login-or-team>"),
                    (
                        "SECURITY_ACCOUNT_HUMAN_ACCESS",
                        "<mfa_sso_verified|approved_exception|accepted_risk>",
                    ),
                    (
                        "SECURITY_ACCOUNT_ACTIVE_KEY_DECISION",
                        "<rotated|removed|approved_exception|accepted_risk>",
                    ),
                    (
                        "SECURITY_ACCOUNT_PERMISSIONS_BOUNDARY",
                        "<boundary_arn|approved_exemption|accepted_risk>",
                    ),
                    (
                        "SECURITY_ACCOUNT_APPROVAL",
                        "<approved|approved_exception|accepted_risk>",
                    ),
                    ("SECURITY_ACCOUNT_EXPIRY_DATE", "<YYYY-MM-DD>"),
                    (
                        "SECURITY_ACCOUNT_ACTION",
                        "<non-secret remediation or exception note>",
                    ),
                ],
                "report-security-account-attestation",
            ),
            "",
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
            _shell_template(
                [
                    (
                        "DEPENDABOT_EXCEPTION_OUTPUT",
                        ".artifacts/well-architected/dependabot-exception.md",
                    ),
                    (
                        "DEPENDABOT_EXCEPTION_JSON_OUTPUT",
                        ".artifacts/well-architected/dependabot-exception.json",
                    ),
                    ("DEPENDABOT_EXCEPTION_REVIEWER", "<reviewer-login>"),
                    ("DEPENDABOT_EXCEPTION_OWNER", "<security-owner-login-or-team>"),
                    (
                        "DEPENDABOT_EXCEPTION_APPROVAL",
                        "<approved|approved_exception|accepted_risk>",
                    ),
                    (
                        "DEPENDABOT_EXCEPTION_REASON",
                        "<non-secret reason alerts cannot close immediately>",
                    ),
                    (
                        "DEPENDABOT_EXCEPTION_REMEDIATION",
                        "<non-secret remediation plan and target>",
                    ),
                    ("DEPENDABOT_EXCEPTION_EXPIRY_DATE", "<YYYY-MM-DD>"),
                    (
                        "DEPENDABOT_EXCEPTION_EVIDENCE_NOTE",
                        "<non-secret owner evidence reference>",
                    ),
                ],
                "report-dependabot-exception",
            ),
            "",
            "### SRE Owner",
            "",
            "- Generate monthly downstream alert-route evidence with "
            "`make report-alert-route-observation`.",
            "",
            _shell_template(
                [
                    (
                        "ALERT_ROUTE_OBSERVATION_OUTPUT",
                        ".artifacts/well-architected/alert-route-observation.md",
                    ),
                    (
                        "ALERT_ROUTE_OBSERVATION_JSON_OUTPUT",
                        ".artifacts/well-architected/alert-route-observation.json",
                    ),
                    ("ALERT_ROUTE_REVIEWER", "<reviewer-login>"),
                    ("ALERT_ROUTE_OWNER", "<route-owner-login-or-team>"),
                    (
                        "ALERT_ROUTE_DOWNSTREAM",
                        "<ChatOps, ticketing, paging, or approved queue-owner process>",
                    ),
                    (
                        "ALERT_ROUTE_SEVERITY",
                        "<non-secret severity and response expectation>",
                    ),
                    ("ALERT_ROUTE_FALLBACK", "<non-secret fallback action>"),
                    ("ALERT_ROUTE_DECISION", "<approved|accepted_risk>"),
                    ("ALERT_ROUTE_EXPIRY_DATE", "<YYYY-MM-DD>"),
                    (
                        "ALERT_ROUTE_ACTION",
                        "<non-secret follow-up or observation note>",
                    ),
                ],
                "report-alert-route-observation",
            ),
            "",
            "- Re-run `ALERT_ROUTE_OBSERVATION_EVIDENCE=<path> "
            "make report-well-architected-evidence`.",
            "",
            "### Production DR Owner",
            "",
            "- Generate production recovery-owner evidence with "
            "`make report-production-dr-owner-evidence`.",
            "",
            _shell_template(
                [
                    (
                        "PRODUCTION_DR_OWNER_OUTPUT",
                        ".artifacts/well-architected/production-dr-owner.md",
                    ),
                    (
                        "PRODUCTION_DR_OWNER_JSON_OUTPUT",
                        ".artifacts/well-architected/production-dr-owner.json",
                    ),
                    ("PRODUCTION_DR_REVIEWER", "<reviewer-login>"),
                    ("PRODUCTION_DR_OWNER", "<production-owner-login-or-team>"),
                    (
                        "PRODUCTION_DR_ESCALATION_PATH",
                        "<non-secret escalation path>",
                    ),
                    ("PRODUCTION_DR_RTO_TARGET", "<production RTO target>"),
                    ("PRODUCTION_DR_RPO_TARGET", "<production RPO target>"),
                    (
                        "PRODUCTION_DR_RECOVERY_ORDER",
                        "<non-secret recovery order>",
                    ),
                    (
                        "PRODUCTION_DR_COMMUNICATIONS_PLAN",
                        "<non-secret communications plan>",
                    ),
                    (
                        "PRODUCTION_DR_LATEST_ACCEPTED_DRILL",
                        "<restore drill evidence id or date>",
                    ),
                    ("PRODUCTION_DR_NEXT_REVIEW_DATE", "<YYYY-MM-DD>"),
                    (
                        "PRODUCTION_DR_EVIDENCE_RETENTION_LOCATION",
                        "<non-secret evidence location>",
                    ),
                    (
                        "PRODUCTION_DR_APPROVAL",
                        "<approved|approved_exception|accepted_risk>",
                    ),
                    ("PRODUCTION_DR_EXPIRY_DATE", "<YYYY-MM-DD>"),
                    (
                        "PRODUCTION_DR_ACTION",
                        "<non-secret follow-up or owner action>",
                    ),
                ],
                "report-production-dr-owner-evidence",
            ),
            "",
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
    except (OSError, ValueError) as exc:
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
