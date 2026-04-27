#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import json
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from _script_support import repo_root, run
from validate_repository_catalogs import (
    _fanout_failures,
    _fanout_threshold_report,
    _fanout_thresholds,
    catalog_fanout_report,
    repository_catalog_paths,
)

ROOT_DIR = repo_root(__file__)
Runner = Callable[..., Any]

PASSING_CHECK_CONCLUSIONS = {"SUCCESS"}
PASSING_STATUS_STATES = {"SUCCESS"}
ALLOWED_SKIPPED_CHECKS = frozenset(
    {
        "Preview (Unprivileged)",
        "IAM Validation (Unprivileged)",
    }
)
DEFAULT_REQUIRED_STATUS_CHECKS = (
    "Preview",
    "Destructive Diff Gate",
    "IAM Validation",
    "Secrets Scan",
    "Dependency Audit",
    "Bandit",
    "Actionlint",
    "CodeQL (python)",
    "CodeQL (actions)",
)


def _check(
    name: str,
    *,
    status: str,
    evidence: dict[str, object] | None = None,
    blockers: Sequence[str] = (),
) -> dict[str, object]:
    """Return one normalized non-secret evidence check."""
    return {
        "name": name,
        "status": status,
        "evidence": evidence or {},
        "blockers": list(blockers),
    }


def _run_json(
    command: list[str],
    *,
    runner: Runner = run,
) -> tuple[bool, Any, str]:
    """Run a metadata-only command and parse its JSON output."""
    result = runner(command, check=False, capture_output=True)
    if result.returncode != 0:
        return False, None, result.stderr.strip() or "command failed"
    try:
        return True, json.loads(result.stdout or "null"), ""
    except json.JSONDecodeError as exc:
        return False, None, f"invalid JSON output: {exc.msg}"


def _rollup_entry_passed(entry: dict[str, Any]) -> bool:
    """Return whether one GitHub status/check rollup entry is acceptable."""
    if entry.get("__typename") == "StatusContext":
        return str(entry.get("state", "")).upper() in PASSING_STATUS_STATES
    if entry.get("__typename") == "CheckRun":
        name = str(entry.get("name") or "")
        status = str(entry.get("status", "")).upper()
        conclusion = str(entry.get("conclusion", "")).upper()
        return status == "COMPLETED" and (
            conclusion in PASSING_CHECK_CONCLUSIONS
            or (conclusion == "SKIPPED" and name in ALLOWED_SKIPPED_CHECKS)
        )
    return False


def _rollup_entry_label(entry: dict[str, Any]) -> str:
    """Return the human-readable name for a GitHub rollup entry."""
    return str(entry.get("name") or entry.get("context") or "unknown")


def _non_passing_rollup_labels(entries: Sequence[dict[str, Any]]) -> list[str]:
    """Return non-passing GitHub status/check names."""
    return [
        _rollup_entry_label(entry)
        for entry in entries
        if not _rollup_entry_passed(entry)
    ]


def _github_pr_check_blockers(
    payload: dict[str, Any], failing: Sequence[str]
) -> list[str]:
    """Return blockers from PR merge, review, and check metadata."""
    blockers = []
    if payload.get("mergeStateStatus") != "CLEAN":
        blockers.append("PR merge state is not CLEAN.")
    if payload.get("reviewDecision") != "APPROVED":
        blockers.append("PR is not approved.")
    if failing:
        blockers.append(f"Non-passing check contexts: {', '.join(sorted(failing))}.")
    return blockers


def github_pr_checks(
    repo: str,
    pr_number: int | None,
    *,
    runner: Runner = run,
) -> dict[str, object]:
    """Collect PR check, review, and mergeability evidence from GitHub."""
    if pr_number is None:
        return _check(
            "github_pr_checks",
            status="missing",
            blockers=["PR number is required for PR check evidence."],
        )
    ok, payload, error = _run_json(
        [
            "gh",
            "pr",
            "view",
            str(pr_number),
            "--repo",
            repo,
            "--json",
            "mergeStateStatus,reviewDecision,headRefOid,statusCheckRollup",
        ],
        runner=runner,
    )
    if not ok or not isinstance(payload, dict):
        return _check("github_pr_checks", status="unknown", blockers=[error])

    rollup = payload.get("statusCheckRollup", [])
    entries = [entry for entry in rollup if isinstance(entry, dict)]
    failing = _non_passing_rollup_labels(entries)
    blockers = _github_pr_check_blockers(payload, failing)
    return _check(
        "github_pr_checks",
        status="passed" if not blockers else "failed",
        evidence={
            "headRefOid": payload.get("headRefOid"),
            "mergeStateStatus": payload.get("mergeStateStatus"),
            "reviewDecision": payload.get("reviewDecision"),
            "checkCount": len(entries),
            "nonPassingCheckCount": len(failing),
        },
        blockers=blockers,
    )


def github_review_threads(
    repo: str,
    pr_number: int | None,
    *,
    runner: Runner = run,
) -> dict[str, object]:
    """Collect unresolved review-thread count without reading secret material."""
    if pr_number is None:
        return _check(
            "github_review_threads",
            status="missing",
            blockers=["PR number is required for review-thread evidence."],
        )
    owner, name = repo.split("/", 1)
    nodes, pagination_error = _collect_review_thread_nodes(
        owner,
        name,
        pr_number,
        runner=runner,
    )
    if pagination_error:
        return _check(
            "github_review_threads",
            status="unknown",
            blockers=[pagination_error],
        )

    unresolved = [
        node for node in nodes if isinstance(node, dict) and not node.get("isResolved")
    ]
    return _check(
        "github_review_threads",
        status="passed" if not unresolved else "failed",
        evidence={"threadCount": len(nodes), "unresolvedThreadCount": len(unresolved)},
        blockers=(
            [f"{len(unresolved)} review thread(s) remain unresolved."]
            if unresolved
            else []
        ),
    )


def _collect_review_thread_nodes(
    owner: str,
    name: str,
    pr_number: int,
    *,
    runner: Runner = run,
) -> tuple[list[dict], str]:
    """Collect paginated review-thread nodes or return a blocker."""
    query = _review_threads_query()
    nodes = []
    after: str | None = None
    for _page in range(20):
        page_nodes, page_info, error = _fetch_review_thread_page(
            owner,
            name,
            pr_number,
            query,
            after,
            runner=runner,
        )
        if error:
            return [], error
        nodes.extend(page_nodes)
        should_continue, after, error = _next_review_thread_cursor(page_info)
        if error:
            return [], error
        if not should_continue:
            return nodes, ""
    return [], "GitHub review thread pagination exceeded 20 pages."


def _fetch_review_thread_page(
    owner: str,
    name: str,
    pr_number: int,
    query: str,
    after: str | None,
    *,
    runner: Runner = run,
) -> tuple[list[dict], dict[str, Any], str]:
    """Fetch one review-thread page."""
    command = _review_threads_command(owner, name, pr_number, query, after)
    ok, payload, error = _run_json(command, runner=runner)
    if not ok or not isinstance(payload, dict):
        return [], {}, error
    page_nodes, page_info = _review_threads_page(payload)
    return page_nodes, page_info, ""


def _next_review_thread_cursor(
    page_info: dict[str, Any],
) -> tuple[bool, str | None, str]:
    """Return pagination decision, cursor, and blocker."""
    if not page_info.get("hasNextPage"):
        return False, None, ""
    after = page_info.get("endCursor")
    if after:
        return True, after, ""
    return False, None, "GitHub review thread pagination did not return a cursor."


def _review_threads_query() -> str:
    """Return the paginated review-thread GraphQL query."""
    return (
        "query($owner:String!, $name:String!, $number:Int!, $after:String) { "
        "repository(owner:$owner, name:$name) { "
        "pullRequest(number:$number) { "
        "reviewThreads(first:100, after:$after) { "
        "nodes { isResolved } pageInfo { hasNextPage endCursor } } } } }"
    )


def _review_threads_command(
    owner: str,
    name: str,
    pr_number: int,
    query: str,
    after: str | None,
) -> list[str]:
    """Build a metadata-only review-thread GraphQL command."""
    command = [
        "gh",
        "api",
        "graphql",
        "-f",
        f"owner={owner}",
        "-f",
        f"name={name}",
        "-F",
        f"number={pr_number}",
        "-f",
        f"query={query}",
    ]
    if after:
        command.extend(["-f", f"after={after}"])
    return command


def _review_threads_page(payload: dict[str, Any]) -> tuple[list[dict], dict[str, Any]]:
    """Extract one review-thread page from a GraphQL response."""
    review_threads = (
        payload.get("data", {})
        .get("repository", {})
        .get("pullRequest", {})
        .get("reviewThreads", {})
    )
    page_nodes = review_threads.get("nodes", [])
    page_info = review_threads.get("pageInfo") or {}
    nodes = [node for node in page_nodes if isinstance(node, dict)]
    return nodes, page_info if isinstance(page_info, dict) else {}


def _github_rulesets(
    repo: str, *, runner: Runner = run
) -> tuple[list[dict], list[str]]:
    """Return detailed repository ruleset metadata where the token can read it."""
    ok, payload, error = _run_json(
        ["gh", "api", f"repos/{repo}/rulesets"], runner=runner
    )
    if not ok or not isinstance(payload, list):
        return [], [error]

    rulesets = []
    errors = []
    for item in payload:
        if not isinstance(item, dict) or item.get("id") is None:
            continue
        detail_ok, detail, detail_error = _run_json(
            ["gh", "api", f"repos/{repo}/rulesets/{item['id']}"],
            runner=runner,
        )
        if detail_ok and isinstance(detail, dict):
            rulesets.append(detail)
        else:
            errors.append(detail_error)
    return rulesets, errors


def _ruleset_has_pull_request_reviews(rulesets: Sequence[dict]) -> bool:
    """Return whether any active branch ruleset requires pull request review."""
    for ruleset in rulesets:
        if not _is_active_branch_ruleset(ruleset):
            continue
        rules = ruleset.get("rules") or []
        if any(rule.get("type") == "pull_request" for rule in rules):
            return True
    return False


def _ruleset_required_status_check_contexts(rulesets: Sequence[dict]) -> set[str]:
    """Return required status check contexts from active branch rulesets."""
    contexts: set[str] = set()
    for ruleset in rulesets:
        if not _is_active_branch_ruleset(ruleset):
            continue
        for rule in ruleset.get("rules") or []:
            contexts.update(_required_status_contexts_from_rule(rule))
    return contexts


def _is_active_branch_ruleset(ruleset: dict[str, Any]) -> bool:
    """Return whether a ruleset is an active branch ruleset."""
    return ruleset.get("target") == "branch" and ruleset.get("enforcement") == "active"


def _required_status_contexts_from_rule(rule: dict[str, Any]) -> set[str]:
    """Return required status contexts from one ruleset rule."""
    if rule.get("type") != "required_status_checks":
        return set()
    parameters = rule.get("parameters") or {}
    checks = parameters.get("required_status_checks") or []
    return {
        str(check.get("context") or check.get("name"))
        for check in checks
        if isinstance(check, dict) and (check.get("context") or check.get("name"))
    }


def github_branch_protection(
    repo: str,
    branch: str,
    expected_required_status_checks: Sequence[str] = DEFAULT_REQUIRED_STATUS_CHECKS,
    *,
    runner: Runner = run,
) -> dict[str, object]:
    """Collect branch-protection evidence for required checks and reviews."""
    protection_ok, payload, protection_error = _run_json(
        ["gh", "api", f"repos/{repo}/branches/{branch}/protection"],
        runner=runner,
    )
    rulesets, ruleset_errors = _github_rulesets(repo, runner=runner)
    if (
        (not protection_ok or not isinstance(payload, dict))
        and not rulesets
        and ruleset_errors
    ):
        return _check(
            "github_branch_protection",
            status="unknown",
            blockers=[protection_error, *ruleset_errors],
        )

    protection = _protection_payload(protection_ok, payload)
    contexts = _classic_required_check_contexts(protection)
    contexts.update(_ruleset_required_status_check_contexts(rulesets))
    required_reviews = protection.get("required_pull_request_reviews")
    ruleset_reviews = _ruleset_has_pull_request_reviews(rulesets)
    enforce_admins = protection.get("enforce_admins") or {}
    missing_required_checks = sorted(
        set(expected_required_status_checks) - set(contexts)
    )
    blockers = _branch_protection_blockers(
        contexts=contexts,
        missing_required_checks=missing_required_checks,
        requires_reviews=bool(required_reviews or ruleset_reviews),
    )
    return _check(
        "github_branch_protection",
        status="passed" if not blockers else "failed",
        evidence={
            "branch": branch,
            "classicProtectionReadable": protection_ok,
            "activeRulesetCount": _active_branch_ruleset_count(rulesets),
            "requiredStatusCheckCount": len(contexts),
            "requiredStatusChecks": sorted(contexts),
            "expectedRequiredStatusChecks": list(expected_required_status_checks),
            "missingRequiredStatusChecks": missing_required_checks,
            "requiresPullRequestReviews": bool(required_reviews or ruleset_reviews),
            "enforceAdmins": bool(enforce_admins.get("enabled")),
        },
        blockers=blockers,
    )


def _protection_payload(protection_ok: bool, payload: Any) -> dict[str, Any]:
    """Return classic protection payload when readable."""
    return payload if protection_ok and isinstance(payload, dict) else {}


def _classic_required_check_contexts(protection: dict[str, Any]) -> set[str]:
    """Return classic branch-protection required status contexts."""
    required_checks = protection.get("required_status_checks") or {}
    return {
        str(context)
        for context in required_checks.get("contexts") or []
        if isinstance(context, str) and context
    }


def _branch_protection_blockers(
    *,
    contexts: set[str],
    missing_required_checks: Sequence[str],
    requires_reviews: bool,
) -> list[str]:
    """Return blockers for branch-protection metadata."""
    blockers = []
    if not contexts:
        blockers.append("Branch protection does not report required status checks.")
    elif missing_required_checks:
        blockers.append(
            "Branch protection is missing required status checks: "
            f"{', '.join(missing_required_checks)}."
        )
    if not requires_reviews:
        blockers.append("Branch protection does not require pull request reviews.")
    return blockers


def _active_branch_ruleset_count(rulesets: Sequence[dict]) -> int:
    """Return active branch ruleset count."""
    return sum(1 for ruleset in rulesets if _is_active_branch_ruleset(ruleset))


def aws_identity(*, runner: Runner = run) -> dict[str, object]:
    """Collect current AWS account identity metadata."""
    ok, payload, error = _run_json(
        ["aws", "sts", "get-caller-identity", "--output", "json"],
        runner=runner,
    )
    if not ok or not isinstance(payload, dict):
        return _check("aws_identity", status="unknown", blockers=[error])
    return _check(
        "aws_identity",
        status="passed",
        evidence={"account": payload.get("Account"), "arn": payload.get("Arn")},
    )


def aws_cost_controls(
    account_id: str | None, *, runner: Runner = run
) -> dict[str, object]:
    """Collect account-level Budget and Cost Anomaly Detection availability."""
    if not account_id:
        account_id = _account_id_from_identity(aws_identity(runner=runner))
    if not account_id:
        return _check(
            "aws_cost_controls",
            status="unknown",
            blockers=["Unable to determine AWS account id."],
        )

    budget_ok, budget_count, budget_error = _run_count(
        [
            "aws",
            "budgets",
            "describe-budgets",
            "--account-id",
            account_id,
            "--max-results",
            "1",
            "--query",
            "length(Budgets)",
            "--output",
            "json",
        ],
        runner=runner,
    )
    anomaly_ok, anomaly_count, anomaly_error = _run_count(
        [
            "aws",
            "ce",
            "get-anomaly-monitors",
            "--max-results",
            "1",
            "--query",
            "length(AnomalyMonitors)",
            "--output",
            "json",
        ],
        runner=runner,
    )
    blockers = []
    if not budget_ok:
        blockers.append(f"Unable to query AWS Budgets: {budget_error}")
    elif budget_count < 1:
        blockers.append("No AWS Budgets were found in the target account.")
    if not anomaly_ok:
        blockers.append(f"Unable to query Cost Anomaly monitors: {anomaly_error}")
    elif anomaly_count < 1:
        blockers.append("No Cost Anomaly monitors were found in the target account.")
    return _check(
        "aws_cost_controls",
        status="passed" if not blockers else "failed",
        evidence={
            "account": account_id,
            "budgetCountAtLeast": budget_count if budget_ok else 0,
            "anomalyMonitorCountAtLeast": anomaly_count if anomaly_ok else 0,
        },
        blockers=blockers,
    )


def _account_id_from_identity(identity: dict[str, object]) -> str:
    """Return account id from a normalized identity check."""
    evidence = identity.get("evidence", {})
    if not isinstance(evidence, dict):
        return ""
    account = evidence.get("account")
    return str(account) if account is not None else ""


def _run_count(
    command: list[str],
    *,
    runner: Runner = run,
) -> tuple[bool, int, str]:
    """Run a count query and normalize the result."""
    ok, count, error = _run_json(command, runner=runner)
    if not ok:
        return False, 0, error
    return True, int(count or 0), ""


def aws_sns_alert_route(
    topic_arn: str | None, *, runner: Runner = run
) -> dict[str, object]:
    """Collect non-secret SNS alert route evidence for the operations topic."""
    if not topic_arn:
        return _check(
            "aws_sns_alert_route",
            status="missing",
            blockers=["Operations SNS topic ARN is required for route evidence."],
        )
    topic_ok, kms_key_id, topic_error = _run_json(
        [
            "aws",
            "sns",
            "get-topic-attributes",
            "--topic-arn",
            topic_arn,
            "--query",
            "Attributes.KmsMasterKeyId",
            "--output",
            "json",
        ],
        runner=runner,
    )
    subs_ok, protocols, subs_error = _run_json(
        [
            "aws",
            "sns",
            "list-subscriptions-by-topic",
            "--topic-arn",
            topic_arn,
            "--query",
            "Subscriptions[].Protocol",
            "--output",
            "json",
        ],
        runner=runner,
    )
    protocols = protocols if isinstance(protocols, list) else []
    blockers = []
    if not topic_ok:
        blockers.append(f"Unable to query SNS topic attributes: {topic_error}")
    elif not kms_key_id:
        blockers.append("Operations SNS topic is not encrypted with a KMS key.")
    if not subs_ok:
        blockers.append(f"Unable to query SNS subscription protocols: {subs_error}")
    elif "sqs" not in protocols:
        blockers.append("Operations SNS topic does not have an SQS subscription.")
    return _check(
        "aws_sns_alert_route",
        status="passed" if not blockers else "failed",
        evidence={
            "topicArn": topic_arn,
            "encrypted": bool(kms_key_id),
            "subscriptionCount": len(protocols),
            "subscriptionProtocols": sorted(set(protocols)),
        },
        blockers=blockers,
    )


def aws_restore_jobs(days: int, *, runner: Runner = run) -> dict[str, object]:
    """Collect recent AWS Backup restore-job status counts."""
    created_after = (
        dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    ok, statuses, error = _run_json(
        [
            "aws",
            "backup",
            "list-restore-jobs",
            "--by-created-after",
            created_after,
            "--query",
            "RestoreJobs[].Status",
            "--output",
            "json",
        ],
        runner=runner,
    )
    if not ok or not isinstance(statuses, list):
        return _check("aws_restore_jobs", status="unknown", blockers=[error])
    status_counts = {status: statuses.count(status) for status in sorted(set(statuses))}
    completed = status_counts.get("COMPLETED", 0)
    return _check(
        "aws_restore_jobs",
        status="passed" if completed else "failed",
        evidence={"windowDays": days, "statusCounts": status_counts},
        blockers=(
            [f"No completed AWS Backup restore jobs found in the last {days} days."]
            if not completed
            else []
        ),
    )


def repository_fanout_evidence(
    root_dir: Path, args: argparse.Namespace
) -> dict[str, object]:
    """Collect static repository fanout evidence from committed catalogs."""
    schema_path = root_dir / "pulumi" / "repositories.schema.json"
    catalog_paths = repository_catalog_paths(root_dir)
    if not catalog_paths:
        return _check(
            "repository_fanout",
            status="missing",
            blockers=["No repository catalog JSON files were found."],
        )
    thresholds = _fanout_thresholds(args)
    reports = []
    failures: list[str] = []
    for catalog_path in catalog_paths:
        report = catalog_fanout_report(catalog_path, schema_path)
        reports.append(
            {
                "catalog": str(catalog_path.relative_to(root_dir)),
                "fanout": report,
                "thresholds": _fanout_threshold_report(report, thresholds),
            }
        )
        failures.extend(_fanout_failures(catalog_path, report, thresholds))
    return _check(
        "repository_fanout",
        status="passed" if not failures else "failed",
        evidence={"catalogCount": len(catalog_paths), "reports": reports},
        blockers=failures,
    )


PILLAR_CHECKS = {
    "Operational Excellence": (
        "github_pr_checks",
        "github_review_threads",
        "github_branch_protection",
        "aws_sns_alert_route",
    ),
    "Security": (
        "github_pr_checks",
        "github_review_threads",
        "github_branch_protection",
        "aws_identity",
    ),
    "Reliability": (
        "github_pr_checks",
        "aws_sns_alert_route",
        "aws_restore_jobs",
        "repository_fanout",
    ),
    "Performance Efficiency": ("repository_fanout",),
    "Cost Optimization": ("aws_cost_controls", "repository_fanout"),
    "Sustainability": ("repository_fanout",),
}


def pillar_scores(checks: Sequence[dict[str, object]]) -> dict[str, float]:
    """Calculate evidence-backed pillar scores from normalized checks."""
    by_name = {str(check["name"]): check for check in checks}
    scores: dict[str, float] = {}
    for pillar, check_names in PILLAR_CHECKS.items():
        passed = sum(
            1
            for check_name in check_names
            if by_name.get(check_name, {}).get("status") == "passed"
        )
        scores[pillar] = round(5 * passed / len(check_names), 2)
    return scores


def collect_evidence(
    args: argparse.Namespace, *, runner: Runner = run
) -> dict[str, Any]:
    """Collect metadata-only Well-Architected evidence."""
    checks = [
        github_pr_checks(args.repo, args.pr, runner=runner),
        github_review_threads(args.repo, args.pr, runner=runner),
        github_branch_protection(
            args.repo,
            args.branch,
            expected_required_status_checks=(
                args.required_status_check or DEFAULT_REQUIRED_STATUS_CHECKS
            ),
            runner=runner,
        ),
        aws_identity(runner=runner),
        aws_cost_controls(args.aws_account_id, runner=runner),
        aws_sns_alert_route(args.operations_topic_arn, runner=runner),
        aws_restore_jobs(args.restore_window_days, runner=runner),
        repository_fanout_evidence(args.root_dir, args),
    ]
    return {
        "generatedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
        "repo": args.repo,
        "pr": args.pr,
        "branch": args.branch,
        "checks": checks,
        "pillarScores": pillar_scores(checks),
        "blockers": _all_blockers(checks),
    }


def _all_blockers(checks: Sequence[dict[str, object]]) -> list[str]:
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


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line parser."""
    parser = argparse.ArgumentParser(
        description="Collect metadata-only Well-Architected evidence.",
    )
    parser.add_argument("--repo", default="VilnaCRM-Org/bootstrap-infrastructure")
    parser.add_argument("--branch", default="main")
    parser.add_argument("--pr", type=int)
    parser.add_argument("--aws-account-id")
    parser.add_argument("--operations-topic-arn")
    parser.add_argument("--restore-window-days", type=int, default=90)
    parser.add_argument(
        "--required-status-check",
        action="append",
        help=(
            "Exact branch-protection status check context that must be required. "
            "Repeat to override the repository default required-check contract."
        ),
    )
    parser.add_argument("--root-dir", type=Path, default=ROOT_DIR)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--max-s3-buckets", type=int, default=200)
    parser.add_argument("--max-kms-keys", type=int, default=100)
    parser.add_argument("--max-iam-roles", type=int, default=300)
    parser.add_argument("--max-backup-selections", type=int, default=500)
    parser.add_argument("--max-ecr-repositories", type=int, default=50)
    parser.add_argument("--max-budgets", type=int, default=20)
    parser.add_argument("--max-sns-subscriptions", type=int, default=50)
    parser.add_argument("--max-sqs-queues", type=int, default=50)
    parser.add_argument("--max-cost-anomaly-monitors", type=int, default=20)
    parser.add_argument("--max-cost-anomaly-subscriptions", type=int, default=20)
    parser.add_argument("--max-cost-allocation-tags", type=int, default=100)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run evidence collection and optionally persist the JSON report."""
    args = build_parser().parse_args(argv)
    report = collect_evidence(args)
    payload = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(f"{payload}\n", encoding="utf-8")
    print(payload)
    return 0 if not report["blockers"] else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
