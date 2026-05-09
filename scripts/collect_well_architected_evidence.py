#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import json
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any, cast

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
RESTORE_DRILL_REQUIRED_FIELDS = (
    "workload",
    "environment",
    "completedAt",
    "sourceRecoveryPointArn",
    "targetRestoreLocation",
    "validationResult",
    "cleanupConfirmed",
)
READINESS_GATES = (
    "question_matrix_evidence",
    "external_control_evidence",
)
QUESTION_MATRIX_REQUIRED_FIELDS = (
    "workload",
    "owner",
    "reviewedAt",
    "questionCount",
    "unresolvedQuestionCount",
    "evidenceLocation",
)
EXTERNAL_CONTROL_REQUIRED_FIELDS = (
    "workload",
    "owner",
    "reviewedAt",
    "controlCount",
    "unresolvedControlCount",
    "controls",
    "evidenceLocation",
    "fallbackPlan",
)
REQUIRED_EXTERNAL_CONTROL_IDS = (
    "branch_protection",
    "alert_route",
    "backup_restore",
    "finops",
    "quota_headroom",
    "security_account_controls",
    "sustainability_governance",
    "production_approval",
)
EXPECTED_WELL_ARCHITECTED_QUESTION_COUNT = 57
STRUCTURED_EVIDENCE_MAX_AGE_DAYS = 30
EXAMPLE_CATALOG_NAMES = frozenset({"repositories.example.json"})


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


def github_pr_local_state(
    repo: str,
    pr_number: int | None,
    root_dir: Path,
    *,
    runner: Runner = run,
) -> dict[str, object]:
    """Verify the local checkout matches the PR head and has no uncommitted work."""
    if pr_number is None:
        return _check(
            "github_pr_local_state",
            status="missing",
            blockers=["PR number is required for local PR state evidence."],
        )

    head_ok, local_head, head_error = _local_git_head(root_dir, runner=runner)
    status_ok, dirty_count, status_error = _local_git_dirty_count(
        root_dir,
        runner=runner,
    )
    pr_ok, pr_payload, pr_error = _github_pr_head_metadata(
        repo,
        pr_number,
        runner=runner,
    )
    blockers = _github_pr_local_state_blockers(
        head_ok=head_ok,
        local_head=local_head,
        head_error=head_error,
        status_ok=status_ok,
        dirty_count=dirty_count,
        status_error=status_error,
        pr_ok=pr_ok,
        pr_payload=pr_payload,
        pr_error=pr_error,
    )
    evidence = _github_pr_local_state_evidence(
        head_ok=head_ok,
        local_head=local_head,
        status_ok=status_ok,
        dirty_count=dirty_count,
        pr_payload=pr_payload if isinstance(pr_payload, dict) else {},
    )
    return _check(
        "github_pr_local_state",
        status="passed" if not blockers else "failed",
        evidence=evidence,
        blockers=blockers,
    )


def _local_git_head(root_dir: Path, *, runner: Runner = run) -> tuple[bool, str, str]:
    """Return the local git HEAD commit."""
    return _run_text(
        ["git", "-C", str(root_dir), "rev-parse", "HEAD"],
        runner=runner,
    )


def _local_git_dirty_count(
    root_dir: Path, *, runner: Runner = run
) -> tuple[bool, int, str]:
    """Return the count of local dirty status entries without returning paths."""
    ok, output, error = _run_text(
        [
            "git",
            "-C",
            str(root_dir),
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
        ],
        runner=runner,
    )
    return ok, len([line for line in output.splitlines() if line.strip()]), error


def _github_pr_head_metadata(
    repo: str,
    pr_number: int,
    *,
    runner: Runner = run,
) -> tuple[bool, Any, str]:
    """Return GitHub PR head metadata."""
    return _run_json(
        [
            "gh",
            "pr",
            "view",
            str(pr_number),
            "--repo",
            repo,
            "--json",
            "headRefOid,headRefName",
        ],
        runner=runner,
    )


def _github_pr_local_state_blockers(
    *,
    head_ok: bool,
    local_head: str,
    head_error: str,
    status_ok: bool,
    dirty_count: int,
    status_error: str,
    pr_ok: bool,
    pr_payload: Any,
    pr_error: str,
) -> list[str]:
    """Return blockers for local PR state evidence."""
    blockers = []
    if not head_ok:
        blockers.append(f"Unable to query local git HEAD: {head_error}")
    if not status_ok:
        blockers.append(f"Unable to query local git status: {status_error}")
    elif dirty_count:
        blockers.append("Local worktree has uncommitted tracked or untracked changes.")
    if not pr_ok or not isinstance(pr_payload, dict):
        blockers.append(f"Unable to query PR head metadata: {pr_error}")
    if head_ok and _pr_head_oid(pr_payload) and local_head != _pr_head_oid(pr_payload):
        blockers.append("Local HEAD does not match the GitHub PR head commit.")
    return blockers


def _github_pr_local_state_evidence(
    *,
    head_ok: bool,
    local_head: str,
    status_ok: bool,
    dirty_count: int,
    pr_payload: dict[str, Any],
) -> dict[str, object]:
    """Return non-secret local PR state evidence."""
    return {
        "localHead": local_head if head_ok else None,
        "prHeadRefOid": _pr_head_oid(pr_payload) or None,
        "prHeadRefName": pr_payload.get("headRefName"),
        "dirtyFileCount": dirty_count if status_ok else None,
    }


def _pr_head_oid(payload: Any) -> str:
    """Return a PR head OID from a decoded payload."""
    if not isinstance(payload, dict):
        return ""
    return str(payload.get("headRefOid") or "")


def _run_text(
    command: list[str],
    *,
    runner: Runner = run,
) -> tuple[bool, str, str]:
    """Run a metadata command and return stripped text output."""
    result = runner(command, check=False, capture_output=True)
    if result.returncode != 0:
        return False, "", result.stderr.strip() or "command failed"
    return True, result.stdout.strip(), ""


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
    outdated_unresolved = [
        node for node in unresolved if bool(node.get("isOutdated"))
    ]
    blocking_unresolved = [
        node for node in unresolved if not bool(node.get("isOutdated"))
    ]
    return _check(
        "github_review_threads",
        status="passed" if not blocking_unresolved else "failed",
        evidence={
            "threadCount": len(nodes),
            "unresolvedThreadCount": len(unresolved),
            "outdatedUnresolvedThreadCount": len(outdated_unresolved),
            "blockingThreadCount": len(blocking_unresolved),
        },
        blockers=(
            [f"{len(blocking_unresolved)} current review thread(s) remain unresolved."]
            if blocking_unresolved
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
        "nodes { isResolved isOutdated } pageInfo { hasNextPage endCursor } } } } }"
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


def _dict_child(payload: dict[str, Any], key: str) -> dict[str, Any]:
    """Return a nested mapping child, treating null GraphQL leaves as absent."""
    value = payload.get(key)
    return value if isinstance(value, dict) else {}


def _review_threads_page(payload: dict[str, Any]) -> tuple[list[dict], dict[str, Any]]:
    """Extract one review-thread page from a GraphQL response."""
    data = _dict_child(payload, "data")
    repository = _dict_child(data, "repository")
    pull_request = _dict_child(repository, "pullRequest")
    review_threads = _dict_child(pull_request, "reviewThreads")
    page_nodes = review_threads.get("nodes") or []
    page_info = _dict_child(review_threads, "pageInfo")
    nodes = [node for node in page_nodes if isinstance(node, dict)]
    return nodes, page_info


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


def _metadata_dict(
    ok: bool,
    payload: object,
    error: str,
    label: str,
) -> tuple[dict[str, object], list[str]]:
    """Normalize a metadata command expected to return a JSON object."""
    if ok and isinstance(payload, dict):
        return cast(dict[str, object], payload), []
    return {}, [f"Unable to query {label}: {error}"]


def _metadata_list(
    ok: bool,
    payload: object,
    error: str,
    label: str,
) -> tuple[list[object], list[str]]:
    """Normalize a metadata command expected to return a JSON list."""
    if ok and isinstance(payload, list):
        return cast(list[object], payload), []
    return [], [f"Unable to query {label}: {error}"]


def _cloudtrail_management_selector_found(selectors: Sequence[object]) -> bool:
    """Return whether CloudTrail captures all read/write management events."""
    return any(
        isinstance(selector, dict)
        and selector.get("IncludeManagementEvents") is True
        and selector.get("ReadWriteType") == "All"
        for selector in selectors
    )


def _cloudtrail_trail_blockers(trail: dict[str, object]) -> list[str]:
    """Return blockers from CloudTrail static metadata."""
    if not trail:
        return []
    required_flags = (
        ("IsMultiRegionTrail", "Operations CloudTrail is not multi-region."),
        (
            "IncludeGlobalServiceEvents",
            "Operations CloudTrail does not include global service events.",
        ),
        (
            "LogFileValidationEnabled",
            "Operations CloudTrail log file validation is not enabled.",
        ),
        ("KmsKeyId", "Operations CloudTrail is not encrypted with a KMS key."),
    )
    return [message for key, message in required_flags if not trail.get(key)]


def _cloudtrail_status_blockers(status: dict[str, object]) -> list[str]:
    """Return blockers from CloudTrail logging status."""
    if not status or status.get("IsLogging"):
        return []
    return ["Operations CloudTrail is not logging."]


def _cloudtrail_selector_blockers(
    *, selectors_queried: bool, management_selector_found: bool
) -> list[str]:
    """Return blockers from CloudTrail event selector metadata."""
    if not selectors_queried or management_selector_found:
        return []
    return ["Operations CloudTrail does not capture all read/write management events."]


def aws_cloudtrail_management_events(
    trail_name: str | None, *, runner: Runner = run
) -> dict[str, object]:
    """Collect metadata-only evidence for the operations CloudTrail trail."""
    if not trail_name:
        return _check(
            "aws_cloudtrail_management_events",
            status="missing",
            blockers=["Operations CloudTrail trail name is required for evidence."],
        )
    trail_ok, trail, trail_error = _run_json(
        [
            "aws",
            "cloudtrail",
            "get-trail",
            "--name",
            trail_name,
            "--query",
            "Trail.{Name:Name,IsMultiRegionTrail:IsMultiRegionTrail,IncludeGlobalServiceEvents:IncludeGlobalServiceEvents,LogFileValidationEnabled:LogFileValidationEnabled,KmsKeyId:KmsKeyId}",
            "--output",
            "json",
        ],
        runner=runner,
    )
    status_ok, status, status_error = _run_json(
        [
            "aws",
            "cloudtrail",
            "get-trail-status",
            "--name",
            trail_name,
            "--query",
            "{IsLogging:IsLogging,LatestDeliveryTime:LatestDeliveryTime}",
            "--output",
            "json",
        ],
        runner=runner,
    )
    selectors_ok, selectors, selectors_error = _run_json(
        [
            "aws",
            "cloudtrail",
            "get-event-selectors",
            "--trail-name",
            trail_name,
            "--query",
            "EventSelectors[].{IncludeManagementEvents:IncludeManagementEvents,ReadWriteType:ReadWriteType}",
            "--output",
            "json",
        ],
        runner=runner,
    )
    trail, trail_blockers = _metadata_dict(
        trail_ok, trail, trail_error, "CloudTrail trail metadata"
    )
    status, status_blockers = _metadata_dict(
        status_ok, status, status_error, "CloudTrail trail status"
    )
    selectors, selector_blockers = _metadata_list(
        selectors_ok,
        selectors,
        selectors_error,
        "CloudTrail management event selectors",
    )
    management_selector_found = _cloudtrail_management_selector_found(selectors)
    blockers = [
        *trail_blockers,
        *status_blockers,
        *selector_blockers,
        *_cloudtrail_trail_blockers(trail),
        *_cloudtrail_status_blockers(status),
        *_cloudtrail_selector_blockers(
            selectors_queried=selectors_ok,
            management_selector_found=management_selector_found,
        ),
    ]
    return _check(
        "aws_cloudtrail_management_events",
        status="passed" if not blockers else "failed",
        evidence={
            "trailName": trail_name,
            "isLogging": bool(status.get("IsLogging")),
            "isMultiRegion": bool(trail.get("IsMultiRegionTrail")),
            "includeGlobalServiceEvents": bool(trail.get("IncludeGlobalServiceEvents")),
            "logFileValidationEnabled": bool(trail.get("LogFileValidationEnabled")),
            "kmsEncrypted": bool(trail.get("KmsKeyId")),
            "managementEventSelectorCount": len(selectors),
            "capturesAllManagementEvents": management_selector_found,
        },
        blockers=blockers,
    )


def aws_restore_jobs(days: int, *, runner: Runner = run) -> dict[str, object]:
    """Collect recent AWS Backup restore-job status counts as account context."""
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


def _read_restore_drill_payload(
    evidence_path: Path,
) -> tuple[dict[str, Any], list[str]]:
    """Read and parse a restore-drill evidence payload."""
    try:
        payload = json.loads(evidence_path.read_text(encoding="utf-8"))
    except OSError as exc:
        return {}, [f"Unable to read restore-drill evidence: {exc}"]
    except json.JSONDecodeError as exc:
        return {}, [f"Restore-drill evidence is not valid JSON: {exc.msg}"]
    if not isinstance(payload, dict):
        return {}, ["Restore-drill evidence must be a JSON object."]
    return payload, []


def _restore_drill_payload_blockers(payload: dict[str, Any]) -> list[str]:
    """Return blockers for workload-scoped restore-drill evidence."""
    blockers: list[str] = [
        f"Restore-drill evidence is missing required field: {field}"
        for field in RESTORE_DRILL_REQUIRED_FIELDS
        if not payload.get(field)
    ]

    if payload.get("workload") != "bootstrap-infrastructure":
        blockers.append(
            "Restore-drill evidence must be scoped to the bootstrap-infrastructure "
            "workload."
        )
    if payload.get("validationResult") != "passed":
        blockers.append("Restore-drill evidence validationResult must be passed.")
    if payload.get("cleanupConfirmed") is not True:
        blockers.append("Restore-drill evidence must confirm cleanup.")

    return blockers


def _restore_drill_evidence_payload(payload: dict[str, Any]) -> dict[str, object]:
    """Return the non-secret restore-drill evidence fields."""
    return {
        "workload": payload.get("workload"),
        "environment": payload.get("environment"),
        "completedAt": payload.get("completedAt"),
        "targetRestoreLocation": payload.get("targetRestoreLocation"),
        "validationResult": payload.get("validationResult"),
        "cleanupConfirmed": payload.get("cleanupConfirmed") is True,
    }


def restore_drill_evidence(evidence_path: Path | None) -> dict[str, object]:
    """Validate a workload-scoped restore-drill evidence record."""
    if evidence_path is None:
        return _check(
            "restore_drill_evidence",
            status="missing",
            blockers=[
                "RESTORE_DRILL_EVIDENCE path is required for workload-scoped "
                "restore evidence."
            ],
        )

    payload, read_blockers = _read_restore_drill_payload(evidence_path)
    blockers = [*read_blockers, *_restore_drill_payload_blockers(payload)]
    return _check(
        "restore_drill_evidence",
        status="passed" if not blockers else "failed",
        evidence=_restore_drill_evidence_payload(payload),
        blockers=blockers,
    )


def repository_fanout_evidence(
    root_dir: Path, args: argparse.Namespace
) -> dict[str, object]:
    """Collect static repository fanout evidence from committed catalogs."""
    schema_path = root_dir / "pulumi" / "repositories.schema.json"
    catalog_paths = _evidence_repository_catalog_paths(root_dir)
    if not catalog_paths:
        return _check(
            "repository_fanout",
            status="missing",
            blockers=[
                "No non-example repository catalog JSON files were found for "
                "fanout evidence."
            ],
        )
    thresholds = _fanout_thresholds(args)
    reports = []
    failures: list[str] = []
    for catalog_path in catalog_paths:
        catalog_name = str(catalog_path.relative_to(root_dir))
        try:
            report = catalog_fanout_report(catalog_path, schema_path)
        except ValueError as exc:
            failures.append(f"{catalog_name}: {exc}")
            reports.append({"catalog": catalog_name, "error": str(exc)})
            continue
        reports.append(
            {
                "catalog": catalog_name,
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


def _evidence_repository_catalog_paths(root_dir: Path) -> list[Path]:
    """Return non-example repository catalogs that can support evidence claims."""
    return [
        path
        for path in repository_catalog_paths(root_dir)
        if path.name not in EXAMPLE_CATALOG_NAMES
    ]


PILLAR_CHECKS = {
    "Operational Excellence": (
        "github_pr_checks",
        "github_pr_local_state",
        "github_review_threads",
        "github_branch_protection",
        "aws_sns_alert_route",
        "aws_cloudtrail_management_events",
    ),
    "Security": (
        "github_pr_checks",
        "github_pr_local_state",
        "github_review_threads",
        "github_branch_protection",
        "aws_identity",
        "aws_cloudtrail_management_events",
    ),
    "Reliability": (
        "github_pr_checks",
        "github_pr_local_state",
        "aws_sns_alert_route",
        "restore_drill_evidence",
        "repository_fanout",
    ),
    "Performance Efficiency": ("repository_fanout",),
    "Cost Optimization": ("aws_cost_controls", "repository_fanout"),
    "Sustainability": ("repository_fanout",),
}
WELL_ARCHITECTED_SCORE_CAP = 4.0


def pillar_scores(checks: Sequence[dict[str, object]]) -> dict[str, float]:
    """Calculate proxy readiness scores from normalized metadata checks."""
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


def well_architected_scores(
    proxy_scores: dict[str, float],
    checks: Sequence[dict[str, object]],
) -> dict[str, float]:
    """Cap final score claims until question-level evidence gates pass."""
    by_name = {str(check["name"]): check for check in checks}
    readiness_passed = all(
        by_name.get(gate, {}).get("status") == "passed" for gate in READINESS_GATES
    )
    if readiness_passed:
        return proxy_scores
    return {
        pillar: min(score, WELL_ARCHITECTED_SCORE_CAP)
        for pillar, score in proxy_scores.items()
    }


def score_blockers(checks: Sequence[dict[str, object]]) -> list[str]:
    """Return score-claim blockers for final Well-Architected scoring."""
    by_name = {str(check["name"]): check for check in checks}
    blockers: list[str] = []
    for gate in READINESS_GATES:
        if by_name.get(gate, {}).get("status") != "passed":
            blockers.append(
                f"{gate} is required before proxy readiness scores can be treated "
                "as final Well-Architected scores."
            )
    return blockers


def question_matrix_evidence(args: argparse.Namespace) -> dict[str, object]:
    """Validate structured evidence for all Well-Architected questions."""
    return _structured_evidence_check(
        name="question_matrix_evidence",
        label="Question-matrix evidence",
        evidence_path=args.question_matrix_evidence,
        legacy_confirmed=args.question_matrix_evidence_confirmed,
        required_fields=QUESTION_MATRIX_REQUIRED_FIELDS,
        count_field="questionCount",
        unresolved_field="unresolvedQuestionCount",
        minimum_count=EXPECTED_WELL_ARCHITECTED_QUESTION_COUNT,
    )


def external_control_evidence(args: argparse.Namespace) -> dict[str, object]:
    """Validate structured evidence for external control ownership and freshness."""
    return _structured_evidence_check(
        name="external_control_evidence",
        label="External-control evidence",
        evidence_path=args.external_control_evidence,
        legacy_confirmed=args.external_control_evidence_confirmed,
        required_fields=EXTERNAL_CONTROL_REQUIRED_FIELDS,
        count_field="controlCount",
        unresolved_field="unresolvedControlCount",
        minimum_count=len(REQUIRED_EXTERNAL_CONTROL_IDS),
        required_control_ids=REQUIRED_EXTERNAL_CONTROL_IDS,
    )


def _structured_evidence_check(
    *,
    name: str,
    label: str,
    evidence_path: Path | None,
    legacy_confirmed: bool,
    required_fields: Sequence[str],
    count_field: str,
    unresolved_field: str,
    minimum_count: int,
    required_control_ids: Sequence[str] = (),
) -> dict[str, object]:
    """Validate a non-secret, owner-backed evidence record."""
    if evidence_path is None:
        blockers = [
            f"{label} JSON path is required for final Well-Architected scoring."
        ]
        if legacy_confirmed:
            blockers.append(
                f"{label} cannot be satisfied by a boolean confirmation flag."
            )
        return _check(name, status="missing", blockers=blockers)

    payload, blockers = _read_structured_evidence_payload(evidence_path, label)
    blockers.extend(_structured_evidence_payload_blockers(payload, required_fields))
    blockers.extend(_structured_evidence_freshness_blockers(payload, label))
    blockers.extend(
        _structured_evidence_count_blockers(
            payload,
            label=label,
            count_field=count_field,
            unresolved_field=unresolved_field,
            minimum_count=minimum_count,
        )
    )
    blockers.extend(
        _structured_evidence_control_id_blockers(payload, required_control_ids)
    )
    return _check(
        name,
        status="passed" if not blockers else "failed",
        evidence=_structured_evidence_payload(payload, count_field, unresolved_field),
        blockers=blockers,
    )


def _read_structured_evidence_payload(
    evidence_path: Path,
    label: str,
) -> tuple[dict[str, Any], list[str]]:
    """Read one structured evidence JSON object."""
    try:
        payload = json.loads(evidence_path.read_text(encoding="utf-8"))
    except OSError as exc:
        return {}, [f"Unable to read {label}: {exc}"]
    except json.JSONDecodeError as exc:
        return {}, [f"{label} is not valid JSON: {exc.msg}"]
    if not isinstance(payload, dict):
        return {}, [f"{label} must be a JSON object."]
    return payload, []


def _structured_evidence_payload_blockers(
    payload: dict[str, Any],
    required_fields: Sequence[str],
) -> list[str]:
    """Return blockers for common structured evidence fields."""
    blockers = [
        f"Structured evidence is missing required field: {field}"
        for field in required_fields
        if not _structured_evidence_field_present(payload, field)
    ]
    if payload.get("workload") != "bootstrap-infrastructure":
        blockers.append(
            "Structured evidence must be scoped to the bootstrap-infrastructure "
            "workload."
        )
    return blockers


def _structured_evidence_field_present(payload: dict[str, Any], field: str) -> bool:
    """Return whether a required structured evidence field is populated."""
    if field not in payload or payload[field] is None:
        return False
    value = payload[field]
    return not (isinstance(value, str) and not value.strip())


def _structured_evidence_freshness_blockers(
    payload: dict[str, Any],
    label: str,
) -> list[str]:
    """Return blockers for stale or invalid reviewedAt values."""
    reviewed_at = payload.get("reviewedAt")
    if not reviewed_at:
        return []
    parsed_at = _parse_reviewed_at(reviewed_at)
    if parsed_at is None:
        return [f"{label} reviewedAt must be an ISO-8601 date or timestamp."]
    now = dt.datetime.now(dt.timezone.utc)
    if parsed_at > now + dt.timedelta(minutes=5):
        return [f"{label} reviewedAt is in the future."]
    max_age = dt.timedelta(days=STRUCTURED_EVIDENCE_MAX_AGE_DAYS)
    if now - parsed_at > max_age:
        return [f"{label} is older than {STRUCTURED_EVIDENCE_MAX_AGE_DAYS} days."]
    return []


def _parse_reviewed_at(value: object) -> dt.datetime | None:
    """Parse an ISO date or timestamp into an aware UTC datetime."""
    if not isinstance(value, str):
        return None
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
        parsed_datetime = parsed_datetime.replace(tzinfo=dt.timezone.utc)
    return parsed_datetime.astimezone(dt.timezone.utc)


def _structured_evidence_count_blockers(
    payload: dict[str, Any],
    *,
    label: str,
    count_field: str,
    unresolved_field: str,
    minimum_count: int,
) -> list[str]:
    """Return blockers for coverage and unresolved counts."""
    blockers = []
    count = payload.get(count_field)
    unresolved = payload.get(unresolved_field)
    if isinstance(count, bool) or not isinstance(count, int):
        blockers.append(f"{label} {count_field} must be an integer.")
    elif count < minimum_count:
        blockers.append(f"{label} {count_field} must be at least {minimum_count}.")
    if isinstance(unresolved, bool) or not isinstance(unresolved, int):
        blockers.append(f"{label} {unresolved_field} must be an integer.")
    elif unresolved != 0:
        blockers.append(f"{label} has {unresolved} unresolved item(s).")
    return blockers


def _structured_evidence_control_id_blockers(
    payload: dict[str, Any],
    required_control_ids: Sequence[str],
) -> list[str]:
    """Return blockers when external-control evidence omits required controls."""
    if not required_control_ids:
        return []
    controls = payload.get("controls")
    if not isinstance(controls, list):
        return ["External-control evidence controls must be a list."]
    observed = {
        str(control.get("id"))
        for control in controls
        if isinstance(control, dict) and control.get("id")
    }
    missing = sorted(set(required_control_ids) - observed)
    if missing:
        return [
            "External-control evidence is missing required controls: "
            f"{', '.join(missing)}."
        ]
    return []


def _structured_evidence_payload(
    payload: dict[str, Any],
    count_field: str,
    unresolved_field: str,
) -> dict[str, object]:
    """Return non-secret structured evidence fields."""
    controls = payload.get("controls")
    control_ids = (
        sorted(
            str(control.get("id"))
            for control in controls
            if isinstance(control, dict) and control.get("id")
        )
        if isinstance(controls, list)
        else []
    )
    return {
        "workload": payload.get("workload"),
        "owner": payload.get("owner"),
        "reviewedAt": payload.get("reviewedAt"),
        "evidenceLocation": payload.get("evidenceLocation"),
        count_field: payload.get(count_field),
        unresolved_field: payload.get(unresolved_field),
        "controlIds": control_ids,
    }


def collect_evidence(
    args: argparse.Namespace, *, runner: Runner = run
) -> dict[str, Any]:
    """Collect metadata-only Well-Architected evidence."""
    checks = [
        github_pr_checks(args.repo, args.pr, runner=runner),
        github_pr_local_state(args.repo, args.pr, args.root_dir, runner=runner),
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
        aws_cloudtrail_management_events(
            args.operations_cloudtrail_name, runner=runner
        ),
        aws_restore_jobs(args.restore_window_days, runner=runner),
        restore_drill_evidence(args.restore_drill_evidence),
        repository_fanout_evidence(args.root_dir, args),
        question_matrix_evidence(args),
        external_control_evidence(args),
    ]
    proxy_scores = pillar_scores(checks)
    return {
        "generatedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
        "repo": args.repo,
        "pr": args.pr,
        "branch": args.branch,
        "checks": checks,
        "proxyPillarScores": proxy_scores,
        "pillarScores": well_architected_scores(proxy_scores, checks),
        "scoreBlockers": score_blockers(checks),
        "blockers": [*_all_blockers(checks), *score_blockers(checks)],
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
    parser.add_argument("--operations-cloudtrail-name")
    parser.add_argument("--restore-drill-evidence", type=Path)
    parser.add_argument("--question-matrix-evidence", type=Path)
    parser.add_argument("--external-control-evidence", type=Path)
    parser.add_argument("--restore-window-days", type=int, default=90)
    parser.add_argument(
        "--question-matrix-evidence-confirmed",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--external-control-evidence-confirmed",
        action="store_true",
        help=argparse.SUPPRESS,
    )
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
    parser.add_argument("--max-cloudtrail-trails", type=int, default=20)
    parser.add_argument("--max-cost-anomaly-monitors", type=int, default=20)
    parser.add_argument("--max-cost-anomaly-subscriptions", type=int, default=20)
    parser.add_argument("--max-cost-allocation-tags", type=int, default=100)
    parser.add_argument("--max-guardduty-detectors", type=int, default=20)
    parser.add_argument("--max-security-hub-accounts", type=int, default=20)
    parser.add_argument("--max-config-recorders", type=int, default=20)
    parser.add_argument("--max-config-delivery-channels", type=int, default=20)
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
