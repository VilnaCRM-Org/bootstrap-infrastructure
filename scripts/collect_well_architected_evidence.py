#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import json
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any, cast
from urllib.parse import quote

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
DEFAULT_PRODUCTION_ENVIRONMENT = "prod"
DEFAULT_PRODUCTION_REVIEWER = "Kravalg"
DEFAULT_DEPENDABOT_DEPENDENCY = "GitPython"
DEFAULT_DEPENDABOT_MANIFEST = "uv.lock"
BLOCKING_DEPENDABOT_SEVERITIES = frozenset({"critical", "high"})
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
EXPECTED_WELL_ARCHITECTED_QUESTION_COUNTS = {
    "Operational Excellence": 11,
    "Security": 11,
    "Reliability": 13,
    "Performance Efficiency": 5,
    "Cost Optimization": 11,
    "Sustainability": 6,
}
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

    evidence, blocking_count = _review_thread_counts(nodes)
    return _check(
        "github_review_threads",
        status="passed" if not blocking_count else "failed",
        evidence=evidence,
        blockers=_review_thread_blockers(blocking_count),
    )


def _review_thread_counts(nodes: list[dict]) -> tuple[dict[str, int], int]:
    """Return review-thread evidence counts and current blocking count."""
    unresolved = [
        node for node in nodes if isinstance(node, dict) and not node.get("isResolved")
    ]
    outdated_count = sum(1 for node in unresolved if bool(node.get("isOutdated")))
    blocking_count = len(unresolved) - outdated_count
    return (
        {
            "threadCount": len(nodes),
            "unresolvedThreadCount": len(unresolved),
            "outdatedUnresolvedThreadCount": outdated_count,
            "blockingThreadCount": blocking_count,
        },
        blocking_count,
    )


def _review_thread_blockers(blocking_count: int) -> list[str]:
    """Return blockers for current unresolved review threads."""
    if not blocking_count:
        return []
    return [f"{blocking_count} current review thread(s) remain unresolved."]


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


def github_dependabot_alerts(
    repo: str,
    dependency: str = DEFAULT_DEPENDABOT_DEPENDENCY,
    manifest_path: str = DEFAULT_DEPENDABOT_MANIFEST,
    blocking_severities: frozenset[str] = BLOCKING_DEPENDABOT_SEVERITIES,
    *,
    runner: Runner = run,
) -> dict[str, object]:
    """Collect open Dependabot alert evidence for one dependency manifest."""
    ok, payload, error = _run_json(
        ["gh", "api", _dependabot_alert_api_path(repo, dependency)],
        runner=runner,
    )
    if not ok or not isinstance(payload, list):
        return _unknown_dependabot_alert_check(
            dependency=dependency,
            manifest_path=manifest_path,
            blocking_severities=blocking_severities,
            error=error,
        )

    matching_alerts = _matching_dependabot_alerts(
        payload,
        dependency=dependency,
        manifest_path=manifest_path,
    )
    blocking_alerts = _blocking_dependabot_alerts(
        matching_alerts,
        blocking_severities,
    )
    open_alert_numbers = _dependabot_alert_numbers(blocking_alerts)
    blockers = _dependabot_alert_blockers(
        dependency=dependency,
        manifest_path=manifest_path,
        open_alert_numbers=open_alert_numbers,
        open_alert_count=len(blocking_alerts),
    )
    return _check(
        "github_dependabot_alerts",
        status="passed" if not blockers else "failed",
        evidence={
            "dependencyName": dependency,
            "manifestPath": manifest_path,
            "blockingSeverities": sorted(blocking_severities),
            "matchingOpenAlertCount": len(matching_alerts),
            "openAlertCount": len(blocking_alerts),
            "openAlertNumbers": open_alert_numbers,
            "alerts": blocking_alerts,
        },
        blockers=blockers,
    )


def _dependabot_alert_api_path(repo: str, dependency: str) -> str:
    """Return the GitHub API path for open Dependabot alerts."""
    return (
        f"repos/{repo}/dependabot/alerts?state=open&dependency_name="
        f"{quote(dependency, safe='')}&per_page=100"
    )


def _unknown_dependabot_alert_check(
    *,
    dependency: str,
    manifest_path: str,
    blocking_severities: frozenset[str],
    error: str,
) -> dict[str, object]:
    """Return an unknown Dependabot check when GitHub metadata is unreadable."""
    return _check(
        "github_dependabot_alerts",
        status="unknown",
        evidence={
            "dependencyName": dependency,
            "manifestPath": manifest_path,
            "blockingSeverities": sorted(blocking_severities),
        },
        blockers=[
            "Unable to read GitHub Dependabot alerts for "
            f"{dependency} in {manifest_path}: {error}."
        ],
    )


def _matching_dependabot_alerts(
    payload: Sequence[object],
    *,
    dependency: str,
    manifest_path: str,
) -> list[dict[str, object]]:
    """Return sorted open alerts for the target dependency manifest."""
    alerts = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        summary = _dependabot_alert_summary(cast("dict[str, Any]", item))
        if _dependabot_alert_matches(
            summary,
            dependency=dependency,
            manifest_path=manifest_path,
        ):
            alerts.append(summary)
    return sorted(alerts, key=lambda alert: _dependabot_alert_number(alert) or 0)


def _blocking_dependabot_alerts(
    alerts: Sequence[dict[str, object]],
    blocking_severities: frozenset[str],
) -> list[dict[str, object]]:
    """Return high-impact Dependabot alerts that still block SEC11."""
    return [
        alert
        for alert in alerts
        if str(alert.get("severity", "")).lower() in blocking_severities
    ]


def _dependabot_alert_numbers(alerts: Sequence[dict[str, object]]) -> list[int]:
    """Return GitHub alert numbers when present."""
    return [
        number
        for alert in alerts
        if (number := _dependabot_alert_number(alert)) is not None
    ]


def _dependabot_alert_summary(alert: dict[str, Any]) -> dict[str, object]:
    """Return non-secret metadata from one Dependabot alert."""
    dependency = _mapping(alert.get("dependency"))
    package = _mapping(dependency.get("package"))
    advisory = _mapping(alert.get("security_advisory"))
    vulnerability = _mapping(alert.get("security_vulnerability"))
    first_patched_version = _mapping(vulnerability.get("first_patched_version"))
    return {
        "number": alert.get("number"),
        "state": str(alert.get("state") or ""),
        "dependencyName": str(package.get("name") or ""),
        "manifestPath": str(dependency.get("manifest_path") or ""),
        "severity": str(advisory.get("severity") or "").lower(),
        "firstPatchedVersion": str(first_patched_version.get("identifier") or ""),
    }


def _mapping(value: object) -> dict[str, Any]:
    """Return a dict payload when an API field is an object."""
    return cast("dict[str, Any]", value) if isinstance(value, dict) else {}


def _dependabot_alert_matches(
    alert: dict[str, object],
    *,
    dependency: str,
    manifest_path: str,
) -> bool:
    """Return whether a Dependabot alert targets the dependency manifest."""
    return (
        str(alert.get("state", "")).lower() == "open"
        and str(alert.get("dependencyName", "")).lower() == dependency.lower()
        and alert.get("manifestPath") == manifest_path
    )


def _dependabot_alert_number(alert: dict[str, object]) -> int | None:
    """Return the alert number if GitHub supplied one."""
    number = alert.get("number")
    return number if isinstance(number, int) else None


def _dependabot_alert_blockers(
    *,
    dependency: str,
    manifest_path: str,
    open_alert_numbers: Sequence[int],
    open_alert_count: int,
) -> list[str]:
    """Return blockers for unresolved high-impact Dependabot alerts."""
    if open_alert_count == 0:
        return []
    if open_alert_numbers:
        alert_text = ", ".join(f"#{number}" for number in open_alert_numbers)
    else:
        alert_text = f"{open_alert_count} alert(s)"
    return [
        "Open default-branch Dependabot alerts remain for "
        f"{dependency} in {manifest_path}: {alert_text}."
    ]


def github_production_environment(
    repo: str,
    environment: str = DEFAULT_PRODUCTION_ENVIRONMENT,
    reviewer_login: str | None = DEFAULT_PRODUCTION_REVIEWER,
    *,
    runner: Runner = run,
) -> dict[str, object]:
    """Collect protected production environment evidence from GitHub."""
    ok, payload, error = _run_json(
        ["gh", "api", f"repos/{repo}/environments/{environment}"],
        runner=runner,
    )
    if not ok or not isinstance(payload, dict):
        return _check(
            "github_production_environment",
            status="failed",
            evidence={"environment": environment, "readable": False},
            blockers=[
                f"GitHub environment {environment!r} is not configured "
                f"or readable: {error}."
            ],
        )

    reviewer_logins = _environment_required_reviewer_logins(payload)
    reviewer_count = _environment_required_reviewer_count(payload)
    branch_policy = payload.get("deployment_branch_policy") or {}
    protected_branches = bool(branch_policy.get("protected_branches"))
    custom_branch_policies = bool(branch_policy.get("custom_branch_policies"))
    prevents_self_review = _environment_prevents_self_review(payload)
    blockers = _production_environment_blockers(
        environment=environment,
        reviewer_login=reviewer_login,
        reviewer_logins=reviewer_logins,
        reviewer_count=reviewer_count,
        prevents_self_review=prevents_self_review,
        protected_branches=protected_branches,
        custom_branch_policies=custom_branch_policies,
    )
    return _check(
        "github_production_environment",
        status="passed" if not blockers else "failed",
        evidence={
            "environment": environment,
            "readable": True,
            "requiredReviewerCount": reviewer_count,
            "requiredReviewerLogins": reviewer_logins,
            "expectedReviewerLogin": reviewer_login,
            "preventSelfReview": prevents_self_review,
            "protectedBranchesOnly": protected_branches and not custom_branch_policies,
        },
        blockers=blockers,
    )


def _production_environment_blockers(
    *,
    environment: str,
    reviewer_login: str | None,
    reviewer_logins: Sequence[str],
    reviewer_count: int,
    prevents_self_review: bool,
    protected_branches: bool,
    custom_branch_policies: bool,
) -> list[str]:
    """Return blockers for protected production environment metadata."""
    blockers: list[str] = []
    if reviewer_count < 1:
        blockers.append(
            f"GitHub environment {environment!r} does not require reviewers."
        )
    elif reviewer_login and reviewer_logins and reviewer_login not in reviewer_logins:
        blockers.append(
            f"GitHub environment {environment!r} required reviewers do not include "
            f"{reviewer_login}."
        )
    if not prevents_self_review:
        blockers.append(
            f"GitHub environment {environment!r} does not prevent self-review."
        )
    if not protected_branches or custom_branch_policies:
        blockers.append(
            f"GitHub environment {environment!r} is not limited to protected branches."
        )
    return blockers


def _environment_required_reviewer_count(payload: dict[str, Any]) -> int:
    """Return required reviewer count from either environment response shape."""
    reviewers = _environment_required_reviewers(payload)
    return len(reviewers)


def _environment_required_reviewer_logins(payload: dict[str, Any]) -> list[str]:
    """Return required reviewer logins exposed by the environment response."""
    logins: set[str] = set()
    for reviewer in _environment_required_reviewers(payload):
        reviewer_payload = reviewer.get("reviewer")
        if isinstance(reviewer_payload, dict) and isinstance(
            reviewer_payload.get("login"), str
        ):
            logins.add(reviewer_payload["login"])
        elif isinstance(reviewer.get("login"), str):
            logins.add(reviewer["login"])
    return sorted(logins)


def _environment_required_reviewers(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Return required reviewer entries from GitHub environment metadata."""
    direct_reviewers = _dict_items(payload.get("reviewers"))
    if direct_reviewers:
        return direct_reviewers
    for rule in _dict_items(payload.get("protection_rules")):
        if rule.get("type") == "required_reviewers":
            rule_reviewers = _dict_items(rule.get("reviewers"))
            if rule_reviewers:
                return rule_reviewers
    return []


def _dict_items(value: object) -> list[dict[str, Any]]:
    """Return dictionary entries from a list-shaped API field."""
    if not isinstance(value, list):
        return []
    items: list[dict[str, Any]] = []
    for item in value:
        if isinstance(item, dict):
            items.append(cast(dict[str, Any], item))
    return items


def _environment_prevents_self_review(payload: dict[str, Any]) -> bool:
    """Return whether the required-reviewer rule prevents self-review."""
    if payload.get("prevent_self_review") is True:
        return True
    rules = payload.get("protection_rules")
    if not isinstance(rules, list):
        return False
    return any(
        isinstance(rule, dict)
        and rule.get("type") == "required_reviewers"
        and rule.get("prevent_self_review") is True
        for rule in rules
    )


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


def aws_iam_account_access(*, runner: Runner = run) -> dict[str, object]:
    """Collect non-secret IAM account and static credential metadata."""
    ok, summary, error = _run_json(
        [
            "aws",
            "iam",
            "get-account-summary",
            "--query",
            "SummaryMap",
            "--output",
            "json",
        ],
        runner=runner,
    )
    if not ok or not isinstance(summary, dict):
        return _check(
            "aws_iam_account_access",
            status="unknown",
            blockers=[f"Unable to query IAM account summary: {error}"],
        )
    users, user_blockers = _iam_user_names(runner=runner)
    key_counts = _iam_access_key_counts(users, runner=runner)
    evidence = _iam_account_access_evidence(summary, users, key_counts)
    blockers = [
        *user_blockers,
        *_iam_account_access_blockers(evidence),
    ]
    return _check(
        "aws_iam_account_access",
        status="passed" if not blockers else "failed",
        evidence=evidence,
        blockers=blockers,
    )


def _iam_user_names(*, runner: Runner = run) -> tuple[list[str], list[str]]:
    """Return IAM user names for follow-up metadata queries without emitting them."""
    ok, payload, error = _run_json(
        ["aws", "iam", "list-users", "--query", "Users[].UserName", "--output", "json"],
        runner=runner,
    )
    if not ok or not isinstance(payload, list):
        return [], [f"Unable to query IAM users: {error}"]
    return [item for item in payload if isinstance(item, str) and item], []


def _iam_access_key_counts(
    users: Sequence[str], *, runner: Runner = run
) -> dict[str, int]:
    """Return aggregate access-key status counts without retaining key ids."""
    counts = {
        "active": 0,
        "inactive": 0,
        "other": 0,
        "usersWithActive": 0,
        "unreadableUsers": 0,
    }
    for user in users:
        ok, statuses, _error = _run_json(
            [
                "aws",
                "iam",
                "list-access-keys",
                "--user-name",
                user,
                "--query",
                "AccessKeyMetadata[].Status",
                "--output",
                "json",
            ],
            runner=runner,
        )
        if not ok or not isinstance(statuses, list):
            counts["unreadableUsers"] += 1
            continue
        _record_access_key_statuses(statuses, counts)
    return counts


def _record_access_key_statuses(
    statuses: Sequence[object], counts: dict[str, int]
) -> None:
    """Accumulate access-key status metadata for one IAM user."""
    user_has_active_key = False
    for status in statuses:
        if status == "Active":
            counts["active"] += 1
            user_has_active_key = True
        elif status == "Inactive":
            counts["inactive"] += 1
        else:
            counts["other"] += 1
    if user_has_active_key:
        counts["usersWithActive"] += 1


def _iam_account_access_evidence(
    summary: dict[str, Any],
    users: Sequence[str],
    key_counts: dict[str, int],
) -> dict[str, object]:
    """Build non-secret IAM account-access evidence."""
    return {
        "summaryUserCount": _summary_int(summary, "Users"),
        "discoveredUserCount": len(users),
        "mfaDeviceCount": _summary_int(summary, "MFADevices"),
        "mfaDevicesInUse": _summary_int(summary, "MFADevicesInUse"),
        "accountMfaEnabled": _summary_int(summary, "AccountMFAEnabled"),
        "accountAccessKeysPresent": _summary_int(summary, "AccountAccessKeysPresent"),
        "activeUserAccessKeyCount": key_counts["active"],
        "inactiveUserAccessKeyCount": key_counts["inactive"],
        "otherUserAccessKeyStatusCount": key_counts["other"],
        "usersWithActiveAccessKeys": key_counts["usersWithActive"],
        "unreadableAccessKeyUserCount": key_counts["unreadableUsers"],
    }


def _iam_account_access_blockers(evidence: dict[str, object]) -> list[str]:
    """Return security-account blockers from non-secret IAM metadata."""
    blockers: list[str] = []
    if evidence["accountMfaEnabled"] != 1:
        blockers.append("IAM account summary does not report root/account MFA enabled.")
    if evidence["accountAccessKeysPresent"] != 0:
        blockers.append("IAM account summary reports root account access keys present.")
    if int(evidence["mfaDevicesInUse"]) < int(evidence["summaryUserCount"]):
        blockers.append(
            "IAM user count exceeds MFA devices in use; human MFA/SSO posture "
            "requires security-owner attestation."
        )
    if evidence["activeUserAccessKeyCount"] != 0:
        blockers.append(
            "IAM access-key metadata reports active user access keys; record an "
            "approved exception or rotate/remove them before Security 5/5."
        )
    if evidence["unreadableAccessKeyUserCount"] != 0:
        blockers.append(
            "Unable to query access-key metadata for one or more IAM users."
        )
    return blockers


def _summary_int(summary: dict[str, Any], key: str) -> int:
    """Return one IAM summary integer value."""
    value = summary.get(key)
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


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
            "Subscriptions[].{Protocol:Protocol,Endpoint:Endpoint}",
            "--output",
            "json",
        ],
        runner=runner,
    )
    subscriptions = _sns_subscription_items(protocols)
    protocol_names = [subscription["protocol"] for subscription in subscriptions]
    blockers = []
    sqs_queue: dict[str, object] | None = None
    if not topic_ok:
        blockers.append(f"Unable to query SNS topic attributes: {topic_error}")
    elif not kms_key_id:
        blockers.append("Operations SNS topic is not encrypted with a KMS key.")
    if not subs_ok:
        blockers.append(f"Unable to query SNS subscriptions: {subs_error}")
    elif "sqs" not in protocol_names:
        blockers.append("Operations SNS topic does not have an SQS subscription.")
    else:
        sqs_queue, sqs_blockers = _sqs_subscription_queue_metadata(
            subscriptions,
            runner=runner,
        )
        blockers.extend(sqs_blockers)
    evidence: dict[str, object] = {
        "topicArn": topic_arn,
        "encrypted": bool(kms_key_id),
        "subscriptionCount": len(protocol_names),
        "subscriptionProtocols": sorted(set(protocol_names)),
    }
    if sqs_queue is not None:
        evidence["sqsQueue"] = sqs_queue
    return _check(
        "aws_sns_alert_route",
        status="passed" if not blockers else "failed",
        evidence=evidence,
        blockers=blockers,
    )


def _sns_subscription_items(payload: object) -> list[dict[str, str]]:
    """Normalize SNS subscription query results."""
    if not isinstance(payload, list):
        return []
    subscriptions: list[dict[str, str]] = []
    for item in payload:
        if isinstance(item, str):
            subscriptions.append({"protocol": item, "endpoint": ""})
            continue
        if not isinstance(item, dict):
            continue
        protocol = item.get("Protocol")
        endpoint = item.get("Endpoint")
        if isinstance(protocol, str) and protocol:
            subscriptions.append(
                {
                    "protocol": protocol,
                    "endpoint": endpoint if isinstance(endpoint, str) else "",
                }
            )
    return subscriptions


def _sqs_subscription_queue_metadata(
    subscriptions: Sequence[dict[str, str]],
    *,
    runner: Runner = run,
) -> tuple[dict[str, object] | None, list[str]]:
    """Collect non-secret queue metadata for the first SQS subscription."""
    endpoint = next(
        (
            subscription["endpoint"]
            for subscription in subscriptions
            if subscription["protocol"] == "sqs" and subscription["endpoint"]
        ),
        "",
    )
    queue_name = _queue_name_from_sqs_arn(endpoint)
    if not queue_name:
        return None, ["Unable to derive SQS queue name from SNS subscription."]

    url_ok, queue_url, url_error = _run_json(
        [
            "aws",
            "sqs",
            "get-queue-url",
            "--queue-name",
            queue_name,
            "--query",
            "QueueUrl",
            "--output",
            "json",
        ],
        runner=runner,
    )
    if not url_ok or not isinstance(queue_url, str) or not queue_url:
        return None, [f"Unable to query SQS queue URL: {url_error}"]

    attributes_ok, attributes, attributes_error = _run_json(
        [
            "aws",
            "sqs",
            "get-queue-attributes",
            "--queue-url",
            queue_url,
            "--attribute-names",
            "ApproximateNumberOfMessages",
            "ApproximateNumberOfMessagesNotVisible",
            "ApproximateNumberOfMessagesDelayed",
            "MessageRetentionPeriod",
            "VisibilityTimeout",
            "--query",
            "Attributes",
            "--output",
            "json",
        ],
        runner=runner,
    )
    if not attributes_ok or not isinstance(attributes, dict):
        return None, [f"Unable to query SQS queue attributes: {attributes_error}"]

    return {
        "queueArn": endpoint,
        "queueName": queue_name,
        "visibleMessages": _metadata_int(attributes.get("ApproximateNumberOfMessages")),
        "notVisibleMessages": _metadata_int(
            attributes.get("ApproximateNumberOfMessagesNotVisible")
        ),
        "delayedMessages": _metadata_int(
            attributes.get("ApproximateNumberOfMessagesDelayed")
        ),
        "messageRetentionSeconds": _metadata_int(
            attributes.get("MessageRetentionPeriod")
        ),
        "visibilityTimeoutSeconds": _metadata_int(attributes.get("VisibilityTimeout")),
    }, []


def _queue_name_from_sqs_arn(value: str) -> str:
    """Return the queue name component from an SQS ARN."""
    parts = value.split(":", maxsplit=5)
    if len(parts) != 6 or parts[2] != "sqs" or not parts[5]:
        return ""
    return parts[5]


def _metadata_int(value: object) -> int | None:
    """Parse an AWS metadata integer represented as a JSON string or number."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return None
    return None


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
        "github_production_environment",
        "aws_sns_alert_route",
        "aws_cloudtrail_management_events",
    ),
    "Security": (
        "github_pr_checks",
        "github_pr_local_state",
        "github_review_threads",
        "github_branch_protection",
        "github_dependabot_alerts",
        "aws_identity",
        "aws_iam_account_access",
        "aws_cloudtrail_management_events",
    ),
    "Reliability": (
        "github_pr_checks",
        "github_pr_local_state",
        "github_production_environment",
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
        status = by_name.get(gate, {}).get("status")
        if status == "passed":
            continue
        if status == "missing" or gate not in by_name:
            blockers.append(
                f"{gate} is required before proxy readiness scores can be treated "
                "as final Well-Architected scores."
            )
            continue
        blockers.append(
            f"{gate} must pass before proxy readiness scores can be treated "
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
        _structured_evidence_control_blockers(payload, required_control_ids)
    )
    if name == "question_matrix_evidence":
        blockers.extend(_question_matrix_source_verification_blockers(payload))
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
    *,
    timestamp_field: str = "reviewedAt",
) -> list[str]:
    """Return blockers for stale or invalid structured evidence timestamps."""
    reviewed_at = payload.get(timestamp_field)
    if not reviewed_at:
        return []
    parsed_at = _parse_reviewed_at(reviewed_at)
    if parsed_at is None:
        return [f"{label} {timestamp_field} must be an ISO-8601 date or timestamp."]
    now = dt.datetime.now(dt.timezone.utc)
    if parsed_at > now + dt.timedelta(minutes=5):
        return [f"{label} {timestamp_field} is in the future."]
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


def _structured_evidence_control_blockers(
    payload: dict[str, Any],
    required_control_ids: Sequence[str],
) -> list[str]:
    """Return blockers for external-control evidence coverage and proof shape."""
    if not required_control_ids:
        return []
    controls = payload.get("controls")
    if not isinstance(controls, list):
        return ["External-control evidence controls must be a list."]
    control_items = [control for control in controls if isinstance(control, dict)]
    return [
        *_missing_external_control_blockers(control_items, required_control_ids),
        *_external_control_count_blockers(payload, control_items),
        *_external_control_unresolved_count_blockers(payload, control_items),
        *_external_control_proof_blockers(control_items),
    ]


def _question_matrix_source_verification_blockers(
    payload: dict[str, Any],
) -> list[str]:
    """Return blockers when AWS framework source coverage is not auditable."""
    verification = payload.get("frameworkSourceVerification")
    if not isinstance(verification, dict):
        return [
            "Question-matrix evidence frameworkSourceVerification must be an object."
        ]

    blockers = _structured_evidence_freshness_blockers(
        verification,
        "Question-matrix framework source verification",
        timestamp_field="checkedAt",
    )
    source = verification.get("source")
    if not isinstance(source, str) or not source.strip():
        blockers.append(
            "Question-matrix framework source verification source is required."
        )
    question_counts = verification.get("questionCounts")
    if question_counts != EXPECTED_WELL_ARCHITECTED_QUESTION_COUNTS:
        blockers.append(
            "Question-matrix framework source verification questionCounts must "
            "match the expected AWS Well-Architected pillar counts."
        )
    source_urls = verification.get("sourceUrls")
    if not _non_empty_string_list(source_urls):
        blockers.append(
            "Question-matrix framework source verification sourceUrls must include "
            "non-empty documentation URLs."
        )
    return blockers


def _missing_external_control_blockers(
    controls: Sequence[dict[str, Any]],
    required_control_ids: Sequence[str],
) -> list[str]:
    """Return blockers for omitted required external controls."""
    observed = {
        str(control.get("id"))
        for control in controls
        if isinstance(control.get("id"), str) and control.get("id")
    }
    missing = sorted(set(required_control_ids) - observed)
    return (
        [
            "External-control evidence is missing required controls: "
            f"{', '.join(missing)}."
        ]
        if missing
        else []
    )


def _external_control_count_blockers(
    payload: dict[str, Any],
    controls: Sequence[dict[str, Any]],
) -> list[str]:
    """Return blockers when controlCount disagrees with control entries."""
    control_count = payload.get("controlCount")
    if not isinstance(control_count, int) or isinstance(control_count, bool):
        return []
    if control_count == len(controls):
        return []
    return [
        "External-control evidence controlCount must match the number "
        "of control entries."
    ]


def _external_control_unresolved_count_blockers(
    payload: dict[str, Any],
    controls: Sequence[dict[str, Any]],
) -> list[str]:
    """Return blockers when unresolvedControlCount disagrees with entries."""
    unresolved_count = payload.get("unresolvedControlCount")
    if not isinstance(unresolved_count, int) or isinstance(unresolved_count, bool):
        return []
    unresolved_ids = [
        str(control.get("id"))
        for control in controls
        if control.get("id") and control.get("status") != "passed"
    ]
    if unresolved_count == len(unresolved_ids):
        return []
    return [
        "External-control evidence unresolvedControlCount must match "
        "the number of non-passed control entries."
    ]


def _external_control_proof_blockers(
    controls: Sequence[dict[str, Any]],
) -> list[str]:
    """Return blockers for missing passed evidence or unresolved reasons."""
    blockers: list[str] = []
    for index, control in enumerate(controls, start=1):
        control_id = control.get("id")
        label = str(control_id) if control_id else f"entry {index}"
        if control.get("status") == "passed":
            evidence = control.get("evidence")
            if not _non_empty_string_list(evidence):
                blockers.append(
                    "External-control evidence passed control "
                    f"{label} must include non-empty evidence."
                )
            continue
        unresolved_reason = control.get("unresolvedReason")
        if not isinstance(unresolved_reason, str) or not unresolved_reason.strip():
            blockers.append(
                "External-control evidence non-passed control "
                f"{label} must include an unresolvedReason."
            )
    return blockers


def _non_empty_string_list(value: object) -> bool:
    """Return whether a value is a non-empty list of non-empty strings."""
    return (
        isinstance(value, list)
        and bool(value)
        and all(isinstance(item, str) and item.strip() for item in value)
    )


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
    evidence: dict[str, object] = {
        "workload": payload.get("workload"),
        "owner": payload.get("owner"),
        "reviewedAt": payload.get("reviewedAt"),
        "evidenceLocation": payload.get("evidenceLocation"),
        count_field: payload.get(count_field),
        unresolved_field: payload.get(unresolved_field),
        "controlIds": control_ids,
    }
    unresolved_question_ids = _string_list(payload.get("unresolvedQuestionIds"))
    if unresolved_question_ids is not None:
        evidence["unresolvedQuestionIds"] = unresolved_question_ids
    question_score_averages = _string_key_number_map(
        payload.get("questionScoreAverages")
    )
    if question_score_averages is not None:
        evidence["questionScoreAverages"] = question_score_averages
    pillar_unresolved_counts = _string_key_int_map(
        payload.get("pillarUnresolvedQuestionCounts")
    )
    if pillar_unresolved_counts is not None:
        evidence["pillarUnresolvedQuestionCounts"] = pillar_unresolved_counts
    framework_source_verification = _framework_source_verification_summary(payload)
    if framework_source_verification:
        evidence["frameworkSourceVerification"] = framework_source_verification
    unresolved_control_ids = _unresolved_control_ids(payload)
    if unresolved_control_ids:
        evidence["unresolvedControlIds"] = unresolved_control_ids
    return evidence


def _framework_source_verification_summary(
    payload: dict[str, Any],
) -> dict[str, object]:
    """Return non-secret framework source verification evidence."""
    verification = payload.get("frameworkSourceVerification")
    if not isinstance(verification, dict):
        return {}
    summary: dict[str, object] = {}
    for key in ("checkedAt", "source"):
        value = verification.get(key)
        if isinstance(value, str):
            summary[key] = value
    question_counts = _string_key_int_map(verification.get("questionCounts"))
    if question_counts is not None:
        summary["questionCounts"] = question_counts
    source_urls = _string_list(verification.get("sourceUrls"))
    if source_urls is not None:
        summary["sourceUrlCount"] = len(source_urls)
    return summary


def _string_list(value: object) -> list[str] | None:
    """Return a JSON-safe string list when all values are strings."""
    if not isinstance(value, list):
        return None
    if not all(isinstance(item, str) for item in value):
        return None
    return cast("list[str]", list(value))


def _string_key_number_map(value: object) -> dict[str, int | float] | None:
    """Return a JSON-safe mapping with string keys and numeric values."""
    if not isinstance(value, dict):
        return None
    result: dict[str, int | float] = {}
    for key, item in value.items():
        if not isinstance(key, str) or isinstance(item, bool):
            return None
        if not isinstance(item, (int, float)):
            return None
        result[key] = item
    return result


def _string_key_int_map(value: object) -> dict[str, int] | None:
    """Return a JSON-safe mapping with string keys and integer values."""
    if not isinstance(value, dict):
        return None
    result: dict[str, int] = {}
    for key, item in value.items():
        if not isinstance(key, str) or isinstance(item, bool):
            return None
        if not isinstance(item, int):
            return None
        result[key] = item
    return result


def _unresolved_control_ids(payload: dict[str, Any]) -> list[str]:
    """Return non-passed external control ids from structured evidence."""
    controls = payload.get("controls")
    if not isinstance(controls, list):
        return []
    ids = [
        str(control.get("id"))
        for control in controls
        if (
            isinstance(control, dict)
            and control.get("id")
            and control.get("status") != "passed"
        )
    ]
    return sorted(ids)


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
        github_dependabot_alerts(
            args.repo,
            args.dependabot_dependency,
            args.dependabot_manifest,
            runner=runner,
        ),
        github_production_environment(
            args.repo,
            args.production_environment,
            args.production_reviewer,
            runner=runner,
        ),
        aws_identity(runner=runner),
        aws_iam_account_access(runner=runner),
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
    parser.add_argument(
        "--production-environment",
        default=DEFAULT_PRODUCTION_ENVIRONMENT,
        help="GitHub environment that must protect production deployments.",
    )
    parser.add_argument(
        "--production-reviewer",
        default=DEFAULT_PRODUCTION_REVIEWER,
        help="GitHub login expected to approve production deployments.",
    )
    parser.add_argument(
        "--dependabot-dependency",
        default=DEFAULT_DEPENDABOT_DEPENDENCY,
        help="Dependency name whose open Dependabot alerts block SEC11.",
    )
    parser.add_argument(
        "--dependabot-manifest",
        default=DEFAULT_DEPENDABOT_MANIFEST,
        help="Manifest path whose open Dependabot alerts block SEC11.",
    )
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
