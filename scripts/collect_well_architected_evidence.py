#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast
from urllib.parse import quote

import _github_repository_controls as _repository_controls
import _well_architected_env as _env
import _well_architected_github_environment as _github_environment
import _well_architected_markdown as _markdown
import _well_architected_recording as _recording
import _well_architected_scoring as _scoring
import _well_architected_structured_evidence as _structured_evidence
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
DEFAULT_REQUIRED_STATUS_CHECKS = _repository_controls.REQUIRED_STATUS_CHECKS
_active_branch_ruleset_count = _repository_controls.active_branch_ruleset_count
_ruleset_required_status_check_contexts = (
    _repository_controls.required_status_contexts_for_rulesets
)
_ruleset_has_pull_request_reviews = _repository_controls.rulesets_have_pull_request_rule
_all_blockers = _markdown.all_blockers
_markdown_checks = _markdown.markdown_checks
_markdown_cell = _markdown.markdown_cell
_markdown_string_entries = _markdown.markdown_string_entries
_markdown_text = _markdown.markdown_text
_markdown_value = _markdown.markdown_value

PASSING_CHECK_CONCLUSIONS = {"SUCCESS"}
PASSING_STATUS_STATES = {"SUCCESS"}
COVERED_AGGREGATE_ALLOWED_CONCLUSIONS = {"NEUTRAL", "SKIPPED"}
ALLOWED_SKIPPED_CHECKS = frozenset(
    {
        "Evidence (Unprivileged)",
        "Preview (Unprivileged)",
        "IAM Validation (Unprivileged)",
    }
)
COVERED_AGGREGATE_CHECKS = {
    "CodeQL": frozenset({"CodeQL (actions)", "CodeQL (python)"}),
}
CURRENT_CHECK_NAME_ENV = "WELL_ARCHITECTED_CURRENT_CHECK_NAME"
ADVISORY_REVIEW_THREAD_AUTHORS = frozenset({"qltysh"})
DEFAULT_PRODUCTION_ENVIRONMENT = "prod"
DEFAULT_PRODUCTION_REVIEWER = "Kravalg"
DEFAULT_DEPENDABOT_DEPENDENCY = ""
DEPENDABOT_ALL_DEPENDENCIES = "all"
DEFAULT_DEPENDABOT_MANIFEST = "uv.lock"
ENV_STRING_DEFAULTS = {
    "aws_account_id": "AWS_ACCOUNT_ID",
    "operations_topic_arn": "OPERATIONS_TOPIC_ARN",
    "operations_cloudtrail_name": "OPERATIONS_CLOUDTRAIL_NAME",
}
ENV_PATH_DEFAULTS = {
    "dependabot_exception_evidence": "DEPENDABOT_EXCEPTION_EVIDENCE",
    "security_account_attestation_evidence": "SECURITY_ACCOUNT_ATTESTATION_EVIDENCE",
    "alert_route_observation_evidence": "ALERT_ROUTE_OBSERVATION_EVIDENCE",
    "production_dr_owner_evidence": "PRODUCTION_DR_OWNER_EVIDENCE",
    "restore_drill_evidence": "RESTORE_DRILL_EVIDENCE",
    "question_matrix_evidence": "QUESTION_MATRIX_EVIDENCE",
    "external_control_evidence": "EXTERNAL_CONTROL_EVIDENCE",
}
BLOCKING_DEPENDABOT_SEVERITIES = frozenset({"critical", "high"})
DEPENDABOT_EXCEPTION_ALLOWED_APPROVALS = frozenset(
    {"approved", "approved_exception", "accepted_risk"}
)
DEPENDABOT_EXCEPTION_REQUIRED_FIELDS = (
    "workload",
    "owner",
    "approvedBy",
    "reviewedAt",
    "expiresAt",
    "dependencyName",
    "manifestPath",
    "alertNumbers",
    "approval",
    "reason",
    "remediationPlan",
)
ALERT_ROUTE_OBSERVATION_REQUIRED_FIELDS = (
    "workload",
    "environment",
    "owner",
    "approvedBy",
    "reviewedAt",
    "expiresAt",
    "downstreamRoute",
    "severityExpectations",
    "fallback",
    "decision",
    "evidence",
    "remediationPlan",
    "routeEvidence",
)
ALERT_ROUTE_OBSERVATION_ROUTE_FIELDS = _recording.ALERT_ROUTE_OBSERVATION_ROUTE_FIELDS
ALERT_ROUTE_OBSERVATION_QUEUE_FIELDS = _recording.ALERT_ROUTE_OBSERVATION_QUEUE_FIELDS
ALERT_ROUTE_ALLOWED_DECISIONS = frozenset(
    {"accepted", "approved", "approved_exception", "accepted_risk"}
)
SECURITY_ACCOUNT_ATTESTATION_REQUIRED_FIELDS = (
    "workload",
    "owner",
    "approvedBy",
    "reviewedAt",
    "expiresAt",
    "humanAccessPosture",
    "activeKeyDecision",
    "permissionsBoundaryDecision",
    "approval",
    "evidence",
    "remediationPlan",
    "accountEvidence",
)
SECURITY_ACCOUNT_ATTESTATION_ACCOUNT_FIELDS = (
    _recording.SECURITY_ACCOUNT_ATTESTATION_ACCOUNT_FIELDS
)
SECURITY_ACCOUNT_ALLOWED_APPROVALS = frozenset(
    {"approved", "approved_exception", "accepted_risk"}
)
SECURITY_ACCOUNT_ALLOWED_HUMAN_ACCESS = frozenset(
    {"mfa_sso_verified", "approved", "approved_exception", "accepted_risk"}
)
SECURITY_ACCOUNT_ALLOWED_ACTIVE_KEY = frozenset(
    {"no_active_keys", "rotated", "approved_exception", "accepted_risk"}
)
SECURITY_ACCOUNT_ALLOWED_BOUNDARY = frozenset(
    {"boundary_verified", "approved_exemption", "accepted_risk", "not_required"}
)
SECURITY_ACCOUNT_ATTESTED_CONTROLS = frozenset(
    {"human_access", "active_key", "permissions_boundary"}
)
PRODUCTION_DR_OWNER_REQUIRED_FIELDS = _recording.PRODUCTION_DR_OWNER_REQUIRED_FIELDS
PRODUCTION_DR_OWNER_RESTORE_FIELDS = _recording.PRODUCTION_DR_OWNER_RESTORE_FIELDS
PRODUCTION_DR_OWNER_TEXT_FIELDS = _recording.PRODUCTION_DR_OWNER_TEXT_FIELDS
PRODUCTION_DR_OWNER_ALLOWED_APPROVALS = _recording.PRODUCTION_DR_OWNER_ALLOWED_APPROVALS
PRODUCTION_DR_OWNER_SUMMARY_FIELDS = _recording.PRODUCTION_DR_OWNER_SUMMARY_FIELDS
RESTORE_DRILL_REQUIRED_FIELDS = (
    "workload",
    "environment",
    "completedAt",
    "sourceRecoveryPointArn",
    "targetRestoreLocation",
    "validationResult",
    "cleanupConfirmed",
)
READINESS_GATES = _scoring.READINESS_GATES
AWS_WELL_ARCHITECTED_TOC_URL = _structured_evidence.AWS_WELL_ARCHITECTED_TOC_URL
STRUCTURED_EVIDENCE_ALLOWED_STATUSES = (
    _structured_evidence.STRUCTURED_EVIDENCE_ALLOWED_STATUSES
)
QUESTION_MATRIX_REQUIRED_FIELDS = _structured_evidence.QUESTION_MATRIX_REQUIRED_FIELDS
EXTERNAL_CONTROL_REQUIRED_FIELDS = _structured_evidence.EXTERNAL_CONTROL_REQUIRED_FIELDS
REQUIRED_EXTERNAL_CONTROL_IDS = _structured_evidence.REQUIRED_EXTERNAL_CONTROL_IDS
MISSING_QUESTION_ID = _structured_evidence.MISSING_QUESTION_ID
EXPECTED_WELL_ARCHITECTED_QUESTION_PREFIX_PILLARS = (
    _structured_evidence.EXPECTED_WELL_ARCHITECTED_QUESTION_PREFIX_PILLARS
)
EXPECTED_WELL_ARCHITECTED_QUESTION_PREFIX_COUNTS = (
    _structured_evidence.EXPECTED_WELL_ARCHITECTED_QUESTION_PREFIX_COUNTS
)
EXPECTED_WELL_ARCHITECTED_QUESTION_IDS = (
    _structured_evidence.EXPECTED_WELL_ARCHITECTED_QUESTION_IDS
)
EXPECTED_WELL_ARCHITECTED_QUESTION_PILLAR_BY_ID = (
    _structured_evidence.EXPECTED_WELL_ARCHITECTED_QUESTION_PILLAR_BY_ID
)
EXPECTED_WELL_ARCHITECTED_QUESTION_COUNT = (
    _structured_evidence.EXPECTED_WELL_ARCHITECTED_QUESTION_COUNT
)
EXPECTED_WELL_ARCHITECTED_QUESTION_COUNTS = (
    _structured_evidence.EXPECTED_WELL_ARCHITECTED_QUESTION_COUNTS
)
STRUCTURED_EVIDENCE_MAX_AGE_DAYS = _structured_evidence.STRUCTURED_EVIDENCE_MAX_AGE_DAYS
StructuredEvidenceSpec = _structured_evidence.StructuredEvidenceSpec
question_matrix_evidence = _structured_evidence.question_matrix_evidence
external_control_evidence = _structured_evidence.external_control_evidence
_structured_evidence_check = _structured_evidence._structured_evidence_check
_read_required_structured_evidence = (
    _structured_evidence._read_required_structured_evidence
)
_read_structured_evidence_payload = (
    _structured_evidence._read_structured_evidence_payload
)
_structured_evidence_payload_blockers = (
    _structured_evidence._structured_evidence_payload_blockers
)
_structured_evidence_field_present = (
    _structured_evidence._structured_evidence_field_present
)
_structured_evidence_mismatch_blockers = (
    _structured_evidence._structured_evidence_mismatch_blockers
)
_structured_evidence_freshness_blockers = (
    _structured_evidence._structured_evidence_freshness_blockers
)
_parse_reviewed_at = _structured_evidence._parse_reviewed_at
_structured_evidence_count_blockers = (
    _structured_evidence._structured_evidence_count_blockers
)
_structured_evidence_control_blockers = (
    _structured_evidence._structured_evidence_control_blockers
)
_question_matrix_source_verification_blockers = (
    _structured_evidence._question_matrix_source_verification_blockers
)
_question_matrix_score_blockers = _structured_evidence._question_matrix_score_blockers
_question_matrix_score_id_blockers = (
    _structured_evidence._question_matrix_score_id_blockers
)
_question_matrix_observed_ids = _structured_evidence._question_matrix_observed_ids
_question_matrix_pillar_blockers = _structured_evidence._question_matrix_pillar_blockers
_expected_question_id_order = _structured_evidence._expected_question_id_order
_sort_question_ids = _structured_evidence._sort_question_ids
_question_id_sort_key = _structured_evidence._question_id_sort_key
_question_matrix_score_count_blockers = (
    _structured_evidence._question_matrix_score_count_blockers
)
_question_matrix_invalid_score_blockers = (
    _structured_evidence._question_matrix_invalid_score_blockers
)
_invalid_question_score = _structured_evidence._invalid_question_score
_question_matrix_status_blockers = _structured_evidence._question_matrix_status_blockers
_question_matrix_score_status_blockers = (
    _structured_evidence._question_matrix_score_status_blockers
)
_valid_question_score = _structured_evidence._valid_question_score
_question_matrix_evidence_ref_blockers = (
    _structured_evidence._question_matrix_evidence_ref_blockers
)
_question_matrix_summary_blockers = (
    _structured_evidence._question_matrix_summary_blockers
)
_question_matrix_unresolved_id_blockers = (
    _structured_evidence._question_matrix_unresolved_id_blockers
)
_question_matrix_pillar_unresolved_blockers = (
    _structured_evidence._question_matrix_pillar_unresolved_blockers
)
_question_matrix_average_blockers = (
    _structured_evidence._question_matrix_average_blockers
)
_non_passed_question_ids = _structured_evidence._non_passed_question_ids
_expected_pillar_unresolved_question_counts = (
    _structured_evidence._expected_pillar_unresolved_question_counts
)
_expected_pillar_question_score_averages = (
    _structured_evidence._expected_pillar_question_score_averages
)
_rounded_average = _structured_evidence._rounded_average
_question_id_list_text = _structured_evidence._question_id_list_text
_missing_external_control_blockers = (
    _structured_evidence._missing_external_control_blockers
)
_external_control_id_blockers = _structured_evidence._external_control_id_blockers
_external_control_status_blockers = (
    _structured_evidence._external_control_status_blockers
)
_external_control_count_blockers = _structured_evidence._external_control_count_blockers
_external_control_unresolved_count_blockers = (
    _structured_evidence._external_control_unresolved_count_blockers
)
_external_control_unresolved_id_blockers = (
    _structured_evidence._external_control_unresolved_id_blockers
)
_valid_structured_status = _structured_evidence._valid_structured_status
_allowed_status_text = _structured_evidence._allowed_status_text
_external_control_proof_blockers = _structured_evidence._external_control_proof_blockers
_non_empty_string_list = _structured_evidence._non_empty_string_list
_structured_evidence_payload = _structured_evidence._structured_evidence_payload
_control_ids = _structured_evidence._control_ids
_question_matrix_payload_fields = _structured_evidence._question_matrix_payload_fields
_question_score_scale = _structured_evidence._question_score_scale
_external_control_payload_fields = _structured_evidence._external_control_payload_fields
_unresolved_question_evidence_ref_ids = (
    _structured_evidence._unresolved_question_evidence_ref_ids
)
_framework_source_verification_summary = (
    _structured_evidence._framework_source_verification_summary
)
_string_list = _structured_evidence._string_list
_string_key_number_map = _structured_evidence._string_key_number_map
_string_key_int_map = _structured_evidence._string_key_int_map
_unresolved_control_ids = _structured_evidence._unresolved_control_ids
_unresolved_control_ids_from_controls = (
    _structured_evidence._unresolved_control_ids_from_controls
)
EXAMPLE_CATALOG_NAMES = frozenset({"repositories.example.json"})
IAM_ACCESS_KEY_STALE_DAYS = 90


@dataclass(frozen=True)
class GitHubPrLocalStateSnapshot:
    """Metadata needed to verify local checkout state against a PR."""

    head_ok: bool
    local_head: str
    head_error: str
    status_ok: bool
    dirty_count: int
    status_error: str
    pr_ok: bool
    pr_payload: Any
    pr_error: str


@dataclass(frozen=True)
class ReviewThreadPageRequest:
    """Inputs shared by every GitHub review-thread pagination request."""

    owner: str
    name: str
    pr_number: int
    query: str


@dataclass(frozen=True)
class DependabotAlertRequest:
    """Scope for Dependabot alert evidence collection."""

    repo: str
    dependency: str = DEFAULT_DEPENDABOT_DEPENDENCY
    manifest_path: str = DEFAULT_DEPENDABOT_MANIFEST
    blocking_severities: frozenset[str] = BLOCKING_DEPENDABOT_SEVERITIES


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


def _rollup_check_run_succeeded(entry: dict[str, Any]) -> bool:
    """Return whether one check run completed successfully."""
    return (
        entry.get("__typename") == "CheckRun"
        and str(entry.get("status", "")).upper() == "COMPLETED"
        and str(entry.get("conclusion", "")).upper() in PASSING_CHECK_CONCLUSIONS
    )


def _rollup_entry_allowed_covered_aggregate(
    entry: dict[str, Any],
    passed_check_names: set[str],
) -> bool:
    """Return whether an aggregate check is covered by concrete checks."""
    if entry.get("__typename") != "CheckRun":
        return False
    name = str(entry.get("name") or "")
    required_checks = COVERED_AGGREGATE_CHECKS.get(name)
    if not required_checks:
        return False
    return (
        str(entry.get("status", "")).upper() == "COMPLETED"
        and str(entry.get("conclusion", "")).upper()
        in COVERED_AGGREGATE_ALLOWED_CONCLUSIONS
        and required_checks.issubset(passed_check_names)
    )


def _rollup_entry_label(entry: dict[str, Any]) -> str:
    """Return the human-readable name for a GitHub rollup entry."""
    return str(entry.get("name") or entry.get("context") or "unknown")


def _current_check_names_from_env() -> frozenset[str]:
    """Return current self-check names that may still be in progress."""
    names = [
        name.strip()
        for name in os.environ.get(CURRENT_CHECK_NAME_ENV, "").split(",")
        if name.strip()
    ]
    return frozenset(names)


def _rollup_entry_current_check_in_progress(
    entry: dict[str, Any], current_check_names: frozenset[str]
) -> bool:
    """Return whether a rollup entry is the current in-progress check."""
    return (
        entry.get("__typename") == "CheckRun"
        and _rollup_entry_label(entry) in current_check_names
        and str(entry.get("status", "")).upper() != "COMPLETED"
    )


def _current_check_in_progress_labels(
    entries: Sequence[dict[str, Any]], current_check_names: frozenset[str]
) -> list[str]:
    """Return current self-check labels omitted from non-passing contexts."""
    return sorted(
        _rollup_entry_label(entry)
        for entry in entries
        if _rollup_entry_current_check_in_progress(entry, current_check_names)
    )


def _non_passing_rollup_labels(
    entries: Sequence[dict[str, Any]],
    *,
    current_check_names: frozenset[str] = frozenset(),
) -> list[str]:
    """Return non-passing GitHub status/check names."""
    passed_check_names = {
        _rollup_entry_label(entry)
        for entry in entries
        if _rollup_check_run_succeeded(entry)
    }
    return [
        _rollup_entry_label(entry)
        for entry in entries
        if not (
            _rollup_entry_passed(entry)
            or _rollup_entry_allowed_covered_aggregate(entry, passed_check_names)
            or _rollup_entry_current_check_in_progress(entry, current_check_names)
        )
    ]


def _github_pr_check_blockers(
    payload: dict[str, Any], failing: Sequence[str]
) -> list[str]:
    """Return blockers from PR merge, review, and check metadata."""
    blockers = []
    merge_state = payload.get("mergeStateStatus")
    mergeable = payload.get("mergeable")
    if merge_state != "CLEAN" and not (
        merge_state == "BLOCKED" and mergeable == "MERGEABLE" and not failing
    ):
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
            "mergeStateStatus,mergeable,reviewDecision,headRefOid",
        ],
        runner=runner,
    )
    if not ok or not isinstance(payload, dict):
        return _check("github_pr_checks", status="unknown", blockers=[error])
    rollup_ok, rollup_payload, rollup_error = _run_json(
        [
            "gh",
            "pr",
            "view",
            str(pr_number),
            "--repo",
            repo,
            "--json",
            "statusCheckRollup",
        ],
        runner=runner,
    )
    if not rollup_ok or not isinstance(rollup_payload, dict):
        return _check("github_pr_checks", status="unknown", blockers=[rollup_error])
    files_ok, changed_files, files_error = _github_pr_changed_file_paths(
        repo,
        pr_number,
        runner=runner,
    )

    rollup = rollup_payload.get("statusCheckRollup", [])
    entries = [entry for entry in rollup if isinstance(entry, dict)]
    current_check_names = _current_check_names_from_env()
    failing = _non_passing_rollup_labels(
        entries,
        current_check_names=current_check_names,
    )
    current_check_in_progress = _current_check_in_progress_labels(
        entries,
        current_check_names,
    )
    blockers = _github_pr_check_blockers_with_files(
        payload,
        failing,
        files_ok,
        files_error,
    )
    return _check(
        "github_pr_checks",
        status="passed" if not blockers else "failed",
        evidence=_github_pr_check_evidence(
            payload,
            entries,
            failing,
            files_ok=files_ok,
            changed_files=changed_files,
            current_check_in_progress=current_check_in_progress,
        ),
        blockers=blockers,
    )


def _github_pr_check_blockers_with_files(
    payload: dict[str, Any],
    failing: Sequence[str],
    files_ok: bool,
    files_error: str,
) -> list[str]:
    """Return PR blockers including changed-file metadata availability."""
    blockers = _github_pr_check_blockers(payload, failing)
    if not files_ok:
        blockers.append(f"Unable to query PR changed files: {files_error}")
    return blockers


def _github_pr_check_evidence(
    payload: dict[str, Any],
    entries: Sequence[dict[str, Any]],
    failing: Sequence[str],
    *,
    files_ok: bool,
    changed_files: Sequence[str],
    current_check_in_progress: Sequence[str] = (),
) -> dict[str, object]:
    """Return PR check evidence including non-secret changed-file metadata."""
    return {
        "headRefOid": payload.get("headRefOid"),
        "mergeStateStatus": payload.get("mergeStateStatus"),
        "mergeable": payload.get("mergeable"),
        "reviewDecision": payload.get("reviewDecision"),
        "checkCount": len(entries),
        "nonPassingCheckCount": len(failing),
        "currentCheckInProgressCount": len(current_check_in_progress),
        "currentCheckInProgressNames": list(current_check_in_progress),
        "changedFileCount": len(changed_files) if files_ok else None,
        "changedFileTopLevelPaths": (
            _changed_file_top_level_paths(changed_files) if files_ok else []
        ),
        "changedFilePaths": list(changed_files) if files_ok else [],
    }


def _github_pr_changed_file_paths(
    repo: str,
    pr_number: int,
    *,
    runner: Runner = run,
) -> tuple[bool, list[str], str]:
    """Return changed PR file paths without file contents."""
    ok, output, error = _run_text(
        ["gh", "pr", "diff", str(pr_number), "--repo", repo, "--name-only"],
        runner=runner,
    )
    if not ok:
        fallback_ok, fallback_output, fallback_error = _run_text(
            [
                "gh",
                "api",
                f"repos/{repo}/pulls/{pr_number}/files",
                "--paginate",
                "--jq",
                ".[].filename",
            ],
            runner=runner,
        )
        if not fallback_ok:
            return False, [], f"{error}; file-list fallback failed: {fallback_error}"
        return (
            True,
            sorted(
                line.strip() for line in fallback_output.splitlines() if line.strip()
            ),
            "",
        )
    return (
        True,
        sorted(line.strip() for line in output.splitlines() if line.strip()),
        "",
    )


def _changed_file_top_level_paths(paths: Sequence[str]) -> list[str]:
    """Return stable top-level path categories for changed files."""
    top_level = set()
    for path in paths:
        if "/" in path:
            top_level.add(path.split("/", 1)[0])
        elif path:
            top_level.add(path)
    return sorted(top_level)


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
    snapshot = GitHubPrLocalStateSnapshot(
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
    blockers = _github_pr_local_state_blockers(snapshot)
    evidence = _github_pr_local_state_evidence(snapshot)
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
    snapshot: GitHubPrLocalStateSnapshot,
) -> list[str]:
    """Return blockers for local PR state evidence."""
    blockers = []
    if not snapshot.head_ok:
        blockers.append(f"Unable to query local git HEAD: {snapshot.head_error}")
    if not snapshot.status_ok:
        blockers.append(f"Unable to query local git status: {snapshot.status_error}")
    elif snapshot.dirty_count:
        blockers.append("Local worktree has uncommitted tracked or untracked changes.")
    if not snapshot.pr_ok or not isinstance(snapshot.pr_payload, dict):
        blockers.append(f"Unable to query PR head metadata: {snapshot.pr_error}")
    if (
        snapshot.head_ok
        and _pr_head_oid(snapshot.pr_payload)
        and snapshot.local_head != _pr_head_oid(snapshot.pr_payload)
    ):
        blockers.append("Local HEAD does not match the GitHub PR head commit.")
    return blockers


def _github_pr_local_state_evidence(
    snapshot: GitHubPrLocalStateSnapshot,
) -> dict[str, object]:
    """Return non-secret local PR state evidence."""
    pr_payload = snapshot.pr_payload if isinstance(snapshot.pr_payload, dict) else {}
    return {
        "localHead": snapshot.local_head if snapshot.head_ok else None,
        "prHeadRefOid": _pr_head_oid(pr_payload) or None,
        "prHeadRefName": pr_payload.get("headRefName"),
        "dirtyFileCount": snapshot.dirty_count if snapshot.status_ok else None,
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
    unresolved = _unresolved_review_threads(nodes)
    outdated_count = sum(1 for node in unresolved if bool(node.get("isOutdated")))
    advisory_count = sum(1 for node in unresolved if _review_thread_is_advisory(node))
    blocking_count = sum(1 for node in unresolved if _review_thread_blocks(node))
    return (
        {
            "threadCount": len(nodes),
            "unresolvedThreadCount": len(unresolved),
            "outdatedUnresolvedThreadCount": outdated_count,
            "advisoryUnresolvedThreadCount": advisory_count,
            "blockingThreadCount": blocking_count,
        },
        blocking_count,
    )


def _unresolved_review_threads(nodes: Sequence[object]) -> list[dict[str, Any]]:
    """Return unresolved review-thread nodes."""
    unresolved = []
    for node in nodes:
        if _review_thread_unresolved(node):
            unresolved.append(cast(dict[str, Any], node))
    return unresolved


def _review_thread_unresolved(node: object) -> bool:
    """Return whether a review-thread node is unresolved."""
    return isinstance(node, dict) and not node.get("isResolved")


def _review_thread_blocks(node: dict[str, Any]) -> bool:
    """Return whether an unresolved review thread blocks evidence."""
    return not bool(node.get("isOutdated")) and not _review_thread_is_advisory(node)


def _review_thread_is_advisory(node: dict) -> bool:
    """Return whether an unresolved review thread is emitted by an advisory bot."""
    first_comment = _review_thread_first_comment(node)
    author = first_comment.get("author", {})
    login = author.get("login") if isinstance(author, dict) else ""
    return login in ADVISORY_REVIEW_THREAD_AUTHORS


def _review_thread_first_comment(node: dict) -> dict[str, Any]:
    """Return the first review-thread comment object, if present."""
    comments = node.get("comments")
    if not isinstance(comments, dict):
        return {}
    comment_nodes = comments.get("nodes")
    if not isinstance(comment_nodes, list) or not comment_nodes:
        return {}
    first_comment = comment_nodes[0]
    if not isinstance(first_comment, dict):
        return {}
    return first_comment


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
    request = ReviewThreadPageRequest(
        owner=owner,
        name=name,
        pr_number=pr_number,
        query=_review_threads_query(),
    )
    nodes = []
    after: str | None = None
    for _page in range(20):
        page_nodes, page_info, error = _fetch_review_thread_page(
            request,
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
    request: ReviewThreadPageRequest,
    after: str | None,
    *,
    runner: Runner = run,
) -> tuple[list[dict], dict[str, Any], str]:
    """Fetch one review-thread page."""
    command = _review_threads_command(request, after)
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
        "nodes { isResolved isOutdated "
        "comments(first:1) { nodes { author { login } body } } } "
        "pageInfo { hasNextPage endCursor } } } } }"
    )


def _review_threads_command(
    request: ReviewThreadPageRequest,
    after: str | None,
) -> list[str]:
    """Build a metadata-only review-thread GraphQL command."""
    command = [
        "gh",
        "api",
        "graphql",
        "-f",
        f"owner={request.owner}",
        "-f",
        f"name={request.name}",
        "-F",
        f"number={request.pr_number}",
        "-f",
        f"query={request.query}",
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


def github_dependabot_alerts(
    request: DependabotAlertRequest,
    exception_evidence: Path | None = None,
    *,
    runner: Runner = run,
) -> dict[str, object]:
    """Collect open Dependabot alert evidence for one dependency manifest."""
    dependency = request.dependency.strip()
    dependency_scope = _dependabot_dependency_scope(dependency)
    manifest_path = request.manifest_path
    blocking_severities = request.blocking_severities
    ok, payload, error = _run_json(
        ["gh", "api", _dependabot_alert_api_path(request.repo, dependency)],
        runner=runner,
    )
    if not ok or not isinstance(payload, list):
        return _unknown_dependabot_alert_check(
            dependency=dependency_scope,
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
    exception_summary, excepted_alert_numbers, exception_blockers = (
        _dependabot_exception_coverage(
            exception_evidence,
            dependency=dependency_scope,
            manifest_path=manifest_path,
            blocking_alerts=blocking_alerts,
        )
    )
    unexcepted_alerts = _unexcepted_dependabot_alerts(
        blocking_alerts,
        excepted_alert_numbers,
    )
    unexcepted_alert_numbers = _dependabot_alert_numbers(unexcepted_alerts)
    open_alert_numbers = _dependabot_alert_numbers(blocking_alerts)
    blockers = [
        *exception_blockers,
        *_dependabot_alert_blockers(
            dependency=dependency_scope,
            manifest_path=manifest_path,
            open_alert_numbers=unexcepted_alert_numbers,
            open_alert_count=len(unexcepted_alerts),
        ),
    ]
    evidence: dict[str, object] = {
        "dependencyName": dependency_scope,
        "dependencyNames": _dependabot_dependency_names(blocking_alerts),
        "manifestPath": manifest_path,
        "blockingSeverities": sorted(blocking_severities),
        "matchingOpenAlertCount": len(matching_alerts),
        "openAlertCount": len(blocking_alerts),
        "openAlertNumbers": open_alert_numbers,
        "unexceptedOpenAlertCount": len(unexcepted_alerts),
        "unexceptedOpenAlertNumbers": unexcepted_alert_numbers,
        "exceptedOpenAlertNumbers": sorted(excepted_alert_numbers),
        "alerts": blocking_alerts,
    }
    if exception_summary:
        evidence["exceptionEvidence"] = exception_summary
    return _check(
        "github_dependabot_alerts",
        status="passed" if not blockers else "failed",
        evidence=evidence,
        blockers=blockers,
    )


def _dependabot_alert_api_path(repo: str, dependency: str) -> str:
    """Return the GitHub API path for open Dependabot alerts."""
    if not dependency.strip():
        return f"repos/{repo}/dependabot/alerts?state=open&per_page=100"
    return (
        f"repos/{repo}/dependabot/alerts?state=open&dependency_name="
        f"{quote(dependency, safe='')}&per_page=100"
    )


def _dependabot_dependency_scope(dependency: str) -> str:
    """Return the evidence label for the requested dependency scope."""
    return dependency or DEPENDABOT_ALL_DEPENDENCIES


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
        summary = _dependabot_alert_summary(cast(dict[str, Any], item))
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


def _unexcepted_dependabot_alerts(
    alerts: Sequence[dict[str, object]],
    excepted_alert_numbers: set[int],
) -> list[dict[str, object]]:
    """Return blocking alerts not covered by approved exception evidence."""
    return [
        alert
        for alert in alerts
        if _dependabot_alert_number(alert) not in excepted_alert_numbers
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
    return cast(dict[str, Any], value) if isinstance(value, dict) else {}


def _dependabot_alert_matches(
    alert: dict[str, object],
    *,
    dependency: str,
    manifest_path: str,
) -> bool:
    """Return whether a Dependabot alert targets the dependency manifest."""
    dependency_name = str(alert.get("dependencyName", ""))
    return (
        str(alert.get("state", "")).lower() == "open"
        and (not dependency or dependency_name.lower() == dependency.lower())
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
    if dependency == DEPENDABOT_ALL_DEPENDENCIES:
        scope = f"in {manifest_path}"
    else:
        scope = f"for {dependency} in {manifest_path}"
    return [f"Open default-branch Dependabot alerts remain {scope}: {alert_text}."]


def _dependabot_dependency_names(
    alerts: Sequence[dict[str, object]],
) -> list[str]:
    """Return sorted dependency names represented by blocking alert evidence."""
    return sorted(
        {
            name
            for alert in alerts
            if (name := str(alert.get("dependencyName") or "").strip())
        }
    )


def _dependabot_exception_coverage(
    evidence_path: Path | None,
    *,
    dependency: str,
    manifest_path: str,
    blocking_alerts: Sequence[dict[str, object]],
) -> tuple[dict[str, object], set[int], list[str]]:
    """Return approved Dependabot exception coverage for open alerts."""
    if evidence_path is None:
        return {}, set(), []

    label = "Dependabot exception evidence"
    payload, blockers = _read_required_structured_evidence(
        evidence_path,
        label,
        DEPENDABOT_EXCEPTION_REQUIRED_FIELDS,
    )
    blockers.extend(
        _dependabot_exception_payload_blockers(
            payload,
            dependency=dependency,
            manifest_path=manifest_path,
            blocking_alerts=blocking_alerts,
        )
    )
    alert_numbers = _dependabot_exception_alert_numbers(payload)
    covered_numbers = set(alert_numbers) if not blockers else set()
    summary = _dependabot_exception_summary(evidence_path, payload, alert_numbers)
    return summary, covered_numbers, blockers


def _dependabot_exception_payload_blockers(
    payload: dict[str, Any],
    *,
    dependency: str,
    manifest_path: str,
    blocking_alerts: Sequence[dict[str, object]],
) -> list[str]:
    """Return blockers for a Dependabot exception evidence payload."""
    blockers: list[str] = []
    if payload.get("dependencyName") != dependency:
        blockers.append(
            f"Dependabot exception evidence dependencyName must be {dependency}."
        )
    if payload.get("manifestPath") != manifest_path:
        blockers.append(
            f"Dependabot exception evidence manifestPath must be {manifest_path}."
        )
    approval = str(payload.get("approval") or "").strip().lower()
    if approval not in DEPENDABOT_EXCEPTION_ALLOWED_APPROVALS:
        blockers.append(
            "Dependabot exception evidence approval must be approved, "
            "approved_exception, or accepted_risk."
        )

    evidence = payload.get("evidence")
    if not isinstance(evidence, list) or not any(
        isinstance(item, str) and item.strip() for item in evidence
    ):
        blockers.append(
            "Dependabot exception evidence must include non-empty evidence strings."
        )

    blockers.extend(_dependabot_exception_expiry_blockers(payload.get("expiresAt")))
    blockers.extend(
        _dependabot_exception_alert_number_blockers(payload, blocking_alerts)
    )
    return blockers


def _dependabot_exception_expiry_blockers(expires_at_value: object) -> list[str]:
    """Return blockers for Dependabot exception expiry."""
    expires_at = _parse_reviewed_at(expires_at_value)
    if expires_at is None:
        return ["Dependabot exception evidence expiresAt must be ISO-8601."]
    now = dt.datetime.now(dt.timezone.utc)
    if expires_at <= now:
        return ["Dependabot exception evidence is expired."]
    return []


def _dependabot_exception_alert_number_blockers(
    payload: dict[str, Any],
    blocking_alerts: Sequence[dict[str, object]],
) -> list[str]:
    """Return blockers for Dependabot exception alert-number coverage."""
    blockers: list[str] = []
    expected_numbers = set(_dependabot_alert_numbers(blocking_alerts))
    actual_numbers = set(_dependabot_exception_alert_numbers(payload))
    if expected_numbers:
        missing_numbers = sorted(expected_numbers - actual_numbers)
        if missing_numbers:
            blockers.append(
                "Dependabot exception evidence does not cover open alert numbers: "
                f"{_alert_number_text(missing_numbers)}."
            )
    elif blocking_alerts:
        blockers.append(
            "Dependabot exception evidence cannot cover alerts without GitHub "
            "alert numbers."
        )
    extra_numbers = sorted(actual_numbers - expected_numbers)
    if extra_numbers:
        blockers.append(
            "Dependabot exception evidence includes alert numbers that are not "
            f"currently open blockers: {_alert_number_text(extra_numbers)}."
        )
    return blockers


def _dependabot_exception_alert_numbers(payload: dict[str, Any]) -> list[int]:
    """Return exception alert numbers when they are a valid integer list."""
    alert_numbers = payload.get("alertNumbers")
    if not isinstance(alert_numbers, list):
        return []
    numbers: list[int] = []
    for item in alert_numbers:
        if isinstance(item, bool) or not isinstance(item, int):
            return []
        numbers.append(item)
    return sorted(numbers)


def _dependabot_exception_summary(
    evidence_path: Path,
    payload: dict[str, Any],
    alert_numbers: Sequence[int],
) -> dict[str, object]:
    """Return non-secret Dependabot exception metadata for the report."""
    return {
        "path": str(evidence_path),
        "owner": str(payload.get("owner") or ""),
        "approvedBy": str(payload.get("approvedBy") or ""),
        "reviewedAt": str(payload.get("reviewedAt") or ""),
        "expiresAt": str(payload.get("expiresAt") or ""),
        "dependencyName": str(payload.get("dependencyName") or ""),
        "dependencyNames": _dependabot_dependency_names_from_payload(payload),
        "manifestPath": str(payload.get("manifestPath") or ""),
        "approval": str(payload.get("approval") or ""),
        "alertNumbers": list(alert_numbers),
        "reason": str(payload.get("reason") or ""),
        "remediationPlan": str(payload.get("remediationPlan") or ""),
    }


def _dependabot_dependency_names_from_payload(payload: dict[str, Any]) -> list[str]:
    """Return optional dependency names from owner exception evidence."""
    names = payload.get("dependencyNames")
    if not isinstance(names, list):
        return []
    return sorted(
        {name.strip() for name in names if isinstance(name, str) and name.strip()}
    )


def _alert_number_text(numbers: Sequence[int]) -> str:
    """Return a human-readable alert-number list."""
    return ", ".join(f"#{number}" for number in numbers)


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

    metadata = _github_environment.production_environment_metadata(
        payload,
        environment=environment,
        reviewer_login=reviewer_login,
    )
    blockers = _github_environment.production_environment_blockers(metadata)
    return _check(
        "github_production_environment",
        status="passed" if not blockers else "failed",
        evidence=_github_environment.production_environment_evidence(metadata),
        blockers=blockers,
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


def aws_iam_account_access(
    *, attestation_evidence: Path | None = None, runner: Runner = run
) -> dict[str, object]:
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
    (
        attestation_summary,
        attested_controls,
        attestation_blockers,
    ) = _security_account_attestation_coverage(attestation_evidence, evidence)
    if attestation_summary:
        evidence["securityAccountAttestation"] = attestation_summary
    blockers = [
        *user_blockers,
        *attestation_blockers,
        *_iam_account_access_blockers(evidence, attested_controls),
    ]
    return _check(
        "aws_iam_account_access",
        status="passed" if not blockers else "failed",
        evidence=evidence,
        blockers=blockers,
    )


def _security_account_attestation_coverage(
    evidence_path: Path | None,
    account_evidence: dict[str, object],
) -> tuple[dict[str, object], frozenset[str], list[str]]:
    """Return approved security-account attestation coverage."""
    if evidence_path is None:
        return {}, frozenset(), []

    label = "Security account attestation evidence"
    payload, blockers = _read_required_structured_evidence(
        evidence_path,
        label,
        SECURITY_ACCOUNT_ATTESTATION_REQUIRED_FIELDS,
    )
    blockers.extend(
        _security_account_attestation_payload_blockers(payload, account_evidence)
    )
    controls = SECURITY_ACCOUNT_ATTESTED_CONTROLS if not blockers else frozenset()
    return (
        _security_account_attestation_summary(evidence_path, payload),
        controls,
        blockers,
    )


def _security_account_attestation_payload_blockers(
    payload: dict[str, Any],
    account_evidence: dict[str, object],
) -> list[str]:
    """Return blockers for security-owner attestation evidence."""
    blockers: list[str] = []
    blockers.extend(
        _security_account_attestation_choice_blockers(
            payload,
            "approval",
            SECURITY_ACCOUNT_ALLOWED_APPROVALS,
        )
    )
    blockers.extend(
        _security_account_attestation_choice_blockers(
            payload,
            "humanAccessPosture",
            SECURITY_ACCOUNT_ALLOWED_HUMAN_ACCESS,
        )
    )
    blockers.extend(
        _security_account_attestation_choice_blockers(
            payload,
            "activeKeyDecision",
            SECURITY_ACCOUNT_ALLOWED_ACTIVE_KEY,
        )
    )
    blockers.extend(
        _security_account_attestation_choice_blockers(
            payload,
            "permissionsBoundaryDecision",
            SECURITY_ACCOUNT_ALLOWED_BOUNDARY,
        )
    )
    if (
        account_evidence.get("activeUserAccessKeyCount") != 0
        and _normalized_text(payload.get("activeKeyDecision")) == "no_active_keys"
    ):
        blockers.append(
            "Security account attestation activeKeyDecision cannot be "
            "no_active_keys while active keys remain."
        )
    if not _non_empty_string_list(payload.get("evidence")):
        blockers.append(
            "Security account attestation evidence must include non-empty strings."
        )
    if not _non_empty_text(payload.get("remediationPlan")):
        blockers.append(
            "Security account attestation remediationPlan must be non-empty."
        )
    blockers.extend(
        _security_account_attestation_expiry_blockers(payload.get("expiresAt"))
    )
    blockers.extend(
        _security_account_attestation_account_blockers(payload, account_evidence)
    )
    return blockers


def _security_account_attestation_choice_blockers(
    payload: dict[str, Any],
    field: str,
    allowed_values: frozenset[str],
) -> list[str]:
    """Return a blocker when an attestation enum field is not accepted."""
    value = _normalized_text(payload.get(field))
    if value in allowed_values:
        return []
    allowed = ", ".join(sorted(allowed_values))
    return [f"Security account attestation {field} must be one of: {allowed}."]


def _normalized_text(value: object) -> str:
    """Return a normalized lowercase text value."""
    return str(value or "").strip().lower()


def _non_empty_text(value: object) -> bool:
    """Return whether a value is non-empty text."""
    return isinstance(value, str) and bool(value.strip())


def _security_account_attestation_expiry_blockers(
    expires_at_value: object,
) -> list[str]:
    """Return blockers for security-account attestation expiry."""
    expires_at = _parse_reviewed_at(expires_at_value)
    if expires_at is None:
        return ["Security account attestation evidence expiresAt must be ISO-8601."]
    now = dt.datetime.now(dt.timezone.utc)
    if expires_at <= now:
        return ["Security account attestation evidence is expired."]
    return []


def _security_account_attestation_account_blockers(
    payload: dict[str, Any],
    account_evidence: dict[str, object],
) -> list[str]:
    """Return blockers when attested IAM counts do not match live evidence."""
    return _structured_evidence_mismatch_blockers(
        payload.get("accountEvidence"),
        account_evidence,
        SECURITY_ACCOUNT_ATTESTATION_ACCOUNT_FIELDS,
        object_error="Security account attestation accountEvidence must be an object.",
        mismatch_message=(
            "Security account attestation accountEvidence does not match live "
            "IAM aggregate fields"
        ),
    )


def _security_account_attestation_summary(
    evidence_path: Path,
    payload: dict[str, Any],
) -> dict[str, object]:
    """Return non-secret security-account attestation metadata."""
    return {
        "path": str(evidence_path),
        "owner": str(payload.get("owner") or ""),
        "approvedBy": str(payload.get("approvedBy") or ""),
        "reviewedAt": str(payload.get("reviewedAt") or ""),
        "expiresAt": str(payload.get("expiresAt") or ""),
        "approval": str(payload.get("approval") or ""),
        "humanAccessPosture": str(payload.get("humanAccessPosture") or ""),
        "activeKeyDecision": str(payload.get("activeKeyDecision") or ""),
        "permissionsBoundaryDecision": str(
            payload.get("permissionsBoundaryDecision") or ""
        ),
        "remediationPlan": str(payload.get("remediationPlan") or ""),
    }


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
    """Return aggregate access-key metadata counts without retaining key ids."""
    counts = {
        "active": 0,
        "inactive": 0,
        "other": 0,
        "usersWithActive": 0,
        "unreadableUsers": 0,
        "activeOlderThan90Days": 0,
        "activeCreateDateUnknown": 0,
        "activeNeverUsed": 0,
        "activeLastUsedWithin90Days": 0,
        "activeLastUsedOlderThan90Days": 0,
        "activeLastUsedUnknown": 0,
        "unreadableAccessKeyLastUsed": 0,
    }
    for user in users:
        ok, key_metadata, _error = _run_json(
            [
                "aws",
                "iam",
                "list-access-keys",
                "--user-name",
                user,
                "--query",
                "AccessKeyMetadata[].{Status:Status,AccessKeyId:AccessKeyId,"
                "CreateDate:CreateDate}",
                "--output",
                "json",
            ],
            runner=runner,
        )
        if not ok or not isinstance(key_metadata, list):
            counts["unreadableUsers"] += 1
            continue
        _record_access_key_metadata(key_metadata, counts, runner=runner)
    return counts


def _record_access_key_metadata(
    key_metadata: Sequence[object], counts: dict[str, int], *, runner: Runner = run
) -> None:
    """Accumulate access-key metadata for one IAM user."""
    user_has_active_key = False
    for item in key_metadata:
        status, access_key_id, create_date = _access_key_metadata_fields(item)
        if status == "Active":
            counts["active"] += 1
            user_has_active_key = True
            _record_active_access_key_age(create_date, counts)
            _record_active_access_key_last_used(access_key_id, counts, runner=runner)
        elif status == "Inactive":
            counts["inactive"] += 1
        else:
            counts["other"] += 1
    if user_has_active_key:
        counts["usersWithActive"] += 1


def _access_key_metadata_fields(item: object) -> tuple[object, object, object]:
    """Return status, id, and create date from one access-key metadata item."""
    if isinstance(item, dict):
        return item.get("Status"), item.get("AccessKeyId"), item.get("CreateDate")
    return item, None, None


def _record_active_access_key_age(create_date: object, counts: dict[str, int]) -> None:
    """Accumulate aggregate active-key age metadata."""
    created_at = _parse_aws_timestamp(create_date)
    if created_at is None:
        counts["activeCreateDateUnknown"] += 1
        return
    stale_after = dt.timedelta(days=IAM_ACCESS_KEY_STALE_DAYS)
    if dt.datetime.now(dt.timezone.utc) - created_at > stale_after:
        counts["activeOlderThan90Days"] += 1


def _record_active_access_key_last_used(
    access_key_id: object, counts: dict[str, int], *, runner: Runner = run
) -> None:
    """Accumulate aggregate active-key last-used metadata without emitting key ids."""
    if not isinstance(access_key_id, str) or not access_key_id:
        counts["activeLastUsedUnknown"] += 1
        return
    ok, payload, _error = _run_json(
        [
            "aws",
            "iam",
            "get-access-key-last-used",
            "--access-key-id",
            access_key_id,
            "--query",
            "AccessKeyLastUsed",
            "--output",
            "json",
        ],
        runner=runner,
    )
    if not ok or not isinstance(payload, dict):
        counts["unreadableAccessKeyLastUsed"] += 1
        return
    last_used_at = _parse_aws_timestamp(payload.get("LastUsedDate"))
    if last_used_at is None:
        counts["activeNeverUsed"] += 1
        return
    stale_after = dt.timedelta(days=IAM_ACCESS_KEY_STALE_DAYS)
    if dt.datetime.now(dt.timezone.utc) - last_used_at > stale_after:
        counts["activeLastUsedOlderThan90Days"] += 1
    else:
        counts["activeLastUsedWithin90Days"] += 1


def _parse_aws_timestamp(value: object) -> dt.datetime | None:
    """Parse an AWS CLI timestamp into an aware UTC datetime."""
    if not isinstance(value, str):
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


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
        "activeUserAccessKeyOlderThan90DaysCount": key_counts["activeOlderThan90Days"],
        "activeUserAccessKeyCreateDateUnknownCount": key_counts[
            "activeCreateDateUnknown"
        ],
        "activeUserAccessKeyNeverUsedCount": key_counts["activeNeverUsed"],
        "activeUserAccessKeyLastUsedWithin90DaysCount": key_counts[
            "activeLastUsedWithin90Days"
        ],
        "activeUserAccessKeyLastUsedOlderThan90DaysCount": key_counts[
            "activeLastUsedOlderThan90Days"
        ],
        "activeUserAccessKeyLastUsedUnknownCount": key_counts["activeLastUsedUnknown"],
        "unreadableAccessKeyLastUsedCount": key_counts["unreadableAccessKeyLastUsed"],
    }


def _iam_account_access_blockers(
    evidence: dict[str, object],
    attested_controls: frozenset[str] = frozenset(),
) -> list[str]:
    """Return security-account blockers from non-secret IAM metadata."""
    blockers: list[str] = []
    if evidence["accountMfaEnabled"] != 1:
        blockers.append("IAM account summary does not report root/account MFA enabled.")
    if evidence["accountAccessKeysPresent"] != 0:
        blockers.append("IAM account summary reports root account access keys present.")
    if (
        int(evidence["mfaDevicesInUse"]) < int(evidence["summaryUserCount"])
        and "human_access" not in attested_controls
    ):
        blockers.append(
            "IAM user count exceeds MFA devices in use; human MFA/SSO posture "
            "requires security-owner attestation."
        )
    if (
        evidence["activeUserAccessKeyCount"] != 0
        and "active_key" not in attested_controls
    ):
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
    topic_arn: str | None,
    *,
    observation_evidence: Path | None = None,
    runner: Runner = run,
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
    observation_summary, observation_blockers = _alert_route_observation_coverage(
        observation_evidence,
        evidence,
    )
    if observation_summary:
        evidence["alertRouteObservation"] = observation_summary
    blockers.extend(observation_blockers)
    return _check(
        "aws_sns_alert_route",
        status="passed" if not blockers else "failed",
        evidence=evidence,
        blockers=blockers,
    )


def _alert_route_observation_coverage(
    evidence_path: Path | None,
    route_evidence: dict[str, object],
) -> tuple[dict[str, object], list[str]]:
    """Return approved alert-route observation metadata."""
    if evidence_path is None:
        return {}, []

    label = "Alert-route observation evidence"
    payload, blockers = _read_required_structured_evidence(
        evidence_path,
        label,
        ALERT_ROUTE_OBSERVATION_REQUIRED_FIELDS,
    )
    blockers.extend(_alert_route_observation_payload_blockers(payload, route_evidence))
    return _alert_route_observation_summary(evidence_path, payload), blockers


def _alert_route_observation_payload_blockers(
    payload: dict[str, Any],
    route_evidence: dict[str, object],
) -> list[str]:
    """Return blockers for SRE alert-route observation evidence."""
    blockers: list[str] = []
    blockers.extend(
        _alert_route_observation_choice_blockers(
            payload,
            "decision",
            ALERT_ROUTE_ALLOWED_DECISIONS,
        )
    )
    if not _non_empty_string_list(payload.get("evidence")):
        blockers.append(
            "Alert-route observation evidence must include non-empty evidence strings."
        )
    if not _non_empty_text(payload.get("remediationPlan")):
        blockers.append("Alert-route observation remediationPlan must be non-empty.")
    blockers.extend(_alert_route_observation_expiry_blockers(payload.get("expiresAt")))
    blockers.extend(_alert_route_observation_route_blockers(payload, route_evidence))
    return blockers


def _alert_route_observation_choice_blockers(
    payload: dict[str, Any],
    field: str,
    allowed_values: frozenset[str],
) -> list[str]:
    """Return a blocker when an alert-route enum field is not accepted."""
    value = _normalized_text(payload.get(field))
    if value in allowed_values:
        return []
    allowed = ", ".join(sorted(allowed_values))
    return [f"Alert-route observation {field} must be one of: {allowed}."]


def _alert_route_observation_expiry_blockers(
    expires_at_value: object,
) -> list[str]:
    """Return blockers for alert-route observation expiry."""
    expires_at = _parse_reviewed_at(expires_at_value)
    if expires_at is None:
        return ["Alert-route observation evidence expiresAt must be ISO-8601."]
    now = dt.datetime.now(dt.timezone.utc)
    if expires_at <= now:
        return ["Alert-route observation evidence is expired."]
    return []


def _alert_route_observation_route_blockers(
    payload: dict[str, Any],
    route_evidence: dict[str, object],
) -> list[str]:
    """Return blockers when observed alert-route metadata is stale."""
    attested_route = payload.get("routeEvidence")
    if not isinstance(attested_route, dict):
        return ["Alert-route observation routeEvidence must be an object."]

    mismatched_fields = [
        field
        for field in ALERT_ROUTE_OBSERVATION_ROUTE_FIELDS
        if attested_route.get(field) != route_evidence.get(field)
    ]
    attested_queue = attested_route.get("sqsQueue")
    live_queue = route_evidence.get("sqsQueue")
    if not isinstance(attested_queue, dict):
        return ["Alert-route observation routeEvidence.sqsQueue must be an object."]
    if not isinstance(live_queue, dict):
        mismatched_fields.append("sqsQueue")
    else:
        mismatched_fields.extend(
            f"sqsQueue.{field}"
            for field in ALERT_ROUTE_OBSERVATION_QUEUE_FIELDS
            if attested_queue.get(field) != live_queue.get(field)
        )
    if not mismatched_fields:
        return []
    return [
        "Alert-route observation routeEvidence does not match live route "
        f"fields: {', '.join(mismatched_fields)}."
    ]


def _alert_route_observation_summary(
    evidence_path: Path,
    payload: dict[str, Any],
) -> dict[str, object]:
    """Return non-secret alert-route observation metadata."""
    return {
        "path": str(evidence_path),
        "owner": str(payload.get("owner") or ""),
        "approvedBy": str(payload.get("approvedBy") or ""),
        "reviewedAt": str(payload.get("reviewedAt") or ""),
        "expiresAt": str(payload.get("expiresAt") or ""),
        "decision": str(payload.get("decision") or ""),
        "downstreamRoute": str(payload.get("downstreamRoute") or ""),
        "severityExpectations": str(payload.get("severityExpectations") or ""),
    }


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


def restore_drill_evidence(
    evidence_path: Path | None,
    production_dr_owner_evidence: Path | None = None,
) -> dict[str, object]:
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
    restore_evidence = _restore_drill_evidence_payload(payload)
    owner_summary, owner_blockers = _production_dr_owner_coverage(
        production_dr_owner_evidence,
        restore_evidence,
    )
    blockers = [
        *read_blockers,
        *_restore_drill_payload_blockers(payload),
        *owner_blockers,
    ]
    evidence = restore_evidence
    if owner_summary:
        evidence["productionDrOwnerEvidence"] = owner_summary
    return _check(
        "restore_drill_evidence",
        status="passed" if not blockers else "failed",
        evidence=evidence,
        blockers=blockers,
    )


def _production_dr_owner_coverage(
    evidence_path: Path | None,
    restore_evidence: dict[str, object],
) -> tuple[dict[str, object], list[str]]:
    """Return approved production DR owner metadata for restore evidence."""
    if evidence_path is None:
        return {}, []

    label = "Production DR owner evidence"
    payload, blockers = _read_required_structured_evidence(
        evidence_path,
        label,
        PRODUCTION_DR_OWNER_REQUIRED_FIELDS,
    )
    blockers.extend(_production_dr_owner_payload_blockers(payload, restore_evidence))
    return _production_dr_owner_summary(evidence_path, payload), blockers


def _production_dr_owner_payload_blockers(
    payload: dict[str, Any],
    restore_evidence: dict[str, object],
) -> list[str]:
    """Return blockers for production DR owner evidence."""
    blockers: list[str] = []
    approval = _normalized_text(payload.get("approval"))
    if approval not in PRODUCTION_DR_OWNER_ALLOWED_APPROVALS:
        allowed = ", ".join(sorted(PRODUCTION_DR_OWNER_ALLOWED_APPROVALS))
        blockers.append(
            f"Production DR owner evidence approval must be one of: {allowed}."
        )
    for field in PRODUCTION_DR_OWNER_TEXT_FIELDS:
        if not _non_empty_text(payload.get(field)):
            blockers.append(f"Production DR owner evidence {field} must be non-empty.")
    if _parse_reviewed_at(payload.get("nextReviewDate")) is None:
        blockers.append("Production DR owner evidence nextReviewDate must be ISO-8601.")
    if not _non_empty_string_list(payload.get("evidence")):
        blockers.append(
            "Production DR owner evidence must include non-empty evidence strings."
        )
    if not _non_empty_text(payload.get("remediationPlan")):
        blockers.append(
            "Production DR owner evidence remediationPlan must be non-empty."
        )
    blockers.extend(_production_dr_owner_expiry_blockers(payload.get("expiresAt")))
    blockers.extend(_production_dr_owner_restore_blockers(payload, restore_evidence))
    return blockers


def _production_dr_owner_expiry_blockers(expires_at_value: object) -> list[str]:
    """Return blockers for production DR owner evidence expiry."""
    expires_at = _parse_reviewed_at(expires_at_value)
    if expires_at is None:
        return ["Production DR owner evidence expiresAt must be ISO-8601."]
    now = dt.datetime.now(dt.timezone.utc)
    if expires_at <= now:
        return ["Production DR owner evidence is expired."]
    return []


def _production_dr_owner_restore_blockers(
    payload: dict[str, Any],
    restore_evidence: dict[str, object],
) -> list[str]:
    """Return blockers when production DR evidence references stale restore data."""
    return _structured_evidence_mismatch_blockers(
        payload.get("restoreDrillEvidence"),
        restore_evidence,
        PRODUCTION_DR_OWNER_RESTORE_FIELDS,
        object_error=(
            "Production DR owner evidence restoreDrillEvidence must be an object."
        ),
        mismatch_message=(
            "Production DR owner evidence restoreDrillEvidence does not match current "
            "restore evidence fields"
        ),
    )


def _production_dr_owner_summary(
    evidence_path: Path,
    payload: dict[str, Any],
) -> dict[str, object]:
    """Return non-secret production DR owner evidence metadata."""
    return {
        "path": str(evidence_path),
        **{
            field: str(payload.get(field) or "")
            for field in PRODUCTION_DR_OWNER_SUMMARY_FIELDS
        },
    }


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


PILLAR_CHECKS = _scoring.PILLAR_CHECKS
WELL_ARCHITECTED_SCORE_CAP = _scoring.WELL_ARCHITECTED_SCORE_CAP
pillar_scores = _scoring.pillar_scores
well_architected_scores = _scoring.well_architected_scores
score_blockers = _scoring.score_blockers


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
            DependabotAlertRequest(
                repo=args.repo,
                dependency=args.dependabot_dependency,
                manifest_path=args.dependabot_manifest,
            ),
            exception_evidence=args.dependabot_exception_evidence,
            runner=runner,
        ),
        github_production_environment(
            args.repo,
            args.production_environment,
            args.production_reviewer,
            runner=runner,
        ),
        aws_identity(runner=runner),
        aws_iam_account_access(
            attestation_evidence=args.security_account_attestation_evidence,
            runner=runner,
        ),
        aws_cost_controls(args.aws_account_id, runner=runner),
        aws_sns_alert_route(
            args.operations_topic_arn,
            observation_evidence=args.alert_route_observation_evidence,
            runner=runner,
        ),
        aws_cloudtrail_management_events(
            args.operations_cloudtrail_name, runner=runner
        ),
        aws_restore_jobs(args.restore_window_days, runner=runner),
        restore_drill_evidence(
            args.restore_drill_evidence,
            production_dr_owner_evidence=args.production_dr_owner_evidence,
        ),
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


def render_markdown_report(report: dict[str, Any]) -> str:
    """Render a sanitized Markdown summary for CI artifacts and step summaries."""
    return _markdown.render_markdown_report(
        report, EXPECTED_WELL_ARCHITECTED_QUESTION_COUNTS
    )


def _score_table_rows(value: object) -> list[str]:
    """Return Markdown table rows for a pillar score mapping."""
    return _markdown.score_table_rows(value, EXPECTED_WELL_ARCHITECTED_QUESTION_COUNTS)


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
        help=(
            "Optional dependency name whose open Dependabot alerts block SEC11; "
            "omit to check the entire manifest."
        ),
    )
    parser.add_argument(
        "--dependabot-manifest",
        default=DEFAULT_DEPENDABOT_MANIFEST,
        help="Manifest path whose open Dependabot alerts block SEC11.",
    )
    parser.add_argument(
        "--dependabot-exception-evidence",
        type=Path,
        help=(
            "Optional non-secret owner-approved exception evidence covering the "
            "current open Dependabot alert numbers."
        ),
    )
    parser.add_argument(
        "--security-account-attestation-evidence",
        type=Path,
        help=(
            "Optional non-secret owner-approved security-account attestation "
            "covering current aggregate IAM account-access evidence."
        ),
    )
    parser.add_argument(
        "--alert-route-observation-evidence",
        type=Path,
        help=(
            "Optional non-secret SRE-approved alert-route observation evidence "
            "covering current stable SNS/SQS route metadata."
        ),
    )
    parser.add_argument(
        "--production-dr-owner-evidence",
        type=Path,
        help=(
            "Optional non-secret production-owner DR evidence covering current "
            "restore-drill metadata, RTO/RPO targets, recovery ownership, "
            "escalation, communications, next review, and retention location."
        ),
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
    parser.add_argument("--markdown-output", type=Path)
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


def apply_environment_defaults(args: argparse.Namespace) -> argparse.Namespace:
    """Populate omitted standard evidence flags from environment variables."""
    return _env.apply_environment_defaults(args, ENV_STRING_DEFAULTS, ENV_PATH_DEFAULTS)


def main(argv: Sequence[str] | None = None) -> int:
    """Run evidence collection and optionally persist report artifacts."""
    args = apply_environment_defaults(build_parser().parse_args(argv))
    report = collect_evidence(args)
    payload = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(f"{payload}\n", encoding="utf-8")
    if args.markdown_output:
        args.markdown_output.parent.mkdir(parents=True, exist_ok=True)
        args.markdown_output.write_text(
            render_markdown_report(report), encoding="utf-8"
        )
    print(payload)
    return 0 if not report["blockers"] else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
