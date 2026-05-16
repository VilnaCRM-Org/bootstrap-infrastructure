from __future__ import annotations

import os
from collections.abc import Sequence
from typing import Any

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
