from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from _script_support import run
from _well_architected_evidence_common import Runner, _check, _run_json, _run_text
from _well_architected_github_rollup import (
    _current_check_in_progress_labels,
    _current_check_names_from_env,
    _github_pr_check_blockers,
    _non_passing_rollup_labels,
)


@dataclass(frozen=True)
class GitHubPrCheckEvidenceInputs:
    """Inputs for rendering normalized PR check evidence."""

    payload: dict[str, Any]
    entries: Sequence[dict[str, Any]]
    failing: Sequence[str]
    files_ok: bool
    changed_files: Sequence[str]
    current_check_in_progress: Sequence[str] = ()


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
            GitHubPrCheckEvidenceInputs(
                payload=payload,
                entries=entries,
                failing=failing,
                files_ok=files_ok,
                changed_files=changed_files,
                current_check_in_progress=current_check_in_progress,
            ),
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


def _github_pr_check_evidence(inputs: GitHubPrCheckEvidenceInputs) -> dict[str, object]:
    """Return PR check evidence including non-secret changed-file metadata."""
    return {
        "headRefOid": inputs.payload.get("headRefOid"),
        "mergeStateStatus": inputs.payload.get("mergeStateStatus"),
        "mergeable": inputs.payload.get("mergeable"),
        "reviewDecision": inputs.payload.get("reviewDecision"),
        "checkCount": len(inputs.entries),
        "nonPassingCheckCount": len(inputs.failing),
        "currentCheckInProgressCount": len(inputs.current_check_in_progress),
        "currentCheckInProgressNames": list(inputs.current_check_in_progress),
        "changedFileCount": len(inputs.changed_files) if inputs.files_ok else None,
        "changedFileTopLevelPaths": (
            _changed_file_top_level_paths(inputs.changed_files)
            if inputs.files_ok
            else []
        ),
        "changedFilePaths": list(inputs.changed_files) if inputs.files_ok else [],
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
