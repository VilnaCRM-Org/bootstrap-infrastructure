from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from _script_support import run
from _well_architected_evidence_common import Runner, _check, _run_json, _run_text


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
