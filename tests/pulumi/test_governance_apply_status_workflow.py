"""Structural tests for the always-reportable Governance Apply status workflow.

`.github/workflows/governance-apply-status.yml` posts a terminal/placeholder
"Governance Apply" commit status to EVERY PR head SHA so the global required
check is always reportable, even for non-governance PRs (architecture §7.5,
FEASIBILITY-1). CRITICAL SAFETY: it uses `pull_request_target` for a
fork-capable `statuses: write` token but must NEVER check out or execute
PR-head code. These checks assert that contract from the parsed YAML directly.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS_DIR = PROJECT_ROOT / ".github" / "workflows"
STATUS_WORKFLOW = "governance-apply-status.yml"
STATUS_CONTEXT = "Governance Apply"
ACTION_SHA_REF = re.compile(r"^[^@]+@[0-9a-f]{40}$")


def _workflow(name: str) -> dict:
    """Load a workflow YAML file from disk."""
    return yaml.safe_load((WORKFLOWS_DIR / name).read_text(encoding="utf-8"))


def _triggers(workflow: dict) -> dict:
    """Normalize the GitHub Actions `on` key when YAML parses it as a boolean."""
    return workflow.get("on", workflow.get(True, {}))


def _job_steps(job: dict) -> list[dict]:
    """Return a job's step list."""
    return job.get("steps", [])


def _only_job(workflow: dict) -> dict:
    """Return the single job in the status workflow."""
    jobs = workflow["jobs"]
    assert len(jobs) == 1, f"expected exactly one job, got {list(jobs)}"  # nosec B101
    return next(iter(jobs.values()))


def test_status_workflow_uses_pull_request_target() -> None:
    """Trigger is pull_request_target (fork-capable statuses: write), not
    pull_request."""
    workflow = _workflow(STATUS_WORKFLOW)
    triggers = _triggers(workflow)

    assert set(triggers) == {"pull_request_target"}  # nosec B101
    assert "pull_request" not in triggers  # nosec B101
    assert set(triggers["pull_request_target"]["types"]) == {  # nosec B101
        "opened",
        "synchronize",
        "reopened",
        "ready_for_review",
    }


def test_status_workflow_permissions_are_minimal_no_id_token() -> None:
    """statuses: write + pull-requests/contents: read, and crucially NO
    id-token / NO AWS credential minting."""
    workflow = _workflow(STATUS_WORKFLOW)
    permissions = workflow.get("permissions", {})

    assert permissions.get("statuses") == "write"  # nosec B101
    assert permissions.get("pull-requests") == "read"  # nosec B101
    assert permissions.get("contents") == "read"  # nosec B101
    assert "id-token" not in permissions  # nosec B101
    # No job re-grants id-token either.
    for job in workflow["jobs"].values():
        assert "id-token" not in job.get("permissions", {})  # nosec B101


def test_status_workflow_does_not_check_out_pr_head_ref() -> None:
    """CRITICAL: no checkout pins `ref` to the PR head — only the BASE repo is
    checked out (no PR-head code executes)."""
    job = _only_job(_workflow(STATUS_WORKFLOW))

    checkout_steps = [
        step
        for step in _job_steps(job)
        if str(step.get("uses", "")).startswith("actions/checkout@")
    ]
    assert checkout_steps, "expected a checkout of the base repo"  # nosec B101
    for step in checkout_steps:
        with_block = step.get("with", {}) or {}
        # Must NOT set ref at all: pull_request_target defaults checkout to the
        # base branch. Any ref pointing at the PR head would run untrusted code.
        assert "ref" not in with_block, (  # nosec B101
            "status workflow must not check out the PR head ref"
        )

    # Belt-and-braces: the PR-head ref expressions must not appear anywhere.
    dumped = yaml.safe_dump(_workflow(STATUS_WORKFLOW))
    assert "pull_request.head.ref" not in dumped  # nosec B101
    assert "github.head_ref" not in dumped  # nosec B101


def test_status_workflow_recomputes_scope_via_governance_paths() -> None:
    """Scope is recomputed from the changed-file LIST (data) via the single
    source of truth predicate, not from PR-head code."""
    job = _only_job(_workflow(STATUS_WORKFLOW))
    run_text = "\n".join(step.get("run", "") for step in _job_steps(job))

    assert "scripts/governance_paths.py --files-stdin" in run_text  # nosec B101
    assert "/files" in run_text  # nosec B101
    assert "--jq '.[].filename'" in run_text  # nosec B101


def test_status_workflow_posts_success_for_non_governance_pr() -> None:
    """Non-governance PR -> terminal success so the required check is satisfied."""
    job = _only_job(_workflow(STATUS_WORKFLOW))
    step = next(
        s
        for s in _job_steps(job)
        if s.get("if") == "steps.scope.outputs.governance_touched != 'true'"
    )
    run_text = step["run"]

    assert "statuses/${HEAD_SHA}" in run_text  # nosec B101
    assert "-f state=success" in run_text  # nosec B101
    assert f'context="{STATUS_CONTEXT}"' in run_text  # nosec B101
    assert "No governance changes; gate not required." in run_text  # nosec B101


def test_status_workflow_posts_pending_for_governance_pr() -> None:
    """Governance PR -> pending placeholder until the runner posts success."""
    job = _only_job(_workflow(STATUS_WORKFLOW))
    step = next(
        s
        for s in _job_steps(job)
        if s.get("if") == "steps.scope.outputs.governance_touched == 'true'"
    )
    run_text = step["run"]

    assert "statuses/${HEAD_SHA}" in run_text  # nosec B101
    assert "-f state=pending" in run_text  # nosec B101
    assert f'context="{STATUS_CONTEXT}"' in run_text  # nosec B101
    assert "@Kravalg must run" in run_text  # nosec B101


def test_status_workflow_posts_to_pr_head_sha_via_env() -> None:
    """The status targets the PR head SHA, exposed via env (not inline in run)."""
    job = _only_job(_workflow(STATUS_WORKFLOW))

    assert (  # nosec B101
        job["env"]["HEAD_SHA"] == "${{ github.event.pull_request.head.sha }}"
    )


def test_status_workflow_concurrency_keyed_per_head_sha() -> None:
    """Re-runs are coherent: one in-flight run per PR head SHA."""
    workflow = _workflow(STATUS_WORKFLOW)
    concurrency = workflow["concurrency"]

    assert (  # nosec B101
        concurrency["group"]
        == "governance-apply-status-${{ github.event.pull_request.head.sha }}"
    )


def test_status_workflow_pins_actions_to_full_shas() -> None:
    """Avoid mutable action tags in the status workflow."""
    workflow = _workflow(STATUS_WORKFLOW)

    for job in workflow["jobs"].values():
        for step in _job_steps(job):
            uses = step.get("uses")
            if uses is None or uses.startswith("./"):
                continue
            assert ACTION_SHA_REF.match(uses), (  # nosec B101
                f"status workflow must pin `{uses}` to a full commit SHA"
            )
