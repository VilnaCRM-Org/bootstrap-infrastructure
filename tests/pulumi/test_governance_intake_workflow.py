"""Structural tests for governance-aware routing in the PR-command intake.

These checks mirror `.github/workflows/pulumi-pr-commands.yml` closely. Update
them alongside the workflow when step ids, env, or dispatch logic change.

The intake (E3.S2) computes `governance_touched` from the PR's changed paths via
`scripts/governance_paths.py` and passes the comment author login plus the
governance flag into the parse/authorize step. When governance is touched it
dispatches the dedicated event type `pulumi-governance-command` (routed to
`pulumi-governance.yml`); otherwise it keeps `pulumi-pr-command` for the existing
runner (architecture §7.2, §7.4). `client_payload.comment_id` is always present
so the governance runner re-resolves the author server-side. Because
actionlint/yamllint run only in CI (docker), this module asserts the
security-critical structure from the parsed YAML directly.
"""

from __future__ import annotations

from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS_DIR = PROJECT_ROOT / ".github" / "workflows"
INTAKE_WORKFLOW = "pulumi-pr-commands.yml"
GOVERNANCE_DISPATCH_TYPE = "pulumi-governance-command"
NON_GOVERNANCE_DISPATCH_TYPE = "pulumi-pr-command"
GOVERNANCE_SCOPE_STEP_ID = "scope"


def _workflow(name: str) -> dict:
    """Load a workflow YAML file from disk."""
    return yaml.safe_load((WORKFLOWS_DIR / name).read_text(encoding="utf-8"))


def _dispatch_job() -> dict:
    """Return the intake `dispatch` job."""
    return _workflow(INTAKE_WORKFLOW)["jobs"]["dispatch"]


def _steps() -> list[dict]:
    """Return the dispatch job's step list."""
    return _dispatch_job().get("steps", [])


def _step_by_id(step_id: str) -> dict:
    """Return the first step with the given id."""
    for step in _steps():
        if step.get("id") == step_id:
            return step
    raise AssertionError(f"step id `{step_id}` not found in intake dispatch job")


def _step_index(predicate) -> int:
    """Return the index of the first step matching predicate."""
    for index, step in enumerate(_steps()):
        if predicate(step):
            return index
    raise AssertionError("no step matched the predicate")


def _all_run_text() -> str:
    """Concatenate every `run` script body in the dispatch job."""
    return "\n".join(step.get("run", "") for step in _steps())


def test_intake_keeps_pull_requests_read_permission() -> None:
    """The intake reads PR files, so it must keep pull-requests: read (FR14)."""
    workflow = _workflow(INTAKE_WORKFLOW)

    assert workflow["permissions"]["pull-requests"] == "read"  # nosec B101


def test_detect_governance_step_lists_changed_paths_via_script() -> None:
    """A scope step lists PR files and pipes them into governance_paths.py."""
    scope = _step_by_id(GOVERNANCE_SCOPE_STEP_ID)
    run_text = scope.get("run", "")

    # Paginated changed-file listing for the PR.
    assert "pulls/" in run_text  # nosec B101
    assert "/files" in run_text  # nosec B101
    assert "--paginate" in run_text  # nosec B101
    assert ".[].filename" in run_text  # nosec B101
    # Single source of truth for the governance path predicate.
    assert "scripts/governance_paths.py" in run_text  # nosec B101
    assert "--files-stdin" in run_text  # nosec B101
    # The script prints governance_touched=true|false; capture it as an output.
    assert "governance_touched" in run_text  # nosec B101
    assert "GITHUB_OUTPUT" in run_text  # nosec B101


def test_detect_governance_step_runs_before_parse_step() -> None:
    """Scope detection precedes the parse/authorize step so it can feed it."""
    scope_index = _step_index(lambda step: step.get("id") == GOVERNANCE_SCOPE_STEP_ID)
    parse_index = _step_index(lambda step: step.get("id") == "parse")

    assert scope_index < parse_index  # nosec B101


def test_parse_step_receives_author_login_and_governance_touched() -> None:
    """Parse step is fed the comment author login + recomputed governance flag."""
    parse = _step_by_id("parse")
    run_text = parse.get("run", "")

    assert "scripts/pulumi_pr_comment.py" in run_text  # nosec B101
    assert "--author-login" in run_text  # nosec B101
    assert "github.event.comment.user.login" in yaml.safe_dump(parse)  # nosec B101
    assert "--governance-touched" in run_text  # nosec B101
    assert (  # nosec B101
        f"steps.{GOVERNANCE_SCOPE_STEP_ID}.outputs.governance_touched"
        in yaml.safe_dump(parse)
    )


def _dispatch_steps() -> list[dict]:
    """Return every step that POSTs a repository_dispatch event."""
    return [
        step
        for step in _steps()
        if "repos/${GITHUB_REPOSITORY}/dispatches" in step.get("run", "")
    ]


def test_governance_changes_dispatch_dedicated_event_type() -> None:
    """A governance-touching PR dispatches pulumi-governance-command."""
    governance_dispatches = [
        step
        for step in _dispatch_steps()
        if f"event_type='{GOVERNANCE_DISPATCH_TYPE}'" in step.get("run", "")
    ]

    assert len(governance_dispatches) == 1  # nosec B101
    governance_dispatch = governance_dispatches[0]
    condition = governance_dispatch.get("if", "")
    # Routed only when scope detection flagged governance.
    assert "steps.scope.outputs.governance_touched == 'true'" in condition  # nosec B101


def test_non_governance_changes_keep_existing_event_type() -> None:
    """A non-governance PR keeps the existing pulumi-pr-command runner."""
    non_governance_dispatches = [
        step
        for step in _dispatch_steps()
        if f"event_type='{NON_GOVERNANCE_DISPATCH_TYPE}'" in step.get("run", "")
    ]

    assert len(non_governance_dispatches) == 1  # nosec B101
    non_governance_dispatch = non_governance_dispatches[0]
    condition = non_governance_dispatch.get("if", "")
    assert "steps.scope.outputs.governance_touched != 'true'" in condition  # nosec B101


def test_both_dispatches_include_comment_id_and_pr_metadata() -> None:
    """Each dispatch carries comment_id (server re-auth) + pr number + head sha."""
    dispatch_steps = _dispatch_steps()

    assert len(dispatch_steps) == 2  # nosec B101
    for step in dispatch_steps:
        run_text = step.get("run", "")
        assert "client_payload[comment_id]" in run_text  # nosec B101
        assert "client_payload[pull_request_number]" in run_text  # nosec B101
        assert "client_payload[head_sha]" in run_text  # nosec B101


def test_dispatch_event_types_are_mutually_exclusive() -> None:
    """Exactly one of the two routing dispatches fires per command."""
    run_text = _all_run_text()

    assert run_text.count(f"event_type='{GOVERNANCE_DISPATCH_TYPE}'") == 1  # nosec B101
    assert (  # nosec B101
        run_text.count(f"event_type='{NON_GOVERNANCE_DISPATCH_TYPE}'") == 1
    )
