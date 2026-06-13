"""Structural tests for the dedicated governance runner workflow.

These checks mirror `.github/workflows/pulumi-governance.yml` closely. Update
them alongside the workflow when job names, env, or `if` expressions change.
The governance runner is a trusted, env-gated apply path (architecture §7.2,
§7.5, §5.1a). Because actionlint/yamllint run only in CI (docker), this module
asserts the security-critical structure from the parsed YAML directly.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS_DIR = PROJECT_ROOT / ".github" / "workflows"
GOVERNANCE_WORKFLOW = "pulumi-governance.yml"
GOVERNANCE_DISPATCH_TYPE = "pulumi-governance-command"
GOVERNANCE_ENVIRONMENT = "governance"
GOVERNANCE_PULUMI_DIR = "pulumi/governance"
GOVERNANCE_STATUS_CONTEXT = "Governance Apply"
APPLY_JOBS = ("governance_test_apply", "governance_prod_apply")
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


def _step_run_text(job: dict) -> str:
    """Concatenate all `run` script bodies in a job for substring assertions."""
    return "\n".join(step.get("run", "") for step in _job_steps(job))


def test_governance_runner_listens_only_on_dedicated_dispatch() -> None:
    """The runner triggers ONLY on its own repository_dispatch event type."""
    workflow = _workflow(GOVERNANCE_WORKFLOW)
    triggers = _triggers(workflow)

    assert set(triggers) == {"repository_dispatch"}  # nosec B101
    assert triggers["repository_dispatch"]["types"] == [  # nosec B101
        GOVERNANCE_DISPATCH_TYPE
    ]


def test_governance_runner_has_no_workflow_dispatch() -> None:
    """No manual workflow_dispatch entry into the governance apply path (SECURITY-1)."""
    workflow = _workflow(GOVERNANCE_WORKFLOW)
    triggers = _triggers(workflow)

    assert "workflow_dispatch" not in triggers  # nosec B101


def test_preflight_has_no_id_token_permission() -> None:
    """Preflight re-derives trust before any credential-minting job (§7.2)."""
    preflight = _workflow(GOVERNANCE_WORKFLOW)["jobs"]["preflight"]

    assert "id-token" not in preflight.get("permissions", {})  # nosec B101


def test_preflight_revalidates_pr_head_open_and_same_repo() -> None:
    """Preflight re-checks PR number, head SHA, open-not-merged, same-repo head."""
    preflight = _workflow(GOVERNANCE_WORKFLOW)["jobs"]["preflight"]
    run_text = _step_run_text(preflight)

    assert "pulls/" in run_text  # nosec B101
    assert ".head.sha" in run_text  # nosec B101
    assert ".head.repo.full_name" in run_text  # nosec B101
    assert ".state" in run_text  # nosec B101
    assert ".merged" in run_text  # nosec B101
    assert "^[0-9a-f]{40}$" in run_text  # nosec B101


def test_preflight_resolves_comment_author_and_asserts_kravalg() -> None:
    """Preflight resolves comment_id -> author and asserts login == Kravalg."""
    preflight = _workflow(GOVERNANCE_WORKFLOW)["jobs"]["preflight"]
    run_text = _step_run_text(preflight)

    assert "issues/comments/" in run_text  # nosec B101
    assert ".user.login" in run_text  # nosec B101
    # Case-insensitive compare against the sole approver login.
    assert "kravalg" in run_text.lower()  # nosec B101
    # The untrusted comment_id arrives via client_payload, never trusted inputs.
    assert "client_payload.comment_id" in yaml.safe_dump(preflight)  # nosec B101


def test_preflight_recomputes_governance_scope_server_side() -> None:
    """Preflight recomputes governance_touched from head SHA via governance_paths."""
    preflight = _workflow(GOVERNANCE_WORKFLOW)["jobs"]["preflight"]
    run_text = _step_run_text(preflight)

    assert "scripts/governance_paths.py" in run_text  # nosec B101
    assert "/files" in run_text  # nosec B101
    assert "governance_touched" in run_text  # nosec B101


def test_preflight_does_not_trust_client_payload_governance_flag() -> None:
    """The client_payload governance_touched flag is never read as authority."""
    preflight = _workflow(GOVERNANCE_WORKFLOW)["jobs"]["preflight"]
    dumped = yaml.safe_dump(preflight)

    assert "client_payload.governance_touched" not in dumped  # nosec B101


def test_both_apply_jobs_are_env_gated_governance() -> None:
    """Both governance apply jobs declare environment: governance (FR11/SECURITY-2)."""
    jobs = _workflow(GOVERNANCE_WORKFLOW)["jobs"]

    for job_id in APPLY_JOBS:
        assert jobs[job_id]["environment"] == GOVERNANCE_ENVIRONMENT  # nosec B101


def test_both_apply_jobs_set_governance_pulumi_dir() -> None:
    """Both apply jobs target PULUMI_DIR=pulumi/governance (FR12)."""
    jobs = _workflow(GOVERNANCE_WORKFLOW)["jobs"]

    for job_id in APPLY_JOBS:
        assert jobs[job_id]["env"]["PULUMI_DIR"] == GOVERNANCE_PULUMI_DIR  # nosec B101


def test_apply_jobs_run_saved_plan_not_direct_up() -> None:
    """Apply jobs run make pulumi-up-plan, never make pulumi-up (IaC-only apply)."""
    jobs = _workflow(GOVERNANCE_WORKFLOW)["jobs"]

    for job_id in APPLY_JOBS:
        run_text = _step_run_text(jobs[job_id])
        assert "make pulumi-up-plan" in run_text  # nosec B101
        assert re.search(r"make pulumi-up(\s|$)", run_text) is None  # nosec B101


def test_no_job_invokes_direct_pulumi_up() -> None:
    """No job anywhere in the workflow invokes the direct (unplanned) apply."""
    jobs = _workflow(GOVERNANCE_WORKFLOW)["jobs"]

    for job in jobs.values():
        run_text = _step_run_text(job)
        assert re.search(r"make pulumi-up(\s|$)", run_text) is None  # nosec B101


def test_apply_jobs_select_correct_governance_stacks() -> None:
    """Test apply targets the test stack; prod apply targets the prod stack."""
    jobs = _workflow(GOVERNANCE_WORKFLOW)["jobs"]

    assert jobs["governance_test_apply"]["env"]["PULUMI_STACK"] == "test"  # nosec B101
    assert jobs["governance_prod_apply"]["env"]["PULUMI_STACK"] == "prod"  # nosec B101


def test_prod_apply_needs_test_apply_and_drift() -> None:
    """Prod apply is gated behind test apply + test post-apply drift (FR15)."""
    jobs = _workflow(GOVERNANCE_WORKFLOW)["jobs"]
    needs = jobs["governance_prod_apply"]["needs"]

    assert "governance_test_apply" in needs  # nosec B101
    assert "governance_test_post_apply_drift" in needs  # nosec B101


def test_post_apply_drift_needs_test_apply() -> None:
    """Test post-apply drift runs after the test apply (ordering preserved)."""
    jobs = _workflow(GOVERNANCE_WORKFLOW)["jobs"]
    needs = jobs["governance_test_post_apply_drift"]["needs"]

    assert "governance_test_apply" in needs  # nosec B101


def test_status_post_job_targets_head_sha_with_governance_context() -> None:
    """Final status job posts `Governance Apply` to the head SHA (FEASIBILITY-1)."""
    jobs = _workflow(GOVERNANCE_WORKFLOW)["jobs"]
    status_job = jobs["governance_status"]
    run_text = _step_run_text(status_job)
    job_env = status_job.get("env", {})

    # The commit status is posted to the verified head SHA exposed via env.
    assert "statuses/${HEAD_SHA}" in run_text  # nosec B101
    assert job_env["HEAD_SHA"] == "${{ needs.preflight.outputs.head_sha }}"  # nosec B101
    # The context string must be byte-identical to the required-check tuple entry.
    assert f'context="{GOVERNANCE_STATUS_CONTEXT}"' in run_text  # nosec B101
    assert GOVERNANCE_STATUS_CONTEXT in run_text  # nosec B101


def test_status_post_state_derives_from_prod_apply_outcome() -> None:
    """The posted commit-status state comes from governance_prod_apply outcome."""
    jobs = _workflow(GOVERNANCE_WORKFLOW)["jobs"]
    status_job = jobs["governance_status"]

    assert status_job["if"] == "always()"  # nosec B101
    assert "governance_prod_apply" in status_job["needs"]  # nosec B101
    dumped = yaml.safe_dump(status_job)
    assert "needs.governance_prod_apply.result" in dumped  # nosec B101


def test_governance_runner_pins_actions_to_full_shas() -> None:
    """Avoid mutable action tags in the governance runner."""
    workflow = _workflow(GOVERNANCE_WORKFLOW)

    for job in workflow["jobs"].values():
        for step in _job_steps(job):
            uses = step.get("uses")
            if uses is None or uses.startswith("./"):
                continue
            assert ACTION_SHA_REF.match(uses), (  # nosec B101
                f"governance runner must pin `{uses}` to a full commit SHA"
            )
