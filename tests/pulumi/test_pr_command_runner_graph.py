"""Regression guard for the monolithic PR command runner's event + graph.

Story E3.S3: routing to the governance apply path happens at the intake via the
dedicated `pulumi-governance-command` event type (E3.S2 -> `pulumi-governance.yml`),
NOT by this runner handing off mid-flow (the "route to another workflow" primitive
does not exist; AWS-SRE-3/FEASIBILITY-2). This module pins the two invariants that
keep that split safe:

1. `pulumi-pr-command-runner.yml` listens for ``pulumi-pr-command`` ONLY and never
   for ``pulumi-governance-command``; it owns no governance apply job and no
   ``environment: governance`` gate. Governance ``up`` is handled exclusively by
   ``pulumi-governance.yml`` (architecture §7.2).
2. The runner's ``prod_*`` jobs still depend on ``test_*`` success, so the
   test-then-prod ordering / success-before-merge graph is not weakened (FR15,
   architecture §7.5).

These checks run from the parsed YAML because actionlint/yamllint execute only in
CI (docker). Update them alongside the runner when job names or `needs` change.
"""

from __future__ import annotations

from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS_DIR = PROJECT_ROOT / ".github" / "workflows"

RUNNER_WORKFLOW = "pulumi-pr-command-runner.yml"
GOVERNANCE_WORKFLOW = "pulumi-governance.yml"

PR_COMMAND_DISPATCH_TYPE = "pulumi-pr-command"
GOVERNANCE_DISPATCH_TYPE = "pulumi-governance-command"
GOVERNANCE_ENVIRONMENT = "governance"
GOVERNANCE_PULUMI_DIR = "pulumi/governance"

# Each prod_* job and the test_* job(s) it must remain gated on (success-before-merge).
PROD_TO_TEST_DEPENDENCIES = {
    "prod_preview": ("test_post_apply_drift",),
    "prod_destructive_diff": ("prod_preview",),
    "prod_iam_validation": ("prod_preview", "prod_destructive_diff"),
    "prod_apply": ("prod_preview", "prod_destructive_diff", "prod_iam_validation"),
    "prod_post_apply_drift": ("prod_apply",),
}


def _workflow(name: str) -> dict:
    """Load a workflow YAML file from disk."""
    return yaml.safe_load((WORKFLOWS_DIR / name).read_text(encoding="utf-8"))


def _triggers(workflow: dict) -> dict:
    """Normalize the GitHub Actions `on` key when YAML parses it as a boolean."""
    return workflow.get("on", workflow.get(True, {}))


def test_runner_listens_only_for_pr_command_dispatch() -> None:
    """The runner triggers on ``pulumi-pr-command`` only, never the governance event."""
    triggers = _triggers(_workflow(RUNNER_WORKFLOW))
    dispatch_types = triggers["repository_dispatch"]["types"]

    assert dispatch_types == [PR_COMMAND_DISPATCH_TYPE]  # nosec B101
    assert GOVERNANCE_DISPATCH_TYPE not in dispatch_types  # nosec B101


def test_runner_does_not_reference_governance_event_anywhere() -> None:
    """No part of the runner reacts to or routes the governance dispatch event."""
    dumped = yaml.safe_dump(_workflow(RUNNER_WORKFLOW))

    assert GOVERNANCE_DISPATCH_TYPE not in dumped  # nosec B101


def test_runner_has_no_governance_apply_job() -> None:
    """The runner owns no governance apply job (no env gate, no governance dir)."""
    jobs = _workflow(RUNNER_WORKFLOW)["jobs"]

    for job in jobs.values():
        assert job.get("environment") != GOVERNANCE_ENVIRONMENT  # nosec B101
        env = job.get("env", {}) or {}
        assert env.get("PULUMI_DIR") != GOVERNANCE_PULUMI_DIR  # nosec B101

    # No governance-named apply job leaked into the monolithic runner.
    assert not any("governance" in job_id for job_id in jobs)  # nosec B101


def test_prod_jobs_remain_gated_on_test_success() -> None:
    """Every prod_* job still depends on the test_* graph (FR15 ordering)."""
    jobs = _workflow(RUNNER_WORKFLOW)["jobs"]

    for prod_job, required in PROD_TO_TEST_DEPENDENCIES.items():
        needs = jobs[prod_job]["needs"]
        for dependency in required:
            assert dependency in needs, (  # nosec B101
                f"{prod_job} must stay gated on {dependency} (success-before-merge)"
            )


def test_prod_preview_gated_on_test_post_apply_drift_result() -> None:
    """prod_preview only runs after a successful test post-apply drift check."""
    jobs = _workflow(RUNNER_WORKFLOW)["jobs"]
    prod_preview = jobs["prod_preview"]

    assert "test_post_apply_drift" in prod_preview["needs"]  # nosec B101
    assert (  # nosec B101
        "needs.test_post_apply_drift.result == 'success'" in prod_preview["if"]
    )


def test_governance_up_is_owned_by_dedicated_governance_runner() -> None:
    """Governance ``up`` is handled exclusively by pulumi-governance.yml, not here."""
    governance = _workflow(GOVERNANCE_WORKFLOW)
    governance_triggers = _triggers(governance)

    # The governance event routes ONLY to the dedicated governance runner.
    assert governance_triggers["repository_dispatch"]["types"] == [  # nosec B101
        GOVERNANCE_DISPATCH_TYPE
    ]
    governance_jobs = governance["jobs"]
    assert "governance_test_apply" in governance_jobs  # nosec B101
    assert "governance_prod_apply" in governance_jobs  # nosec B101

    # The monolithic runner exposes none of those apply jobs.
    runner_jobs = _workflow(RUNNER_WORKFLOW)["jobs"]
    assert "governance_test_apply" not in runner_jobs  # nosec B101
    assert "governance_prod_apply" not in runner_jobs  # nosec B101


def test_all_credentials_wait_for_a_protected_environment_and_sha_recheck():
    """No PR code or AWS credentials run before the matching environment gate."""
    for filename in (RUNNER_WORKFLOW, GOVERNANCE_WORKFLOW):
        for job in _workflow(filename)["jobs"].values():
            if job.get("permissions", {}).get("id-token") != "write":
                continue
            assert job["environment"] in {
                "test",
                "test-preview",
                "prod",
                "prod-preview",
                "governance",
                "governance-preview",
            }
            steps = job["steps"]
            recheck = next(
                i
                for i, step in enumerate(steps)
                if step.get("name") == "Recheck current PR head before credentials"
            )
            credentials = next(
                i
                for i, step in enumerate(steps)
                if "configure-aws-credentials@" in step.get("uses", "")
                or "load-aws-ci-env" in step.get("uses", "")
            )
            assert recheck < credentials
            if filename == RUNNER_WORKFLOW:
                action = next(
                    step for step in steps if "load-aws-ci-env" in step.get("uses", "")
                )
                assert action["uses"] == "./.trusted/.github/actions/load-aws-ci-env"


def test_dispatch_runners_share_single_use_claim_serialization():
    runners = [
        _workflow(filename) for filename in (RUNNER_WORKFLOW, GOVERNANCE_WORKFLOW)
    ]
    assert runners[0]["concurrency"] == runners[1]["concurrency"]
    for runner in runners:
        assert "workflow_dispatch" not in _triggers(runner)
        assert "pulumi_command_preflight.py" in str(runner["jobs"]["preflight"])


def test_plan_commands_never_apply_test_or_prod():
    for filename, prefix in (
        (RUNNER_WORKFLOW, ""),
        (GOVERNANCE_WORKFLOW, "governance_"),
    ):
        jobs = _workflow(filename)["jobs"]
        for target in ("test", "prod"):
            assert "command == 'up'" in jobs[f"{prefix}{target}_apply"]["if"]
        prod_preview = jobs[f"{prefix}prod_plan" if prefix else "prod_preview"]
        assert "command == 'plan'" in prod_preview["if"]
        assert (
            f"needs.{prefix}test_post_apply_drift.result == 'success'"
            in prod_preview["if"]
        )


def test_platform_promotion_uses_trusted_credential_free_same_run_final_job():
    document = yaml.safe_load(
        (PROJECT_ROOT / ".github/workflows/pulumi-pr-command-runner.yml").read_text()
    )
    job = document["jobs"]["platform_promotion"]
    assert set(job["needs"]) == {
        "preflight",
        "test_apply",
        "test_post_apply_drift",
        "prod_apply",
        "prod_post_apply_drift",
    }
    assert job["environment"] == "governance-evidence"
    assert job["permissions"] == {
        "contents": "read",
        "pull-requests": "read",
    }
    assert job["env"]["PROMOTION_KIND"] == "platform"
    assert (
        job["concurrency"]["group"]
        == "promotion-status-${{ needs.preflight.outputs.pull_request_number }}"
    )
    downloads = []
    for step in job["steps"]:
        action = step.get("uses", "")
        if "checkout@" in action:
            assert step["with"]["ref"] == "${{ github.sha }}"
        if "download-artifact@" in action:
            downloads.append(step["with"])
            assert "run-id" not in step["with"]
            assert "${{ needs.preflight.outputs.head_sha }}" in step["with"]["name"]
        assert "configure-aws-credentials" not in action
    assert {item["path"] for item in downloads} == {
        ".artifacts/promotion-inputs/test",
        ".artifacts/promotion-inputs/prod",
    }
