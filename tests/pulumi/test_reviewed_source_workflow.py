"""Credential issuance must be downstream of trusted exact-source admission."""

import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]


def workflow(name):
    return yaml.safe_load((ROOT / ".github/workflows" / name).read_text())


@pytest.mark.parametrize(
    ("event", "repository", "active", "privileged"),
    [
        ("pull_request", "VilnaCRM-Org/bootstrap-infrastructure", "", True),
        ("pull_request", "VilnaCRM-Org/bootstrap-infrastructure", "false", True),
        ("pull_request", "VilnaCRM-Org/bootstrap-infrastructure", "true", False),
        ("pull_request", "fork/repo", "", False),
        ("pull_request", "fork/repo", "true", False),
        ("push", "VilnaCRM-Org/bootstrap-infrastructure", "true", True),
    ],
)
def test_staged_activation_preserves_legacy_checks_until_cutover(
    event, repository, active, privileged, tmp_path
):
    mode_job = workflow("pulumi-pr-guardrails.yml")["jobs"]["preview_mode"]
    assert mode_job["env"]["REVIEWED_SOURCE_PREVIEW_ACTIVE"] == (
        "${{ vars.REVIEWED_SOURCE_PREVIEW_ACTIVE }}"
    )
    mode = mode_job["steps"][0]["run"]
    output = tmp_path / "output"
    subprocess.run(
        ["bash", "-eu", "-c", mode],
        check=True,
        env={
            "GITHUB_EVENT_NAME": event,
            "GITHUB_HEAD_REPOSITORY": repository,
            "GITHUB_REPOSITORY_NAME": "VilnaCRM-Org/bootstrap-infrastructure",
            "REVIEWED_SOURCE_PREVIEW_ACTIVE": active,
            "GITHUB_OUTPUT": str(output),
        },
    )
    assert output.read_text() == f"privileged={str(privileged).lower()}\n"


def test_trusted_credentials_precede_only_admitted_pr_execution():
    trusted = workflow("reviewed-pr-preview.yml")
    assert set(trusted["on"]) == {"workflow_run"}
    for job_id in ["preview", "iam_validation"]:
        job = trusted["jobs"][job_id]
        steps = job["steps"]
        gate = next(i for i, s in enumerate(steps) if s.get("id") == "admission")
        loader = next(i for i, s in enumerate(steps) if s.get("id") == "ci_config")
        source = next(
            i
            for i, s in enumerate(steps)
            if s.get("name") == "Check out exact independently admitted source"
        )
        assert gate < loader < source
        assert steps[0]["with"]["ref"] == "${{ github.sha }}"
        assert steps[0]["with"]["path"] == ".trusted"
        assert steps[source]["with"]["ref"] == "${{ needs.admission.outputs.head_sha }}"
        assert (
            'python3 -I "${GITHUB_WORKSPACE}/.trusted/scripts/'
            'reviewed_source_admission.py"' in steps[gate]["run"]
        )
        assert all("make " not in step.get("run", "") for step in steps[:source])
        assert job["permissions"].get("statuses") is None
        assert job["permissions"].get("pull-requests") == "read"
    assert set(trusted["jobs"]) == {
        "admission",
        "preview",
        "destructive_diff",
        "iam_validation",
        "publish",
    }
    assert "make test-destructive-diff" in str(trusted["jobs"]["destructive_diff"])
    assert "make test-cost-proxy" in str(trusted["jobs"]["destructive_diff"])
    assert "make test-iam-validation" in str(trusted["jobs"]["iam_validation"])


def test_fork_signal_is_rejected_before_admission_and_credentialed_jobs():
    jobs = workflow("reviewed-pr-preview.yml")["jobs"]
    assert " ".join(jobs["admission"]["if"].split()) == (
        "${{ github.event.workflow_run.head_repository.full_name == "
        "github.repository && "
        "(github.event.workflow_run.event == 'pull_request' || "
        "github.event.workflow_run.event == 'pull_request_review') }}"
    )
    for job_id in ("preview", "iam_validation"):
        assert "admission" in jobs[job_id]["needs"]
        # Default success() keeps a skipped/failed admission from issuing credentials.
        assert "if" not in jobs[job_id]


def test_only_clean_publisher_can_complete_required_pr_contexts():
    trusted = workflow("reviewed-pr-preview.yml")
    jobs = trusted["jobs"]
    admission = next(
        s for s in jobs["admission"]["steps"] if s.get("id") == "admission"
    )
    assert "--publish-pending" in admission["run"]
    publisher = jobs["publish"]
    assert publisher["needs"] == [
        "admission",
        "preview",
        "destructive_diff",
        "iam_validation",
    ]
    assert publisher["permissions"] == {
        "contents": "read",
        "pull-requests": "read",
    }
    assert publisher["steps"][0]["with"]["ref"] == "${{ github.sha }}"
    result = publisher["steps"][-1]
    for job in ("preview", "destructive_diff", "iam_validation"):
        assert f"needs.{job}.result == 'success'" in result["env"]["GUARDRAIL_RESULT"]
    assert "--publish-result" in result["run"]
    assert all("make " not in step.get("run", "") for step in publisher["steps"])
    legacy = workflow("pulumi-pr-guardrails.yml")
    legacy_contexts = {"Preview", "Destructive Diff Gate", "IAM Validation"}
    assert legacy_contexts <= {job["name"] for job in legacy["jobs"].values()}
    reviewed_contexts = {
        "Reviewed Preview",
        "Reviewed Destructive Diff Gate",
        "Reviewed IAM Validation",
    }
    # Neither a skipped legacy job nor a native execution job can satisfy these.
    assert reviewed_contexts.isdisjoint(
        {job.get("name", "") for job in (*legacy["jobs"].values(), *jobs.values())}
    )


def test_only_main_bound_clean_jobs_can_mint_dedicated_status_tokens():
    jobs = workflow("reviewed-pr-preview.yml")["jobs"]
    for name, job in jobs.items():
        assert job.get("permissions", {}).get("statuses") != "write"
        app_steps = [s for s in job["steps"] if s.get("id") == "reviewed_app"]
        if name not in {"admission", "publish"}:
            assert app_steps == []
            assert "REVIEWED_SOURCE_APP_PRIVATE_KEY" not in str(job)
            continue
        assert job["environment"] == "reviewed-source-publisher"
        assert len(app_steps) == 1
        app = app_steps[0]
        assert app["uses"] == (
            "actions/create-github-app-token@fee1f7d63c2ff003460e3d139729b119787bc349"
        )
        assert app["with"]["app-id"] == "${{ vars.REVIEWED_SOURCE_APP_ID }}"
        assert (
            app["with"]["private-key"]
            == "${{ secrets.REVIEWED_SOURCE_APP_PRIVATE_KEY }}"
        )
        assert app["with"]["owner"] == "VilnaCRM-Org"
        assert app["with"]["repositories"] == "bootstrap-infrastructure"
        assert app["with"]["permission-statuses"] == "write"
        boundary = next(
            s for s in job["steps"] if "--verify-publisher-boundary" in s.get("run", "")
        )
        assert job["steps"].index(boundary) < job["steps"].index(app)
        assert boundary["env"]["GH_TOKEN"] == "${{ github.token }}"
        publication = job["steps"][-1]
        assert (
            publication["env"]["GH_TOKEN"] == "${{ steps.reviewed_app.outputs.token }}"
        )
        assert all("make " not in s.get("run", "") for s in job["steps"])
