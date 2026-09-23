"""Credential issuance must be downstream of trusted exact-source admission."""

import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]


def workflow(name):
    return yaml.safe_load((ROOT / ".github/workflows" / name).read_text())


@pytest.mark.parametrize(
    "repository", ["VilnaCRM-Org/bootstrap-infrastructure", "fork/repo"]
)
def test_all_prs_select_unprivileged_mode(repository, tmp_path):
    mode = workflow("pulumi-pr-guardrails.yml")["jobs"]["preview_mode"]["steps"][0][
        "run"
    ]
    output = tmp_path / "output"
    subprocess.run(
        ["bash", "-eu", "-c", mode],
        check=True,
        env={
            "GITHUB_EVENT_NAME": "pull_request",
            "GITHUB_HEAD_REPOSITORY": repository,
            "GITHUB_REPOSITORY_NAME": "VilnaCRM-Org/bootstrap-infrastructure",
            "GITHUB_OUTPUT": str(output),
        },
    )
    assert output.read_text() == "privileged=false\n"


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
    assert jobs["admission"]["permissions"]["statuses"] == "write"
    assert "--publish-pending" in jobs["admission"]["steps"][1]["run"]
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
        "statuses": "write",
    }
    assert publisher["steps"][0]["with"]["ref"] == "${{ github.sha }}"
    result = publisher["steps"][1]
    for job in ("preview", "destructive_diff", "iam_validation"):
        assert f"needs.{job}.result == 'success'" in result["env"]["GUARDRAIL_RESULT"]
    assert "--publish-result" in result["run"]
    assert all("make " not in step.get("run", "") for step in publisher["steps"])
    legacy = workflow("pulumi-pr-guardrails.yml")
    assert all(
        job["name"] not in {"Preview", "Destructive Diff Gate", "IAM Validation"}
        for job in legacy["jobs"].values()
    )
