"""Authenticated rejection feedback cannot satisfy privileged execution guards."""

import json
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]


def workflow(name):
    """Read an exact local workflow for offline boundary checks."""
    return yaml.safe_load((ROOT / ".github/workflows" / name).read_text())


@pytest.mark.parametrize(
    "name", ["pulumi-governance.yml", "pulumi-pr-command-runner.yml"]
)
def test_feedback_cannot_authorize_aws(name):
    """AWS jobs depend on successful preflight and never consume feedback fields."""
    jobs = workflow(name)["jobs"]
    preflight = jobs["preflight"]
    for field in ("head_sha", "pull_request_number", "command", "target_environment"):
        assert (
            preflight["outputs"][field] == f"${{{{ steps.resolve.outputs.{field} }}}}"
        )
        assert preflight["outputs"][f"feedback_{field}"] == (
            f"${{{{ steps.resolve.outputs.feedback_{field} }}}}"
        )
    assert "continue-on-error" not in json.dumps(preflight)
    for job in jobs.values():
        if job.get("permissions", {}).get("id-token") == "write":
            assert "preflight" in job["needs"]
            assert "feedback_" not in json.dumps(job)
            guard = job.get("if", "")
            if "always()" in guard:
                assert guard.startswith(
                    "always() && needs.preflight.result == 'success' &&"
                )


def test_results_require_bound_feedback():
    """No raw dispatch PR/head can become a status or comment target."""
    governance = workflow("pulumi-governance.yml")["jobs"]["governance_status"]
    assert governance["if"] == "always()"
    assert governance["steps"][0]["if"] == (
        "needs.preflight.outputs.feedback_head_sha != ''"
    )
    assert governance["steps"][1]["if"] == (
        "always() && needs.preflight.outputs.feedback_pull_request_number != ''"
    )
    for key, field in (("HEAD_SHA", "head_sha"), ("PR_NUMBER", "pull_request_number")):
        assert governance["env"][key] == (
            f"${{{{ needs.preflight.outputs.{field} || "
            f"needs.preflight.outputs.feedback_{field} }}}}"
        )
    platform = workflow("pulumi-pr-command-runner.yml")["jobs"]["comment_result"]
    assert platform["if"] == "always()"
    assert "outputs.feedback_pull_request_number" in json.dumps(platform)
    assert "outputs.feedback_head_sha" in json.dumps(platform)
    assert "client_payload" not in json.dumps((governance, platform))


def test_rejected_status_is_terminal(tmp_path):
    """Execute the real status shell body with a function double for every gh call."""
    job = workflow("pulumi-governance.yml")["jobs"]["governance_status"]
    script = 'gh() { printf "%s\\n" "$@"; };\n' + job["steps"][0]["run"]
    result = subprocess.run(
        ["bash", "-euo", "pipefail", "-c", script],
        env={
            "PATH": "/usr/bin:/bin",
            "GITHUB_REPOSITORY": "org/repo",
            "HEAD_SHA": "a" * 40,
            "REQUEST_COMMAND": "up",
            "REQUEST_TARGET_ENVIRONMENT": "test",
            "TEST_PLAN_RESULT": "skipped",
            "TEST_APPLY_RESULT": "skipped",
            "PROD_PLAN_RESULT": "skipped",
            "PROD_APPLY_RESULT": "skipped",
            "RUN_URL": "https://github.com/org/repo/actions/runs/100",
        },
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
    )
    assert f"repos/org/repo/statuses/{'a' * 40}" in result.stdout
    assert "state=failure" in result.stdout
    assert "context=Governance Apply" in result.stdout
    assert "state=success" not in result.stdout
    assert "state=pending" not in result.stdout


@pytest.mark.parametrize(
    "event,ref,head,code,privileged",
    [
        ("workflow_dispatch", "refs/heads/main", "org/repo", 0, "true"),
        ("workflow_dispatch", "refs/heads/feature", "org/repo", 1, None),
        ("workflow_dispatch", "refs/tags/main", "org/repo", 1, None),
        ("pull_request", "refs/pull/1/merge", "org/repo", 0, "true"),
        ("pull_request", "refs/pull/1/merge", "fork/repo", 0, "false"),
        ("schedule", "refs/heads/main", "org/repo", 0, "true"),
    ],
)
def test_manual_evidence_requires_main(tmp_path, event, ref, head, code, privileged):
    """Non-main manual dispatch fails in the credential-free mode job."""
    jobs = workflow("well-architected-evidence.yml")["jobs"]
    mode = jobs["evidence_mode"]
    assert mode["env"]["GITHUB_REF"] == "${{ github.ref }}"
    assert "permissions" not in mode
    assert jobs["test_account_evidence"]["needs"] == ["evidence_mode"]
    output = tmp_path / "output"
    result = subprocess.run(
        ["bash", "-euo", "pipefail", "-c", mode["steps"][0]["run"]],
        env={
            "PATH": "/usr/bin:/bin",
            "GITHUB_EVENT_NAME": event,
            "GITHUB_REF": ref,
            "GITHUB_HEAD_REPOSITORY": head,
            "GITHUB_REPOSITORY_NAME": "org/repo",
            "GITHUB_OUTPUT": str(output),
        },
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == code
    if privileged is None:
        assert not output.exists()
        assert "must run from main" in result.stdout
    else:
        assert output.read_text() == f"privileged={privileged}\n"
