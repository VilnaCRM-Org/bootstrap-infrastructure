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
    "credential",
    [
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
    ],
)
@pytest.mark.parametrize("exit_code", [0, 7])
def test_advisory_evidence_strips_credentials_and_propagates_failure(
    tmp_path, credential, exit_code
):
    """Execute the exact workflow shell with a local uv double, without network."""
    job = workflow("well-architected-evidence.yml")["jobs"]["evidence_data"]
    assert job["permissions"] == {"contents": "read"}
    step = next(
        item
        for item in job["steps"]
        if item.get("name") == "Validate selected committed evidence and receipt hashes"
    )
    executable = tmp_path / ".local/bin/uv"
    executable.parent.mkdir(parents=True)
    executable.write_text(
        '#!/bin/sh\n/usr/bin/env\nprintf "arg=%s\\n" "$@"\nexit '
        + str(exit_code)
        + "\n"
    )
    executable.chmod(0o700)
    result = subprocess.run(
        ["bash", "-euo", "pipefail", "-c", step["run"]],
        env={
            "PATH": "/usr/bin:/bin",
            "HOME": str(tmp_path),
            credential: "synthetic-never-forward",
            "GITHUB_REF": "refs/heads/untrusted",
        },
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == exit_code
    assert credential + "=" not in result.stdout
    assert "synthetic-never-forward" not in result.stdout
    assert "GITHUB_REF=" not in result.stdout
    assert "arg=--frozen" in result.stdout
    assert "arg=tests/unit/test_well_architected_evidence_data.py" in result.stdout
