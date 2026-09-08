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


def test_feedback_cannot_authorize_aws():
    """Only admitted selected root calls can schedule credentialed workers."""
    jobs = workflow("pulumi-pr-command-runner.yml")["jobs"]
    preflight = jobs["preflight"]
    for field in ("head_sha", "pull_request_number", "command", "target_environment"):
        assert preflight["outputs"][field] == f"${{{{ steps.accept.outputs.{field} }}}}"
    for field in ("head_sha", "pull_request_number", "display_command"):
        assert (
            preflight["outputs"][f"feedback_{field}"]
            == f"${{{{ steps.accept.outputs.feedback_{field} }}}}"
        )
    assert "continue-on-error" not in json.dumps(preflight)
    credential_jobs = {
        name: job
        for name, job in jobs.items()
        if job.get("permissions", {}).get("id-token") == "write"
    }
    assert set(credential_jobs) == {
        f"{scope}_{account}"
        for scope in ("operator", "governance", "platform")
        for account in ("test", "prod")
    }
    for name, job in credential_jobs.items():
        assert "preflight" in job["needs"]
        assert "feedback_" not in json.dumps(job)
        assert "needs.preflight.result == 'success'" in job["if"]
        assert "needs.preflight.outputs.execution_ready == 'true'" in job["if"]
        scope = name.split("_")[0]
        assert f"needs.preflight.outputs.{scope}_selected == 'true'" in job["if"]
        assert job["uses"] == f"./.github/workflows/pulumi-{scope}-account.yml"


def test_results_require_bound_feedback():
    """No raw dispatch PR/head can become a status or comment target."""
    comment = workflow("pulumi-pr-command-runner.yml")["jobs"]["comment_result"]
    assert "always()" in comment["if"]
    assert "needs.preflight.outputs.feedback_pull_request_number != ''" in comment["if"]
    step = comment["steps"][0]
    assert (
        step["env"]["PR_NUMBER"]
        == "${{ needs.preflight.outputs.feedback_pull_request_number }}"
    )
    assert step["env"]["HEAD_SHA"] == "${{ needs.preflight.outputs.feedback_head_sha }}"
    assert "client_payload" not in json.dumps(comment)
    assert 'outputs.published == "true"' in step["run"]
    assert "/statuses/" not in step["run"]


def test_retired_route_cannot_post_success(tmp_path):
    """Old dispatch fails without posting status, feedback or credentials."""
    document = workflow("pulumi-governance.yml")
    assert document["permissions"] == {}
    assert set(document["jobs"]) == {"retired"}
    job = document["jobs"]["retired"]
    assert job["permissions"] == {}
    assert len(job["steps"]) == 1
    script = "gh() { echo forbidden-gh-call; };\n" + job["steps"][0]["run"]
    result = subprocess.run(
        ["bash", "-euo", "pipefail", "-c", script],
        env={"PATH": "/usr/bin:/bin"},
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "forbidden-gh-call" not in result.stdout
    assert "state=success" not in result.stdout
    assert "uses" not in job["steps"][0]


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
