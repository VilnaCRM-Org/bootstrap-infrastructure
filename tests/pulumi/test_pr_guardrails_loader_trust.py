"""Check the installed loader pin and local candidate isolation beside hostile code."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
PIN = (
    "VilnaCRM-Org/bootstrap-infrastructure/.github/actions/load-aws-ci-env"
    "@d1297f1f00658c351dd6b94e510b394835b13ede"
)
LOCAL_CANDIDATE_CLOSURE = {
    ".github/actions/load-aws-ci-env/action.yml": (
        "0a56fbd02fc6c06dbf88b1821abf9db5272a19311b0baf0fd03852587e491644"
    ),
    "scripts/validate_ci_environment.py": (
        "598cce5370e9132c935c919f1b256debaa19744af988e7a61e1bd24e0ddc2d93"
    ),
}


@pytest.mark.parametrize("job_id", ["preview", "iam_validation"])
def test_guardrails_loader_is_reviewed_and_keeps_pr_role_contract(job_id: str) -> None:
    """A PR checkout cannot supply the selected composite or validator closure."""
    jobs = yaml.safe_load(
        (ROOT / ".github/workflows/pulumi-pr-guardrails.yml").read_text()
    )["jobs"]
    job = jobs[job_id]
    loader = next(step for step in job["steps"] if step.get("id") == "ci_config")
    assert loader["uses"] == PIN
    assert loader["with"]["expected-account-id"] == "${{ vars.AWS_TEST_ACCOUNT_ID }}"
    assert loader["with"]["config-role-arn"] == (
        "${{ steps.ci_config_target.outputs.config-role-arn }}"
    )
    target = next(step for step in job["steps"] if step.get("id") == "ci_config_target")
    assert 'ci_environment="test-pr"' in target["run"]
    assert 'config_role_arn="${AWS_TEST_PR_CI_CONFIG_ROLE_ARN}"' in target["run"]
    # This is deliberately still a bounded PR preview, not a trusted apply job.
    assert job["permissions"] == {"contents": "read", "id-token": "write"}
    assert "environment" not in job
    assert jobs["preview_unprivileged"]["permissions"] == {"contents": "read"}
    assert jobs["iam_validation_unprivileged"]["permissions"] == {"contents": "read"}


def test_local_candidate_loader_rejects_composite_and_validator_substitution(
    tmp_path: Path,
) -> None:
    """Exercise the local candidate; the installed PIN above is a separate contract."""
    remote = tmp_path / "reviewed-action-checkout"
    for relative, digest in LOCAL_CANDIDATE_CLOSURE.items():
        data = (ROOT / relative).read_bytes()
        assert hashlib.sha256(data).hexdigest() == digest
        destination = remote / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
    checkout = tmp_path / "hostile-pr-checkout"
    local_action = checkout / ".github/actions/load-aws-ci-env/action.yml"
    local_action.parent.mkdir(parents=True)
    marker = tmp_path / "pr-code-executed"
    malicious = (
        "import os\n"
        f"open({str(marker)!r}, 'w').write(os.environ['AWS_SESSION_TOKEN'])\n"
    )
    (checkout / "scripts").mkdir()
    (checkout / "scripts/validate_ci_environment.py").write_text(malicious)
    for filename in ("json.py", "re.py", "sitecustomize.py", "usercustomize.py"):
        (checkout / filename).write_text(
            malicious + "raise RuntimeError('PR import')\n"
        )
    local_action.write_text(
        yaml.safe_dump(
            {
                "runs": {
                    "steps": [
                        {
                            "run": "python3 -I scripts/validate_ci_environment.py",
                        }
                    ]
                }
            }
        )
    )
    tools = tmp_path / "tools"
    tools.mkdir()
    payload = json.dumps(
        {"AWS_ACCOUNT_ID": "123456789012", "AWS_REGION": "eu-central-1"}
    )
    aws = tools / "aws"
    aws.write_text(f"#!/bin/sh\nprintf '%s\\n' '{payload}'\n")
    aws.chmod(0o700)
    env = {
        "PATH": f"{tools}:{os.environ['PATH']}",
        "PYTHONPATH": str(checkout),
        "RUNNER_TEMP": str(tmp_path),
        "CI_CONFIG_SECRET_ID": "/example/ci/test-pr",
        "CI_CONFIG_ACCOUNT_ID": "123456789012",
        "CI_CONFIG_EXPECTED_REGION": "eu-central-1",
        "CI_CONFIG_PURPOSE": "offline pinned loader regression",
        "CI_CONFIG_ACTION_PATH": str(remote / ".github/actions/load-aws-ci-env"),
        "REQUIRED_KEYS": "AWS_ACCOUNT_ID,AWS_REGION",
        "AWS_ACCOUNT_ID": "123456789012",
        "AWS_REGION": "eu-central-1",
        "AWS_SESSION_TOKEN": "offline-not-an-aws-credential",
        "GITHUB_ENV": str(tmp_path / "github-env"),
        "GITHUB_OUTPUT": str(tmp_path / "github-output"),
    }
    old_step = yaml.safe_load(local_action.read_text())["runs"]["steps"][0]
    result = subprocess.run(
        ["bash", "-c", old_step["run"]],
        cwd=checkout,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert marker.read_text() == "offline-not-an-aws-credential"
    marker.unlink()
    steps = yaml.safe_load(
        (remote / ".github/actions/load-aws-ci-env/action.yml").read_text()
    )["runs"]["steps"]
    selected = [
        step
        for step in steps
        if step.get("id") == "load"
        or step.get("name") == "Validate AWS Secrets Manager CI environment"
    ]
    assert len(selected) == 2
    for step in selected:
        result = subprocess.run(
            ["bash", "-c", step["run"]],
            cwd=checkout,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        assert not marker.exists()
        assert env["AWS_SESSION_TOKEN"] not in result.stdout + result.stderr
    assert "AWS_ACCOUNT_ID=123456789012" in (tmp_path / "github-env").read_text()
    assert not list(tmp_path.glob("ci-config.*"))
