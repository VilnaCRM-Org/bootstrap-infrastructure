"""Run credential-loader Python steps with a hostile checkout import path."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
ACTION_PATH = ROOT / ".github/actions/load-aws-ci-env"


@pytest.mark.parametrize("step_id", ["aws-target", "load", "validate"])
def test_loader_ignores_checkout_code(tmp_path: Path, step_id: str) -> None:
    """Neither current-directory modules nor PYTHONPATH hooks may execute."""
    steps = yaml.safe_load((ACTION_PATH / "action.yml").read_text())["runs"]["steps"]
    step = next(
        step
        for step in steps
        if step.get("id") == step_id
        or (
            step_id == "validate"
            and step.get("name") == "Validate AWS Secrets Manager CI environment"
        )
    )
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    marker = tmp_path / "injected-code-ran"
    malicious = (
        f"open({str(marker)!r}, 'w').write('injected')\n"
        "raise RuntimeError('untrusted import')\n"
    )
    for filename in ("json.py", "re.py", "sitecustomize.py", "usercustomize.py"):
        (checkout / filename).write_text(malicious)
    tools = tmp_path / "tools"
    tools.mkdir()
    aws = tools / "aws"
    # All AWS responses are fixed public metadata from a stub, never real credentials.
    payload = json.dumps(
        {"AWS_ACCOUNT_ID": "123456789012", "AWS_REGION": "eu-central-1"}
    )
    aws.write_text(f"#!/bin/sh\nprintf '%s\\n' '{payload}'\n")
    aws.chmod(0o700)
    env = {
        "PATH": f"{tools}:{os.environ['PATH']}",
        "PYTHONPATH": str(checkout),
        "RUNNER_TEMP": str(tmp_path),
        "CI_CONFIG_ENVIRONMENT": "test-pr",
        "CI_CONFIG_ROLE_ARN": "arn:aws:iam::123456789012:role/ConfigRead",
        "CI_CONFIG_EXPECTED_ACCOUNT_ID": "123456789012",
        "CI_CONFIG_AWS_REGION": "eu-central-1",
        "CI_CONFIG_SECRET_ID": "/example/ci/test-pr",
        "CI_CONFIG_ACCOUNT_ID": "123456789012",
        "CI_CONFIG_PURPOSE": "offline isolation regression",
        "CI_CONFIG_ACTION_PATH": str(ACTION_PATH),
        "REQUIRED_KEYS": "AWS_ACCOUNT_ID,AWS_REGION",
        "AWS_ACCOUNT_ID": "123456789012",
        "AWS_REGION": "eu-central-1",
        "GITHUB_REPOSITORY": "example/example",
        "GITHUB_ENV": str(tmp_path / "github-env"),
        "GITHUB_OUTPUT": str(tmp_path / "github-output"),
    }
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
    assert not list(tmp_path.glob("ci-config.*"))
