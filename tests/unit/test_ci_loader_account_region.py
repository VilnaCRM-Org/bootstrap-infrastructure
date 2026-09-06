"""Execute the actual isolated loader with account/region failure fixtures."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
ACTION = ROOT / ".github/actions/load-aws-ci-env/action.yml"
ACCOUNT = "123456789012"
REGION = "eu-central-1"


def action_steps():
    return yaml.safe_load(ACTION.read_text())["runs"]["steps"]


def load(tmp_path, payload, required="AWS_APPLY_ROLE_ARN"):
    tools = tmp_path / "tools"
    tools.mkdir()
    fixture = tmp_path / "payload.json"
    fixture.write_text(json.dumps(payload))
    aws = tools / "aws"
    aws.write_text('#!/bin/sh\ncat "$FIXTURE_PAYLOAD"\n')
    aws.chmod(0o700)
    marker = tmp_path / "hostile-import"
    for filename in ("json.py", "re.py", "sitecustomize.py"):
        (tmp_path / filename).write_text(
            f"open({str(marker)!r}, 'w').write('unsafe')\n"
        )
    env = {
        "PATH": f"{tools}:{os.environ['PATH']}",
        "PYTHONPATH": str(tmp_path),
        "RUNNER_TEMP": str(tmp_path),
        "FIXTURE_PAYLOAD": str(fixture),
        "CI_CONFIG_SECRET_ID": "/example/ci/test",
        "CI_CONFIG_ACCOUNT_ID": ACCOUNT,
        "CI_CONFIG_EXPECTED_REGION": REGION,
        "REQUIRED_KEYS": required,
        "GITHUB_ENV": str(tmp_path / "github-env"),
        "GITHUB_OUTPUT": str(tmp_path / "github-output"),
    }
    step = next(s for s in action_steps() if s.get("id") == "load")
    result = subprocess.run(
        ["bash", "-c", step["run"]],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert not marker.exists()
    assert not list(tmp_path.glob("ci-config.*"))
    return result, env


def payload():
    return {
        "AWS_ACCOUNT_ID": ACCOUNT,
        "AWS_REGION": REGION,
        "AWS_APPLY_ROLE_ARN": f"arn:aws:iam::{ACCOUNT}:role/Apply",
    }


def test_account_and_region_export_even_when_caller_omits_both(tmp_path):
    result, env = load(tmp_path, payload())
    assert result.returncode == 0, result.stderr
    exports = dict(
        line.split("=", 1)
        for line in (tmp_path / "github-env").read_text().splitlines()
    )
    assert exports["AWS_ACCOUNT_ID"] == ACCOUNT and exports["AWS_REGION"] == REGION
    collect = next(s for s in action_steps() if s.get("id") == "collect")
    result = subprocess.run(
        ["bash", "-c", collect["run"]],
        cwd=tmp_path,
        env={**env, **exports},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    output = (tmp_path / "github-output").read_text()
    assert "aws-account-id=" + ACCOUNT in output and "aws-region=" + REGION in output


@pytest.mark.parametrize("field", ["AWS_ACCOUNT_ID", "AWS_REGION"])
@pytest.mark.parametrize(
    "value",
    [None, "", False, [], "DO_NOT_LOG_UNTRUSTED_VALUE", "us-east-1", "999999999999"],
)
def test_missing_or_mismatched_identity_never_exports(tmp_path, field, value):
    candidate = payload()
    if value is None:
        del candidate[field]
    else:
        candidate[field] = value
    result, _ = load(tmp_path, candidate)
    assert result.returncode != 0
    assert not (tmp_path / "github-env").exists()
    assert not (tmp_path / "github-output").exists()
    assert "DO_NOT_LOG_UNTRUSTED_VALUE" not in result.stdout + result.stderr


def test_expected_region_is_wired_from_validated_target():
    step = next(s for s in action_steps() if s.get("id") == "load")
    assert (
        step["env"]["CI_CONFIG_EXPECTED_REGION"]
        == "${{ steps.aws-target.outputs.aws_region }}"
    )
    assert "python3 -I" in step["run"]
