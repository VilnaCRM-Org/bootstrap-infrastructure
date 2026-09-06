"""Exercise the new local loader closure without claiming its old remote pin changed."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest
import yaml
from infra.bootstrap_settings import BootstrapSettings
from infra.ci_config import _ci_secret_id

ROOT = Path(__file__).resolve().parents[2]
ACTION = ROOT / ".github/actions/load-aws-ci-env"


def steps():
    """Read this branch's action, independently of the old published pin."""
    return yaml.safe_load((ACTION / "action.yml").read_text())["runs"]["steps"]


def step(identifier):
    return next(
        row
        for row in steps()
        if row.get("id") == identifier
        or identifier == "validate"
        and row["name"] == "Validate AWS Secrets Manager CI environment"
    )


def environment(tmp_path):
    return {
        "PATH": os.environ["PATH"],
        "GITHUB_OUTPUT": str(tmp_path / "output"),
        "GITHUB_ENV": str(tmp_path / "env"),
        "RUNNER_TEMP": str(tmp_path),
        "GITHUB_REPOSITORY": "example/example",
        "CI_CONFIG_ENVIRONMENT": "test-pr",
        "CI_CONFIG_ROLE_ARN": "arn:aws:iam::123456789012:role/ConfigRead",
        "CI_CONFIG_EXPECTED_ACCOUNT_ID": "123456789012",
        "CI_CONFIG_AWS_REGION": "eu-central-1",
        "CI_CONFIG_ACTION_PATH": str(ACTION),
        "CI_CONFIG_PURPOSE": "offline local closure validation",
        "CI_CONFIG_SECRET_ID": "/example/ci/test-pr",
        "CI_CONFIG_ACCOUNT_ID": "123456789012",
        "REQUIRED_KEYS": "AWS_ACCOUNT_ID,AWS_REGION",
        "AWS_ACCOUNT_ID": "123456789012",
        "AWS_REGION": "eu-central-1",
    }


def run_step(row, env, cwd):
    return subprocess.run(
        ["bash", "-c", row["run"]],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.mark.parametrize(
    "name",
    [
        "Service---Infrastructure",
        "service__infra",
        "service...infra",
        ".--Service___Infra--.",
        "a" * 63,
    ],
)
def test_target_secret_id_matches_actual_provisioning(tmp_path, name):
    expected = _ci_secret_id(object.__new__(BootstrapSettings), "test-pr", name)
    env = {**environment(tmp_path), "GITHUB_REPOSITORY": "example/" + name}
    result = run_step(step("aws-target"), env, tmp_path)
    assert result.returncode == 0, result.stderr
    assert f"secret_id={expected}\n" in (tmp_path / "output").read_text()


@pytest.mark.parametrize(
    "name",
    [
        "service.-infra",
        "service-.infra",
        "127.0.0.1",
        "999.999.999.999",
        "::1",
        "...",
        "a" * 64,
    ],
)
def test_target_rejects_names_provisioning_rejects(tmp_path, name):
    with pytest.raises(ValueError):
        _ci_secret_id(object.__new__(BootstrapSettings), "test-pr", name)
    result = run_step(
        step("aws-target"),
        {**environment(tmp_path), "GITHUB_REPOSITORY": "example/" + name},
        tmp_path,
    )
    assert result.returncode == 1
    assert not (tmp_path / "output").exists()


@pytest.mark.parametrize(
    "field,value",
    [
        ("CI_CONFIG_AWS_REGION", "cn-north-1"),
        ("CI_CONFIG_AWS_REGION", "us-gov-west-1"),
        ("CI_CONFIG_ROLE_ARN", "arn:aws-us-gov:iam::123456789012:role/ConfigRead"),
        ("CI_CONFIG_EXPECTED_ACCOUNT_ID", "١٢٣٤٥٦٧٨٩٠١٢"),
    ],
)
def test_target_rejects_unsupported_partition_inputs(tmp_path, field, value):
    result = run_step(
        step("aws-target"), {**environment(tmp_path), field: value}, tmp_path
    )
    assert result.returncode == 1
    assert not (tmp_path / "output").exists()


@pytest.mark.parametrize("delimiter", [",", "\n", "\r\n", ",\n"])
def test_loader_and_validator_agree_on_required_key_delimiters(tmp_path, delimiter):
    payload = {
        "AWS_ACCOUNT_ID": "123456789012",
        "AWS_REGION": "eu-central-1",
        "PULUMI_BACKEND_URL": "s3://example/state/test",
        "PULUMI_SECRETS_PROVIDER": "awskms://alias/example?region=eu-central-1",
    }
    tools = tmp_path / "tools"
    tools.mkdir()
    aws = tools / "aws"
    aws.write_text("#!/bin/sh\nprintf '%s\\n' '" + json.dumps(payload) + "'\n")
    aws.chmod(0o700)
    env = {
        **environment(tmp_path),
        "PATH": f"{tools}:{os.environ['PATH']}",
        "REQUIRED_KEYS": delimiter.join(payload),
    }
    loaded = run_step(step("load"), env, tmp_path)
    assert loaded.returncode == 0, loaded.stderr
    exported = dict(
        line.split("=", 1) for line in (tmp_path / "env").read_text().splitlines()
    )
    assert all(exported[key] == value for key, value in payload.items())
    validated = run_step(step("validate"), {**env, **exported}, tmp_path)
    assert validated.returncode == 0, validated.stderr
    assert not list(tmp_path.glob("ci-config.*"))


@pytest.mark.parametrize(
    "field,value",
    [
        ("PULUMI_BACKEND_URL", "s3://example/state/../test"),
        ("PULUMI_SECRETS_PROVIDER", "awskms://alias/example?region=us-east-1"),
        (
            "PULUMI_SECRETS_PROVIDER",
            "awskms://arn:aws:kms:eu-central-1:999999999999:key/existing?region=eu-central-1",
        ),
    ],
)
def test_action_relative_validator_rejects_bad_uris_before_success(
    tmp_path, field, value
):
    env = {**environment(tmp_path), "REQUIRED_KEYS": field, field: value}
    result = run_step(step("validate"), env, tmp_path)
    assert result.returncode == 1
    assert value not in result.stdout + result.stderr
    assert not (tmp_path / "env").exists()


def test_new_stdlib_import_keeps_interpreter_isolation(tmp_path):
    marker = tmp_path / "injected"
    (tmp_path / "ipaddress.py").write_text(
        f"open({str(marker)!r}, 'w').write('fixture')\n"
        "raise RuntimeError('hostile checkout')\n"
    )
    env = {**environment(tmp_path), "PYTHONPATH": str(tmp_path)}
    vulnerable = {
        **step("aws-target"),
        "run": step("aws-target")["run"].replace("python3 -I", "python3", 1),
    }
    result = run_step(vulnerable, env, tmp_path)
    assert result.returncode != 0 and marker.read_text() == "fixture"
    marker.unlink()
    result = run_step(step("aws-target"), env, tmp_path)
    assert result.returncode == 0, result.stderr
    assert not marker.exists()
    assert (
        'python3 -I "${CI_CONFIG_ACTION_PATH}/../../../scripts/'
        'validate_ci_environment.py"' in step("validate")["run"]
    )
