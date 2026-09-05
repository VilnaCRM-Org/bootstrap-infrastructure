"""Execute the credential loader's account gate before any AWS action runs."""

import os
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
ACTION = ROOT / ".github/actions/load-aws-ci-env/action.yml"


@pytest.mark.parametrize(
    ("expected_account", "role_account", "succeeds"),
    [
        ("891377212104", "891377212104", True),
        ("933245420672", "933245420672", True),
        ("891377212104", "933245420672", False),
        ("933245420672", "891377212104", False),
        ("", "891377212104", False),
        ("123", "891377212104", False),
        ("0000000000000", "891377212104", False),
        ("89137721210x", "891377212104", False),
    ],
)
def test_account_identity_is_independent_of_role_arn(
    tmp_path, expected_account, role_account, succeeds
):
    """A plausible but wrong-account role must fail before credential issuance."""
    action = yaml.safe_load(ACTION.read_text())
    script = action["runs"]["steps"][0]["run"]
    output = tmp_path / "output"
    result = subprocess.run(
        ["bash", "-c", script],
        check=False,
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "CI_CONFIG_ENVIRONMENT": "test",
            "CI_CONFIG_ROLE_ARN": f"arn:aws:iam::{role_account}:role/config-reader",
            "CI_CONFIG_EXPECTED_ACCOUNT_ID": expected_account,
            "CI_CONFIG_AWS_REGION": "eu-central-1",
            "GITHUB_REPOSITORY": "VilnaCRM-Org/bootstrap-infrastructure",
            "GITHUB_OUTPUT": str(output),
        },
    )
    assert (result.returncode == 0) is succeeds
    if succeeds:
        assert f"config_account_id={expected_account}\n" in output.read_text()
    else:
        assert not output.exists()
        assert "account" in result.stderr.lower()
