"""Exercise reviewed workflow boundaries without GitHub or AWS credentials."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]


def workflow(name: str, *, service: bool = False) -> dict:
    """Load a workflow from the platform or governed service template."""
    base = ROOT / "pulumi/user-service-infrastructure" if service else ROOT
    return yaml.safe_load((base / ".github/workflows" / name).read_text())


@pytest.mark.parametrize(
    ("backend", "passed"),
    [
        ("s3://pulumi-bootstrap-infrastructure-test-state/governance", True),
        ("s3://reviewed-operator-state/governance", True),
        ("", False),
        ("file:///tmp/governance", False),
        ("s3://operator-state", False),
        ("s3://operator-state/state/test", False),
        ("s3://operator-state/governance/", False),
        ("s3://operator-state/governance?prefix=other", False),
        ("s3://operator-state/governance\n", False),
    ],
)
def test_backend_preflight(backend: str, passed: bool, tmp_path: Path) -> None:
    """All credential jobs reject configurations that could skip real drift."""
    (tmp_path / ".trusted").symlink_to(ROOT, target_is_directory=True)
    jobs = workflow("pulumi-governance-account.yml")["jobs"]
    guard_name = (
        "Validate fixed governance backend and requested account before credentials"
    )
    guarded = 0
    for job in jobs.values():
        if job.get("permissions", {}).get("id-token") != "write":
            continue
        guarded += 1
        steps = job["steps"]
        guard_index = next(
            i for i, step in enumerate(steps) if step.get("name") == guard_name
        )
        credential_index = next(
            i
            for i, step in enumerate(steps)
            if step.get("uses", "").startswith("aws-actions/configure-aws-credentials@")
        )
        assert guard_index < credential_index
        result = subprocess.run(
            ["bash", "-e", "-o", "pipefail", "-c", steps[guard_index]["run"]],
            env={
                "PATH": os.environ["PATH"],
                "PULUMI_BACKEND_URL": backend,
                "GITHUB_WORKSPACE": str(tmp_path),
                "PULUMI_DIR": "pulumi/governance",
                "ACCOUNT": "test",
                "PULUMI_STACK": "test",
                "PULUMI_PREVIEW_STACKS": "test",
                "PULUMI_DRIFT_STACKS": "test",
                "AWS_ACCOUNT_ID": "111111111111",
                "AWS_REGION": "eu-central-1",
                "PULUMI_SECRETS_PROVIDER": "awskms://alias/governance?region=eu-central-1",
            },
            capture_output=True,
            check=False,
        )
        assert (result.returncode == 0) == passed
    assert guarded == 4


def test_advisory_evidence_executes_without_privileged_loader() -> None:
    """No PR-controlled local collector runs after a cloud credential request."""
    jobs = workflow("well-architected-evidence.yml")["jobs"]
    assert set(jobs) == {"evidence_data"}
    job = jobs["evidence_data"]
    assert job["permissions"] == {"contents": "read"}
    assert not any(step.get("id") == "ci_config" for step in job["steps"])
    assert not any(
        "configure-aws-credentials" in step.get("uses", "") for step in job["steps"]
    )
