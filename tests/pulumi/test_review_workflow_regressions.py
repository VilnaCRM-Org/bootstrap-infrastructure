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
def test_backend_preflight(backend: str, passed: bool) -> None:
    """All credential jobs reject configurations that could skip real drift."""
    jobs = workflow("pulumi-governance.yml")["jobs"]
    guarded = 0
    for job in jobs.values():
        if job.get("permissions", {}).get("id-token") != "write":
            continue
        guarded += 1
        steps = job["steps"]
        guard_index = next(
            i
            for i, step in enumerate(steps)
            if step.get("name")
            == "Validate isolated governance backend before credentials"
        )
        credential_index = next(
            i
            for i, step in enumerate(steps)
            if step.get("uses", "").startswith("aws-actions/configure-aws-credentials@")
        )
        assert guard_index < credential_index
        result = subprocess.run(
            ["bash", "-c", steps[guard_index]["run"]],
            env={"PATH": os.environ["PATH"], "PULUMI_BACKEND_URL": backend},
            capture_output=True,
            check=False,
        )
        assert (result.returncode == 0) == passed
    assert guarded == 6


def test_evidence_loader_is_immutable() -> None:
    """Changing a PR's local composite action cannot change the loader invoked."""
    steps = workflow("well-architected-evidence.yml")["jobs"]["test_account_evidence"][
        "steps"
    ]
    loader = next(step for step in steps if step.get("id") == "ci_config")
    assert loader["uses"] == (
        "VilnaCRM-Org/bootstrap-infrastructure/.github/actions/load-aws-ci-env"
        "@a6496ad72285878db3c6b74b7a2b489249969e70"
    )
