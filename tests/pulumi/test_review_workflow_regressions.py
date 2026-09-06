"""Exercise reviewed workflow boundaries without GitHub or AWS credentials."""

from __future__ import annotations

import json
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


@pytest.mark.parametrize("count", [0, 1, 2])
def test_backfill_single_object(count: int) -> None:
    """Execute the actual jq validator against zero, one and multiple events."""
    job = workflow("operations-alert-backfill.yml")["jobs"]["backfill"]
    script = job["steps"][1]["run"]
    validator = script.split("jq -es '", 1)[1].split("' >", 1)[0]
    event = {
        "source": "aws.backup",
        "detailType": "Backup Job State Change",
        "state": "EXPIRED",
        "resourceArn": "arn:aws:s3:::example",
    }
    result = subprocess.run(
        ["jq", "-es", validator],
        input="\n".join([json.dumps(event)] * count),
        text=True,
        capture_output=True,
        check=False,
    )
    assert (result.returncode == 0) == (count == 1)
    if count == 1:
        assert json.loads(result.stdout) == event


def test_admin_jobs_require_main() -> None:
    """Privileged manual jobs remain in existing reviewer-gated environments."""
    cleanup = workflow("github-environment-legacy-cleanup.yml")["jobs"]["cleanup"]
    backfill = workflow("operations-alert-backfill.yml")["jobs"]["backfill"]
    assert cleanup["if"] == backfill["if"] == "github.ref == 'refs/heads/main'"
    assert cleanup["environment"] == "governance"
    assert backfill["environment"] == "operations-alert-reconcile"
    assert backfill["steps"][0]["with"]["ref"] == "${{ github.sha }}"


def test_evidence_loader_is_immutable() -> None:
    """Changing a PR's local composite action cannot change the loader invoked."""
    steps = workflow("well-architected-evidence.yml")["jobs"]["test_account_evidence"][
        "steps"
    ]
    loader = next(step for step in steps if step.get("id") == "ci_config")
    assert loader["uses"] == (
        "VilnaCRM-Org/bootstrap-infrastructure/.github/actions/load-aws-ci-env"
        "@d1297f1f00658c351dd6b94e510b394835b13ede"
    )


def test_template_gate_event_path() -> None:
    """Both deployment gates stage labels at the path consumed by Make."""
    jobs = workflow("self-deploy.yml", service=True)["jobs"]
    expected = ".artifacts/pulumi-preview/pull-request-event.json"
    stages = [
        step
        for job in jobs.values()
        for step in job.get("steps", [])
        if step.get("name") == "Stage pull request labels for destructive diff override"
    ]
    assert len(stages) == 2
    assert all(f"> {expected}" in step["run"] for step in stages)
    makefile = (ROOT / "pulumi/user-service-infrastructure/Makefile").read_text()
    assert f"--event-path {expected}" in makefile


def test_init_environment_permissions() -> None:
    """Environment verification receives API read scope without OIDC or writes."""
    preflight = workflow("initialize-stack.yml", service=True)["jobs"]["preflight"]
    assert preflight["permissions"] == {"contents": "read", "actions": "read"}
