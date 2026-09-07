"""Promotion scope reads repository kind only from trusted default-branch source."""

from pathlib import Path

import yaml


def test_scope_source_and_read_permissions():
    root = Path(__file__).resolve().parents[2]
    workflow = yaml.safe_load(
        (root / ".github/workflows/governance-promotion.yml").read_text()
    )
    assert workflow["permissions"] == {
        "actions": "read",
        "contents": "read",
        "pull-requests": "read",
    }
    job = workflow["jobs"]["scope"]
    assert job["environment"] == "governance-evidence"
    steps = job["steps"]
    assert steps[0]["with"] == {
        "ref": "${{ github.sha }}",
        "persist-credentials": False,
    }
    assert steps[1]["run"] == (
        "python3 -I scripts/deployment_promotion_scope.py verify-environment"
    )
    assert steps[-1]["run"] == "python3 -I scripts/deployment_promotion_scope.py scope"
    assert not any("path" in step.get("with", {}) for step in steps)
