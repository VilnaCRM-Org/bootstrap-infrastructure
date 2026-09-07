"""Central reporter retains trusted main source and minimal App authority."""

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


def workflow():
    return yaml.safe_load(
        (ROOT / ".github/workflows/governance-promotion.yml").read_text()
    )


def test_immutable_trusted_scope_context():
    value = workflow()
    trigger = value["on"] if "on" in value else value[True]
    assert trigger == {
        "pull_request_target": {
            "branches": ["main"],
            "types": ["opened", "synchronize", "reopened", "edited"],
        }
    }
    assert value["concurrency"] == {
        "group": "promotion-status-${{ github.event.pull_request.number }}",
        "cancel-in-progress": False,
    }
    job = value["jobs"]["scope"]
    assert job["environment"] == "governance-evidence"
    checkout = job["steps"][0]
    assert checkout["with"] == {
        "ref": "${{ github.sha }}",
        "persist-credentials": False,
    }
    assert (
        checkout["uses"] == "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5"
    )


def test_scoped_app_status_only_and_isolated_python():
    value = workflow()
    assert value["permissions"] == {
        "actions": "read",
        "contents": "read",
        "pull-requests": "read",
    }
    steps = value["jobs"]["scope"]["steps"]
    verify, token, report = steps[1:]
    assert (
        verify["run"]
        == "python3 -I scripts/deployment_promotion_scope.py verify-environment"
    )
    assert verify["env"] == {"GH_TOKEN": "${{ github.token }}"}
    assert (
        token["uses"]
        == "actions/create-github-app-token@fee1f7d63c2ff003460e3d139729b119787bc349"
    )
    assert token["with"] == {
        "app-id": 4840884,
        "owner": "VilnaCRM-Org",
        "repositories": "bootstrap-infrastructure",
        "private-key": "${{ secrets.GOVERNANCE_PROMOTION_APP_PRIVATE_KEY }}",
        "permission-statuses": "write",
        "permission-deployments": "read",
        "permission-actions": "read",
        "permission-contents": "read",
        "permission-pull-requests": "read",
    }
    assert report["run"] == "python3 -I scripts/deployment_promotion_scope.py scope"
    assert report["env"] == {"GH_TOKEN": "${{ steps.promotion_app.outputs.token }}"}
    assert all("governance_promotion.py" not in step.get("run", "") for step in steps)
