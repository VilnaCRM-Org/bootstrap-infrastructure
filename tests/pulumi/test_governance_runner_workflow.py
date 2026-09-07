"""The retired event cannot reach AWS, publisher credentials, or PR code."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = yaml.safe_load(
    (ROOT / ".github/workflows/pulumi-governance.yml").read_text()
)


def test_only_legacy_event_reaches_static_rejection():
    assert WORKFLOW.get("on", WORKFLOW.get(True)) == {
        "repository_dispatch": {"types": ["pulumi-governance-command"]}
    }
    assert WORKFLOW["permissions"] == {}
    assert set(WORKFLOW["jobs"]) == {"retired"}
    job = WORKFLOW["jobs"]["retired"]
    assert job["permissions"] == {}
    assert job["timeout-minutes"] == 1
    assert len(job["steps"]) == 1
    assert job["steps"][0]["shell"] == "bash"


def test_retired_event_has_no_credential_or_execution_route():
    job = WORKFLOW["jobs"]["retired"]
    assert set(job) == {"name", "runs-on", "timeout-minutes", "permissions", "steps"}
    step = job["steps"][0]
    assert set(step) == {"name", "shell", "run"}
    script = step["run"]
    assert "${{" not in script
    assert "client_payload" not in script
    assert script.splitlines()[-1] == "exit 1"
    assert all(
        line.startswith("echo ") or line == "exit 1" for line in script.splitlines()
    )
    for fragment in (
        "id-token",
        "configure-aws-credentials",
        "create-github-app-token",
        "secrets.",
        "github.token",
        "environment:",
        "workflow_call",
        "workflow_dispatch",
    ):
        assert fragment not in yaml.safe_dump(WORKFLOW)


@pytest.mark.parametrize(
    "payload",
    [
        {"command": "up", "target_environment": "prod", "head_sha": "a" * 40},
        {
            "command": "$(touch injected)",
            "target_environment": "prod",
            "role_arn": "admin",
        },
        {"scope": "operator", "approved": True, "skip_preflight": True},
        {"source_run_id": "1", "comment_id": "9", "pulumi_command": "up"},
    ],
)
def test_malicious_legacy_dispatch_fails_without_running_payload(tmp_path, payload):
    event = tmp_path / "event.json"
    event.write_text(json.dumps({"client_payload": payload}))
    script = WORKFLOW["jobs"]["retired"]["steps"][0]["run"]
    result = subprocess.run(
        ["bash", "-euo", "pipefail", "-c", script],
        cwd=tmp_path,
        env={"PATH": os.defpath, "GITHUB_EVENT_PATH": str(event)},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1
    assert "retired" in result.stderr
    assert result.stdout == ""
    assert {path.name for path in tmp_path.iterdir()} == {"event.json"}
