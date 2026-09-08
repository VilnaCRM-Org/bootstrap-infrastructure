"""Exercise the single central intake protocol without network or credentials."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = yaml.safe_load(
    (ROOT / ".github/workflows/pulumi-pr-commands.yml").read_text()
)
STEPS = WORKFLOW["jobs"]["dispatch"]["steps"]
FIELDS = {
    "pull_request_number",
    "head_sha",
    "comment_id",
    "source_run_id",
    "command",
    "target_environment",
}


def step(name):
    return next(row for row in STEPS if row.get("name") == name)


def run_step(name, *, cwd, environment):
    return subprocess.run(
        ["bash", "-euo", "pipefail", "-c", step(name)["run"]],
        cwd=cwd,
        env={
            "PATH": str(Path(sys.executable).parent) + os.pathsep + os.defpath,
            **environment,
        },
        capture_output=True,
        text=True,
        check=True,
    )


def test_created_pr_comments_use_trusted_intake_without_scope_routing():
    assert WORKFLOW.get("on", WORKFLOW.get(True)) == {
        "issue_comment": {"types": ["created"]}
    }
    job = WORKFLOW["jobs"]["dispatch"]
    assert "github.event.issue.pull_request != null" in job["if"]
    assert "github.event.issue.state == 'open'" in job["if"]
    checkout = next(
        row for row in STEPS if row.get("uses", "").startswith("actions/checkout@")
    )
    assert checkout["with"] == {
        "ref": "${{ github.sha }}",
        "persist-credentials": False,
    }
    text = yaml.safe_dump(WORKFLOW)
    for forbidden in (
        "governance_touched",
        "governance_paths.py",
        "pulumi-governance-command",
        "id-token",
        "configure-aws-credentials",
    ):
        assert forbidden not in text


def test_every_eligible_command_has_one_six_field_root_dispatch():
    dispatches = [row for row in STEPS if "/dispatches" in row.get("run", "")]
    assert dispatches == [step("Dispatch trusted runner")]
    dispatch = dispatches[0]
    assert "event_type='pulumi-pr-command'" in dispatch["run"]
    assert set(re.findall(r"client_payload\[([a-z_]+)\]", dispatch["run"])) == FIELDS
    assert set(part.strip() for part in dispatch["if"].split("&&")) == {
        "steps.parse.outputs.skip != 'true'",
        "steps.parse.outputs.authorized == 'true'",
        "steps.pr.outputs.state == 'open'",
        "steps.pr.outputs.merged == 'false'",
        "steps.pr.outputs.head_repo == github.repository",
    }


def test_request_artifact_precedes_dispatch_with_identical_eligibility():
    record, upload, dispatch = (
        step(name)
        for name in (
            "Record immutable command request",
            "Upload immutable command request",
            "Dispatch trusted runner",
        )
    )
    assert STEPS.index(record) < STEPS.index(upload) < STEPS.index(dispatch)
    assert record["if"] == upload["if"] == dispatch["if"]
    assert upload["with"] == {
        "name": "pulumi-command-request",
        "path": ".artifacts/pulumi-command-request/request.json",
        "if-no-files-found": "error",
        "retention-days": 1,
    }
    assert record["env"]["HEAD_SHA"] == "${{ steps.pr.outputs.head_sha }}"


@pytest.mark.parametrize("target", ["test", "prod"])
@pytest.mark.parametrize("command", ["plan", "up"])
def test_real_shell_records_and_dispatches_same_immutable_request(
    tmp_path, target, command
):
    event = tmp_path / "event.json"
    event.write_text(json.dumps({"issue": {"number": 217}, "comment": {"id": 9}}))
    expected = {
        "pull_request_number": "217",
        "head_sha": "a" * 40,
        "comment_id": "9",
        "source_run_id": "100",
        "command": command,
        "target_environment": target,
    }
    environment = {
        "GITHUB_EVENT_PATH": str(event),
        "GITHUB_REPOSITORY": "VilnaCRM-Org/bootstrap-infrastructure",
        "GITHUB_RUN_ID": "100",
        "PR_NUMBER": "217",
        "COMMENT_ID": "9",
        "HEAD_SHA": expected["head_sha"],
        "PULUMI_COMMAND": command,
        "TARGET_ENVIRONMENT": target,
    }
    run_step("Record immutable command request", cwd=tmp_path, environment=environment)
    artifact = tmp_path / ".artifacts/pulumi-command-request/request.json"
    assert json.loads(artifact.read_text()) == expected
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    capture = tmp_path / "arguments.json"
    shim = fake_bin / "gh"
    shim.write_text(
        f"#!{sys.executable}\nimport json,os,sys\n"
        "with open(os.environ['CAPTURE'], 'w') as handle: "
        "json.dump(sys.argv[1:], handle)\n"
    )
    shim.chmod(0o755)
    run_step(
        "Dispatch trusted runner",
        cwd=tmp_path,
        environment={
            **environment,
            "PATH": str(fake_bin) + os.pathsep + os.defpath,
            "CAPTURE": str(capture),
        },
    )
    arguments = json.loads(capture.read_text())
    assert "event_type=pulumi-pr-command" in arguments
    assert arguments.count("--method") == 1 and "POST" in arguments
    actual = dict(
        (argument.split("[", 1)[1].split("]", 1)[0], argument.split("=", 1)[1])
        for argument in arguments
        if argument.startswith("client_payload[")
    )
    assert actual == expected


@pytest.mark.parametrize("target", ["test", "prod"])
@pytest.mark.parametrize(
    "login,association,command,authorized",
    [
        ("Writer", "MEMBER", "up", "true"),
        ("Kravalg", "OWNER", "up", "false"),
        ("kRaVaLg", "OWNER", "up", "false"),
        ("Kravalg", "OWNER", "plan", "true"),
        ("Outsider", "NONE", "up", "false"),
    ],
)
def test_actual_parser_preserves_apply_approver_separation(
    tmp_path, target, login, association, command, authorized
):
    result = run_step(
        "Parse Pulumi command",
        cwd=ROOT,
        environment={
            "COMMENT_BODY": f"/pulumi {target} {command}",
            "COMMENT_ASSOCIATION": association,
            "COMMENT_LOGIN": login,
            "GITHUB_OUTPUT": str(tmp_path / "outputs"),
        },
    )
    outputs = dict(line.split("=", 1) for line in result.stdout.splitlines())
    assert outputs["authorized"] == authorized
    assert outputs["target_environment"] == target and outputs["command"] == command
    assert "python3 -I" in step("Parse Pulumi command")["run"]


def test_hostile_comment_remains_parser_data_and_cannot_execute(tmp_path):
    marker = tmp_path / "injected"
    result = run_step(
        "Parse Pulumi command",
        cwd=ROOT,
        environment={
            "COMMENT_BODY": f"/pulumi test up; touch {marker}",
            "COMMENT_ASSOCIATION": "OWNER",
            "COMMENT_LOGIN": "Writer",
        },
    )
    assert "skip=true" in result.stdout
    assert not marker.exists()
