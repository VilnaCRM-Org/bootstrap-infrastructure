"""Offline rendering and stubbed AWS validation for the publisher stack."""

from __future__ import annotations

import hashlib
import importlib
import json
import runpy
import subprocess
import sys
from pathlib import Path

import pytest
from seed import poc_publisher_stack_verification as verification
from seed import poc_runtime as runtime
from seed import poc_runtime_fence_stack as fences

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))
renderer = importlib.import_module("render_runtime_seed_policies")
ROLE = runtime.PUBLISHER_NAME
EXPECTED = {
    f"inline/{ROLE}-Issue219TestImagePush.json": "IDENTITY_POLICY",
    f"policies/{ROLE}-Boundary.json": "IDENTITY_POLICY",
    f"policies/{ROLE}-Guard.json": "IDENTITY_POLICY",
    f"trust/{ROLE}.json": "RESOURCE_POLICY",
}


def _no_aws(*_args, **_kwargs):
    raise AssertionError("AWS CLI must not run")


class FakeAws:
    """Record exact argv and return synthetic metadata; never calls AWS."""

    def __init__(self, findings=(), returncode=0):
        self.calls, self.findings, self.returncode = [], list(findings), returncode

    def __call__(self, command, **kwargs):
        assert kwargs == {"check": False, "capture_output": True}
        self.calls.append(command)
        body = {"findings": self.findings} if command[1] == "accessanalyzer" else {}
        return subprocess.CompletedProcess(
            command, self.returncode, json.dumps(body), "denied"
        )


def _validate(tmp_path, monkeypatch, fake):
    monkeypatch.setattr(renderer, "run", fake)
    monkeypatch.setattr(renderer.shutil, "which", lambda _: "/usr/bin/aws")
    return renderer.main(["--output", str(tmp_path)], {"AWS_PROFILE": "test"})


def test_render_writes_exact_template_and_every_iam_document(tmp_path):
    manifest = renderer.render(tmp_path)
    packet = fences.build_fence_stack_packet()
    template = (tmp_path / "template.json").read_bytes()
    assert hashlib.sha256(template).hexdigest() == packet.template_sha256
    assert manifest["template_sha256"] == packet.template_sha256
    assert manifest["stack_name"] == packet.stack_name
    stack_policy = (tmp_path / "stack-policy.json").read_text()
    assert stack_policy == packet.deny_update_policy_json
    assert {r["path"]: r["policy_type"] for r in manifest["documents"]} == EXPECTED
    for row in manifest["documents"]:
        text = (tmp_path / row["path"]).read_text()
        assert hashlib.sha256(text.encode()).hexdigest() == row["sha256"]
    trust = json.loads((tmp_path / f"trust/{ROLE}.json").read_text())
    assert trust == json.loads(runtime.publisher_trust(runtime.PUBLISHER_SUBJECT))
    inline = tmp_path / f"inline/{ROLE}-Issue219TestImagePush.json"
    assert json.loads(inline.read_text()) == json.loads(runtime.publisher_policy())
    assert json.loads((tmp_path / "manifest.json").read_text()) == manifest
    assert set(manifest) == {
        "stack_name",
        "template_sha256",
        "amended_template_sha256",
        "break_glass_during_update_policy_sha256",
        "documents",
    }
    amended = (tmp_path / "amended-template.json").read_bytes()
    assert amended == verification._amended_packet().template_json.encode()
    template = (tmp_path / "template.json").read_bytes()
    assert amended != template
    roles = [
        r
        for r in json.loads(amended)["Resources"].values()
        if r["Type"] == "AWS::IAM::Role"
    ]
    assert len(roles) == 1
    assert roles[0]["Properties"]["AssumeRolePolicyDocument"] == json.loads(
        runtime.disabled_trust()
    )
    assert hashlib.sha256(amended).hexdigest() == manifest["amended_template_sha256"]
    during_update = (tmp_path / "break-glass-during-update-policy.json").read_bytes()
    assert during_update == fences.break_glass_during_update_policy_json().encode()
    assert (
        hashlib.sha256(during_update).hexdigest()
        == manifest["break_glass_during_update_policy_sha256"]
    )


@pytest.mark.parametrize("argv", [[], ["--render-only"]])
def test_main_renders_only_without_credentials_or_when_requested(
    tmp_path, monkeypatch, argv
):
    monkeypatch.setattr(renderer, "run", _no_aws)
    environ = {"AWS_PROFILE": "test"} if argv else {}
    assert renderer.main([*argv, "--output", str(tmp_path)], environ) == 0
    assert (tmp_path / "manifest.json").exists()


def test_main_uses_default_output_and_process_environment(tmp_path, monkeypatch):
    for name in renderer.CREDENTIAL_VARIABLES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(renderer, "run", _no_aws)
    assert renderer.main([]) == 0
    assert (tmp_path / renderer.DEFAULT_OUTPUT / "template.json").exists()


@pytest.mark.parametrize("name", renderer.CREDENTIAL_VARIABLES)
def test_each_credential_variable_enables_validation(name):
    assert renderer.credentials_present({name: "x"}) is True
    assert renderer.credentials_present({name: ""}) is False


def test_validation_runs_read_only_calls_with_exact_policy_types(tmp_path, monkeypatch):
    findings = [
        {"findingType": "SUGGESTION", "issueCode": "S"},
        {"findingType": "WARNING", "issueCode": "W"},
    ]
    fake = FakeAws(findings)
    assert _validate(tmp_path, monkeypatch, fake) == 0
    assert [call[1:3] for call in fake.calls] == [
        ["accessanalyzer", "validate-policy"]
    ] * 4 + [["cloudformation", "validate-template"]]
    assert all(
        call[-4:] == ["--region", "eu-central-1", "--output", "json"]
        for call in fake.calls
    )
    trust = next(call for call in fake.calls if "RESOURCE_POLICY" in call)
    flag = trust.index("--validate-policy-resource-type")
    assert trust[flag + 1] == "AWS::IAM::AssumeRolePolicyDocument"
    document = trust[trust.index("--policy-document") + 1]
    assert document == f"file://{tmp_path / f'trust/{ROLE}.json'}"
    identity = [call for call in fake.calls if "IDENTITY_POLICY" in call]
    assert len(identity) == 3
    assert not any("--validate-policy-resource-type" in c for c in identity)


@pytest.mark.parametrize("finding_type", ["ERROR", "SECURITY_WARNING"])
def test_blocking_findings_fail_validation(tmp_path, monkeypatch, capsys, finding_type):
    fake = FakeAws([{"findingType": finding_type, "issueCode": "BAD"}])
    assert _validate(tmp_path, monkeypatch, fake) == 1
    assert f"{finding_type} BAD" in capsys.readouterr().err


def test_failed_aws_call_blocks_validation(tmp_path, monkeypatch, capsys):
    assert _validate(tmp_path, monkeypatch, FakeAws(returncode=255)) == 2
    assert "BLOCKED" in capsys.readouterr().err


def test_missing_aws_cli_blocks_validation(tmp_path, monkeypatch):
    monkeypatch.setattr(renderer, "run", _no_aws)
    monkeypatch.setattr(renderer.shutil, "which", lambda _: None)
    argv = ["--output", str(tmp_path)]
    assert renderer.main(argv, {"AWS_ACCESS_KEY_ID": "x"}) == 2


def test_script_entrypoint_renders_only(tmp_path, monkeypatch):
    script = SCRIPTS / "render_runtime_seed_policies.py"
    argv = [str(script), "--render-only", "--output", str(tmp_path)]
    monkeypatch.setattr(sys, "argv", argv)
    with pytest.raises(SystemExit) as exit_info:
        runpy.run_path(str(script), run_name="__main__")
    assert exit_info.value.code == 0
