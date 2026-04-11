"""Unit tests for Pulumi CI guardrail helper scripts."""

from __future__ import annotations

import importlib.util
import json
import os
import runpy
import subprocess
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = PROJECT_ROOT / "scripts" / "pulumi_ci_guardrails.py"


@pytest.fixture
def guardrails_module(monkeypatch: pytest.MonkeyPatch):
    """Load the CLI helper module from disk for direct unit testing."""
    module_name = "pulumi_ci_guardrails_under_test"
    monkeypatch.delitem(sys.modules, module_name, raising=False)

    spec = importlib.util.spec_from_file_location(module_name, SCRIPT_PATH)
    assert spec is not None
    assert spec.loader is not None

    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _write_preview(path: Path, *, steps: list[dict], summary: dict[str, int]) -> Path:
    """Write a minimal Pulumi preview artifact."""
    path.write_text(
        json.dumps({"steps": steps, "changeSummary": summary}, indent=2),
        encoding="utf-8",
    )
    return path


def test_load_preview_requires_json_object(guardrails_module, tmp_path: Path) -> None:
    """Reject non-object preview artifacts."""
    path = tmp_path / "preview.json"
    path.write_text("[]", encoding="utf-8")

    with pytest.raises(ValueError, match="JSON object preview artifact"):
        guardrails_module.load_preview(path)


def test_summarize_preview_and_find_destructive_steps(
    guardrails_module, tmp_path: Path
) -> None:
    """Summaries should include operation counts and destructive-step notes."""
    path = _write_preview(
        tmp_path / "dev.json",
        steps=[
            {
                "op": "create",
                "urn": "urn:pulumi:dev::stack::aws:s3/bucket:Bucket::bucket",
                "newState": {"type": "aws:s3/bucket:Bucket"},
            },
            {
                "op": "replace",
                "urn": "urn:pulumi:dev::stack::aws:cloudwatch/logGroup:LogGroup::logs",
                "newState": {"type": "aws:cloudwatch/logGroup:LogGroup"},
            },
            {
                "op": "replace",
                "urn": "urn:pulumi:dev::stack::aws:rds/instance:Instance::db",
                "newState": {"type": "aws:rds/instance:Instance"},
            },
        ],
        summary={"create": 1, "replace": 2},
    )

    preview = guardrails_module.load_preview(path)
    destructive = guardrails_module.find_destructive_steps(
        guardrails_module.preview_steps(preview)
    )
    rendered = guardrails_module.summarize_preview(path, stack="dev")

    assert len(destructive) == 1
    assert "Pulumi Preview: dev" in rendered
    assert "| create | 1 |" in rendered
    assert "Destructive-step count: `1`" in rendered
    assert "aws:rds/instance:Instance" in rendered

    empty_path = _write_preview(
        tmp_path / "empty.json",
        steps=[],
        summary={},
    )
    assert guardrails_module.preview_steps({"steps": "invalid"}) == []
    assert "| none | 0 |" in guardrails_module.summarize_preview(empty_path)


def test_extract_iam_validation_inputs_covers_identity_resource_and_inline_policies(
    guardrails_module, tmp_path: Path
) -> None:
    """Extract every policy-bearing field from preview state."""
    path = _write_preview(
        tmp_path / "iam.json",
        steps=[
            {
                "op": "create",
                "urn": "urn:pulumi:dev::stack::aws:iam/policy:Policy::policy",
                "newState": {
                    "type": "aws:iam/policy:Policy",
                    "policy": json.dumps(
                        {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject"}]}
                    ),
                },
            },
            {
                "op": "update",
                "urn": "urn:pulumi:dev::stack::aws:iam/role:Role::role",
                "newState": {
                    "type": "aws:iam/role:Role",
                    "assumeRolePolicy": json.dumps(
                        {"Statement": [{"Effect": "Allow", "Principal": "*"}]}
                    ),
                    "inlinePolicies": [
                        "invalid",
                        {"policy": "{not-json}"},
                        {
                            "policy": json.dumps(
                                {
                                    "Statement": [
                                        {
                                            "Effect": "Allow",
                                            "Action": "logs:CreateLogGroup",
                                            "Resource": "*",
                                        }
                                    ]
                                }
                            )
                        },
                    ],
                },
            },
            {
                "op": "create",
                "urn": (
                    "urn:pulumi:dev::stack::aws:s3/bucketPolicy:BucketPolicy::bucket"
                ),
                "newState": {
                    "type": "aws:s3/bucketPolicy:BucketPolicy",
                    "policy": json.dumps(
                        {"Statement": [{"Effect": "Allow", "Principal": "*"}]}
                    ),
                },
            },
            {
                "op": "create",
                "urn": "urn:pulumi:dev::stack::aws:s3/bucket:Bucket::inline-bucket",
                "newState": {
                    "type": "aws:s3/bucket:Bucket",
                    "policy": json.dumps(
                        {"Statement": [{"Effect": "Allow", "Principal": "*"}]}
                    ),
                },
            },
            {
                "op": "create",
                "urn": "urn:pulumi:dev::stack::custom::bad",
                "newState": "invalid",
            },
        ],
        summary={"create": 2, "update": 1},
    )

    items = guardrails_module.extract_iam_validation_inputs(path)

    assert [item["policy_type"] for item in items] == [
        "IDENTITY_POLICY",
        "RESOURCE_POLICY",
        "IDENTITY_POLICY",
        "RESOURCE_POLICY",
        "RESOURCE_POLICY",
    ]
    assert any(item["field"] == "inlinePolicies[2].policy" for item in items)
    assert any(
        item["resource_type"] == "aws:s3/bucketPolicy:BucketPolicy" for item in items
    )
    assert any(item["resource_type"] == "aws:s3/bucket:Bucket" for item in items)
    assert any(
        item["field"] == "assumeRolePolicy"
        and item["validate_policy_resource_type"]
        == "AWS::IAM::AssumeRolePolicyDocument"
        for item in items
    )
    assert any(
        item["resource_type"] == "aws:s3/bucketPolicy:BucketPolicy"
        and item["validate_policy_resource_type"] == "AWS::S3::Bucket"
        for item in items
    )
    assert any(
        item["resource_type"] == "aws:s3/bucket:Bucket"
        and item["validate_policy_resource_type"] == "AWS::S3::Bucket"
        for item in items
    )


def test_load_destructive_override_reads_github_event_payload(
    guardrails_module, tmp_path: Path
) -> None:
    """Respect the explicit destructive-change override label only."""
    event_path = tmp_path / "event.json"
    event_path.write_text(
        json.dumps(
            {"pull_request": {"labels": [{"name": "allow-destructive-infra-change"}]}}
        ),
        encoding="utf-8",
    )
    empty_path = tmp_path / "empty.json"
    empty_path.write_text("{}", encoding="utf-8")
    invalid_labels_path = tmp_path / "invalid-labels.json"
    invalid_labels_path.write_text(
        json.dumps({"pull_request": {"labels": "invalid"}}), encoding="utf-8"
    )

    assert guardrails_module.load_destructive_override(str(event_path)) is True
    assert guardrails_module.load_destructive_override(str(empty_path)) is False
    assert (
        guardrails_module.load_destructive_override(str(invalid_labels_path)) is False
    )
    assert guardrails_module.load_destructive_override(None) is False


def test_validate_iam_inputs_handles_success_and_failing_findings(
    guardrails_module, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Surface Access Analyzer failures and risky findings clearly."""
    calls: list[list[str]] = []
    envs: list[dict[str, str]] = []
    for key in list(os.environ):
        if key.startswith("AWS_"):
            monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("HOME", "/tmp/home")
    monkeypatch.setenv("PATH", "/usr/bin")

    def fake_run(*args, **kwargs):
        envs.append(dict(kwargs["env"]))
        calls.append(args[0])
        return subprocess.CompletedProcess(
            args=args[0],
            returncode=0,
            stdout=json.dumps(
                {
                    "findings": [
                        {
                            "findingType": "SUGGESTION",
                            "findingDetails": "consider narrowing scope",
                        },
                        {
                            "findingType": "SECURITY_WARNING",
                            "findingDetails": "too broad",
                        },
                    ]
                }
            ),
            stderr="",
        )

    monkeypatch.setattr(guardrails_module.subprocess, "run", fake_run)

    failures = guardrails_module.validate_iam_inputs(
        [
            {
                "urn": "urn:pulumi:dev::stack::aws:iam/policy:Policy::policy",
                "field": "policy",
                "policy_type": "IDENTITY_POLICY",
                "policy_document": json.dumps({"Statement": []}),
                "validate_policy_resource_type": "AWS::IAM::AssumeRolePolicyDocument",
            }
        ]
    )

    assert calls[0][:4] == ["aws", "accessanalyzer", "validate-policy", "--policy-type"]
    assert "--validate-policy-resource-type" in calls[0]
    assert "AWS::IAM::AssumeRolePolicyDocument" in calls[0]
    assert sorted(envs[0]) == ["HOME", "PATH"]
    assert "too broad" in failures[0]


def test_validate_iam_inputs_raises_on_cli_failure(
    guardrails_module, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Bubble AWS CLI failures with resource context."""

    def fake_run(*args, **kwargs):
        del args, kwargs
        return subprocess.CompletedProcess(
            args=["aws"],
            returncode=255,
            stdout="",
            stderr="AccessDenied",
        )

    monkeypatch.setattr(guardrails_module.subprocess, "run", fake_run)

    with pytest.raises(RuntimeError, match="AccessDenied"):
        guardrails_module.validate_iam_inputs(
            [
                {
                    "urn": "urn:pulumi:dev::stack::aws:iam/policy:Policy::policy",
                    "field": "policy",
                    "policy_type": "IDENTITY_POLICY",
                    "policy_document": json.dumps({"Statement": []}),
                }
            ]
        )


def test_validate_iam_inputs_raises_on_cli_timeout(
    guardrails_module, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Treat Access Analyzer timeouts like ordinary guardrail failures."""

    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], timeout=120, output="", stderr="")

    monkeypatch.setattr(guardrails_module.subprocess, "run", fake_run)

    with pytest.raises(RuntimeError, match="timed out"):
        guardrails_module.validate_iam_inputs(
            [
                {
                    "urn": "urn:pulumi:dev::stack::aws:iam/policy:Policy::policy",
                    "field": "policy",
                    "policy_type": "IDENTITY_POLICY",
                    "policy_document": json.dumps({"Statement": []}),
                }
            ]
        )


def test_validate_iam_inputs_treats_malformed_access_analyzer_output_as_failure(
    guardrails_module, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Normalize bad CLI JSON into an actionable guardrail failure."""

    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(args[0], returncode=0, stdout="{", stderr="")

    monkeypatch.setattr(guardrails_module.subprocess, "run", fake_run)

    failures = guardrails_module.validate_iam_inputs(
        [
            {
                "urn": "urn:pulumi:dev::stack::aws:iam/role:Role::role",
                "field": "assumeRolePolicy",
                "policy_type": "RESOURCE_POLICY",
                "policy_document": json.dumps({"Statement": []}),
                "validate_policy_resource_type": "AWS::IAM::AssumeRolePolicyDocument",
            }
        ]
    )

    assert failures
    assert "malformed access-analyzer response" in failures[0]


def test_iam_policy_fields_maps_identity_and_resource_policy_types(
    guardrails_module,
) -> None:
    """Keep the supported IAM-bearing resource field map stable."""
    assert list(guardrails_module.iam_policy_fields("aws:iam/policy:Policy")) == [
        ("policy", "IDENTITY_POLICY"),
        ("policyDocument", "IDENTITY_POLICY"),
    ]
    assert list(guardrails_module.iam_policy_fields("aws:iam/role:Role")) == [
        ("policy", "IDENTITY_POLICY"),
        ("policyDocument", "IDENTITY_POLICY"),
        ("assumeRolePolicy", "RESOURCE_POLICY"),
    ]
    assert list(
        guardrails_module.iam_policy_fields("aws:s3/bucketPolicy:BucketPolicy")
    ) == [
        ("policy", "RESOURCE_POLICY"),
        ("policyDocument", "RESOURCE_POLICY"),
    ]
    assert list(guardrails_module.iam_policy_fields("aws:s3/bucket:Bucket")) == [
        ("policy", "RESOURCE_POLICY"),
        ("policyDocument", "RESOURCE_POLICY"),
    ]
    assert list(guardrails_module.iam_policy_fields("aws:ec2/vpc:Vpc")) == []


def test_validate_policy_resource_type_maps_specific_access_analyzer_modes(
    guardrails_module,
) -> None:
    """Enable the strictest Access Analyzer checks for supported resource policies."""
    assert (
        guardrails_module._validate_policy_resource_type(
            "aws:iam/role:Role",
            "assumeRolePolicy",
            "RESOURCE_POLICY",
        )
        == "AWS::IAM::AssumeRolePolicyDocument"
    )
    assert (
        guardrails_module._validate_policy_resource_type(
            "aws:s3/bucketPolicy:BucketPolicy",
            "policy",
            "RESOURCE_POLICY",
        )
        == "AWS::S3::Bucket"
    )
    assert (
        guardrails_module._validate_policy_resource_type(
            "aws:s3/bucket:Bucket",
            "policy",
            "RESOURCE_POLICY",
        )
        == "AWS::S3::Bucket"
    )
    assert (
        guardrails_module._validate_policy_resource_type(
            "aws:iam/policy:Policy",
            "policy",
            "IDENTITY_POLICY",
        )
        is None
    )
    assert (
        guardrails_module._validate_policy_resource_type(
            "aws:sns/topicPolicy:TopicPolicy",
            "policy",
            "RESOURCE_POLICY",
        )
        is None
    )


def test_write_iam_inputs_serializes_extracted_documents(
    guardrails_module, tmp_path: Path
) -> None:
    """Keep the artifact-export path stable for CI debugging."""
    preview_path = _write_preview(
        tmp_path / "iam.json",
        steps=[
            {
                "op": "create",
                "urn": "urn:pulumi:dev::stack::aws:iam/policy:Policy::policy",
                "newState": {
                    "type": "aws:iam/policy:Policy",
                    "policy": json.dumps({"Statement": []}),
                },
            }
        ],
        summary={"create": 1},
    )
    output_path = tmp_path / "iam-inputs.json"

    guardrails_module.write_iam_inputs(output_path, preview_paths=[preview_path])

    exported = json.loads(output_path.read_text(encoding="utf-8"))
    assert exported[0]["policy_type"] == "IDENTITY_POLICY"


def test_cli_commands_cover_summary_destructive_gate_iam_inputs_and_validation(
    guardrails_module,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Exercise the CLI subcommands without shelling out to real AWS."""
    preview_path = _write_preview(
        tmp_path / "preview.json",
        steps=[
            {
                "op": "delete",
                "urn": "urn:pulumi:dev::stack::aws:kms/key:Key::key",
                "newState": {"type": "aws:kms/key:Key"},
            },
            {
                "op": "create",
                "urn": "urn:pulumi:dev::stack::aws:iam/policy:Policy::policy",
                "newState": {
                    "type": "aws:iam/policy:Policy",
                    "policy": json.dumps({"Statement": []}),
                },
            },
        ],
        summary={"create": 1, "delete": 1},
    )
    event_path = tmp_path / "event.json"
    event_path.write_text("{}", encoding="utf-8")
    output_path = tmp_path / "iam-inputs.json"

    assert guardrails_module.cli(["summarize", str(preview_path)]) == 0
    assert "Pulumi Preview" in capsys.readouterr().out

    assert (
        guardrails_module.cli(
            ["destructive-gate", str(preview_path), "--event-path", str(event_path)]
        )
        == 1
    )
    assert "destructive change blocked" in capsys.readouterr().err

    assert (
        guardrails_module.cli(
            ["iam-inputs", str(preview_path), "--output", str(output_path)]
        )
        == 0
    )
    assert output_path.exists()

    monkeypatch.setattr(guardrails_module, "validate_iam_inputs", lambda inputs: [])
    assert guardrails_module.cli(["validate-iam", str(preview_path)]) == 0
    assert "Validated 1 IAM policy document" in capsys.readouterr().out

    override_event_path = tmp_path / "override.json"
    override_event_path.write_text(
        json.dumps(
            {"pull_request": {"labels": [{"name": "allow-destructive-infra-change"}]}}
        ),
        encoding="utf-8",
    )
    assert (
        guardrails_module.cli(
            [
                "destructive-gate",
                str(preview_path),
                "--event-path",
                str(override_event_path),
            ]
        )
        == 0
    )


def test_validate_iam_cli_short_circuits_when_no_policies_present(
    guardrails_module, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Avoid requiring AWS credentials for previews that contain no IAM policies."""
    preview_path = _write_preview(
        tmp_path / "preview.json",
        steps=[{"op": "create", "newState": {"type": "aws:s3/bucket:Bucket"}}],
        summary={"create": 1},
    )

    assert guardrails_module.cli(["validate-iam", str(preview_path)]) == 0
    assert "No IAM policy documents" in capsys.readouterr().out


def test_validate_iam_cli_reports_runtime_errors_and_findings(
    guardrails_module,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Cover the remaining CLI branches for Access Analyzer failures."""
    preview_path = _write_preview(
        tmp_path / "preview.json",
        steps=[
            {
                "op": "create",
                "newState": {
                    "type": "aws:iam/policy:Policy",
                    "policy": json.dumps({"Statement": []}),
                },
            }
        ],
        summary={"create": 1},
    )

    def raise_error(_: list[dict[str, str]]) -> list[str]:
        raise RuntimeError("boom")

    monkeypatch.setattr(guardrails_module, "validate_iam_inputs", raise_error)
    assert guardrails_module.cli(["validate-iam", str(preview_path)]) == 1
    assert "boom" in capsys.readouterr().err

    monkeypatch.setattr(
        guardrails_module,
        "validate_iam_inputs",
        lambda _: ["urn:pulumi:dev::stack::policy: SECURITY_WARNING: too broad"],
    )
    assert guardrails_module.cli(["validate-iam", str(preview_path)]) == 1
    assert "too broad" in capsys.readouterr().err


def test_parse_policy_document_and_step_resource_type_helpers(
    guardrails_module,
) -> None:
    """Keep small helper behavior explicit for malformed input."""
    assert guardrails_module.parse_policy_document({"Statement": []}) == {
        "Statement": []
    }
    assert guardrails_module.parse_policy_document("{not-json}") is None
    assert guardrails_module.parse_policy_document([]) is None
    assert guardrails_module.step_resource_type(
        {"oldState": {"type": "aws:s3/bucket:Bucket"}}
    ) == ("aws:s3/bucket:Bucket")
    assert guardrails_module.step_resource_type({}) == ""


def test_main_guard_runs_cli_entrypoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Exercise the script's __main__ path with a safe preview artifact."""
    preview_path = _write_preview(
        tmp_path / "preview.json",
        steps=[{"op": "create", "newState": {"type": "aws:s3/bucket:Bucket"}}],
        summary={"create": 1},
    )
    original_argv = sys.argv[:]
    monkeypatch.setattr(
        sys,
        "argv",
        [str(SCRIPT_PATH), "validate-iam", str(preview_path)],
    )

    try:
        with pytest.raises(SystemExit, match="0"):
            runpy.run_path(str(SCRIPT_PATH), run_name="__main__")
    finally:
        sys.argv = original_argv

    assert "No IAM policy documents" in capsys.readouterr().out
