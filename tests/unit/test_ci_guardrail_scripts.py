from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _load_module(relative_path: str, module_name: str):
    module_path = ROOT / relative_path
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None or spec.loader is None:
        raise AssertionError(f"Unable to load module from {module_path}")  # nosec B101
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


preview_guard = _load_module(
    "scripts/analyze_pulumi_preview.py", "scripts.analyze_pulumi_preview"
)
iam_validation = _load_module(
    "scripts/validate_iam_policies.py", "scripts.validate_iam_policies"
)


def test_preview_guard_detects_critical_destructive_steps():
    preview = {
        "changeSummary": {"delete": 1, "update": 1},
        "steps": [
            {
                "op": "delete",
                "urn": "urn:pulumi:test::bootstrap::aws:s3/bucket:Bucket::state",
                "oldState": {"type": "aws:s3/bucket:Bucket"},
            },
            {
                "op": "update",
                "urn": (
                    "urn:pulumi:test::bootstrap::aws:ecr/repository:Repository::runner"
                ),
                "newState": {"type": "aws:ecr/repository:Repository"},
            },
        ],
    }

    steps = preview_guard.extract_preview_steps(preview)
    dangerous = preview_guard.destructive_critical_steps(steps)

    assert len(steps) == 2  # nosec B101
    assert len(dangerous) == 1  # nosec B101
    assert dangerous[0].resource_type == "aws:s3/bucket:Bucket"  # nosec B101
    assert dangerous[0].op == "delete"  # nosec B101


def test_preview_guard_summary_changes_when_override_is_enabled():
    preview = {
        "changeSummary": {"replace": 1},
        "steps": [
            {
                "op": "replace",
                "urn": "urn:pulumi:test::bootstrap::aws:kms/key:Key::secrets",
                "oldState": {"type": "aws:kms/key:Key"},
            }
        ],
    }
    dangerous = preview_guard.destructive_critical_steps(
        preview_guard.extract_preview_steps(preview)
    )

    blocked = preview_guard.render_markdown_summary(
        preview,
        dangerous,
        override_enabled=False,
    )
    overridden = preview_guard.render_markdown_summary(
        preview,
        dangerous,
        override_enabled=True,
    )

    assert "Destructive Diff Gate: blocked" in blocked  # nosec B101
    assert "Destructive Diff Gate: override enabled" in overridden  # nosec B101


def test_iam_validation_builds_expected_documents_and_commands():
    specs = iam_validation.build_policy_documents("123456789012")
    names = {spec.name for spec in specs}

    assert "github-deploy-state-policy" in names  # nosec B101
    assert "github-automation-bootstrap-policy" in names  # nosec B101
    assert "state-bucket-policy" in names  # nosec B101

    resource_spec = next(spec for spec in specs if spec.name == "state-bucket-policy")
    command = iam_validation.build_validate_policy_command(resource_spec)
    assert command[:4] == [  # nosec B101
        "aws",
        "accessanalyzer",
        "validate-policy",
        "--policy-document",
    ]
    assert "--validate-policy-resource-type" in command  # nosec B101
    assert "AWS::S3::Bucket" in command  # nosec B101


def test_iam_validation_filters_non_blocking_findings():
    findings = [
        {"findingType": "SUGGESTION", "issueCode": "STYLE_ONLY"},
        {"findingType": "WARNING", "issueCode": "REAL_WARNING"},
        {"findingType": "SECURITY_WARNING", "issueCode": "IGNORE_ME"},
    ]

    blocked = iam_validation.blocking_findings(findings, {"IGNORE_ME"})
    assert blocked == [  # nosec B101
        {"findingType": "WARNING", "issueCode": "REAL_WARNING"}
    ]
