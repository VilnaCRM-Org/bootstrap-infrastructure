#!/usr/bin/env python3
"""Validate generated IAM-related policies with AWS IAM Access Analyzer."""
# ruff: noqa: E402

from __future__ import annotations

import json
import os
import shutil
import subprocess  # nosec B404 - this validator intentionally shells out to aws.
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
PULUMI_ROOT = REPO_ROOT / "pulumi"

for import_path in (str(REPO_ROOT), str(PULUMI_ROOT)):
    if import_path not in sys.path:
        sys.path.insert(0, import_path)

os.environ.setdefault("PULUMI_ALLOW_TEST_DEFAULTS", "1")

from infra.automation import _automation_policy
from infra.iam.github_oidc import _deploy_policy
from infra.logging_bucket import (
    _log_bucket_policy,
)
from infra.logging_bucket import (
    _replication_role_policy as _log_replication_role_policy,
)
from infra.pulumi_state import (
    _bucket_policy,
)
from infra.pulumi_state import (
    _replication_role_policy as _state_replication_role_policy,
)

BLOCKING_FINDING_TYPES = {"ERROR", "SECURITY_WARNING", "WARNING"}
EXAMPLE_STATE_BUCKET_ARN = "arn:aws:s3:::example-state-bucket"
EXAMPLE_STATE_OBJECTS_ARN = "arn:aws:s3:::example-state-bucket/state/*"


@dataclass(frozen=True)
class PolicyDocumentSpec:
    """One policy document that should be validated in CI."""

    name: str
    policy_document: str
    policy_type: str
    resource_type: str | None = None
    ignored_issue_codes: set[str] = field(default_factory=set)


def build_policy_documents(account_id: str) -> list[PolicyDocumentSpec]:
    """Build the static policy documents used by bootstrap-infrastructure."""
    return [
        PolicyDocumentSpec(
            name="github-deploy-state-policy",
            policy_document=_deploy_policy(
                EXAMPLE_STATE_BUCKET_ARN,
                EXAMPLE_STATE_OBJECTS_ARN,
                f"arn:aws:kms:eu-central-1:{account_id}:key/example",
            ),
            policy_type="IDENTITY_POLICY",
        ),
        PolicyDocumentSpec(
            name="github-automation-bootstrap-policy",
            policy_document=_automation_policy(account_id),
            policy_type="IDENTITY_POLICY",
        ),
        PolicyDocumentSpec(
            name="state-replication-role-policy",
            policy_document=_state_replication_role_policy(
                [
                    "arn:aws:s3:::example-state-bucket",
                    "arn:aws:s3:::example-state-bucket-replica",
                ]
            ),
            policy_type="IDENTITY_POLICY",
        ),
        PolicyDocumentSpec(
            name="logging-replication-role-policy",
            policy_document=_log_replication_role_policy(
                [
                    "arn:aws:s3:::example-log-bucket",
                    "arn:aws:s3:::example-log-bucket-replica",
                ]
            ),
            policy_type="IDENTITY_POLICY",
        ),
        PolicyDocumentSpec(
            name="state-bucket-policy",
            policy_document=_bucket_policy(EXAMPLE_STATE_BUCKET_ARN),
            policy_type="RESOURCE_POLICY",
            resource_type="AWS::S3::Bucket",
        ),
        PolicyDocumentSpec(
            name="logging-bucket-policy",
            policy_document=_log_bucket_policy(
                "arn:aws:s3:::example-log-bucket",
                account_id,
            ),
            policy_type="RESOURCE_POLICY",
            resource_type="AWS::S3::Bucket",
        ),
    ]


def build_validate_policy_command(spec: PolicyDocumentSpec) -> list[str]:
    """Build an `aws accessanalyzer validate-policy` command for a spec."""
    command = [
        "aws",
        "accessanalyzer",
        "validate-policy",
        "--policy-document",
        spec.policy_document,
        "--policy-type",
        spec.policy_type,
        "--output",
        "json",
    ]
    if spec.resource_type is not None:
        command.extend(["--validate-policy-resource-type", spec.resource_type])
    return command


def _aws_cli() -> str:
    aws_cli = shutil.which("aws")
    if aws_cli is None:
        raise FileNotFoundError("aws CLI is required for IAM policy validation.")
    return aws_cli


def _run_aws_command(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [_aws_cli(), *command],
        capture_output=True,
        text=True,
        check=False,
    )  # nosec B603


def aws_credentials_available() -> bool:
    """Return True when Access Analyzer can be called with current credentials."""
    result = _run_aws_command(["sts", "get-caller-identity", "--output", "json"])
    return result.returncode == 0


def blocking_findings(
    findings: list[dict[str, Any]],
    ignored_issue_codes: set[str],
) -> list[dict[str, Any]]:
    """Filter Access Analyzer findings down to the ones that should fail CI."""
    blocked: list[dict[str, Any]] = []
    for finding in findings:
        finding_type = finding.get("findingType")
        issue_code = finding.get("issueCode")
        if finding_type not in BLOCKING_FINDING_TYPES:
            continue
        if isinstance(issue_code, str) and issue_code in ignored_issue_codes:
            continue
        blocked.append(finding)
    return blocked


def validate_policy_document(spec: PolicyDocumentSpec) -> list[dict[str, Any]]:
    """Call Access Analyzer and return any blocking findings."""
    command = build_validate_policy_command(spec)[1:]
    result = _run_aws_command(command)
    if result.returncode != 0:
        raise RuntimeError(
            f"AWS Access Analyzer validation failed for {spec.name}: {result.stderr}"
        )
    payload = json.loads(result.stdout)
    findings = payload.get("findings")
    if not isinstance(findings, list):
        raise ValueError(
            f"AWS Access Analyzer returned an unexpected payload for {spec.name}."
        )
    return blocking_findings(findings, spec.ignored_issue_codes)


def main() -> int:
    """CLI entrypoint."""
    require_aws = os.getenv("REQUIRE_AWS_ACCESS_ANALYZER", "").lower() in {
        "1",
        "true",
        "yes",
    }
    if not aws_credentials_available():
        message = (
            "Skipping IAM policy validation because AWS credentials are not available."
        )
        if require_aws:
            sys.stderr.write(message + "\n")
            return 1
        sys.stdout.write(message + "\n")
        return 0

    account_id = json.loads(
        _run_aws_command(["sts", "get-caller-identity", "--output", "json"]).stdout
    )["Account"]

    failures: list[str] = []
    for spec in build_policy_documents(account_id):
        findings = validate_policy_document(spec)
        if not findings:
            sys.stdout.write(f"[ok] {spec.name}\n")
            continue
        sys.stdout.write(f"[fail] {spec.name}\n")
        for finding in findings:
            failures.append(
                f"{spec.name}: {finding['findingType']} {finding['issueCode']} "
                f"{finding['findingDetails']}"
            )

    if failures:
        sys.stderr.write("\n".join(failures) + "\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
