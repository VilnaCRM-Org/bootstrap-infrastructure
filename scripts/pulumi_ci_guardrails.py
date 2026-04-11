"""Helpers for Pulumi preview summaries, destructive-diff gates, and IAM validation."""

from __future__ import annotations

import argparse
import json
import os
import subprocess  # nosec B404
import sys
from collections.abc import Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from pathlib import Path
from typing import Any, cast

DESTRUCTIVE_OPS = frozenset({"delete", "replace", "delete-replaced"})
CRITICAL_TYPE_PATTERNS = (
    "aws:ec2/vpc:",
    "aws:ec2/internetGateway:",
    "aws:ec2/natGateway:",
    "aws:ec2/routeTable:",
    "aws:iam/",
    "aws:kms/",
    "aws:s3/bucket:Bucket",
    "aws:rds/",
    "aws:secretsmanager/",
    "aws:route53/",
    "aws:eks/",
)
DESTRUCTIVE_OVERRIDE_LABEL = "allow-destructive-infra-change"
FAIL_FINDING_TYPES = frozenset({"ERROR", "SECURITY_WARNING"})


def load_preview(path: Path) -> dict[str, Any]:
    """Load a Pulumi JSON preview artifact from disk."""
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        return data
    raise ValueError(f"{path} must contain a JSON object preview artifact.")


def preview_steps(preview: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the normalized list of preview steps."""
    steps = preview.get("steps", [])
    if not isinstance(steps, list):
        return []
    return [step for step in steps if isinstance(step, dict)]


def summarize_preview(path: Path, *, stack: str | None = None) -> str:
    """Render a compact Markdown summary for a preview artifact."""
    preview = load_preview(path)
    summary = preview.get("changeSummary", {})
    lines = [
        f"### Pulumi Preview: {stack or path.stem}",
        "",
        "| Operation | Count |",
        "| --- | ---: |",
    ]

    if isinstance(summary, dict) and summary:
        for operation in sorted(summary):
            lines.append(f"| {operation} | {summary[operation]} |")
    else:
        lines.append("| none | 0 |")

    destructive = find_destructive_steps(preview_steps(preview))
    lines.extend(["", f"Destructive-step count: `{len(destructive)}`"])
    if destructive:
        lines.append("")
        lines.append("Critical destructive candidates:")
        for step in destructive:
            resource_type = step_resource_type(step)
            lines.append(f"- `{step.get('op')}` `{resource_type}`")
    lines.append("")
    return "\n".join(lines)


def find_destructive_steps(steps: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return destructive preview steps that touch critical resource types."""
    destructive_steps: list[dict[str, Any]] = []
    for step in steps:
        op = step.get("op")
        resource_type = step_resource_type(step)
        if op not in DESTRUCTIVE_OPS:
            continue
        if any(pattern in resource_type for pattern in CRITICAL_TYPE_PATTERNS):
            destructive_steps.append(step)
    return destructive_steps


def extract_iam_validation_inputs(
    path: Path,
) -> list[dict[str, str]]:
    """Extract IAM policy documents from a preview artifact."""
    inputs: list[dict[str, str]] = []
    for step in preview_steps(load_preview(path)):
        state = step.get("newState")
        if not isinstance(state, dict):
            continue

        resource_type = step_resource_type(step)
        for field_name, policy_type in iam_policy_fields(resource_type):
            document = parse_policy_document(state.get(field_name))
            if document is None:
                continue
            item = {
                "urn": str(step.get("urn", "")),
                "resource_type": resource_type,
                "field": field_name,
                "policy_type": policy_type,
                "policy_document": json.dumps(document, sort_keys=True),
            }
            validate_policy_resource_type = _validate_policy_resource_type(
                resource_type,
                field_name,
                policy_type,
            )
            if validate_policy_resource_type is not None:
                item["validate_policy_resource_type"] = validate_policy_resource_type
            inputs.append(item)

        inline_policies = state.get("inlinePolicies")
        if isinstance(inline_policies, list):
            for index, policy in enumerate(inline_policies):
                if not isinstance(policy, dict):
                    continue
                document = parse_policy_document(policy.get("policy"))
                if document is None:
                    continue
                inputs.append(
                    {
                        "urn": str(step.get("urn", "")),
                        "resource_type": resource_type,
                        "field": f"inlinePolicies[{index}].policy",
                        "policy_type": "IDENTITY_POLICY",
                        "policy_document": json.dumps(document, sort_keys=True),
                    }
                )
    return inputs


def load_destructive_override(event_path: str | None) -> bool:
    """Return whether the current GitHub event opts into destructive changes."""
    if not event_path:
        return False

    event = json.loads(Path(event_path).read_text(encoding="utf-8"))
    pull_request = event.get("pull_request")
    if not isinstance(pull_request, dict):
        return False

    labels = pull_request.get("labels", [])
    if not isinstance(labels, list):
        return False
    return any(
        isinstance(label, dict) and label.get("name") == DESTRUCTIVE_OVERRIDE_LABEL
        for label in labels
    )


def validate_iam_inputs(inputs: Sequence[dict[str, str]]) -> list[str]:
    """Validate IAM policy documents with AWS IAM Access Analyzer."""
    failures: list[str] = []
    aws_env = _aws_validation_env()
    load_response = partial(_load_validation_response, aws_env=aws_env)

    with ThreadPoolExecutor(max_workers=max(1, min(4, len(inputs)))) as executor:
        for item, response in executor.map(load_response, inputs):
            failures.extend(_validation_failures(item, response))
    return failures


def _aws_validation_env() -> dict[str, str]:
    """Pass only the AWS and shell environment needed by the AWS CLI."""
    return {
        key: value
        for key, value in os.environ.items()
        if key.startswith("AWS_") or key in {"HOME", "PATH"}
    }


def _access_analyzer_command(item: dict[str, str]) -> list[str]:
    """Build a fixed AWS CLI argv list for policy validation."""
    command = [
        "aws",
        "accessanalyzer",
        "validate-policy",
        "--policy-type",
        item["policy_type"],
        "--policy-document",
        item["policy_document"],
        "--output",
        "json",
    ]
    validate_policy_resource_type = item.get("validate_policy_resource_type")
    if validate_policy_resource_type is not None:
        command.extend(
            [
                "--validate-policy-resource-type",
                validate_policy_resource_type,
            ]
        )
    return command


def _run_access_analyzer_validation(
    item: dict[str, str], aws_env: dict[str, str]
) -> subprocess.CompletedProcess[str]:
    """Run AWS IAM Access Analyzer and normalize CLI failures."""
    command = _access_analyzer_command(item)

    try:
        result = subprocess.run(  # nosec B603
            command,
            check=False,
            capture_output=True,
            env=aws_env,
            text=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"IAM Access Analyzer validation timed out for {item['urn']} "
            f"({item['field']}): {_subprocess_failure_details(exc)}"
        ) from exc

    if result.returncode != 0:
        raise RuntimeError(
            f"IAM Access Analyzer validation failed for {item['urn']} "
            f"({item['field']}): {_subprocess_failure_details(result)}"
        )
    return result


def _load_validation_response(
    item: dict[str, str], *, aws_env: dict[str, str]
) -> tuple[dict[str, str], dict[str, Any]]:
    """Run Access Analyzer for one item and decode the JSON response."""
    result = _run_access_analyzer_validation(item, aws_env)
    try:
        return item, json.loads(result.stdout or "{}")
    except json.JSONDecodeError as error:
        return item, {
            "status": "FAILED",
            "reason": "malformed access-analyzer response",
            "error": str(error),
            "raw_output": result.stdout or "",
        }


def _subprocess_failure_details(
    result: subprocess.CompletedProcess[str] | subprocess.TimeoutExpired,
) -> str:
    """Extract a useful stderr/stdout summary from subprocess failures."""
    return (
        getattr(result, "stderr", None)
        or getattr(result, "stdout", None)
        or str(result)
    ).strip()


def _validation_failures(item: dict[str, str], response: dict[str, Any]) -> list[str]:
    """Convert Access Analyzer findings into CI failure messages."""
    failures: list[str] = []
    if response.get("status") == "FAILED":
        failures.append(
            f"{item['urn']} [{item['field']}] "
            f"{response.get('reason', 'validation failed')}: "
            f"{response.get('error', 'unknown analyzer error')}"
        )
        return failures
    for finding in response.get("findings", []):
        if finding.get("findingType") in FAIL_FINDING_TYPES:
            failures.append(
                f"{item['urn']} [{item['field']}] {finding['findingType']}: "
                f"{finding.get('findingDetails', 'unspecified finding')}"
            )
    return failures


def iam_policy_fields(resource_type: str) -> Iterable[tuple[str, str]]:
    """Yield policy-bearing fields for a resource type."""
    if "aws:iam/role:Role" in resource_type:
        yield ("policy", "IDENTITY_POLICY")
        yield ("policyDocument", "IDENTITY_POLICY")
        yield ("assumeRolePolicy", "RESOURCE_POLICY")
        return
    if "iam/" in resource_type:
        yield ("policy", "IDENTITY_POLICY")
        yield ("policyDocument", "IDENTITY_POLICY")
        return

    if any(
        suffix in resource_type
        for suffix in (
            "s3/bucket:Bucket",
            "s3/bucketPolicy:",
            "sns/topicPolicy:",
            "sqs/queuePolicy:",
            "kms/key:",
            "secretsmanager/secretPolicy:",
        )
    ):
        yield ("policy", "RESOURCE_POLICY")
        yield ("policyDocument", "RESOURCE_POLICY")


def _validate_policy_resource_type(
    resource_type: str, field_name: str, policy_type: str
) -> str | None:
    """Map preview resource types to Access Analyzer resource validators."""
    if policy_type != "RESOURCE_POLICY":
        return None
    if field_name == "assumeRolePolicy":
        return "AWS::IAM::AssumeRolePolicyDocument"
    if "s3/bucket:Bucket" in resource_type or "s3/bucketPolicy:" in resource_type:
        return "AWS::S3::Bucket"
    return None


def parse_policy_document(value: object) -> dict[str, Any] | None:
    """Parse a JSON IAM policy document."""
    if isinstance(value, dict):
        return cast(dict[str, Any], value)
    if not isinstance(value, str):
        return None
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def step_resource_type(step: dict[str, Any]) -> str:
    """Return the best available resource type for a preview step."""
    for key in ("newState", "oldState"):
        state = step.get(key)
        if isinstance(state, dict) and isinstance(state.get("type"), str):
            return state["type"]
    return ""


def write_iam_inputs(path: Path, *, preview_paths: Sequence[Path]) -> None:
    """Serialize IAM validation inputs to disk for CI artifact inspection."""
    items: list[dict[str, str]] = []
    for preview_path in preview_paths:
        items.extend(extract_iam_validation_inputs(preview_path))
    path.write_text(json.dumps(items, indent=2, sort_keys=True), encoding="utf-8")


def _build_parser() -> argparse.ArgumentParser:
    """Construct the CLI parser for the guardrail helper entrypoints."""
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    summarize_parser = subparsers.add_parser("summarize")
    summarize_parser.add_argument("preview_files", nargs="+", type=Path)

    destructive_parser = subparsers.add_parser("destructive-gate")
    destructive_parser.add_argument("preview_files", nargs="+", type=Path)
    destructive_parser.add_argument(
        "--event-path",
        default=os.environ.get("GITHUB_EVENT_PATH"),
    )

    iam_inputs_parser = subparsers.add_parser("iam-inputs")
    iam_inputs_parser.add_argument("preview_files", nargs="+", type=Path)
    iam_inputs_parser.add_argument("--output", required=True, type=Path)

    validate_iam_parser = subparsers.add_parser("validate-iam")
    validate_iam_parser.add_argument("preview_files", nargs="+", type=Path)
    return parser


def _run_summarize(preview_files: Sequence[Path]) -> int:
    """Print Markdown summaries for each preview artifact."""
    for preview_file in preview_files:
        sys.stdout.write(summarize_preview(preview_file))
    return 0


def _run_destructive_gate(
    preview_files: Sequence[Path], *, event_path: str | None
) -> int:
    """Fail unless dangerous preview steps were explicitly approved."""
    override = load_destructive_override(event_path)
    findings: list[str] = []
    for preview_file in preview_files:
        for step in find_destructive_steps(preview_steps(load_preview(preview_file))):
            findings.append(f"{step.get('op')} {step_resource_type(step)}")

    if findings and not override:
        for finding in findings:
            print(f"destructive change blocked: {finding}", file=sys.stderr)
        print(
            f"Apply the `{DESTRUCTIVE_OVERRIDE_LABEL}` label only after manual review.",
            file=sys.stderr,
        )
        return 1
    return 0


def _run_validate_iam(preview_files: Sequence[Path]) -> int:
    """Validate every extracted IAM document and surface actionable findings."""
    inputs: list[dict[str, str]] = []
    for preview_file in preview_files:
        inputs.extend(extract_iam_validation_inputs(preview_file))

    if not inputs:
        print("No IAM policy documents were present in the Pulumi preview.")
        return 0

    try:
        failures = validate_iam_inputs(inputs)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        return 1

    print(f"Validated {len(inputs)} IAM policy document(s) with Access Analyzer.")
    return 0


def cli(argv: Sequence[str] | None = None) -> int:
    """Run the requested guardrail helper command."""
    args = _build_parser().parse_args(argv)

    if args.command == "summarize":
        return _run_summarize(args.preview_files)

    if args.command == "destructive-gate":
        return _run_destructive_gate(args.preview_files, event_path=args.event_path)

    if args.command == "iam-inputs":
        write_iam_inputs(args.output, preview_paths=args.preview_files)
        return 0

    if args.command == "validate-iam":
        return _run_validate_iam(args.preview_files)

    raise AssertionError(f"Unhandled command: {args.command}")  # pragma: no cover


if __name__ == "__main__":
    raise SystemExit(cli())
