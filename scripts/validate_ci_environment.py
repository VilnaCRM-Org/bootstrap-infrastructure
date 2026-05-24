#!/usr/bin/env python3
"""Validate ESC-derived CI configuration without printing secret values."""

from __future__ import annotations

import argparse
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass

AWS_ACCOUNT_ID_PATTERN = re.compile(r"^\d{12}$")
AWS_REGION_PATTERN = re.compile(r"^[a-z]{2}-[a-z]+-\d+$")
AWS_ROLE_ARN_PATTERN = re.compile(r"^arn:aws:iam::\d{12}:role/[A-Za-z0-9+=,.@_/-]+$")
SNS_TOPIC_ARN_PATTERN = re.compile(r"^arn:aws:sns:[a-z0-9-]+:\d{12}:[A-Za-z0-9_.-]+$")


@dataclass(frozen=True)
class ValidationIssue:
    """One non-secret validation failure."""

    name: str
    message: str


def parse_required_keys(raw_value: str) -> tuple[str, ...]:
    """Parse a comma-separated key list from the composite action input."""
    return tuple(key.strip() for key in raw_value.split(",") if key.strip())


def missing_or_blank(keys: tuple[str, ...], environ: Mapping[str, str]) -> list[str]:
    """Return required environment variable names that are unset or blank."""
    return [key for key in keys if not environ.get(key, "").strip()]


def validate_environment(
    keys: tuple[str, ...],
    environ: Mapping[str, str],
) -> list[ValidationIssue]:
    """Return non-secret validation failures for ESC-derived values."""
    issues = [
        ValidationIssue(key, "is required") for key in missing_or_blank(keys, environ)
    ]
    if issues:
        return issues

    validators = {
        "AWS_ACCOUNT_ID": _validate_account_id,
        "AWS_REGION": _validate_region,
        "AWS_PREVIEW_ROLE_ARN": _validate_role_arn,
        "AWS_APPLY_ROLE_ARN": _validate_role_arn,
        "AWS_DRIFT_ROLE_ARN": _validate_role_arn,
        "AWS_OPERATIONS_ALERT_TRIAGE_ROLE_ARN": _validate_role_arn,
        "PULUMI_BACKEND_URL": _validate_backend_url,
        "PULUMI_SECRETS_PROVIDER": _validate_secrets_provider,
        "PULUMI_PREVIEW_STACKS": _validate_stack_list,
        "PULUMI_DRIFT_STACKS": _validate_stack_list,
        "OPERATIONS_TOPIC_ARN": _validate_sns_topic_arn,
        "OPERATIONS_ALERT_QUEUE_NAME": _validate_resource_name,
        "OPERATIONS_CLOUDTRAIL_NAME": _validate_resource_name,
    }
    for key in keys:
        validator = validators.get(key)
        if validator is None:
            continue
        message = validator(environ[key].strip())
        if message:
            issues.append(ValidationIssue(key, message))
    return issues


def _validate_account_id(value: str) -> str | None:
    if AWS_ACCOUNT_ID_PATTERN.fullmatch(value):
        return None
    return "must be a 12-digit AWS account ID"


def _validate_region(value: str) -> str | None:
    if AWS_REGION_PATTERN.fullmatch(value):
        return None
    return "must be an AWS region code"


def _validate_role_arn(value: str) -> str | None:
    if AWS_ROLE_ARN_PATTERN.fullmatch(value):
        return None
    return "must be an IAM role ARN"


def _validate_backend_url(value: str) -> str | None:
    if value.startswith("s3://"):
        return None
    return "must use an s3:// Pulumi backend"


def _validate_secrets_provider(value: str) -> str | None:
    if value.startswith("awskms://"):
        return None
    return "must use an awskms:// Pulumi secrets provider"


def _validate_stack_list(value: str) -> str | None:
    stacks = [stack.strip() for stack in value.split(",") if stack.strip()]
    if stacks and all(re.fullmatch(r"[A-Za-z0-9_.:-]+", stack) for stack in stacks):
        return None
    return "must be a comma-separated list of stack names"


def _validate_sns_topic_arn(value: str) -> str | None:
    if SNS_TOPIC_ARN_PATTERN.fullmatch(value):
        return None
    return "must be an SNS topic ARN"


def _validate_resource_name(value: str) -> str | None:
    if re.fullmatch(r"[A-Za-z0-9_.-]{1,256}", value):
        return None
    return "must be a metadata-only AWS resource name"


def write_github_environment(
    environ: Mapping[str, str],
    output_path: str | None,
) -> None:
    """Persist derived environment values for later GitHub Actions steps."""
    if not output_path:
        return
    aws_region = _github_env_value("AWS_REGION", environ.get("AWS_REGION", ""))
    with open(output_path, "a", encoding="utf-8") as github_env:
        if aws_region:
            github_env.write(f"AWS_DEFAULT_REGION={aws_region}\n")


def _github_env_value(name: str, value: str) -> str:
    """Return a single-line value safe for GitHub environment files."""
    stripped = value.strip()
    if "\n" in stripped or "\r" in stripped:
        raise ValueError(f"{name} must not contain newline characters")
    return stripped


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate CI configuration injected from Pulumi ESC."
    )
    parser.add_argument("--purpose", required=True)
    parser.add_argument("--required-keys", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    required_keys = parse_required_keys(args.required_keys)
    if not required_keys:
        print("error: required-keys must include at least one environment variable.")
        return 1

    issues = validate_environment(required_keys, os.environ)
    if issues:
        for issue in issues:
            print(f"error: {issue.name} {issue.message}.")
        return 1

    try:
        write_github_environment(os.environ, os.environ.get("GITHUB_ENV"))
    except ValueError as exc:
        print(f"error: {exc}.")
        return 1
    esc_environment = os.environ.get("PULUMI_ESC_ENVIRONMENT", "unknown")
    print(
        "Validated ESC-derived CI configuration "
        f"for {args.purpose} using {esc_environment}."
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
