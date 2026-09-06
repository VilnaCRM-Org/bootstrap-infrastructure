#!/usr/bin/env python3
"""Validate commercial-AWS CI configuration without printing derived values."""

from __future__ import annotations

import argparse
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import SplitResult, parse_qs, unquote, urlsplit

AWS_ACCOUNT_ID_PATTERN = re.compile(r"^[0-9]{12}$")
AWS_REGION_PATTERN = re.compile(r"^(?!cn-)[a-z]{2}-[a-z]+-[0-9]+$")
AWS_ROLE_ARN_PATTERN = re.compile(r"^arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]+$")
SNS_TOPIC_ARN_PATTERN = re.compile(
    r"^arn:aws:sns:[a-z0-9-]+:[0-9]{12}:[A-Za-z0-9_.-]+$"
)


@dataclass(frozen=True)
class ValidationIssue:
    """One non-secret validation failure."""

    name: str
    message: str


def parse_required_keys(raw_value: str) -> tuple[str, ...]:
    """Parse the action's newline/comma-delimited required environment keys."""
    return tuple(
        key.strip()
        for line in raw_value.splitlines()
        for key in line.split(",")
        if key.strip()
    )


def missing_or_blank(keys: tuple[str, ...], environ: Mapping[str, str]) -> list[str]:
    """Return required environment variable names that are unset or blank."""
    return [key for key in keys if not environ.get(key, "").strip()]


def validate_environment(
    keys: tuple[str, ...],
    environ: Mapping[str, str],
) -> list[ValidationIssue]:
    """Return non-secret validation failures for AWS Secrets Manager-derived values."""
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
        "PULUMI_DIR": _validate_pulumi_dir,
        "PULUMI_SECRETS_PROVIDER": lambda value: _validate_secrets_provider(
            value, environ
        ),
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
        value = environ[key]
        if key not in {"PULUMI_BACKEND_URL", "PULUMI_SECRETS_PROVIDER"}:
            value = value.strip()
        message = validator(value)
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
    return "must be a commercial AWS region code"


def _validate_role_arn(value: str) -> str | None:
    if AWS_ROLE_ARN_PATTERN.fullmatch(value):
        return None
    return "must be an IAM role ARN in the commercial aws partition"


def _validate_backend_url(value: str) -> str | None:
    """Mirror the frozen stack parser's exact S3 bucket/path contract."""
    invalid = (
        "must be an exact s3:// bucket/backend path without escapes, query or fragment"
    )
    if re.search(r"[%\\\x00-\x20]", value):
        return invalid
    try:
        backend = urlsplit(value)
    except ValueError:
        return invalid
    if (
        backend.scheme == "s3"
        and re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", backend.netloc)
        and not backend.query
        and not backend.fragment
        and all(
            part not in {".", "..", ""}
            for part in backend.path.removeprefix("/").split("/")
            if backend.path.removeprefix("/")
        )
    ):
        return None
    return invalid


def _validate_pulumi_dir(value: str) -> str | None:
    if re.fullmatch(r"pulumi(?:/[A-Za-z0-9_.-]+)*", value):
        return None
    return "must be a safe Pulumi project path"


def _validate_secrets_provider(value: str, environ: Mapping[str, str]) -> str | None:
    """Check KMS URI and explicit ARN pins before any Pulumi metadata access."""
    invalid = (
        "must use an existing KMS identifier and exact pinned "
        "commercial AWS account/region"
    )
    try:
        provider = urlsplit(value)
    except ValueError:
        return invalid
    region = environ.get("AWS_REGION") or environ.get("AWS_DEFAULT_REGION", "")
    account = environ.get("AWS_ACCOUNT_ID", "")
    identifier = unquote(provider.netloc + provider.path)
    if not _provider_uri_matches_context(value, provider, identifier, region, account):
        return invalid
    if identifier.lower().startswith("arn:"):
        arn = re.fullmatch(
            r"arn:aws:kms:([^:]+):([0-9]{12}):(?:key|alias)/[A-Za-z0-9/_-]+",
            identifier,
        )
        if not arn or arn.group(1) != region or arn.group(2) != account:
            return invalid
    # Aliases and bare key IDs need the existing describe-key check to establish
    # their actual account, region and Enabled state; URI syntax cannot prove it.
    return None


def _provider_uri_matches_context(
    value: str, provider: SplitResult, identifier: str, region: str, account: str
) -> bool:
    """Validate URI structure and its independently configured account/region."""
    return (
        value.startswith("awskms://")
        and not provider.fragment
        and bool(identifier)
        and re.search(r"[\x00-\x20]", value + identifier) is None
        and AWS_REGION_PATTERN.fullmatch(region) is not None
        and AWS_ACCOUNT_ID_PATTERN.fullmatch(account) is not None
        and parse_qs(provider.query, keep_blank_values=True) == {"region": [region]}
    )


def _validate_stack_list(value: str) -> str | None:
    stacks = [stack.strip() for stack in value.split(",") if stack.strip()]
    if stacks and all(re.fullmatch(r"[A-Za-z0-9_.:-]+", stack) for stack in stacks):
        return None
    return "must be a comma-separated list of stack names"


def _validate_sns_topic_arn(value: str) -> str | None:
    if SNS_TOPIC_ARN_PATTERN.fullmatch(value):
        return None
    return "must be an SNS topic ARN in the commercial aws partition"


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
        description="Validate CI configuration injected from AWS Secrets Manager."
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
    print(
        "Validated AWS Secrets Manager-derived CI configuration "
        f"for {args.purpose} using a fixed CI secret."
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
