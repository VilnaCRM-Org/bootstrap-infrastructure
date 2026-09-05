"""Metadata-only discovery for operator adoption of existing IAM attachments."""

from __future__ import annotations

import json
import subprocess  # nosec B404

import pulumi_aws as aws


def _assert_cli_account() -> None:
    """Ensure CLI discovery cannot use a different account from the AWS provider."""
    expected = aws.get_caller_identity().account_id
    result = subprocess.run(  # nosec B603 B607
        ["aws", "sts", "get-caller-identity", "--query", "Account", "--output", "text"],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if result.returncode or result.stdout.strip() != expected:
        raise RuntimeError("IAM adoption CLI account does not match Pulumi provider")


def _role_metadata(operation: str, role_name: str, field: str) -> list:
    """List names/ARNs only; unknown API errors must never become create decisions."""
    _assert_cli_account()
    result = subprocess.run(  # nosec B603 B607
        ["aws", "iam", operation, "--role-name", role_name, "--output", "json"],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if result.returncode:
        if "(NoSuchEntity)" in result.stderr:
            return []
        raise RuntimeError(f"IAM adoption metadata failed for {operation}")
    return json.loads(result.stdout)[field]


def _validate_preferred_name(prefix: str, preferred_name: str | None) -> None:
    """A configured adoption pin cannot escape its allowed policy family."""
    if preferred_name is not None and not (
        preferred_name == prefix or preferred_name.startswith(prefix + "-")
    ):
        raise ValueError("Preferred inline policy is outside the allowed prefix")


def inline_policy_name(
    role_name: str, prefix: str, *, preferred_name: str | None = None
) -> str | None:
    """Resolve one exact or prior Pulumi-generated policy name, rejecting ambiguity."""
    _validate_preferred_name(prefix, preferred_name)
    names = _role_metadata("list-role-policies", role_name, "PolicyNames")
    if preferred_name is not None:
        if preferred_name not in names:
            raise ValueError("Preferred inline policy is absent from live metadata")
        return preferred_name
    matching = [
        name for name in names if name == prefix or name.startswith(prefix + "-")
    ]
    if len(matching) > 1:
        raise ValueError(f"Ambiguous existing inline policy for {role_name}/{prefix}")
    return matching[0] if matching else None


def attachment_exists(role_name: str, policy_arn: str) -> bool:
    """Check one exact managed policy attachment without retrieving its document."""
    attached = _role_metadata(
        "list-attached-role-policies", role_name, "AttachedPolicies"
    )
    return any(policy["PolicyArn"] == policy_arn for policy in attached)
