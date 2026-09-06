"""Fail closed before allocating resources in an unexpected AWS account."""

import re


def assert_bootstrap_account(expected: str | None, actual: str) -> None:
    """Reject missing, malformed or mismatched account config before allocation."""
    if expected is None or re.fullmatch(r"[0-9]{12}", expected) is None:
        raise ValueError("github-ci-bootstrap requires a 12-digit awsAccountId")
    if actual != expected:
        raise ValueError(
            f"github-ci-bootstrap account mismatch: expected {expected}, got {actual}"
        )
