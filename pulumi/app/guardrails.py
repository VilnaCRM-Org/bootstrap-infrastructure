"""Input guardrails for the Pulumi application layer."""

from __future__ import annotations

import re

# 1-32 lowercase alphanumeric chars; hyphens are allowed only in the middle.
_IDENTIFIER_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$")


def _validate_identifier(value: str, *, label: str) -> str:
    """Require stable lowercase identifiers for stack metadata."""
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string.")

    normalized = value.strip()

    if not normalized:
        raise ValueError(f"{label} must not be empty.")

    if normalized != value:
        raise ValueError(f"{label} must not contain surrounding whitespace.")

    if not _IDENTIFIER_PATTERN.fullmatch(normalized):
        raise ValueError(
            f"{label} must use lowercase letters, digits, and hyphens only."
        )

    return normalized


def validate_environment_name(value: str) -> str:
    """Validate the environment name used in stack exports and tags."""
    return _validate_identifier(value, label="environment")


def validate_service_name(value: str) -> str:
    """Validate the service name used in stack exports and tags."""
    return _validate_identifier(value, label="service name")
