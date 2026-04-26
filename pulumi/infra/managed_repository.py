"""Typed repository metadata used by bootstrap infrastructure components."""

from __future__ import annotations

import datetime as dt
import re
from dataclasses import dataclass

_VALID_LIFECYCLE_STATES = frozenset({"active", "planned", "deprecated", "archived"})
_LAST_REVIEWED_PATTERN = re.compile(r"\d{4}-\d{2}-\d{2}")


def _required_string(value: object, label: str) -> str:
    """Return a stripped non-empty string or raise a typed validation error."""
    if not isinstance(value, str):
        raise TypeError(f"Managed repository {label} must be a string.")
    normalized = value.strip()
    if not normalized:
        if label == "name":
            raise ValueError("Managed repository name must be a non-empty string.")
        if label == "default_branch":
            raise ValueError("Managed repository default_branch must be non-empty.")
        raise ValueError(f"Managed repository {label} must be non-empty.")
    return normalized


def _optional_string(value: object, label: str) -> str | None:
    """Return a stripped optional string or raise a typed validation error."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise TypeError(f"Managed repository {label} must be a string when set.")
    normalized = value.strip()
    if not normalized:
        if label == "project":
            raise ValueError("Managed repository project must be non-empty when set.")
        raise ValueError(f"Managed repository {label} must be non-empty when set.")
    return normalized


def _lifecycle_state(value: object) -> str:
    """Normalize and validate repository lifecycle state."""
    normalized = _required_string(value, "lifecycle_state").lower()
    if normalized not in _VALID_LIFECYCLE_STATES:
        valid_states = ", ".join(sorted(_VALID_LIFECYCLE_STATES))
        raise ValueError(
            f"Managed repository lifecycle_state must be one of: {valid_states}."
        )
    return normalized


def _last_reviewed(value: object) -> str | None:
    """Normalize and validate optional last-reviewed date metadata."""
    normalized = _optional_string(value, "last_reviewed")
    if normalized is None:
        return None
    if not _LAST_REVIEWED_PATTERN.fullmatch(normalized):
        raise ValueError("Managed repository last_reviewed must use YYYY-MM-DD format.")
    try:
        dt.date.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError(
            "Managed repository last_reviewed must use YYYY-MM-DD format."
        ) from exc
    return normalized


def _expected_environments(value: object) -> int:
    """Validate expected environment fanout metadata."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("Managed repository expected_environments must be an int.")
    if value < 1:
        raise ValueError("Managed repository expected_environments must be at least 1.")
    return value


@dataclass(frozen=True)
class ManagedRepository:
    """Configuration for one managed GitHub repository."""

    name: str
    default_branch: str
    project: str | None = None
    owner: str | None = None
    lifecycle_state: str = "active"
    last_reviewed: str | None = None
    expected_environments: int = 2

    def __post_init__(self) -> None:
        normalized_name = _required_string(self.name, "name")
        normalized_branch = _required_string(self.default_branch, "default_branch")
        normalized_project = _optional_string(self.project, "project")
        normalized_owner = _optional_string(self.owner, "owner")
        normalized_lifecycle_state = _lifecycle_state(self.lifecycle_state)
        normalized_last_reviewed = _last_reviewed(self.last_reviewed)
        expected_environments = _expected_environments(self.expected_environments)

        object.__setattr__(self, "name", normalized_name)
        object.__setattr__(self, "default_branch", normalized_branch)
        object.__setattr__(self, "project", normalized_project)
        object.__setattr__(self, "owner", normalized_owner)
        object.__setattr__(self, "lifecycle_state", normalized_lifecycle_state)
        object.__setattr__(self, "last_reviewed", normalized_last_reviewed)
        object.__setattr__(self, "expected_environments", expected_environments)

    @property
    def project_name(self) -> str:
        """Return the configured project name or fall back to the repo name."""
        return self.project or self.name

    def evidence_metadata(self) -> dict[str, object]:
        """Return non-secret metadata used by reviews and quota guardrails."""
        metadata: dict[str, object] = {
            "defaultBranch": self.default_branch,
            "project": self.project_name,
            "lifecycleState": self.lifecycle_state,
            "expectedEnvironments": self.expected_environments,
        }
        if self.owner is not None:
            metadata["owner"] = self.owner
        if self.last_reviewed is not None:
            metadata["lastReviewed"] = self.last_reviewed
        return metadata

    def tag_metadata(self) -> dict[str, str]:
        """Return repository metadata in an AWS tag-safe string form."""
        tags = {
            "RepositoryLifecycle": self.lifecycle_state,
            "ExpectedEnvironments": str(self.expected_environments),
        }
        if self.owner is not None:
            tags["RepositoryOwner"] = self.owner
        if self.last_reviewed is not None:
            tags["RepositoryLastReviewed"] = self.last_reviewed
        return tags
