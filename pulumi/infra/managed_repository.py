"""Typed repository metadata used by bootstrap infrastructure components."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ManagedRepository:
    """Configuration for one managed GitHub repository."""

    name: str
    default_branch: str
    project: str | None = None

    def __post_init__(self) -> None:
        normalized_name = self.name.strip()
        normalized_branch = self.default_branch.strip()
        normalized_project = (
            self.project.strip() if isinstance(self.project, str) else self.project
        )

        if not normalized_name:
            raise ValueError("Managed repository name must be a non-empty string.")
        if not normalized_branch:
            raise ValueError("Managed repository default_branch must be non-empty.")
        if normalized_project is not None and not normalized_project:
            raise ValueError("Managed repository project must be non-empty when set.")

        object.__setattr__(self, "name", normalized_name)
        object.__setattr__(self, "default_branch", normalized_branch)
        object.__setattr__(self, "project", normalized_project)

    @property
    def project_name(self) -> str:
        """Return the configured project name or fall back to the repo name."""
        return self.project or self.name
