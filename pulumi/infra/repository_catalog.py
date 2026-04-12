"""Repository catalog loading for bootstrap infrastructure."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pulumi

from .bootstrap_settings import BootstrapSettings
from .managed_repository import ManagedRepository


class ManagedRepositoryCatalog:
    """Load and expose the repositories managed by the bootstrap stack."""

    def __init__(self, repositories: list[ManagedRepository]) -> None:
        if not repositories:
            raise ValueError("Managed repository catalog cannot be empty.")
        self._repositories = repositories

    @property
    def repositories(self) -> list[ManagedRepository]:
        """Return a copy of the managed repository list."""
        return list(self._repositories)

    def project_mapping(self) -> dict[str, str]:
        """Return the resolved repo-to-project mapping."""
        return {
            repository.name: repository.project_name
            for repository in self._repositories
        }

    @classmethod
    def from_settings(
        cls,
        settings: BootstrapSettings,
        cfg: pulumi.Config | None = None,
    ) -> "ManagedRepositoryCatalog":
        """Build the repository catalog from JSON config, inline config, or repoSlug."""
        config = cfg or pulumi.Config()
        if settings.managed_repo_overrides:
            return cls(list(settings.managed_repo_overrides))
        if settings.repository_catalog_path:
            return cls(cls.load_from_json_file(settings.repository_catalog_path))

        inline = config.get_object("managedRepositories")
        if inline is not None:
            return cls(cls.load_from_items(inline))
        if settings.repo:
            return cls(
                [
                    ManagedRepository(
                        name=settings.repo,
                        default_branch=settings.github_branch or "main",
                        project=settings.repo,
                    )
                ]
            )
        raise ValueError(
            "No managed repositories specified. Set "
            "bootstrap-infrastructure:repositoryCatalogPath or "
            "bootstrap-infrastructure:managedRepositories, or provide repoSlug."
        )

    @classmethod
    def load_from_items(cls, raw: Any) -> list[ManagedRepository]:
        """Normalize inline repository config into typed repository definitions."""
        if raw is None:
            return []
        if not isinstance(raw, list):
            raise ValueError(
                "managedRepositories config must be a list of repository names or "
                "objects."
            )
        repositories = [cls.repository_from_item(item) for item in raw]
        if not repositories:
            raise ValueError("managedRepositories config cannot be empty.")
        return repositories

    @classmethod
    def load_from_json_file(cls, path: str) -> list[ManagedRepository]:
        """Load repository definitions from a JSON file."""
        resolved_path = Path(path).expanduser()
        if not resolved_path.is_absolute():
            resolved_path = (Path.cwd() / resolved_path).resolve()
        if not resolved_path.is_file():
            raise ValueError(
                f"repositoryCatalogPath '{resolved_path}' must point to a JSON file."
            )

        payload = json.loads(resolved_path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("Repository catalog JSON must be an object.")
        repositories = payload.get("repositories")
        if repositories is None:
            raise ValueError("Repository catalog JSON must include 'repositories'.")
        return cls.load_from_items(repositories)

    @staticmethod
    def _repository_from_string(name: str) -> ManagedRepository:
        """Build a repository definition from a bare repository name."""
        return ManagedRepository(name=name, default_branch="main", project=name)

    @staticmethod
    def _repository_from_mapping(item: dict[str, Any]) -> ManagedRepository:
        """Build a repository definition from a mapping entry."""
        name = item.get("name")
        default_branch = item.get("defaultBranch") or "main"
        project = item.get("project") or name

        if not isinstance(name, str) or not name.strip():
            raise ValueError(
                "Each managedRepositories entry must include a non-empty 'name'."
            )
        if not isinstance(default_branch, str) or not default_branch.strip():
            raise ValueError(
                "managedRepositories defaultBranch values must be non-empty strings."
            )
        if not isinstance(project, str) or not project.strip():
            raise ValueError(
                "Each managedRepositories entry must include a non-empty 'project'."
            )

        return ManagedRepository(
            name=name,
            default_branch=default_branch,
            project=project,
        )

    @staticmethod
    def repository_from_item(item: Any) -> ManagedRepository:
        """Normalize one inline repository config object."""
        if isinstance(item, str):
            return ManagedRepositoryCatalog._repository_from_string(item)
        if isinstance(item, dict):
            return ManagedRepositoryCatalog._repository_from_mapping(item)
        raise ValueError(
            "Each managedRepositories entry must be a string or an object with 'name'."
        )
