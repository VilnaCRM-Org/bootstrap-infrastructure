"""Repository catalog loading for bootstrap infrastructure."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pulumi

from .bootstrap_settings import BootstrapSettings
from .managed_repository import ManagedRepository


def _required_mapping_string(item: dict[str, Any], key: str, error_message: str) -> str:
    """Return a required non-empty string from a repository mapping."""
    value = item.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(error_message)
    return value.strip()


def _optional_mapping_string(
    item: dict[str, Any],
    key: str,
    *,
    fallback: str | None,
    error_message: str,
) -> str | None:
    """Return an optional non-empty string from a repository mapping."""
    value = item.get(key)
    if value is None:
        return fallback
    if not isinstance(value, str) or not value.strip():
        raise ValueError(error_message)
    return value.strip()


def _optional_mapping_int(
    item: dict[str, Any],
    key: str,
    *,
    fallback: int,
    error_message: str,
) -> int:
    """Return an optional positive integer from a repository mapping."""
    value = item.get(key)
    if value is None:
        return fallback
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(error_message)
    return value


class ManagedRepositoryCatalog:
    """Load and expose the repositories managed by the bootstrap stack."""

    def __init__(self, repositories: list[ManagedRepository]) -> None:
        if not repositories:
            raise ValueError("Managed repository catalog cannot be empty.")
        self._validate_unique_names(repositories)
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

    def metadata_mapping(self) -> dict[str, dict[str, object]]:
        """Return non-secret repository metadata for review and quota evidence."""
        return {
            repository.name: repository.evidence_metadata()
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
        cls._validate_unique_names(repositories)
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

        try:
            payload = json.loads(resolved_path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise ValueError(
                f"Unable to read repository catalog JSON '{resolved_path}'."
            ) from exc
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"Repository catalog JSON '{resolved_path}' is not valid JSON."
            ) from exc
        if not isinstance(payload, dict):
            raise ValueError("Repository catalog JSON must be an object.")
        repositories = payload.get("repositories")
        if repositories is None:
            raise ValueError("Repository catalog JSON must include 'repositories'.")
        return cls.load_from_items(repositories)

    @staticmethod
    def _repository_from_string(name: str) -> ManagedRepository:
        """Build a repository definition from a bare repository name."""
        normalized_name = name.strip()
        if not normalized_name:
            raise ValueError(
                "Each managedRepositories entry must be a non-empty string."
            )
        return ManagedRepository(
            name=normalized_name,
            default_branch="main",
            project=normalized_name,
        )

    @staticmethod
    def _repository_from_mapping(item: dict[str, Any]) -> ManagedRepository:
        """Build a repository definition from a mapping entry."""
        name = _required_mapping_string(
            item,
            "name",
            "Each managedRepositories entry must include a non-empty 'name'.",
        )
        default_branch = _optional_mapping_string(
            item,
            "defaultBranch",
            fallback="main",
            error_message=(
                "managedRepositories defaultBranch values must be non-empty strings."
            ),
        )
        project = _optional_mapping_string(
            item,
            "project",
            fallback=name,
            error_message=(
                "Each managedRepositories entry must include a non-empty 'project'."
            ),
        )
        owner = _optional_mapping_string(
            item,
            "owner",
            fallback=None,
            error_message=(
                "managedRepositories owner values must be non-empty strings."
            ),
        )
        lifecycle_state = _optional_mapping_string(
            item,
            "lifecycleState",
            fallback="active",
            error_message=(
                "managedRepositories lifecycleState values must be non-empty strings."
            ),
        )
        last_reviewed = _optional_mapping_string(
            item,
            "lastReviewed",
            fallback=None,
            error_message=(
                "managedRepositories lastReviewed values must be non-empty strings."
            ),
        )
        expected_environments = _optional_mapping_int(
            item,
            "expectedEnvironments",
            fallback=2,
            error_message=(
                "managedRepositories expectedEnvironments values must be integers."
            ),
        )

        return ManagedRepository(
            name=name,
            default_branch=default_branch,
            project=project,
            owner=owner,
            lifecycle_state=lifecycle_state,
            last_reviewed=last_reviewed,
            expected_environments=expected_environments,
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

    @staticmethod
    def _validate_unique_names(repositories: list[ManagedRepository]) -> None:
        """Reject duplicate repository names before downstream maps overwrite keys."""
        seen: dict[str, str] = {}
        duplicates: set[str] = set()

        for repository in repositories:
            normalized_name = repository.name.casefold()
            if normalized_name in seen:
                duplicates.add(seen[normalized_name])
                duplicates.add(repository.name)
            else:
                seen[normalized_name] = repository.name

        if duplicates:
            duplicate_names = ", ".join(sorted(duplicates, key=str.casefold))
            raise ValueError(
                f"Managed repository names must be unique: {duplicate_names}."
            )
