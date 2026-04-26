#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

from _script_support import repo_root
from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError, ValidationError

ROOT_DIR = repo_root(__file__)


def repository_catalog_paths(root_dir: Path) -> list[Path]:
    """Return committed repository catalog JSON files, excluding the schema."""
    return sorted(
        path
        for path in (root_dir / "pulumi").glob("repositories*.json")
        if path.name != "repositories.schema.json"
    )


def _load_json(path: Path) -> Any:
    """Load a JSON document for schema validation."""
    return json.loads(path.read_text(encoding="utf-8"))


def _json_pointer(path_parts: Sequence[object]) -> str:
    """Render a readable JSON path for a validation error."""
    pointer = "$"
    for part in path_parts:
        if isinstance(part, int):
            pointer = f"{pointer}[{part}]"
        else:
            pointer = f"{pointer}.{part}"
    return pointer


def _format_schema_error(error: ValidationError) -> str:
    """Format the most specific schema validation failure."""
    return f"{_json_pointer(error.absolute_path)}: {error.message}"


def _required_non_blank_string(value: object, label: str) -> str:
    """Return a stripped string or raise the loader-compatible validation error."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(label)
    return value.strip()


def _repository_name(item: object) -> str:
    """Normalize one repository catalog entry name."""
    if isinstance(item, str):
        return _required_non_blank_string(
            item,
            "Each managedRepositories entry must be a non-empty string.",
        )
    if isinstance(item, Mapping):
        return _required_non_blank_string(
            item.get("name"),
            "Each managedRepositories entry must include a non-empty 'name'.",
        )
    raise ValueError(
        "Each managedRepositories entry must be a string or an object with 'name'."
    )


def _validate_repository_mapping(item: Mapping[str, object]) -> None:
    """Validate optional repository mapping fields that default in the loader."""
    raw_default_branch = item.get("defaultBranch")
    if raw_default_branch is not None:
        _required_non_blank_string(
            raw_default_branch,
            "managedRepositories defaultBranch values must be non-empty strings.",
        )

    raw_project = item.get("project")
    if raw_project is not None:
        _required_non_blank_string(
            raw_project,
            "Each managedRepositories entry must include a non-empty 'project'.",
        )


def _validate_loader_semantics(payload: Mapping[str, object]) -> None:
    """Validate catalog rules that the JSON Schema cannot fully express."""
    repositories = payload["repositories"]
    if not isinstance(repositories, list):
        raise ValueError("managedRepositories config must be a list.")

    seen: dict[str, str] = {}
    duplicates: set[str] = set()
    for item in repositories:
        name = _repository_name(item)
        if isinstance(item, Mapping):
            _validate_repository_mapping(item)
        normalized_name = name.casefold()
        if normalized_name in seen:
            duplicates.add(seen[normalized_name])
            duplicates.add(name)
        else:
            seen[normalized_name] = name

    if duplicates:
        duplicate_names = ", ".join(sorted(duplicates, key=str.casefold))
        raise ValueError(f"Managed repository names must be unique: {duplicate_names}.")


def validate_catalog(catalog_path: Path, schema_path: Path) -> Path:
    """Validate one repository catalog against JSON Schema and loader semantics."""
    schema = _load_json(schema_path)
    payload = _load_json(catalog_path)
    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError as exc:
        raise ValueError(
            f"{schema_path}: invalid repository catalog schema: {exc.message}"
        ) from exc
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(payload), key=lambda item: item.json_path)
    if errors:
        raise ValueError(f"{catalog_path}: {_format_schema_error(errors[0])}")

    _validate_loader_semantics(payload)
    return catalog_path


def validate_catalogs(catalog_paths: Sequence[Path], schema_path: Path) -> list[Path]:
    """Validate all repository catalog files."""
    return [
        validate_catalog(catalog_path, schema_path) for catalog_path in catalog_paths
    ]


def main(argv: Sequence[str] | None = None) -> int:
    """Validate committed repository catalog JSON files."""
    parser = argparse.ArgumentParser(
        description="Validate repository catalog JSON files.",
    )
    parser.add_argument(
        "catalogs",
        nargs="*",
        type=Path,
        help="Repository catalog JSON files. Defaults to pulumi/repositories*.json.",
    )
    parser.add_argument(
        "--schema",
        type=Path,
        default=ROOT_DIR / "pulumi" / "repositories.schema.json",
        help="JSON Schema file used for repository catalogs.",
    )
    args = parser.parse_args(argv)

    catalog_paths = list(args.catalogs) or repository_catalog_paths(ROOT_DIR)
    if not catalog_paths:
        print("error: no repository catalog JSON files found.", file=sys.stderr)
        return 1

    try:
        validated_paths = validate_catalogs(catalog_paths, args.schema)
    except (json.JSONDecodeError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    for path in validated_paths:
        print(f"validated repository catalog: {path}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
