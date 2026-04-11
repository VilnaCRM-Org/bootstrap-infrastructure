"""Configuration loading for the VilnaCRM Pulumi policy pack."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping, cast

import yaml

POLICY_ROOT = Path(__file__).resolve().parent
POLICY_CONFIG_FILE = POLICY_ROOT / "vilnacrm_guardrails.yaml"


@dataclass(frozen=True)
class PolicyConfig:
    """Normalized guardrail settings loaded from the repo policy config."""

    required_tags: tuple[str, ...]
    allowed_regions: tuple[str, ...]
    production_environments: tuple[str, ...]
    public_s3_bucket_allowlist: frozenset[str]
    wildcard_iam_allowlist: frozenset[str]
    annotations: Mapping[str, str]


def load_policy_config(path: Path | None = None) -> PolicyConfig:
    """Load and normalize the VilnaCRM policy configuration document."""
    document = _load_config_document(path or POLICY_CONFIG_FILE)
    allowlists = _mapping(document.get("allowlists"), label="allowlists")

    return PolicyConfig(
        required_tags=tuple(_required_string_list(document, "required_tags")),
        allowed_regions=tuple(_required_string_list(document, "allowed_regions")),
        production_environments=tuple(
            _required_string_list(document, "production_environments")
        ),
        public_s3_bucket_allowlist=frozenset(
            _string_list(
                allowlists.get("public_s3_buckets"),
                "allowlists.public_s3_buckets",
            )
        ),
        wildcard_iam_allowlist=frozenset(
            _string_list(
                allowlists.get("wildcard_iam"),
                "allowlists.wildcard_iam",
            )
        ),
        annotations=MappingProxyType(
            _string_mapping(
                document.get("annotations"),
                label="annotations",
            )
        ),
    )


def _load_config_document(path: Path) -> dict[str, Any]:
    """Read the YAML config file and return the mapping document."""
    content = path.read_text(encoding="utf-8")
    document = yaml.safe_load(content)
    if not isinstance(document, dict):
        raise ValueError(f"{path} must contain a top-level mapping.")
    return document


def _mapping(value: object, *, label: str) -> dict[str, Any]:
    """Normalize optional mapping values while rejecting invalid shapes."""
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a mapping.")
    return cast(dict[str, Any], value)


def _string_list(value: object, label: str) -> list[str]:
    """Normalize a list of non-empty strings."""
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError(f"{label} must be a list.")

    normalized: list[str] = []
    for item in value:
        normalized.append(_string_value(item, label))
    return normalized


def _required_string_list(document: Mapping[str, object], label: str) -> list[str]:
    """Require a list-valued setting to be present in the config document."""
    if label not in document:
        raise ValueError(f"{label} is required.")
    return _string_list(document[label], label)


def _string_mapping(value: object, *, label: str) -> dict[str, str]:
    """Normalize mappings whose keys and values must both be strings."""
    mapping = _mapping(value, label=label)
    return {
        _string_value(key, f"{label}.key"): _string_value(item, f"{label}[{key!r}]")
        for key, item in mapping.items()
    }


def _string_value(value: object, label: str) -> str:
    """Require a non-empty string value."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty string.")
    return value.strip()
