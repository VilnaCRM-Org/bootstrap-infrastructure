"""Exact GitHub identities for legacy and immutable OIDC subject formats."""

from __future__ import annotations

import json
import re
from collections.abc import Sequence


def normalize_identity(
    repository_id: str | int | None, owner_id: str | int | None
) -> tuple[str | None, str | None]:
    """Validate a complete pair of canonical positive ASCII decimal IDs."""
    if repository_id is None and owner_id is None:
        return None, None
    values = []
    for value in (repository_id, owner_id):
        if (
            isinstance(value, bool)
            or not isinstance(value, (str, int))
            or re.fullmatch(r"[1-9][0-9]*", str(value)) is None
        ):
            raise ValueError(
                "GitHub repository_id and repository_owner_id must both be "
                "canonical positive ASCII decimal IDs."
            )
        values.append(str(value))
    return values[0], values[1]


def identity_conditions(
    repository_id: str | int | None, owner_id: str | int | None
) -> dict[str, str]:
    """Pin JWT identity claims; omitted pairs retain legacy library compatibility."""
    repository_id, owner_id = normalize_identity(repository_id, owner_id)
    if repository_id is None:
        return {}
    return {
        "token.actions.githubusercontent.com:repository_id": repository_id,
        "token.actions.githubusercontent.com:repository_owner_id": str(owner_id),
    }


def expand_subjects(
    subjects: Sequence[str],
    repository: str,
    repository_id: str | int | None,
    owner_id: str | int | None,
) -> list[str]:
    """Preserve exact allowed contexts while adding the pinned immutable format."""
    repository_id, owner_id = normalize_identity(repository_id, owner_id)
    if re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) is None:
        raise ValueError("GitHub repository must be an exact owner/repository name.")
    prefix = f"repo:{repository}:"
    owner, name = repository.split("/")
    expanded = []
    for subject in subjects:
        if not subject.startswith(prefix) or subject == prefix:
            raise ValueError(
                "GitHub OIDC subject must belong to the pinned repository."
            )
        expanded.append(subject)
        if repository_id is not None:
            expanded.append(
                f"repo:{owner}@{owner_id}/{name}@{repository_id}:"
                f"{subject[len(prefix) :]}"
            )
    return list(dict.fromkeys(expanded))


def validate_trust_policy_size(document: str) -> str:
    """Keep exact subjects within the default, unraised IAM trust quota.

    AWS excludes insignificant JSON whitespace. Return the original serialization
    so supported existing roles retain their exact policy documents.
    """
    size = len(json.dumps(json.loads(document), separators=(",", ":")))
    if size > 2048:
        raise ValueError(
            f"GitHub OIDC trust policy is {size} characters; supported default IAM "
            "quota is 2048. Shorten configured identity/context names or review "
            "an explicit account trust-quota increase (AWS maximum 8192) and "
            "update the supported contract; do not remove identity claims."
        )
    return document
