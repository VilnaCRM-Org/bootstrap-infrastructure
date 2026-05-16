from __future__ import annotations

from typing import cast


def _metadata_int(value: object) -> int | None:
    """Parse an AWS metadata integer represented as a JSON string or number."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return None
    return None


def _metadata_dict(
    ok: bool,
    payload: object,
    error: str,
    label: str,
) -> tuple[dict[str, object], list[str]]:
    """Normalize a metadata command expected to return a JSON object."""
    if ok and isinstance(payload, dict):
        return cast(dict[str, object], payload), []
    return {}, [f"Unable to query {label}: {error}"]


def _metadata_list(
    ok: bool,
    payload: object,
    error: str,
    label: str,
) -> tuple[list[object], list[str]]:
    """Normalize a metadata command expected to return a JSON list."""
    if ok and isinstance(payload, list):
        return cast(list[object], payload), []
    return [], [f"Unable to query {label}: {error}"]
