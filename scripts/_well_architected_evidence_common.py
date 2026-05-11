from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import _well_architected_structured_evidence as _structured_evidence
from _script_support import run

Runner = Callable[..., Any]
_read_required_structured_evidence = (
    _structured_evidence._read_required_structured_evidence
)


@dataclass(frozen=True)
class OptionalOwnerEvidenceSpec:
    """Validation hooks for optional owner evidence attached to live metadata."""

    label: str
    required_fields: Sequence[str]
    payload_blockers: Callable[[dict[str, Any], dict[str, object]], list[str]]
    summary: Callable[[Path, dict[str, Any]], dict[str, object]]


def _check(
    name: str,
    *,
    status: str,
    evidence: dict[str, object] | None = None,
    blockers: Sequence[str] = (),
) -> dict[str, object]:
    """Return one normalized non-secret evidence check."""
    return {
        "name": name,
        "status": status,
        "evidence": evidence or {},
        "blockers": list(blockers),
    }


def _run_json(
    command: list[str],
    *,
    runner: Runner = run,
) -> tuple[bool, Any, str]:
    """Run a metadata-only command and parse its JSON output."""
    result = runner(command, check=False, capture_output=True)
    if result.returncode != 0:
        return False, None, result.stderr.strip() or "command failed"
    try:
        return True, json.loads(result.stdout or "null"), ""
    except json.JSONDecodeError as exc:
        return False, None, f"invalid JSON output: {exc.msg}"


def _run_text(
    command: list[str],
    *,
    runner: Runner = run,
) -> tuple[bool, str, str]:
    """Run a metadata command and return stripped text output."""
    result = runner(command, check=False, capture_output=True)
    if result.returncode != 0:
        return False, "", result.stderr.strip() or "command failed"
    return True, result.stdout.strip(), ""


def _optional_owner_evidence_coverage(
    evidence_path: Path | None,
    *,
    spec: OptionalOwnerEvidenceSpec,
    live_evidence: dict[str, object],
) -> tuple[dict[str, object], list[str]]:
    """Return optional owner evidence summary and blockers."""
    if evidence_path is None:
        return {}, []

    payload, blockers = _read_required_structured_evidence(
        evidence_path,
        spec.label,
        spec.required_fields,
    )
    blockers.extend(spec.payload_blockers(payload, live_evidence))
    return spec.summary(evidence_path, payload), blockers


def _normalized_text(value: object) -> str:
    """Return a normalized lowercase text value."""
    return str(value or "").strip().lower()


def _non_empty_text(value: object) -> bool:
    """Return whether a value is non-empty text."""
    return isinstance(value, str) and bool(value.strip())
