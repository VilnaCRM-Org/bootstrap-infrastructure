from __future__ import annotations

import datetime as dt
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast
from urllib.parse import quote

import _well_architected_structured_evidence as _structured_evidence
from _script_support import run
from _well_architected_evidence_common import Runner, _check, _run_json

DEFAULT_DEPENDABOT_DEPENDENCY = ""
DEPENDABOT_ALL_DEPENDENCIES = "all"
DEFAULT_DEPENDABOT_MANIFEST = "uv.lock"
BLOCKING_DEPENDABOT_SEVERITIES = frozenset({"critical", "high"})
DEPENDABOT_EXCEPTION_ALLOWED_APPROVALS = frozenset(
    {"approved", "approved_exception", "accepted_risk"}
)
DEPENDABOT_EXCEPTION_REQUIRED_FIELDS = (
    "workload",
    "owner",
    "approvedBy",
    "reviewedAt",
    "expiresAt",
    "dependencyName",
    "manifestPath",
    "alertNumbers",
    "approval",
    "reason",
    "remediationPlan",
)
_parse_reviewed_at = _structured_evidence._parse_reviewed_at
_read_required_structured_evidence = (
    _structured_evidence._read_required_structured_evidence
)


@dataclass(frozen=True)
class DependabotAlertRequest:
    """Scope for Dependabot alert evidence collection."""

    repo: str
    dependency: str = DEFAULT_DEPENDABOT_DEPENDENCY
    manifest_path: str = DEFAULT_DEPENDABOT_MANIFEST
    blocking_severities: frozenset[str] = BLOCKING_DEPENDABOT_SEVERITIES


def github_dependabot_alerts(
    request: DependabotAlertRequest,
    exception_evidence: Path | None = None,
    *,
    runner: Runner = run,
) -> dict[str, object]:
    """Collect open Dependabot alert evidence for one dependency manifest."""
    dependency = request.dependency.strip()
    dependency_scope = _dependabot_dependency_scope(dependency)
    manifest_path = request.manifest_path
    blocking_severities = request.blocking_severities
    ok, payload, error = _run_json(
        ["gh", "api", _dependabot_alert_api_path(request.repo, dependency)],
        runner=runner,
    )
    if not ok or not isinstance(payload, list):
        return _unknown_dependabot_alert_check(
            dependency=dependency_scope,
            manifest_path=manifest_path,
            blocking_severities=blocking_severities,
            error=error,
        )

    matching_alerts = _matching_dependabot_alerts(
        payload,
        dependency=dependency,
        manifest_path=manifest_path,
    )
    blocking_alerts = _blocking_dependabot_alerts(
        matching_alerts,
        blocking_severities,
    )
    exception_summary, excepted_alert_numbers, exception_blockers = (
        _dependabot_exception_coverage(
            exception_evidence,
            dependency=dependency_scope,
            manifest_path=manifest_path,
            blocking_alerts=blocking_alerts,
        )
    )
    unexcepted_alerts = _unexcepted_dependabot_alerts(
        blocking_alerts,
        excepted_alert_numbers,
    )
    unexcepted_alert_numbers = _dependabot_alert_numbers(unexcepted_alerts)
    open_alert_numbers = _dependabot_alert_numbers(blocking_alerts)
    blockers = [
        *exception_blockers,
        *_dependabot_alert_blockers(
            dependency=dependency_scope,
            manifest_path=manifest_path,
            open_alert_numbers=unexcepted_alert_numbers,
            open_alert_count=len(unexcepted_alerts),
        ),
    ]
    evidence: dict[str, object] = {
        "dependencyName": dependency_scope,
        "dependencyNames": _dependabot_dependency_names(blocking_alerts),
        "manifestPath": manifest_path,
        "blockingSeverities": sorted(blocking_severities),
        "matchingOpenAlertCount": len(matching_alerts),
        "openAlertCount": len(blocking_alerts),
        "openAlertNumbers": open_alert_numbers,
        "unexceptedOpenAlertCount": len(unexcepted_alerts),
        "unexceptedOpenAlertNumbers": unexcepted_alert_numbers,
        "exceptedOpenAlertNumbers": sorted(excepted_alert_numbers),
        "alerts": blocking_alerts,
    }
    if exception_summary:
        evidence["exceptionEvidence"] = exception_summary
    return _check(
        "github_dependabot_alerts",
        status="passed" if not blockers else "failed",
        evidence=evidence,
        blockers=blockers,
    )


def _dependabot_alert_api_path(repo: str, dependency: str) -> str:
    """Return the GitHub API path for open Dependabot alerts."""
    if not dependency.strip():
        return f"repos/{repo}/dependabot/alerts?state=open&per_page=100"
    return (
        f"repos/{repo}/dependabot/alerts?state=open&dependency_name="
        f"{quote(dependency, safe='')}&per_page=100"
    )


def _dependabot_dependency_scope(dependency: str) -> str:
    """Return the evidence label for the requested dependency scope."""
    return dependency or DEPENDABOT_ALL_DEPENDENCIES


def _unknown_dependabot_alert_check(
    *,
    dependency: str,
    manifest_path: str,
    blocking_severities: frozenset[str],
    error: str,
) -> dict[str, object]:
    """Return an unknown Dependabot check when GitHub metadata is unreadable."""
    return _check(
        "github_dependabot_alerts",
        status="unknown",
        evidence={
            "dependencyName": dependency,
            "manifestPath": manifest_path,
            "blockingSeverities": sorted(blocking_severities),
        },
        blockers=[
            "Unable to read GitHub Dependabot alerts for "
            f"{dependency} in {manifest_path}: {error}."
        ],
    )


def _matching_dependabot_alerts(
    payload: Sequence[object],
    *,
    dependency: str,
    manifest_path: str,
) -> list[dict[str, object]]:
    """Return sorted open alerts for the target dependency manifest."""
    alerts = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        summary = _dependabot_alert_summary(cast(dict[str, Any], item))
        if _dependabot_alert_matches(
            summary,
            dependency=dependency,
            manifest_path=manifest_path,
        ):
            alerts.append(summary)
    return sorted(alerts, key=lambda alert: _dependabot_alert_number(alert) or 0)


def _blocking_dependabot_alerts(
    alerts: Sequence[dict[str, object]],
    blocking_severities: frozenset[str],
) -> list[dict[str, object]]:
    """Return high-impact Dependabot alerts that still block SEC11."""
    return [
        alert
        for alert in alerts
        if str(alert.get("severity", "")).lower() in blocking_severities
    ]


def _unexcepted_dependabot_alerts(
    alerts: Sequence[dict[str, object]],
    excepted_alert_numbers: set[int],
) -> list[dict[str, object]]:
    """Return blocking alerts not covered by approved exception evidence."""
    return [
        alert
        for alert in alerts
        if _dependabot_alert_number(alert) not in excepted_alert_numbers
    ]


def _dependabot_alert_numbers(alerts: Sequence[dict[str, object]]) -> list[int]:
    """Return GitHub alert numbers when present."""
    return [
        number
        for alert in alerts
        if (number := _dependabot_alert_number(alert)) is not None
    ]


def _dependabot_alert_summary(alert: dict[str, Any]) -> dict[str, object]:
    """Return non-secret metadata from one Dependabot alert."""
    dependency = _mapping(alert.get("dependency"))
    package = _mapping(dependency.get("package"))
    advisory = _mapping(alert.get("security_advisory"))
    vulnerability = _mapping(alert.get("security_vulnerability"))
    first_patched_version = _mapping(vulnerability.get("first_patched_version"))
    return {
        "number": alert.get("number"),
        "state": str(alert.get("state") or ""),
        "dependencyName": str(package.get("name") or ""),
        "manifestPath": str(dependency.get("manifest_path") or ""),
        "severity": str(advisory.get("severity") or "").lower(),
        "firstPatchedVersion": str(first_patched_version.get("identifier") or ""),
    }


def _mapping(value: object) -> dict[str, Any]:
    """Return a dict payload when an API field is an object."""
    return cast(dict[str, Any], value) if isinstance(value, dict) else {}


def _dependabot_alert_matches(
    alert: dict[str, object],
    *,
    dependency: str,
    manifest_path: str,
) -> bool:
    """Return whether a Dependabot alert targets the dependency manifest."""
    dependency_name = str(alert.get("dependencyName", ""))
    return (
        str(alert.get("state", "")).lower() == "open"
        and (not dependency or dependency_name.lower() == dependency.lower())
        and alert.get("manifestPath") == manifest_path
    )


def _dependabot_alert_number(alert: dict[str, object]) -> int | None:
    """Return the alert number if GitHub supplied one."""
    number = alert.get("number")
    return number if isinstance(number, int) else None


def _dependabot_alert_blockers(
    *,
    dependency: str,
    manifest_path: str,
    open_alert_numbers: Sequence[int],
    open_alert_count: int,
) -> list[str]:
    """Return blockers for unresolved high-impact Dependabot alerts."""
    if open_alert_count == 0:
        return []
    if open_alert_numbers:
        alert_text = ", ".join(f"#{number}" for number in open_alert_numbers)
    else:
        alert_text = f"{open_alert_count} alert(s)"
    if dependency == DEPENDABOT_ALL_DEPENDENCIES:
        scope = f"in {manifest_path}"
    else:
        scope = f"for {dependency} in {manifest_path}"
    return [f"Open default-branch Dependabot alerts remain {scope}: {alert_text}."]


def _dependabot_dependency_names(
    alerts: Sequence[dict[str, object]],
) -> list[str]:
    """Return sorted dependency names represented by blocking alert evidence."""
    return sorted(
        {
            name
            for alert in alerts
            if (name := str(alert.get("dependencyName") or "").strip())
        }
    )


def _dependabot_exception_coverage(
    evidence_path: Path | None,
    *,
    dependency: str,
    manifest_path: str,
    blocking_alerts: Sequence[dict[str, object]],
) -> tuple[dict[str, object], set[int], list[str]]:
    """Return approved Dependabot exception coverage for open alerts."""
    if evidence_path is None:
        return {}, set(), []

    label = "Dependabot exception evidence"
    payload, blockers = _read_required_structured_evidence(
        evidence_path,
        label,
        DEPENDABOT_EXCEPTION_REQUIRED_FIELDS,
    )
    blockers.extend(
        _dependabot_exception_payload_blockers(
            payload,
            dependency=dependency,
            manifest_path=manifest_path,
            blocking_alerts=blocking_alerts,
        )
    )
    alert_numbers = _dependabot_exception_alert_numbers(payload)
    covered_numbers = set(alert_numbers) if not blockers else set()
    summary = _dependabot_exception_summary(evidence_path, payload, alert_numbers)
    return summary, covered_numbers, blockers


def _dependabot_exception_payload_blockers(
    payload: dict[str, Any],
    *,
    dependency: str,
    manifest_path: str,
    blocking_alerts: Sequence[dict[str, object]],
) -> list[str]:
    """Return blockers for a Dependabot exception evidence payload."""
    blockers: list[str] = []
    if payload.get("dependencyName") != dependency:
        blockers.append(
            f"Dependabot exception evidence dependencyName must be {dependency}."
        )
    if payload.get("manifestPath") != manifest_path:
        blockers.append(
            f"Dependabot exception evidence manifestPath must be {manifest_path}."
        )
    approval = str(payload.get("approval") or "").strip().lower()
    if approval not in DEPENDABOT_EXCEPTION_ALLOWED_APPROVALS:
        blockers.append(
            "Dependabot exception evidence approval must be approved, "
            "approved_exception, or accepted_risk."
        )

    evidence = payload.get("evidence")
    if not isinstance(evidence, list) or not any(
        isinstance(item, str) and item.strip() for item in evidence
    ):
        blockers.append(
            "Dependabot exception evidence must include non-empty evidence strings."
        )

    blockers.extend(_dependabot_exception_expiry_blockers(payload.get("expiresAt")))
    blockers.extend(
        _dependabot_exception_alert_number_blockers(payload, blocking_alerts)
    )
    return blockers


def _dependabot_exception_expiry_blockers(expires_at_value: object) -> list[str]:
    """Return blockers for Dependabot exception expiry."""
    expires_at = _parse_reviewed_at(expires_at_value)
    if expires_at is None:
        return ["Dependabot exception evidence expiresAt must be ISO-8601."]
    now = dt.datetime.now(dt.timezone.utc)
    if expires_at <= now:
        return ["Dependabot exception evidence is expired."]
    return []


def _dependabot_exception_alert_number_blockers(
    payload: dict[str, Any],
    blocking_alerts: Sequence[dict[str, object]],
) -> list[str]:
    """Return blockers for Dependabot exception alert-number coverage."""
    blockers: list[str] = []
    expected_numbers = set(_dependabot_alert_numbers(blocking_alerts))
    actual_numbers = set(_dependabot_exception_alert_numbers(payload))
    if expected_numbers:
        missing_numbers = sorted(expected_numbers - actual_numbers)
        if missing_numbers:
            blockers.append(
                "Dependabot exception evidence does not cover open alert numbers: "
                f"{_alert_number_text(missing_numbers)}."
            )
    elif blocking_alerts:
        blockers.append(
            "Dependabot exception evidence cannot cover alerts without GitHub "
            "alert numbers."
        )
    extra_numbers = sorted(actual_numbers - expected_numbers)
    if extra_numbers:
        blockers.append(
            "Dependabot exception evidence includes alert numbers that are not "
            f"currently open blockers: {_alert_number_text(extra_numbers)}."
        )
    return blockers


def _dependabot_exception_alert_numbers(payload: dict[str, Any]) -> list[int]:
    """Return exception alert numbers when they are a valid integer list."""
    alert_numbers = payload.get("alertNumbers")
    if not isinstance(alert_numbers, list):
        return []
    numbers: list[int] = []
    for item in alert_numbers:
        if isinstance(item, bool) or not isinstance(item, int):
            return []
        numbers.append(item)
    return sorted(numbers)


def _dependabot_exception_summary(
    evidence_path: Path,
    payload: dict[str, Any],
    alert_numbers: Sequence[int],
) -> dict[str, object]:
    """Return non-secret Dependabot exception metadata for the report."""
    return {
        "path": str(evidence_path),
        "owner": str(payload.get("owner") or ""),
        "approvedBy": str(payload.get("approvedBy") or ""),
        "reviewedAt": str(payload.get("reviewedAt") or ""),
        "expiresAt": str(payload.get("expiresAt") or ""),
        "dependencyName": str(payload.get("dependencyName") or ""),
        "dependencyNames": _dependabot_dependency_names_from_payload(payload),
        "manifestPath": str(payload.get("manifestPath") or ""),
        "approval": str(payload.get("approval") or ""),
        "alertNumbers": list(alert_numbers),
        "reason": str(payload.get("reason") or ""),
        "remediationPlan": str(payload.get("remediationPlan") or ""),
    }


def _dependabot_dependency_names_from_payload(payload: dict[str, Any]) -> list[str]:
    """Return optional dependency names from owner exception evidence."""
    names = payload.get("dependencyNames")
    if not isinstance(names, list):
        return []
    return sorted(
        {name.strip() for name in names if isinstance(name, str) and name.strip()}
    )


def _alert_number_text(numbers: Sequence[int]) -> str:
    """Return a human-readable alert-number list."""
    return ", ".join(f"#{number}" for number in numbers)
