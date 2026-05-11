from __future__ import annotations

import datetime as dt
from pathlib import Path
from typing import Any

import _well_architected_recording as _recording
import _well_architected_structured_evidence as _structured_evidence
from _well_architected_evidence_common import (
    OptionalOwnerEvidenceSpec,
    _non_empty_text,
    _normalized_text,
    _optional_owner_evidence_coverage,
)

ALERT_ROUTE_OBSERVATION_REQUIRED_FIELDS = (
    "workload",
    "environment",
    "owner",
    "approvedBy",
    "reviewedAt",
    "expiresAt",
    "downstreamRoute",
    "severityExpectations",
    "fallback",
    "decision",
    "evidence",
    "remediationPlan",
    "routeEvidence",
)
ALERT_ROUTE_OBSERVATION_ROUTE_FIELDS = _recording.ALERT_ROUTE_OBSERVATION_ROUTE_FIELDS
ALERT_ROUTE_OBSERVATION_QUEUE_FIELDS = _recording.ALERT_ROUTE_OBSERVATION_QUEUE_FIELDS
ALERT_ROUTE_ALLOWED_DECISIONS = frozenset(
    {"accepted", "approved", "approved_exception", "accepted_risk"}
)
_parse_reviewed_at = _structured_evidence._parse_reviewed_at
_structured_evidence_mismatch_blockers = (
    _structured_evidence._structured_evidence_mismatch_blockers
)
_non_empty_string_list = _structured_evidence._non_empty_string_list


def _alert_route_observation_coverage(
    evidence_path: Path | None,
    route_evidence: dict[str, object],
) -> tuple[dict[str, object], list[str]]:
    """Return approved alert-route observation metadata."""
    return _optional_owner_evidence_coverage(
        evidence_path,
        spec=ALERT_ROUTE_OBSERVATION_SPEC,
        live_evidence=route_evidence,
    )


def _alert_route_observation_payload_blockers(
    payload: dict[str, Any],
    route_evidence: dict[str, object],
) -> list[str]:
    """Return blockers for SRE alert-route observation evidence."""
    blockers: list[str] = []
    blockers.extend(
        _alert_route_observation_choice_blockers(
            payload,
            "decision",
            ALERT_ROUTE_ALLOWED_DECISIONS,
        )
    )
    if not _non_empty_string_list(payload.get("evidence")):
        blockers.append(
            "Alert-route observation evidence must include non-empty evidence strings."
        )
    if not _non_empty_text(payload.get("remediationPlan")):
        blockers.append("Alert-route observation remediationPlan must be non-empty.")
    blockers.extend(_alert_route_observation_expiry_blockers(payload.get("expiresAt")))
    blockers.extend(_alert_route_observation_route_blockers(payload, route_evidence))
    return blockers


def _alert_route_observation_choice_blockers(
    payload: dict[str, Any],
    field: str,
    allowed_values: frozenset[str],
) -> list[str]:
    """Return a blocker when an alert-route enum field is not accepted."""
    value = _normalized_text(payload.get(field))
    if value in allowed_values:
        return []
    allowed = ", ".join(sorted(allowed_values))
    return [f"Alert-route observation {field} must be one of: {allowed}."]


def _alert_route_observation_expiry_blockers(
    expires_at_value: object,
) -> list[str]:
    """Return blockers for alert-route observation expiry."""
    expires_at = _parse_reviewed_at(expires_at_value)
    if expires_at is None:
        return ["Alert-route observation evidence expiresAt must be ISO-8601."]
    now = dt.datetime.now(dt.timezone.utc)
    if expires_at <= now:
        return ["Alert-route observation evidence is expired."]
    return []


def _alert_route_observation_route_blockers(
    payload: dict[str, Any],
    route_evidence: dict[str, object],
) -> list[str]:
    """Return blockers when observed alert-route metadata is stale."""
    attested_route = payload.get("routeEvidence")
    if not isinstance(attested_route, dict):
        return ["Alert-route observation routeEvidence must be an object."]

    mismatched_fields = [
        field
        for field in ALERT_ROUTE_OBSERVATION_ROUTE_FIELDS
        if attested_route.get(field) != route_evidence.get(field)
    ]
    attested_queue = attested_route.get("sqsQueue")
    live_queue = route_evidence.get("sqsQueue")
    if not isinstance(attested_queue, dict):
        return ["Alert-route observation routeEvidence.sqsQueue must be an object."]
    if not isinstance(live_queue, dict):
        mismatched_fields.append("sqsQueue")
    else:
        mismatched_fields.extend(
            f"sqsQueue.{field}"
            for field in ALERT_ROUTE_OBSERVATION_QUEUE_FIELDS
            if attested_queue.get(field) != live_queue.get(field)
        )
    if not mismatched_fields:
        return []
    return [
        "Alert-route observation routeEvidence does not match live route "
        f"fields: {', '.join(mismatched_fields)}."
    ]


def _alert_route_observation_summary(
    evidence_path: Path,
    payload: dict[str, Any],
) -> dict[str, object]:
    """Return non-secret alert-route observation metadata."""
    return {
        "path": str(evidence_path),
        "owner": str(payload.get("owner") or ""),
        "approvedBy": str(payload.get("approvedBy") or ""),
        "reviewedAt": str(payload.get("reviewedAt") or ""),
        "expiresAt": str(payload.get("expiresAt") or ""),
        "decision": str(payload.get("decision") or ""),
        "downstreamRoute": str(payload.get("downstreamRoute") or ""),
        "severityExpectations": str(payload.get("severityExpectations") or ""),
    }


ALERT_ROUTE_OBSERVATION_SPEC = OptionalOwnerEvidenceSpec(
    label="Alert-route observation evidence",
    required_fields=ALERT_ROUTE_OBSERVATION_REQUIRED_FIELDS,
    payload_blockers=_alert_route_observation_payload_blockers,
    summary=_alert_route_observation_summary,
)
