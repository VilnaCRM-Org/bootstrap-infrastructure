from __future__ import annotations

import datetime as dt
from pathlib import Path
from typing import Any

import _well_architected_recording as _recording
import _well_architected_structured_evidence as _structured_evidence
from _well_architected_evidence_common import _non_empty_text, _normalized_text

SECURITY_ACCOUNT_ATTESTATION_REQUIRED_FIELDS = (
    "workload",
    "owner",
    "approvedBy",
    "reviewedAt",
    "expiresAt",
    "humanAccessPosture",
    "activeKeyDecision",
    "permissionsBoundaryDecision",
    "approval",
    "evidence",
    "remediationPlan",
    "accountEvidence",
)
SECURITY_ACCOUNT_ATTESTATION_ACCOUNT_FIELDS = (
    _recording.SECURITY_ACCOUNT_ATTESTATION_ACCOUNT_FIELDS
)
SECURITY_ACCOUNT_ALLOWED_APPROVALS = frozenset(
    {"approved", "approved_exception", "accepted_risk", "technical_review"}
)
SECURITY_ACCOUNT_ALLOWED_HUMAN_ACCESS = frozenset(
    {
        "mfa_sso_verified",
        "approved",
        "approved_exception",
        "accepted_risk",
        "not_assessed",
    }
)
SECURITY_ACCOUNT_ALLOWED_ACTIVE_KEY = frozenset(
    {"no_active_keys", "rotated", "approved_exception", "accepted_risk"}
)
SECURITY_ACCOUNT_ALLOWED_BOUNDARY = frozenset(
    {"boundary_verified", "approved_exemption", "accepted_risk", "not_required"}
)
SECURITY_ACCOUNT_ATTESTED_CONTROLS = frozenset(
    {"human_access", "active_key", "permissions_boundary"}
)
_read_required_structured_evidence = (
    _structured_evidence._read_required_structured_evidence
)
_parse_reviewed_at = _structured_evidence._parse_reviewed_at
_structured_evidence_mismatch_blockers = (
    _structured_evidence._structured_evidence_mismatch_blockers
)
_non_empty_string_list = _structured_evidence._non_empty_string_list


def _security_account_attestation_coverage(
    evidence_path: Path | None,
    account_evidence: dict[str, object],
) -> tuple[dict[str, object], frozenset[str], list[str]]:
    """Return approved security-account attestation coverage."""
    if evidence_path is None:
        return {}, frozenset(), []

    label = "Security account attestation evidence"
    payload, blockers = _read_required_structured_evidence(
        evidence_path,
        label,
        SECURITY_ACCOUNT_ATTESTATION_REQUIRED_FIELDS,
    )
    blockers.extend(
        _security_account_attestation_payload_blockers(payload, account_evidence)
    )
    controls = SECURITY_ACCOUNT_ATTESTED_CONTROLS if not blockers else frozenset()
    if _normalized_text(payload.get("approval")) == "technical_review":
        controls = controls - {"human_access"}
    return (
        _security_account_attestation_summary(evidence_path, payload),
        controls,
        blockers,
    )


def _security_account_attestation_payload_blockers(
    payload: dict[str, Any],
    account_evidence: dict[str, object],
) -> list[str]:
    """Return blockers for security-owner attestation evidence."""
    blockers: list[str] = []
    blockers.extend(
        _security_account_attestation_choice_blockers(
            payload,
            "approval",
            SECURITY_ACCOUNT_ALLOWED_APPROVALS,
        )
    )
    blockers.extend(
        _security_account_attestation_choice_blockers(
            payload,
            "humanAccessPosture",
            SECURITY_ACCOUNT_ALLOWED_HUMAN_ACCESS,
        )
    )
    blockers.extend(
        _security_account_attestation_choice_blockers(
            payload,
            "activeKeyDecision",
            SECURITY_ACCOUNT_ALLOWED_ACTIVE_KEY,
        )
    )
    blockers.extend(
        _security_account_attestation_choice_blockers(
            payload,
            "permissionsBoundaryDecision",
            SECURITY_ACCOUNT_ALLOWED_BOUNDARY,
        )
    )
    if _normalized_text(payload.get("approval")) == "technical_review":
        expected = {
            "humanAccessPosture": "not_assessed",
            "activeKeyDecision": "no_active_keys",
            "permissionsBoundaryDecision": "boundary_verified",
        }
        if any(
            _normalized_text(payload.get(key)) != value
            for key, value in expected.items()
        ):
            blockers.append(
                "Technical review must not claim human access approval, "
                "active-key exceptions or permissions-boundary exemptions."
            )
    elif _normalized_text(payload.get("humanAccessPosture")) == "not_assessed":
        blockers.append("Human-access approval cannot use a not_assessed posture.")
    if (
        account_evidence.get("activeUserAccessKeyCount") != 0
        and _normalized_text(payload.get("activeKeyDecision")) == "no_active_keys"
    ):
        blockers.append(
            "Security account attestation activeKeyDecision cannot be "
            "no_active_keys while active keys remain."
        )
    if not _non_empty_string_list(payload.get("evidence")):
        blockers.append(
            "Security account attestation evidence must include non-empty strings."
        )
    if not _non_empty_text(payload.get("remediationPlan")):
        blockers.append(
            "Security account attestation remediationPlan must be non-empty."
        )
    blockers.extend(
        _security_account_attestation_expiry_blockers(payload.get("expiresAt"))
    )
    blockers.extend(
        _security_account_attestation_account_blockers(payload, account_evidence)
    )
    return blockers


def _security_account_attestation_choice_blockers(
    payload: dict[str, Any],
    field: str,
    allowed_values: frozenset[str],
) -> list[str]:
    """Return a blocker when an attestation enum field is not accepted."""
    value = _normalized_text(payload.get(field))
    if value in allowed_values:
        return []
    allowed = ", ".join(sorted(allowed_values))
    return [f"Security account attestation {field} must be one of: {allowed}."]


def _security_account_attestation_expiry_blockers(
    expires_at_value: object,
) -> list[str]:
    """Return blockers for security-account attestation expiry."""
    expires_at = _parse_reviewed_at(expires_at_value)
    if expires_at is None:
        return ["Security account attestation evidence expiresAt must be ISO-8601."]
    now = dt.datetime.now(dt.timezone.utc)
    if expires_at <= now:
        return ["Security account attestation evidence is expired."]
    return []


def _security_account_attestation_account_blockers(
    payload: dict[str, Any],
    account_evidence: dict[str, object],
) -> list[str]:
    """Return blockers when attested IAM counts do not match live evidence."""
    return _structured_evidence_mismatch_blockers(
        payload.get("accountEvidence"),
        account_evidence,
        SECURITY_ACCOUNT_ATTESTATION_ACCOUNT_FIELDS,
        object_error="Security account attestation accountEvidence must be an object.",
        mismatch_message=(
            "Security account attestation accountEvidence does not match live "
            "IAM aggregate fields"
        ),
    )


def _security_account_attestation_summary(
    evidence_path: Path,
    payload: dict[str, Any],
) -> dict[str, object]:
    """Return non-secret security-account attestation metadata."""
    return {
        "path": str(evidence_path),
        "owner": str(payload.get("owner") or ""),
        "approvedBy": str(payload.get("approvedBy") or ""),
        "reviewedAt": str(payload.get("reviewedAt") or ""),
        "expiresAt": str(payload.get("expiresAt") or ""),
        "approval": str(payload.get("approval") or ""),
        "humanAccessPosture": str(payload.get("humanAccessPosture") or ""),
        "activeKeyDecision": str(payload.get("activeKeyDecision") or ""),
        "permissionsBoundaryDecision": str(
            payload.get("permissionsBoundaryDecision") or ""
        ),
        "remediationPlan": str(payload.get("remediationPlan") or ""),
    }
