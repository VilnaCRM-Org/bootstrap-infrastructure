#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import _well_architected_recording as _recording

SECURITY_ACCOUNT_ATTESTATION_ACCOUNT_FIELDS = (
    "summaryUserCount",
    "discoveredUserCount",
    "mfaDeviceCount",
    "mfaDevicesInUse",
    "accountMfaEnabled",
    "accountAccessKeysPresent",
    "activeUserAccessKeyCount",
    "inactiveUserAccessKeyCount",
    "otherUserAccessKeyStatusCount",
    "usersWithActiveAccessKeys",
    "unreadableAccessKeyUserCount",
    "activeUserAccessKeyOlderThan90DaysCount",
    "activeUserAccessKeyCreateDateUnknownCount",
    "activeUserAccessKeyNeverUsedCount",
    "activeUserAccessKeyLastUsedWithin90DaysCount",
    "activeUserAccessKeyLastUsedOlderThan90DaysCount",
    "activeUserAccessKeyLastUsedUnknownCount",
    "unreadableAccessKeyLastUsedCount",
)
SECURITY_ACCOUNT_ALLOWED_APPROVALS = frozenset(
    {"approved", "approved_exception", "accepted_risk"}
)
SECURITY_ACCOUNT_ALLOWED_HUMAN_ACCESS = frozenset(
    {"mfa_sso_verified", "approved", "approved_exception", "accepted_risk"}
)
SECURITY_ACCOUNT_ALLOWED_ACTIVE_KEY = frozenset(
    {"no_active_keys", "rotated", "approved_exception", "accepted_risk"}
)
SECURITY_ACCOUNT_ALLOWED_BOUNDARY = frozenset(
    {"boundary_verified", "approved_exemption", "accepted_risk", "not_required"}
)
STRUCTURED_EVIDENCE_MAX_AGE_DAYS = _recording.STRUCTURED_EVIDENCE_MAX_AGE_DAYS
_load_report = _recording.load_report
_check_by_name = _recording.check_by_name
_markdown_cell = _recording.markdown_cell
_table = _recording.markdown_table
_parse_iso_date_or_timestamp = _recording.parse_iso_date_or_timestamp
_validate_structured_dates = _recording.validate_structured_dates


def _iam_access_check(report: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    check = _check_by_name(report, "aws_iam_account_access")
    evidence = check.get("evidence")
    if not isinstance(evidence, dict):
        raise ValueError("aws_iam_account_access evidence must be a JSON object")
    return check, evidence


def _identity_account(report: dict[str, Any]) -> object:
    try:
        identity = _check_by_name(report, "aws_identity")
    except ValueError:
        return ""
    evidence = identity.get("evidence")
    if not isinstance(evidence, dict):
        return ""
    return evidence.get("account", "")


def _blocker_lines(check: dict[str, Any]) -> str:
    blockers = check.get("blockers", [])
    if not blockers:
        return "- None reported by the collector."
    return "\n".join(f"- {_markdown_cell(item)}" for item in blockers)


def render_attestation(report: dict[str, Any], args: argparse.Namespace) -> str:
    check, evidence = _iam_access_check(report)
    actions = args.action or ["No follow-up actions recorded."]
    action_lines = "\n".join(f"- {_markdown_cell(action)}" for action in actions)

    return "\n".join(
        [
            f"# Security Account Attestation {args.review_date}",
            "",
            "This attestation record is generated from metadata-only "
            "Well-Architected collector output and completed with security-owner "
            "review fields. Do not add IAM user names, access key IDs, secret "
            "values, screenshots containing private identities, credentials, "
            "tokens, or raw account exports.",
            "",
            "## Review Metadata",
            "",
            _table(
                [
                    ("Workload", args.workload),
                    ("Environment", args.environment),
                    ("Review date", args.review_date),
                    ("Reviewer", args.reviewer),
                    ("Security owner", args.security_owner),
                    ("Human MFA/SSO posture", args.human_access_posture),
                    ("Active IAM user access-key decision", args.active_key_decision),
                    (
                        "Permissions-boundary or exemption decision",
                        args.permissions_boundary_decision,
                    ),
                    ("Approval decision", args.approval_decision),
                    ("Evidence expiry", args.expiry_date or "Not specified"),
                    ("Evidence source generated at", report.get("generatedAt", "")),
                ]
            ),
            "",
            "## Collector Account Evidence",
            "",
            _table(
                [
                    ("AWS account", _identity_account(report)),
                    ("Collector check status", check.get("status", "")),
                    ("Root/account MFA enabled", evidence.get("accountMfaEnabled", "")),
                    (
                        "Root/account access keys present",
                        evidence.get("accountAccessKeysPresent", ""),
                    ),
                    ("Discovered IAM users", evidence.get("discoveredUserCount", "")),
                    ("Summary IAM users", evidence.get("summaryUserCount", "")),
                    ("MFA devices in use", evidence.get("mfaDevicesInUse", "")),
                    ("Total MFA devices", evidence.get("mfaDeviceCount", "")),
                    (
                        "Active IAM user access keys",
                        evidence.get("activeUserAccessKeyCount", ""),
                    ),
                    (
                        "Active keys older than 90 days",
                        evidence.get("activeUserAccessKeyOlderThan90DaysCount", ""),
                    ),
                    (
                        "Active keys with unknown create date",
                        evidence.get("activeUserAccessKeyCreateDateUnknownCount", ""),
                    ),
                    (
                        "Active keys never used",
                        evidence.get("activeUserAccessKeyNeverUsedCount", ""),
                    ),
                    (
                        "Active keys last used within 90 days",
                        evidence.get(
                            "activeUserAccessKeyLastUsedWithin90DaysCount", ""
                        ),
                    ),
                    (
                        "Active keys last used older than 90 days",
                        evidence.get(
                            "activeUserAccessKeyLastUsedOlderThan90DaysCount", ""
                        ),
                    ),
                    (
                        "Active keys with unknown last-used metadata",
                        evidence.get("activeUserAccessKeyLastUsedUnknownCount", ""),
                    ),
                    (
                        "Inactive IAM user access keys",
                        evidence.get("inactiveUserAccessKeyCount", ""),
                    ),
                    (
                        "Unreadable access-key user metadata",
                        evidence.get("unreadableAccessKeyUserCount", ""),
                    ),
                    (
                        "Unreadable access-key last-used metadata",
                        evidence.get("unreadableAccessKeyLastUsedCount", ""),
                    ),
                ]
            ),
            "",
            "## Collector Blockers",
            "",
            _blocker_lines(check),
            "",
            "## Follow-Up Actions",
            "",
            action_lines,
            "",
        ]
    )


def structured_attestation(
    report: dict[str, Any], args: argparse.Namespace
) -> dict[str, object]:
    """Return machine-readable, non-secret security-owner attestation evidence."""
    _check, evidence = _iam_access_check(report)
    if not args.action:
        raise ValueError(
            "structured security account attestation requires at least one --action"
        )
    _validate_attestation_choices(args)
    _validate_structured_dates(
        "Security account attestation", args.review_date, args.expiry_date
    )
    actions = args.action
    return {
        "workload": args.workload,
        "environment": args.environment,
        "owner": args.reviewer,
        "approvedBy": args.security_owner,
        "reviewedAt": args.review_date,
        "expiresAt": args.expiry_date,
        "humanAccessPosture": args.human_access_posture,
        "activeKeyDecision": args.active_key_decision,
        "permissionsBoundaryDecision": args.permissions_boundary_decision,
        "approval": args.approval_decision,
        "evidence": actions,
        "remediationPlan": " ".join(actions),
        "accountEvidence": {
            field: evidence.get(field)
            for field in SECURITY_ACCOUNT_ATTESTATION_ACCOUNT_FIELDS
        },
    }


def _validate_attestation_choices(args: argparse.Namespace) -> None:
    """Reject structured evidence choices the collector would later reject."""
    blockers: list[str] = []
    blockers.extend(
        _choice_blockers(
            "Security account attestation approval-decision",
            args.approval_decision,
            SECURITY_ACCOUNT_ALLOWED_APPROVALS,
        )
    )
    blockers.extend(
        _choice_blockers(
            "Security account attestation human-access-posture",
            args.human_access_posture,
            SECURITY_ACCOUNT_ALLOWED_HUMAN_ACCESS,
        )
    )
    blockers.extend(
        _choice_blockers(
            "Security account attestation active-key-decision",
            args.active_key_decision,
            SECURITY_ACCOUNT_ALLOWED_ACTIVE_KEY,
        )
    )
    blockers.extend(
        _choice_blockers(
            "Security account attestation permissions-boundary-decision",
            args.permissions_boundary_decision,
            SECURITY_ACCOUNT_ALLOWED_BOUNDARY,
        )
    )
    if blockers:
        raise ValueError(" ".join(blockers))


def _choice_blockers(
    field: str, value: str, allowed_values: frozenset[str]
) -> list[str]:
    """Return a blocker when a structured evidence choice is not accepted."""
    normalized = value.strip().lower()
    if normalized in allowed_values:
        return []
    allowed = ", ".join(sorted(allowed_values))
    return [f"{field} must be one of: {allowed}."]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Render a non-secret security account attestation from "
            "Well-Architected collector evidence."
        )
    )
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--json-output", type=Path)
    parser.add_argument(
        "--review-date", default=dt.datetime.now(dt.timezone.utc).date().isoformat()
    )
    parser.add_argument("--workload", default="bootstrap-infrastructure")
    parser.add_argument("--environment", default="test")
    parser.add_argument("--reviewer", required=True)
    parser.add_argument("--security-owner", required=True)
    parser.add_argument("--human-access-posture", required=True)
    parser.add_argument("--active-key-decision", required=True)
    parser.add_argument("--permissions-boundary-decision", required=True)
    parser.add_argument("--approval-decision", required=True)
    parser.add_argument("--expiry-date", default="")
    parser.add_argument("--action", action="append", default=[])
    parser.add_argument("--force", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.output.exists() and not args.force:
        print(f"error: output already exists: {args.output}", file=sys.stderr)
        return 2
    if args.json_output and args.json_output.exists() and not args.force:
        print(f"error: JSON output already exists: {args.json_output}", file=sys.stderr)
        return 2

    try:
        report = _load_report(args.evidence)
        markdown = render_attestation(report, args)
        json_payload = (
            structured_attestation(report, args) if args.json_output else None
        )
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(markdown, encoding="utf-8")
    if args.json_output:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(
            f"{json.dumps(json_payload, indent=2, sort_keys=True)}\n",
            encoding="utf-8",
        )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
