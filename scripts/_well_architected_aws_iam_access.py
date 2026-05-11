from __future__ import annotations

import datetime as dt
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from _script_support import run
from _well_architected_evidence_common import Runner, _check, _run_json
from _well_architected_security_account_evidence import (
    _security_account_attestation_coverage,
)

IAM_ACCESS_KEY_STALE_DAYS = 90


def aws_identity(*, runner: Runner = run) -> dict[str, object]:
    """Collect current AWS account identity metadata."""
    ok, payload, error = _run_json(
        ["aws", "sts", "get-caller-identity", "--output", "json"],
        runner=runner,
    )
    if not ok or not isinstance(payload, dict):
        return _check("aws_identity", status="unknown", blockers=[error])
    return _check(
        "aws_identity",
        status="passed",
        evidence={"account": payload.get("Account"), "arn": payload.get("Arn")},
    )


def aws_iam_account_access(
    *, attestation_evidence: Path | None = None, runner: Runner = run
) -> dict[str, object]:
    """Collect non-secret IAM account and static credential metadata."""
    ok, summary, error = _run_json(
        [
            "aws",
            "iam",
            "get-account-summary",
            "--query",
            "SummaryMap",
            "--output",
            "json",
        ],
        runner=runner,
    )
    if not ok or not isinstance(summary, dict):
        return _check(
            "aws_iam_account_access",
            status="unknown",
            blockers=[f"Unable to query IAM account summary: {error}"],
        )
    users, user_blockers = _iam_user_names(runner=runner)
    key_counts = _iam_access_key_counts(users, runner=runner)
    evidence = _iam_account_access_evidence(summary, users, key_counts)
    (
        attestation_summary,
        attested_controls,
        attestation_blockers,
    ) = _security_account_attestation_coverage(attestation_evidence, evidence)
    if attestation_summary:
        evidence["securityAccountAttestation"] = attestation_summary
    blockers = [
        *user_blockers,
        *attestation_blockers,
        *_iam_account_access_blockers(evidence, attested_controls),
    ]
    return _check(
        "aws_iam_account_access",
        status="passed" if not blockers else "failed",
        evidence=evidence,
        blockers=blockers,
    )


def _iam_user_names(*, runner: Runner = run) -> tuple[list[str], list[str]]:
    """Return IAM user names for follow-up metadata queries without emitting them."""
    ok, payload, error = _run_json(
        ["aws", "iam", "list-users", "--query", "Users[].UserName", "--output", "json"],
        runner=runner,
    )
    if not ok or not isinstance(payload, list):
        return [], [f"Unable to query IAM users: {error}"]
    return [item for item in payload if isinstance(item, str) and item], []


def _iam_access_key_counts(
    users: Sequence[str], *, runner: Runner = run
) -> dict[str, int]:
    """Return aggregate access-key metadata counts without retaining key ids."""
    counts = {
        "active": 0,
        "inactive": 0,
        "other": 0,
        "usersWithActive": 0,
        "unreadableUsers": 0,
        "activeOlderThan90Days": 0,
        "activeCreateDateUnknown": 0,
        "activeNeverUsed": 0,
        "activeLastUsedWithin90Days": 0,
        "activeLastUsedOlderThan90Days": 0,
        "activeLastUsedUnknown": 0,
        "unreadableAccessKeyLastUsed": 0,
    }
    for user in users:
        ok, key_metadata, _error = _run_json(
            [
                "aws",
                "iam",
                "list-access-keys",
                "--user-name",
                user,
                "--query",
                "AccessKeyMetadata[].{Status:Status,AccessKeyId:AccessKeyId,"
                "CreateDate:CreateDate}",
                "--output",
                "json",
            ],
            runner=runner,
        )
        if not ok or not isinstance(key_metadata, list):
            counts["unreadableUsers"] += 1
            continue
        _record_access_key_metadata(key_metadata, counts, runner=runner)
    return counts


def _record_access_key_metadata(
    key_metadata: Sequence[object], counts: dict[str, int], *, runner: Runner = run
) -> None:
    """Accumulate access-key metadata for one IAM user."""
    user_has_active_key = False
    for item in key_metadata:
        status, access_key_id, create_date = _access_key_metadata_fields(item)
        if status == "Active":
            counts["active"] += 1
            user_has_active_key = True
            _record_active_access_key_age(create_date, counts)
            _record_active_access_key_last_used(access_key_id, counts, runner=runner)
        elif status == "Inactive":
            counts["inactive"] += 1
        else:
            counts["other"] += 1
    if user_has_active_key:
        counts["usersWithActive"] += 1


def _access_key_metadata_fields(item: object) -> tuple[object, object, object]:
    """Return status, id, and create date from one access-key metadata item."""
    if isinstance(item, dict):
        return item.get("Status"), item.get("AccessKeyId"), item.get("CreateDate")
    return item, None, None


def _record_active_access_key_age(create_date: object, counts: dict[str, int]) -> None:
    """Accumulate aggregate active-key age metadata."""
    created_at = _parse_aws_timestamp(create_date)
    if created_at is None:
        counts["activeCreateDateUnknown"] += 1
        return
    stale_after = dt.timedelta(days=IAM_ACCESS_KEY_STALE_DAYS)
    if dt.datetime.now(dt.timezone.utc) - created_at > stale_after:
        counts["activeOlderThan90Days"] += 1


def _record_active_access_key_last_used(
    access_key_id: object, counts: dict[str, int], *, runner: Runner = run
) -> None:
    """Accumulate aggregate active-key last-used metadata without emitting key ids."""
    if not isinstance(access_key_id, str) or not access_key_id:
        counts["activeLastUsedUnknown"] += 1
        return
    ok, payload, _error = _run_json(
        [
            "aws",
            "iam",
            "get-access-key-last-used",
            "--access-key-id",
            access_key_id,
            "--query",
            "AccessKeyLastUsed",
            "--output",
            "json",
        ],
        runner=runner,
    )
    if not ok or not isinstance(payload, dict):
        counts["unreadableAccessKeyLastUsed"] += 1
        return
    last_used_at = _parse_aws_timestamp(payload.get("LastUsedDate"))
    if last_used_at is None:
        counts["activeNeverUsed"] += 1
        return
    stale_after = dt.timedelta(days=IAM_ACCESS_KEY_STALE_DAYS)
    if dt.datetime.now(dt.timezone.utc) - last_used_at > stale_after:
        counts["activeLastUsedOlderThan90Days"] += 1
    else:
        counts["activeLastUsedWithin90Days"] += 1


def _parse_aws_timestamp(value: object) -> dt.datetime | None:
    """Parse an AWS CLI timestamp into an aware UTC datetime."""
    if not isinstance(value, str):
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def _iam_account_access_evidence(
    summary: dict[str, Any],
    users: Sequence[str],
    key_counts: dict[str, int],
) -> dict[str, object]:
    """Build non-secret IAM account-access evidence."""
    return {
        "summaryUserCount": _summary_int(summary, "Users"),
        "discoveredUserCount": len(users),
        "mfaDeviceCount": _summary_int(summary, "MFADevices"),
        "mfaDevicesInUse": _summary_int(summary, "MFADevicesInUse"),
        "accountMfaEnabled": _summary_int(summary, "AccountMFAEnabled"),
        "accountAccessKeysPresent": _summary_int(summary, "AccountAccessKeysPresent"),
        "activeUserAccessKeyCount": key_counts["active"],
        "inactiveUserAccessKeyCount": key_counts["inactive"],
        "otherUserAccessKeyStatusCount": key_counts["other"],
        "usersWithActiveAccessKeys": key_counts["usersWithActive"],
        "unreadableAccessKeyUserCount": key_counts["unreadableUsers"],
        "activeUserAccessKeyOlderThan90DaysCount": key_counts["activeOlderThan90Days"],
        "activeUserAccessKeyCreateDateUnknownCount": key_counts[
            "activeCreateDateUnknown"
        ],
        "activeUserAccessKeyNeverUsedCount": key_counts["activeNeverUsed"],
        "activeUserAccessKeyLastUsedWithin90DaysCount": key_counts[
            "activeLastUsedWithin90Days"
        ],
        "activeUserAccessKeyLastUsedOlderThan90DaysCount": key_counts[
            "activeLastUsedOlderThan90Days"
        ],
        "activeUserAccessKeyLastUsedUnknownCount": key_counts["activeLastUsedUnknown"],
        "unreadableAccessKeyLastUsedCount": key_counts["unreadableAccessKeyLastUsed"],
    }


def _iam_account_access_blockers(
    evidence: dict[str, object],
    attested_controls: frozenset[str] = frozenset(),
) -> list[str]:
    """Return security-account blockers from non-secret IAM metadata."""
    blockers: list[str] = []
    if evidence["accountMfaEnabled"] != 1:
        blockers.append("IAM account summary does not report root/account MFA enabled.")
    if evidence["accountAccessKeysPresent"] != 0:
        blockers.append("IAM account summary reports root account access keys present.")
    if (
        int(evidence["mfaDevicesInUse"]) < int(evidence["summaryUserCount"])
        and "human_access" not in attested_controls
    ):
        blockers.append(
            "IAM user count exceeds MFA devices in use; human MFA/SSO posture "
            "requires security-owner attestation."
        )
    if (
        evidence["activeUserAccessKeyCount"] != 0
        and "active_key" not in attested_controls
    ):
        blockers.append(
            "IAM access-key metadata reports active user access keys; record an "
            "approved exception or rotate/remove them before Security 5/5."
        )
    if evidence["unreadableAccessKeyUserCount"] != 0:
        blockers.append(
            "Unable to query access-key metadata for one or more IAM users."
        )
    return blockers


def _summary_int(summary: dict[str, Any], key: str) -> int:
    """Return one IAM summary integer value."""
    value = summary.get(key)
    return value if isinstance(value, int) and not isinstance(value, bool) else 0
