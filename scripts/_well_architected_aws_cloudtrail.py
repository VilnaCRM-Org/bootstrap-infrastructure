from __future__ import annotations

from collections.abc import Sequence

from _script_support import run
from _well_architected_aws_metadata import _metadata_dict, _metadata_list
from _well_architected_evidence_common import Runner, _check, _run_json


def _cloudtrail_management_selector_found(selectors: Sequence[object]) -> bool:
    """Return whether CloudTrail captures all read/write management events."""
    return any(
        isinstance(selector, dict)
        and selector.get("IncludeManagementEvents") is True
        and selector.get("ReadWriteType") == "All"
        for selector in selectors
    )


def _cloudtrail_trail_blockers(trail: dict[str, object]) -> list[str]:
    """Return blockers from CloudTrail static metadata."""
    if not trail:
        return []
    required_flags = (
        ("IsMultiRegionTrail", "Operations CloudTrail is not multi-region."),
        (
            "IncludeGlobalServiceEvents",
            "Operations CloudTrail does not include global service events.",
        ),
        (
            "LogFileValidationEnabled",
            "Operations CloudTrail log file validation is not enabled.",
        ),
        ("KmsKeyId", "Operations CloudTrail is not encrypted with a KMS key."),
    )
    return [message for key, message in required_flags if not trail.get(key)]


def _cloudtrail_status_blockers(status: dict[str, object]) -> list[str]:
    """Return blockers from CloudTrail logging status."""
    if not status or status.get("IsLogging"):
        return []
    return ["Operations CloudTrail is not logging."]


def _cloudtrail_selector_blockers(
    *, selectors_queried: bool, management_selector_found: bool
) -> list[str]:
    """Return blockers from CloudTrail event selector metadata."""
    if not selectors_queried or management_selector_found:
        return []
    return ["Operations CloudTrail does not capture all read/write management events."]


def aws_cloudtrail_management_events(
    trail_name: str | None, *, runner: Runner = run
) -> dict[str, object]:
    """Collect metadata-only evidence for the operations CloudTrail trail."""
    if not trail_name:
        return _check(
            "aws_cloudtrail_management_events",
            status="missing",
            blockers=["Operations CloudTrail trail name is required for evidence."],
        )
    trail_ok, trail, trail_error = _run_json(
        [
            "aws",
            "cloudtrail",
            "get-trail",
            "--name",
            trail_name,
            "--query",
            "Trail.{Name:Name,IsMultiRegionTrail:IsMultiRegionTrail,IncludeGlobalServiceEvents:IncludeGlobalServiceEvents,LogFileValidationEnabled:LogFileValidationEnabled,KmsKeyId:KmsKeyId}",
            "--output",
            "json",
        ],
        runner=runner,
    )
    status_ok, status, status_error = _run_json(
        [
            "aws",
            "cloudtrail",
            "get-trail-status",
            "--name",
            trail_name,
            "--query",
            "{IsLogging:IsLogging,LatestDeliveryTime:LatestDeliveryTime}",
            "--output",
            "json",
        ],
        runner=runner,
    )
    selectors_ok, selectors, selectors_error = _run_json(
        [
            "aws",
            "cloudtrail",
            "get-event-selectors",
            "--trail-name",
            trail_name,
            "--query",
            "EventSelectors[].{IncludeManagementEvents:IncludeManagementEvents,ReadWriteType:ReadWriteType}",
            "--output",
            "json",
        ],
        runner=runner,
    )
    trail, trail_blockers = _metadata_dict(
        trail_ok, trail, trail_error, "CloudTrail trail metadata"
    )
    status, status_blockers = _metadata_dict(
        status_ok, status, status_error, "CloudTrail trail status"
    )
    selectors, selector_blockers = _metadata_list(
        selectors_ok,
        selectors,
        selectors_error,
        "CloudTrail management event selectors",
    )
    management_selector_found = _cloudtrail_management_selector_found(selectors)
    blockers = [
        *trail_blockers,
        *status_blockers,
        *selector_blockers,
        *_cloudtrail_trail_blockers(trail),
        *_cloudtrail_status_blockers(status),
        *_cloudtrail_selector_blockers(
            selectors_queried=selectors_ok,
            management_selector_found=management_selector_found,
        ),
    ]
    return _check(
        "aws_cloudtrail_management_events",
        status="passed" if not blockers else "failed",
        evidence={
            "trailName": trail_name,
            "isLogging": bool(status.get("IsLogging")),
            "isMultiRegion": bool(trail.get("IsMultiRegionTrail")),
            "includeGlobalServiceEvents": bool(trail.get("IncludeGlobalServiceEvents")),
            "logFileValidationEnabled": bool(trail.get("LogFileValidationEnabled")),
            "kmsEncrypted": bool(trail.get("KmsKeyId")),
            "managementEventSelectorCount": len(selectors),
            "capturesAllManagementEvents": management_selector_found,
        },
        blockers=blockers,
    )
