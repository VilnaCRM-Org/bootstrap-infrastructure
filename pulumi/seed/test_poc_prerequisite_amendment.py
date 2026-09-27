"""Render the closed TEST prerequisite seed amendment without activating it.

This module makes no AWS calls. The live CloudFormation owner and exact observed
policy versions must be authenticated before any change set can be executed.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

from .policy_registry import CATALOG_HASHES, document_hash, load_catalog

ACCOUNT = "891377212104"
REPOSITORY = "user-service-infrastructure"
POLICY_ARN = (
    f"arn:aws:iam::{ACCOUNT}:policy/GitHubCiApply-{REPOSITORY}-test-poc-prerequisites"
)
BOUNDARY = f"arn:aws:iam::{ACCOUNT}:policy/GovernanceBoundary-{REPOSITORY}-test"
PREVIEW_CEILING = (
    f"arn:aws:iam::{ACCOUNT}:policy/issue215-seed/test/ceiling/"
    "C-GitHubGovernancePreview"
)
DRIFT_CEILING = (
    f"arn:aws:iam::{ACCOUNT}:policy/issue215-seed/test/ceiling/C-GitHubGovernanceDrift"
)
APPLY_GUARD = (
    f"arn:aws:iam::{ACCOUNT}:policy/issue215-seed/test/guard/G-GitHubGovernanceApply"
)
TARGETS = frozenset({BOUNDARY, PREVIEW_CEILING, DRIFT_CEILING, APPLY_GUARD})
RESULT_CATALOG_SHA256 = (
    "ff2eaf296e5bd6e6bf8b02c7cdc31a2cfbcaef53fdea6173c64f77a3095effe7"
)
BASELINE_POLICY_HASHES = {
    BOUNDARY: "4a170a1cf18cc87dba99289f1e4ac342082e6d7198c64855662cd40527bdaf84",
    PREVIEW_CEILING: "ebf09dc35113bf01aacc94677f45b465ef22f58e2d0842e655838ae6c7041a4f",
    DRIFT_CEILING: "fef4d440e7363d45e3717af3f3c06f990e14af35d8335031cd4ad6fdd147c94a",
    APPLY_GUARD: "1115f1219a9cee5b299fa17d1dafcfb23e197deecd15d0c0d04752a660f85024",
}


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def _document(catalog: dict, arn: str) -> dict:
    record = catalog["policies"][arn]
    return {
        "Version": "2012-10-17",
        "Statement": [
            copy.deepcopy(catalog["statements"][sid]) for sid in record["statement_ids"]
        ],
    }


def _replace_document(catalog: dict, arn: str, document: dict) -> None:
    _require(arn in TARGETS, "Policy is outside the TEST amendment")
    record = catalog["policies"][arn]
    statement_ids = []
    for statement in document["Statement"]:
        sid = document_hash(statement)
        previous = catalog["statements"].setdefault(sid, statement)
        _require(previous == statement, "Statement hash collision")
        statement_ids.append(sid)
    record["statement_ids"] = statement_ids
    record["template_sha256"] = document_hash(document)
    _require(
        len(json.dumps(document, sort_keys=True, separators=(",", ":"))) <= 6144,
        "Managed policy exceeds IAM size limit",
    )


def _add_to_exact_list(statement: dict, field: str, required: str) -> None:
    values = statement.get(field)
    if not isinstance(values, list):
        raise ValueError("Expected IAM list changed")
    _require(required in values, "Expected IAM list changed")
    _require(POLICY_ARN not in values, "TEST policy already admitted")
    values.append(POLICY_ARN)


def build_catalog() -> dict:
    """Return the exact proposed catalog; leave the active pin untouched."""
    baseline = load_catalog("test")
    _require(
        document_hash(baseline) == CATALOG_HASHES["test"],
        "Active TEST baseline changed",
    )
    _require(
        {arn: baseline["policies"][arn]["template_sha256"] for arn in TARGETS}
        == BASELINE_POLICY_HASHES,
        "A target policy differs from the reviewed TEST baseline",
    )
    amendment = json.loads(
        Path(__file__)
        .with_name("test_poc_prerequisites.json")
        .read_text(encoding="utf-8")
    )
    _require(
        set(amendment) == {"version", "statements"}
        and amendment["version"] == "test-poc-prerequisites/v1"
        and isinstance(amendment["statements"], list)
        and len(amendment["statements"]) == 6,
        "Unexpected TEST capability manifest",
    )
    result = copy.deepcopy(baseline)
    boundary = _document(result, BOUNDARY)
    _require(len(boundary["Statement"]) == 5, "Service boundary shape changed")
    boundary["Statement"].extend(amendment["statements"])
    _replace_document(result, BOUNDARY, boundary)

    for arn in (PREVIEW_CEILING, DRIFT_CEILING):
        ceiling = _document(result, arn)
        _require(len(ceiling["Statement"]) == 12, "Governor ceiling shape changed")
        statement = ceiling["Statement"][1]
        _require(
            set(statement["Action"])
            == {
                "iam:GetPolicy",
                "iam:GetPolicyVersion",
                "iam:ListEntitiesForPolicy",
                "iam:ListPolicyTags",
                "iam:ListPolicyVersions",
            },
            "Governor policy-read action set changed",
        )
        _add_to_exact_list(statement, "Resource", BOUNDARY)
        _replace_document(result, arn, ceiling)

    guard = _document(result, APPLY_GUARD)
    _require(len(guard["Statement"]) == 8, "Governor guard shape changed")
    _require(guard["Statement"][6]["Action"] == "iam:*", "IAM guard changed")
    _add_to_exact_list(guard["Statement"][6], "NotResource", BOUNDARY)
    _require(
        "iam:CreatePolicy" in guard["Statement"][7]["Action"],
        "Policy-write guard changed",
    )
    _add_to_exact_list(
        guard["Statement"][7],
        "NotResource",
        POLICY_ARN.removesuffix("poc-prerequisites") + "pulumi-backend",
    )
    _replace_document(result, APPLY_GUARD, guard)

    result["provenance"]["test_poc_prerequisites_amendment"] = {
        "baseline_catalog_sha256": CATALOG_HASHES["test"],
        "target_policy_arns": sorted(TARGETS),
        "scope": "TEST-only registry, SES DKIM and exact backend-versioning read",
        "activation_authorized": False,
    }
    _require(
        {
            arn
            for arn in baseline["policies"]
            if baseline["policies"][arn] != result["policies"][arn]
        }
        == TARGETS,
        "TEST policy delta is not exactly the four reviewed policies",
    )
    _require(
        document_hash(result) == RESULT_CATALOG_SHA256,
        "TEST amendment differs from the reviewed result",
    )
    return result
