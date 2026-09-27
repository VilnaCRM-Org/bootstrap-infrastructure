"""Prepare and validate a TEST-only CloudFormation seed policy amendment.

No AWS call or installation is made here. An independent, authenticated non-root
installer must compare the complete live stack template, stack policy, IAM
versions, attachments and policy documents before creating a change set. It must
execute only the reviewed change-set ID, restore the deny-update stack policy,
and re-observe the entire active enrollment before enabling the service grant.
"""

from __future__ import annotations

import copy
import dataclasses
import json
from collections.abc import Mapping
from dataclasses import dataclass

from operator_seed_installation import (
    ActivationPacket,
    _logical_id,
    validate_activation,
)
from seed.policy_registry import (
    SeedRegistry,
    _bind,
    canonical_json,
    document_hash,
)
from seed.test_poc_prerequisite_amendment import (
    RESULT_CATALOG_SHA256,
    TARGETS,
    build_catalog,
)


@dataclass(frozen=True)
class TestPocSeedAmendment:
    """Pinned before/after artifacts, not authorization to install them."""

    baseline_template: str
    candidate_template: str
    temporary_stack_policy: str
    final_stack_policy: str
    resulting_registry: SeedRegistry


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def _catalog_document(catalog: dict, arn: str) -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            catalog["statements"][sid]
            for sid in catalog["policies"][arn]["statement_ids"]
        ],
    }


def build_amendment(activation: ActivationPacket) -> TestPocSeedAmendment:
    """Change only four TEST managed-policy documents in the active seed stack."""
    validate_activation(activation)
    registry = activation.installation.registry
    _require(registry.environment == "test", "Only TEST seed may be amended")
    catalog = build_catalog()
    old = json.loads(activation.activation_template)
    candidate = copy.deepcopy(old)
    _require(len(candidate["Resources"]) == 58, "Seed resource graph changed")
    new_policies = []
    for policy in registry.policies:
        if policy.arn not in TARGETS:
            new_policies.append(policy)
            continue
        logical_id = _logical_id(policy.arn)
        resource = candidate["Resources"][logical_id]
        _require(
            resource["Type"] == "AWS::IAM::ManagedPolicy"
            and resource["Properties"]["PolicyDocument"]
            == json.loads(policy.document_json),
            "Target policy is not the exact pinned baseline",
        )
        desired = _bind(_catalog_document(catalog, policy.arn), registry.seed_key.arn)
        resource["Properties"]["PolicyDocument"] = desired
        new_policies.append(
            dataclasses.replace(
                policy,
                document_json=canonical_json(desired),
                sha256=document_hash(desired),
            )
        )
    _require(len(new_policies) == 55, "TEST policy count changed")
    result_registry = dataclasses.replace(
        registry,
        catalog_sha256=RESULT_CATALOG_SHA256,
        policies=tuple(new_policies),
    )
    candidate["Metadata"]["CatalogSha256"] = RESULT_CATALOG_SHA256
    candidate["Metadata"]["RegistrySha256"] = result_registry.sha256
    targets = sorted(f"LogicalResourceId/{_logical_id(arn)}" for arn in TARGETS)
    temporary = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "Update:Modify",
                "Principal": "*",
                "Resource": targets,
            },
            {
                "Effect": "Deny",
                "Action": ["Update:Replace", "Update:Delete"],
                "Principal": "*",
                "Resource": "*",
            },
        ]
    }
    return TestPocSeedAmendment(
        baseline_template=activation.activation_template,
        candidate_template=canonical_json(candidate),
        temporary_stack_policy=canonical_json(temporary),
        final_stack_policy=activation.installation.stack_policy,
        resulting_registry=result_registry,
    )


def _validate_policy_detail(details: object) -> None:
    if not isinstance(details, list) or len(details) != 1:
        raise ValueError("One policy-document change is required")
    detail = details[0]
    if not isinstance(detail, Mapping):
        raise ValueError("Malformed policy detail")
    _require(
        (
            detail.get("Evaluation"),
            detail.get("ChangeSource"),
            detail.get("CausingEntity"),
        )
        == ("Static", "DirectModification", None),
        "Only a direct PolicyDocument edit is permitted",
    )
    target = detail.get("Target")
    if not isinstance(target, Mapping):
        raise ValueError("Malformed policy target")
    _require(
        (
            target.get("Attribute"),
            target.get("Name"),
            target.get("RequiresRecreation"),
        )
        == ("Properties", "PolicyDocument", "Never")
        and target.get("Path") in (None, "/Properties/PolicyDocument")
        and target.get("AttributeChangeType") in (None, "Modify"),
        "Only a direct PolicyDocument edit is permitted",
    )


def _validate_policy_change(change: object, expected: set[str]) -> str:
    if not isinstance(change, Mapping):
        raise ValueError("Malformed change")
    resource = change.get("ResourceChange")
    if change.get("Type") != "Resource" or not isinstance(resource, Mapping):
        raise ValueError("Malformed resource change")
    logical_id = resource.get("LogicalResourceId")
    if not isinstance(logical_id, str) or logical_id not in expected:
        raise ValueError("Unexpected policy change")
    arn = next(arn for arn in TARGETS if _logical_id(arn) == logical_id)
    _require(
        (
            resource.get("Action"),
            resource.get("ResourceType"),
            resource.get("PhysicalResourceId"),
            resource.get("Replacement"),
            resource.get("Scope"),
            resource.get("ChangeSetId"),
            resource.get("PolicyAction"),
        )
        == (
            "Modify",
            "AWS::IAM::ManagedPolicy",
            arn,
            "False",
            ["Properties"],
            None,
            None,
        ),
        "Only in-place managed-policy modification is permitted",
    )
    _validate_policy_detail(resource.get("Details"))
    return logical_id


def validate_change_set(
    activation: ActivationPacket,
    amendment: TestPocSeedAmendment,
    changes: object,
) -> None:
    """Reject any change beyond four in-place PolicyDocument modifications.

    The independent installer must authenticate the complete paginated AWS
    DescribeChangeSet response and the exact live before/after template bodies.
    These untrusted summaries alone never authorize execution.
    """
    _require(
        amendment == build_amendment(activation),
        "Amendment packet differs from reviewed source",
    )
    if not isinstance(changes, list):
        raise ValueError("Complete change list required")
    actual = set()
    expected = {_logical_id(arn) for arn in TARGETS}
    for change in changes:
        logical_id = _validate_policy_change(change, expected)
        _require(logical_id not in actual, "Duplicate policy change")
        actual.add(logical_id)
    _require(actual == expected, "All four policy changes are required")
