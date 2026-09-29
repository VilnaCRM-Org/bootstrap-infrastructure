"""Closed CloudFormation packet for the TEST image publisher only.

This pure module does not authenticate AWS observations or execute a change set.
The publisher stack owns exactly the publisher boundary, its sole guard and the
``user-service-test-ImagePublisher`` role. ECS execution/task fences stay outside
this retained deny-update owner until a later reviewed runtime amendment adds
their log, secret, KMS, queue and mail grants. An independent installer must
verify that the stack, policy and role names are absent, authenticate the
complete AWS response, and restore the deny-update stack policy after creation.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass

from .poc_runtime import (
    ACCOUNT_ID,
    APPLICATION_REPOSITORY,
    PUBLISHER_NAME,
    PUBLISHER_SUBJECT,
    REGION,
    RuntimeIdentity,
    enrollment_records,
    publisher_policy,
    publisher_trust,
)
from .policy_registry import (
    PolicyRecord,
    PrincipalRecord,
    RegistryError,
    canonical_json,
    document_hash,
)

STACK_NAME = "issue219-runtime-fences-test"
CONTRACT_VERSION = "issue219-test-publisher-seed/v3"
PUBLISHER = RuntimeIdentity("publisher", PUBLISHER_NAME)


@dataclass(frozen=True)
class FenceStackPacket:
    """Exact proposed new owner; neither installed state nor apply authority."""

    stack_name: str
    template_json: str
    deny_update_policy_json: str
    absent_policy_arns: tuple[str, ...]
    absent_role_arns: tuple[str, ...]

    @property
    def template_sha256(self) -> str:
        """Bind a reviewed packet to the complete canonical template bytes."""
        return hashlib.sha256(self.template_json.encode("utf-8")).hexdigest()


def _logical_id(arn: str) -> str:
    return "RuntimeFence" + hashlib.sha256(arn.encode("utf-8")).hexdigest()


def _verified_publisher(
    policies: tuple[PolicyRecord, ...], principals: tuple[PrincipalRecord, ...]
) -> tuple[PrincipalRecord, tuple[PolicyRecord, ...]]:
    publisher = next((row for row in principals if row.arn == PUBLISHER.arn), None)
    if (
        publisher is None
        or publisher.owner_project != "independent-seed"
        or publisher.existing
        or len(publisher.guard_arns) != 1
        or publisher.attachment_arns != publisher.guard_arns
    ):
        raise RegistryError("Publisher ownership changed")
    return publisher, _publisher_fences(policies, publisher)


def _publisher_fences(
    policies: tuple[PolicyRecord, ...], publisher: PrincipalRecord
) -> tuple[PolicyRecord, ...]:
    """Select the exact publisher boundary and sole guard, never an ECS fence."""
    fences = (PUBLISHER.policy_arn("boundary"), PUBLISHER.policy_arn("guard"))
    owned = tuple(policy for policy in policies if policy.arn in fences)
    bound = (publisher.boundary_arn, *publisher.guard_arns)
    if bound != fences or sorted(policy.arn for policy in owned) != sorted(fences):
        raise RegistryError("Publisher fence binding changed")
    for policy in owned:
        if policy.ownership != "independent-seed" or policy.installed_arn:
            raise RegistryError("Runtime fence ownership changed")
    return owned


def _managed_policy(policy: PolicyRecord) -> dict:
    """Render one retained publisher fence at its reviewed path."""
    path, name = policy.arn.split(":policy/", 1)[1].rsplit("/", 1)
    return {
        "Type": "AWS::IAM::ManagedPolicy",
        "DeletionPolicy": "Retain",
        "UpdateReplacePolicy": "Retain",
        "Properties": {
            "ManagedPolicyName": name,
            "Path": f"/{path}/",
            "PolicyDocument": json.loads(policy.document_json),
        },
    }


def _publisher_role() -> dict:
    """Render the exact OIDC publisher with its boundary, sole guard and push."""
    boundary, guard = PUBLISHER.policy_arn("boundary"), PUBLISHER.policy_arn("guard")
    return {
        "Type": "AWS::IAM::Role",
        "DeletionPolicy": "Retain",
        "UpdateReplacePolicy": "Retain",
        "DependsOn": [_logical_id(boundary), _logical_id(guard)],
        "Properties": {
            "RoleName": PUBLISHER_NAME,
            "Path": "/",
            "AssumeRolePolicyDocument": json.loads(publisher_trust(PUBLISHER_SUBJECT)),
            "PermissionsBoundary": boundary,
            "ManagedPolicyArns": [guard],
            "Policies": [
                {
                    "PolicyName": "Issue219TestImagePush",
                    "PolicyDocument": json.loads(publisher_policy()),
                }
            ],
            "MaxSessionDuration": 3600,
            "Tags": [
                {"Key": "OwnerProject", "Value": "independent-seed"},
                {"Key": "Environment", "Value": "test"},
                {"Key": "Repository", "Value": APPLICATION_REPOSITORY},
                {"Key": "Purpose", "Value": "publisher"},
            ],
        },
    }


def build_fence_stack_packet() -> FenceStackPacket:
    """Render only the publisher boundary, sole guard and exact OIDC role."""
    policies, principals = enrollment_records()
    if len(policies) != 6 or len(principals) != 3:
        raise RegistryError("Runtime fence inventory changed")
    publisher, owned = _verified_publisher(policies, principals)
    resources = {_logical_id(policy.arn): _managed_policy(policy) for policy in owned}
    resources[_logical_id(publisher.arn)] = _publisher_role()
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Metadata": {
            "Contract": CONTRACT_VERSION,
            "AccountId": ACCOUNT_ID,
            "Region": REGION,
            "PolicySetSha256": document_hash(
                [(policy.arn, policy.sha256) for policy in owned]
            ),
            "PublisherSubjectSha256": hashlib.sha256(
                PUBLISHER_SUBJECT.encode("utf-8")
            ).hexdigest(),
        },
        "Resources": resources,
    }
    deny_update = {
        "Statement": [
            {
                "Effect": "Deny",
                "Action": "Update:*",
                "Principal": "*",
                "Resource": "*",
            }
        ]
    }
    return FenceStackPacket(
        STACK_NAME,
        canonical_json(template),
        canonical_json(deny_update),
        tuple(sorted(policy.arn for policy in owned)),
        (publisher.arn,),
    )


def validate_fence_stack_packet(packet: FenceStackPacket) -> None:
    """Reject even plausible changes to a reviewed creation packet."""
    if not isinstance(packet, FenceStackPacket) or packet != build_fence_stack_packet():
        raise RegistryError("Runtime seed packet differs from reviewed source")


def _validate_add_metadata(row: Mapping, expected_type: str) -> None:
    if row.get("Action") != "Add" or row.get("ResourceType") != expected_type:
        raise RegistryError("Only exact new runtime seed resources may be added")
    if row.get("PhysicalResourceId") is not None or row.get("ChangeSetId") is not None:
        raise RegistryError("Only exact new runtime seed resources may be added")
    if row.get("Replacement") not in (None, "False"):
        raise RegistryError("Only exact new runtime seed resources may be added")
    if row.get("PolicyAction") not in (None, "Retain"):
        raise RegistryError("Only exact new runtime seed resources may be added")


def _validate_add_row(change: object, expected: dict, seen: set[str]) -> str:
    if not isinstance(change, Mapping) or change.get("Type") != "Resource":
        raise RegistryError("Unexpected runtime seed change")
    row = change.get("ResourceChange")
    if not isinstance(row, Mapping):
        raise RegistryError("Malformed runtime seed resource change")
    logical = row.get("LogicalResourceId")
    if not isinstance(logical, str) or logical not in expected or logical in seen:
        raise RegistryError("Only exact new runtime seed resources may be added")
    _validate_add_metadata(row, expected[logical]["Type"])
    return logical


def validate_fence_create_changes(packet: FenceStackPacket, changes: object) -> None:
    """Require exactly three Add rows from an authenticated complete change set.

    Obsolete seven-resource and six-policy change sets fail because ECS fence
    rows are foreign to the publisher stack. The caller must separately prove
    TEST account/region, absent stack and names, reviewed template digest,
    change-set ID/type/status and pagination closure. This offline summary
    validator cannot establish those live facts.
    """
    validate_fence_stack_packet(packet)
    if not isinstance(changes, list):
        raise RegistryError("Complete runtime seed change list required")
    expected = json.loads(packet.template_json)["Resources"]
    seen: set[str] = set()
    for change in changes:
        seen.add(_validate_add_row(change, expected, seen))
    if seen != set(expected):
        raise RegistryError("All three publisher stack additions are required")
