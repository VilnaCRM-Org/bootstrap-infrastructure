"""Closed CloudFormation packet for TEST fences and the image publisher.

This pure module does not authenticate AWS observations or execute a change set.
An independent installer must verify that the stack, policy and role names
are absent, authenticate the complete AWS response, and restore the deny-update
stack policy after creation. ECS role enrollment remains separate.
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
    enrollment_records,
    publisher_policy,
    publisher_trust,
)
from .policy_registry import RegistryError, canonical_json, document_hash

STACK_NAME = "issue219-runtime-fences-test"
CONTRACT_VERSION = "issue219-test-runtime-seed/v2"


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


def build_fence_stack_packet() -> FenceStackPacket:
    """Render six independent fences and one exact OIDC publisher role."""
    policies, principals = enrollment_records()
    if len(policies) != 6 or len(principals) != 3:
        raise RegistryError("Runtime fence inventory changed")
    publisher = next(
        (row for row in principals if row.arn.endswith("/" + PUBLISHER_NAME)), None
    )
    if (
        publisher is None
        or publisher.owner_project != "independent-seed"
        or publisher.existing
        or len(publisher.guard_arns) != 1
        or publisher.attachment_arns != publisher.guard_arns
    ):
        raise RegistryError("Publisher ownership changed")
    resources = {}
    for policy in policies:
        if policy.ownership != "independent-seed" or policy.installed_arn:
            raise RegistryError("Runtime fence ownership changed")
        path, name = policy.arn.split(":policy/", 1)[1].rsplit("/", 1)
        resources[_logical_id(policy.arn)] = {
            "Type": "AWS::IAM::ManagedPolicy",
            "DeletionPolicy": "Retain",
            "UpdateReplacePolicy": "Retain",
            "Properties": {
                "ManagedPolicyName": name,
                "Path": f"/{path}/",
                "PolicyDocument": json.loads(policy.document_json),
            },
        }
    publisher_logical_id = _logical_id(publisher.arn)
    publisher_guard = publisher.guard_arns[0]
    if not {
        publisher.boundary_arn,
        publisher_guard,
    } <= {policy.arn for policy in policies}:
        raise RegistryError("Publisher fence binding changed")
    resources[publisher_logical_id] = {
        "Type": "AWS::IAM::Role",
        "DeletionPolicy": "Retain",
        "UpdateReplacePolicy": "Retain",
        "DependsOn": [
            _logical_id(publisher.boundary_arn),
            _logical_id(publisher_guard),
        ],
        "Properties": {
            "RoleName": PUBLISHER_NAME,
            "Path": "/",
            "AssumeRolePolicyDocument": json.loads(publisher_trust(PUBLISHER_SUBJECT)),
            "PermissionsBoundary": publisher.boundary_arn,
            "ManagedPolicyArns": [publisher_guard],
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
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Metadata": {
            "Contract": CONTRACT_VERSION,
            "AccountId": ACCOUNT_ID,
            "Region": REGION,
            "PolicySetSha256": document_hash(
                [(policy.arn, policy.sha256) for policy in policies]
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
        tuple(sorted(policy.arn for policy in policies)),
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
    """Require seven exact Add rows from an authenticated complete change set.

    The caller must separately prove TEST account/region, absent stack and names,
    reviewed template digest, change-set ID/type/status and pagination closure.
    This offline summary validator cannot establish those live facts.
    """
    validate_fence_stack_packet(packet)
    if not isinstance(changes, list):
        raise RegistryError("Complete runtime seed change list required")
    expected = json.loads(packet.template_json)["Resources"]
    seen: set[str] = set()
    for change in changes:
        seen.add(_validate_add_row(change, expected, seen))
    if seen != set(expected):
        raise RegistryError("All seven runtime seed additions are required")
