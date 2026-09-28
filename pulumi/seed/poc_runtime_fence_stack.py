"""Closed CloudFormation creation packet for the six TEST runtime fences.

This pure module does not authenticate AWS observations or execute a change set.
An independent non-root installer must verify that the stack and policy names
are absent, authenticate the complete AWS response, and restore the deny-update
stack policy after creation before runtime role enrollment is permitted.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass

from .poc_runtime import ACCOUNT_ID, REGION, enrollment_records
from .policy_registry import RegistryError, canonical_json, document_hash

STACK_NAME = "issue219-runtime-fences-test"
CONTRACT_VERSION = "issue219-test-runtime-fences/v1"


@dataclass(frozen=True)
class FenceStackPacket:
    """Exact proposed new owner; neither installed state nor apply authority."""

    stack_name: str
    template_json: str
    deny_update_policy_json: str
    absent_policy_arns: tuple[str, ...]

    @property
    def template_sha256(self) -> str:
        """Bind a reviewed packet to the complete canonical template bytes."""
        return hashlib.sha256(self.template_json.encode("utf-8")).hexdigest()


def _logical_id(arn: str) -> str:
    return "RuntimeFence" + hashlib.sha256(arn.encode("utf-8")).hexdigest()


def build_fence_stack_packet() -> FenceStackPacket:
    """Render a separate owner without altering the installed seed catalog."""
    policies, principals = enrollment_records()
    if len(policies) != 6 or len(principals) != 3:
        raise RegistryError("Runtime fence inventory changed")
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
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Metadata": {
            "Contract": CONTRACT_VERSION,
            "AccountId": ACCOUNT_ID,
            "Region": REGION,
            "PolicySetSha256": document_hash(
                [(policy.arn, policy.sha256) for policy in policies]
            ),
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
    )


def validate_fence_stack_packet(packet: FenceStackPacket) -> None:
    """Reject even plausible changes to a reviewed creation packet."""
    if not isinstance(packet, FenceStackPacket) or packet != build_fence_stack_packet():
        raise RegistryError("Runtime fence packet differs from reviewed source")


def _validate_add_metadata(row: Mapping) -> None:
    if (
        row.get("Action") != "Add"
        or row.get("ResourceType") != "AWS::IAM::ManagedPolicy"
    ):
        raise RegistryError("Only exact new runtime fence policies may be added")
    if row.get("PhysicalResourceId") is not None or row.get("ChangeSetId") is not None:
        raise RegistryError("Only exact new runtime fence policies may be added")
    if row.get("Replacement") not in (None, "False"):
        raise RegistryError("Only exact new runtime fence policies may be added")
    if row.get("PolicyAction") not in (None, "Retain"):
        raise RegistryError("Only exact new runtime fence policies may be added")


def _validate_add_row(change: object, expected: dict, seen: set[str]) -> str:
    if not isinstance(change, Mapping) or change.get("Type") != "Resource":
        raise RegistryError("Unexpected runtime fence change")
    row = change.get("ResourceChange")
    if not isinstance(row, Mapping):
        raise RegistryError("Malformed runtime fence resource change")
    logical = row.get("LogicalResourceId")
    if not isinstance(logical, str) or logical not in expected or logical in seen:
        raise RegistryError("Only exact new runtime fence policies may be added")
    _validate_add_metadata(row)
    return logical


def validate_fence_create_changes(packet: FenceStackPacket, changes: object) -> None:
    """Require six exact Add rows from an authenticated complete change set.

    The caller must separately prove TEST account/region, absent stack and names,
    reviewed template digest, change-set ID/type/status and pagination closure.
    This offline summary validator cannot establish those live facts.
    """
    validate_fence_stack_packet(packet)
    if not isinstance(changes, list):
        raise RegistryError("Complete runtime fence change list required")
    expected = json.loads(packet.template_json)["Resources"]
    seen: set[str] = set()
    for change in changes:
        seen.add(_validate_add_row(change, expected, seen))
    if seen != set(expected):
        raise RegistryError("All six runtime fence additions are required")
