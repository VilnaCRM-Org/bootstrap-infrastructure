"""Compare post-create publisher stack metadata; never authorize activation.

The caller must authenticate every observation in the TEST account, follow all
pagination and URL-decode IAM documents before calling this pure comparison.
Only the publisher boundary, its sole guard and the publisher role are covered;
the ECS execution/task roles and fences are neither required nor accepted.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from .poc_runtime import ACCOUNT_ID, REGION, disabled_trust
from .poc_runtime_fence_stack import (
    PUBLISHER,
    FenceStackPacket,
    build_fence_stack_packet,
)
from .policy_registry import ObservedPolicy, RegistryError, canonical_json

ROLE_TYPE = "AWS::IAM::Role"
POLICY_TYPE = "AWS::IAM::ManagedPolicy"


@dataclass(frozen=True)
class ObservedPublisherRole:
    """URL-decoded GetRole, attachment, inline-policy and tag metadata."""

    arn: str
    path: str
    boundary_arn: str | None
    attachment_arns: tuple[str, ...]
    inline_policies: tuple[tuple[str, str], ...]
    max_session_duration: int
    tags: tuple[tuple[str, str], ...]
    trust_json: str


@dataclass(frozen=True)
class ObservedPublisherStack:
    """Complete caller-collected post-create state; not authenticated evidence."""

    account_id: str
    region: str
    stack_name: str
    stack_status: str
    template_json: str
    termination_protection: bool
    stack_policy_json: str
    stack_resources: tuple[tuple[str, str, str], ...]
    policies: tuple[ObservedPolicy, ...]
    role: ObservedPublisherRole


@dataclass(frozen=True)
class PublisherStackVerification:
    """Exact post-create comparison result carrying no activation authority."""

    template_sha256: str
    policies_verified: int = 2
    roles_verified: int = 1
    activation_authorized: bool = False


def _canonical(document: str) -> str:
    """Compare decoded JSON independent of whitespace and object key order."""
    return canonical_json(json.loads(document))


def _physical_id(resource: dict) -> str:
    """Return the identifier CloudFormation reports for one owned resource."""
    properties = resource["Properties"]
    if resource["Type"] == ROLE_TYPE:
        return properties["RoleName"]
    return (
        f"arn:aws:iam::{ACCOUNT_ID}:policy"
        f"{properties['Path']}{properties['ManagedPolicyName']}"
    )


def _verify_stack(
    observed: ObservedPublisherStack, packet: FenceStackPacket, status: str
) -> None:
    """Bind target, name, status, template and both protection controls."""
    if (observed.account_id, observed.region) != (ACCOUNT_ID, REGION):
        raise RegistryError("Publisher stack target differs")
    if observed.stack_name != packet.stack_name:
        raise RegistryError("Publisher stack name differs")
    if observed.stack_status != status:
        raise RegistryError(f"Publisher stack status is not {status}")
    if _canonical(observed.template_json) != packet.template_json:
        raise RegistryError("Publisher stack template differs from reviewed packet")
    if observed.termination_protection is not True:
        raise RegistryError("Publisher stack termination protection is disabled")
    if _canonical(observed.stack_policy_json) != packet.deny_update_policy_json:
        raise RegistryError("Publisher stack deny-update policy differs")


def _verify_inventory(observed: ObservedPublisherStack, resources: dict) -> None:
    """Require exactly three stack resources and the two publisher fences."""
    expected = {
        (logical, resource["Type"], _physical_id(resource))
        for logical, resource in resources.items()
    }
    rows = set(observed.stack_resources)
    if len(rows) != len(observed.stack_resources) or rows != expected:
        raise RegistryError("Publisher stack resource inventory differs")
    arns = [policy.arn for policy in observed.policies]
    fences = {arn for _, kind, arn in expected if kind == POLICY_TYPE}
    if len(set(arns)) != len(arns) or set(arns) != fences:
        raise RegistryError("Publisher stack policy inventory differs")


def _verify_policies(observed: ObservedPublisherStack, resources: dict) -> None:
    """Require creation-time default versions and exact fence documents."""
    actual = {policy.arn: policy for policy in observed.policies}
    for resource in resources.values():
        if resource["Type"] != POLICY_TYPE:
            continue
        policy = actual[_physical_id(resource)]
        if policy.default_version_id != "v1":
            raise RegistryError("Publisher fence default version changed")
        document = canonical_json(resource["Properties"]["PolicyDocument"])
        if _canonical(policy.document_json) != document:
            raise RegistryError("Publisher fence document differs")


def _verify_role(role: ObservedPublisherRole, properties: dict) -> None:
    """Require exact identity, path, boundary, sole guard and session limit."""
    if role.arn != PUBLISHER.arn:
        raise RegistryError("Publisher role identity differs")
    if role.path != properties["Path"]:
        raise RegistryError("Publisher role path differs")
    if role.boundary_arn != properties["PermissionsBoundary"]:
        raise RegistryError("Publisher permissions boundary differs")
    if tuple(role.attachment_arns) != tuple(properties["ManagedPolicyArns"]):
        raise RegistryError("Publisher must keep only its single guard attachment")
    if role.max_session_duration != properties["MaxSessionDuration"]:
        raise RegistryError("Publisher maximum session duration differs")
    _verify_role_documents(role, properties)


def _verify_role_documents(role: ObservedPublisherRole, properties: dict) -> None:
    """Require the complete inline grant, exact tags and exact trust document."""
    inline = sorted((name, _canonical(text)) for name, text in role.inline_policies)
    expected_inline = sorted(
        (row["PolicyName"], canonical_json(row["PolicyDocument"]))
        for row in properties["Policies"]
    )
    if inline != expected_inline:
        raise RegistryError("Publisher inline grants differ")
    tags = dict(role.tags)
    expected_tags = {row["Key"]: row["Value"] for row in properties["Tags"]}
    if len(tags) != len(role.tags) or tags != expected_tags:
        raise RegistryError("Publisher role tags differ")
    trust = canonical_json(properties["AssumeRolePolicyDocument"])
    if _canonical(role.trust_json) != trust:
        raise RegistryError("Publisher trust document differs")


def _verify(
    observed: ObservedPublisherStack, packet: FenceStackPacket, status: str
) -> PublisherStackVerification:
    """Run every per-field comparison against one explicit expected packet."""
    if not isinstance(observed, ObservedPublisherStack) or not isinstance(
        observed.role, ObservedPublisherRole
    ):
        raise RegistryError("Complete publisher stack observation required")
    resources = json.loads(packet.template_json)["Resources"]
    _verify_stack(observed, packet, status)
    _verify_inventory(observed, resources)
    _verify_policies(observed, resources)
    role = next(row for row in resources.values() if row["Type"] == ROLE_TYPE)
    _verify_role(observed.role, role["Properties"])
    return PublisherStackVerification(packet.template_sha256)


def _amended_packet() -> FenceStackPacket:
    """Reviewed break-glass amendment: only the role trust becomes disabled."""
    base = build_fence_stack_packet()
    template = json.loads(base.template_json)
    for resource in template["Resources"].values():
        if resource["Type"] == ROLE_TYPE:
            resource["Properties"]["AssumeRolePolicyDocument"] = json.loads(
                disabled_trust()
            )
    return FenceStackPacket(
        base.stack_name,
        canonical_json(template),
        base.deny_update_policy_json,
        base.absent_policy_arns,
        base.absent_role_arns,
    )


def verify_publisher_stack(
    observed: ObservedPublisherStack,
) -> PublisherStackVerification:
    """Require exact post-create state of the three-resource publisher stack.

    Termination protection and the stack policy must come from authenticated
    DescribeStacks/GetStackPolicy reads. A match proves neither authentication,
    authority nor atomicity and never authorizes activation.
    """
    return _verify(observed, build_fence_stack_packet(), "CREATE_COMPLETE")


def verify_amended_publisher_stack(
    observed: ObservedPublisherStack,
) -> PublisherStackVerification:
    """Require exact UPDATE_COMPLETE state after the break-glass trust amendment.

    Identical per-field checks, but against the reviewed amended template whose
    only difference is the disabled role trust; the caller supplies no expected
    packet, and the original enabled trust is rejected. Never authorizes
    activation.
    """
    return _verify(observed, _amended_packet(), "UPDATE_COMPLETE")
