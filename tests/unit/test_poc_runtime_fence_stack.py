"""Creation packet for TEST runtime fences and OIDC image publisher."""

from __future__ import annotations

import json
from dataclasses import replace

import pytest
from seed import poc_runtime
from seed import poc_runtime_fence_stack as fences
from seed.policy_registry import RegistryError, canonical_json, document_hash


def _changes(packet):
    resources = json.loads(packet.template_json)["Resources"]
    return [
        {
            "Type": "Resource",
            "ResourceChange": {
                "Action": "Add",
                "LogicalResourceId": logical,
                "ResourceType": resource["Type"],
            },
        }
        for logical, resource in resources.items()
    ]


def test_separate_stack_owns_six_fences_and_exact_publisher():
    packet = fences.build_fence_stack_packet()
    fences.validate_fence_stack_packet(packet)
    assert packet.stack_name == "issue219-runtime-fences-test"
    assert len(packet.template_sha256) == 64
    template = json.loads(packet.template_json)
    policies, _ = poc_runtime.enrollment_records()
    assert len(template["Resources"]) == 7
    assert packet.absent_policy_arns == tuple(sorted(p.arn for p in policies))
    publisher_arn = (
        f"arn:aws:iam::{poc_runtime.ACCOUNT_ID}:role/{poc_runtime.PUBLISHER_NAME}"
    )
    assert packet.absent_role_arns == (publisher_arn,)
    assert template["Metadata"] == {
        "Contract": fences.CONTRACT_VERSION,
        "AccountId": poc_runtime.ACCOUNT_ID,
        "Region": poc_runtime.REGION,
        "PolicySetSha256": document_hash([(p.arn, p.sha256) for p in policies]),
        "PublisherSubjectSha256": fences.hashlib.sha256(
            poc_runtime.PUBLISHER_SUBJECT.encode("utf-8")
        ).hexdigest(),
    }
    for policy in policies:
        resource = template["Resources"][fences._logical_id(policy.arn)]
        assert resource["Type"] == "AWS::IAM::ManagedPolicy"
        assert resource["DeletionPolicy"] == "Retain"
        assert resource["UpdateReplacePolicy"] == "Retain"
        properties = resource["Properties"]
        assert set(properties) == {"ManagedPolicyName", "Path", "PolicyDocument"}
        assert canonical_json(properties["PolicyDocument"]) == policy.document_json
        assert (
            f"arn:aws:iam::{poc_runtime.ACCOUNT_ID}:policy"
            f"{properties['Path']}{properties['ManagedPolicyName']}" == policy.arn
        )
    publisher = template["Resources"][fences._logical_id(publisher_arn)]
    assert publisher["Type"] == "AWS::IAM::Role"
    assert publisher["DeletionPolicy"] == "Retain"
    assert publisher["UpdateReplacePolicy"] == "Retain"
    props = publisher["Properties"]
    assert props["RoleName"] == poc_runtime.PUBLISHER_NAME
    assert props["Path"] == "/"
    assert props["AssumeRolePolicyDocument"] == json.loads(
        poc_runtime.publisher_trust(poc_runtime.PUBLISHER_SUBJECT)
    )
    assert props["PermissionsBoundary"] in packet.absent_policy_arns
    assert props["ManagedPolicyArns"] == [
        next(
            arn for arn in packet.absent_policy_arns if arn.endswith("Publisher-Guard")
        )
    ]
    assert props["Policies"] == [
        {
            "PolicyName": "Issue219TestImagePush",
            "PolicyDocument": json.loads(poc_runtime.publisher_policy()),
        }
    ]
    assert set(publisher["DependsOn"]) == {
        fences._logical_id(props["PermissionsBoundary"]),
        fences._logical_id(props["ManagedPolicyArns"][0]),
    }
    assert json.loads(packet.deny_update_policy_json) == {
        "Statement": [
            {
                "Effect": "Deny",
                "Action": "Update:*",
                "Principal": "*",
                "Resource": "*",
            }
        ]
    }


@pytest.mark.parametrize(
    "field",
    [
        "stack_name",
        "template_json",
        "deny_update_policy_json",
        "absent_policy_arns",
        "absent_role_arns",
    ],
)
def test_packet_tampering_rejected(field):
    packet = fences.build_fence_stack_packet()
    value = getattr(packet, field)
    changed = value + "-other" if isinstance(value, str) else value[:-1]
    with pytest.raises(RegistryError, match="reviewed source"):
        fences.validate_fence_stack_packet(replace(packet, **{field: changed}))


def test_complete_synthetic_create_change_set_accepted():
    packet = fences.build_fence_stack_packet()
    fences.validate_fence_create_changes(packet, _changes(packet))


def test_stack_packet_rejects_incomplete_or_foreign_enrollment(monkeypatch):
    policies, principals = poc_runtime.enrollment_records()
    monkeypatch.setattr(
        fences, "enrollment_records", lambda: (policies[:-1], principals)
    )
    with pytest.raises(RegistryError, match="inventory changed"):
        fences.build_fence_stack_packet()
    monkeypatch.setattr(
        fences,
        "enrollment_records",
        lambda: (
            (replace(policies[0], ownership="foreign"), *policies[1:]),
            principals,
        ),
    )
    with pytest.raises(RegistryError, match="ownership changed"):
        fences.build_fence_stack_packet()


def test_publisher_cannot_lose_its_independent_owner_or_exact_guard(monkeypatch):
    policies, principals = poc_runtime.enrollment_records()
    for changed in (
        replace(principals[-1], owner_project="governance"),
        replace(principals[-1], guard_arns=()),
    ):
        monkeypatch.setattr(
            fences,
            "enrollment_records",
            lambda changed=changed: (policies, (*principals[:-1], changed)),
        )
        with pytest.raises(RegistryError, match="Publisher ownership changed"):
            fences.build_fence_stack_packet()


@pytest.mark.parametrize(
    "edit",
    [
        {"Action": "Modify"},
        {"Action": "Import"},
        {"ResourceType": "AWS::IAM::Role"},
        {"PhysicalResourceId": "existing-policy"},
        {"Replacement": "True"},
        {"PolicyAction": "Delete"},
        {"ChangeSetId": "nested"},
        {"LogicalResourceId": "Foreign"},
    ],
)
def test_create_change_set_rejects_foreign_or_destructive_rows(edit):
    packet = fences.build_fence_stack_packet()
    changes = _changes(packet)
    changes[0]["ResourceChange"].update(edit)
    with pytest.raises(RegistryError, match="Only exact new"):
        fences.validate_fence_create_changes(packet, changes)


def test_create_change_set_rejects_missing_duplicate_or_malformed_rows():
    packet = fences.build_fence_stack_packet()
    changes = _changes(packet)
    for bad in (changes[:-1], changes + changes[:1], changes + [{"Type": "Other"}]):
        with pytest.raises(RegistryError):
            fences.validate_fence_create_changes(packet, bad)
    with pytest.raises(RegistryError, match="Complete"):
        fences.validate_fence_create_changes(packet, None)
    changes = _changes(packet)
    changes[0].pop("ResourceChange")
    with pytest.raises(RegistryError, match="Malformed"):
        fences.validate_fence_create_changes(packet, changes)
