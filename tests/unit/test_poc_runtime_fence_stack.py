"""Creation packet for the TEST OIDC image publisher stack only."""

from __future__ import annotations

import json
from dataclasses import replace

import pytest
from seed import poc_runtime
from seed import poc_runtime_fence_stack as fences
from seed.policy_registry import RegistryError, canonical_json, document_hash

PUBLISHER = poc_runtime.runtime_identities()[2]
EXECUTION = poc_runtime.runtime_identities()[0]
BOUNDARY = PUBLISHER.policy_arn("boundary")
GUARD = PUBLISHER.policy_arn("guard")
FOREIGN = f"arn:aws:iam::{poc_runtime.ACCOUNT_ID}:policy/foreign"


def _ecs_fences():
    policies, _ = poc_runtime.enrollment_records()
    return [p.arn for p in policies if p.arn not in (BOUNDARY, GUARD)]


def _use_records(monkeypatch, policies, principals):
    monkeypatch.setattr(fences, "enrollment_records", lambda: (policies, principals))


def _with_publisher(monkeypatch, **changes):
    policies, principals = poc_runtime.enrollment_records()
    changed = tuple(
        replace(row, **changes) if row.arn == PUBLISHER.arn else row
        for row in principals
    )
    _use_records(monkeypatch, policies, changed)


def _policy_row(changes):
    return next(
        c
        for c in changes
        if c["ResourceChange"]["ResourceType"] == "AWS::IAM::ManagedPolicy"
    )


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


def test_publisher_stack_owns_only_publisher_fences_and_role():
    packet = fences.build_fence_stack_packet()
    fences.validate_fence_stack_packet(packet)
    assert packet.stack_name == "issue219-runtime-fences-test"
    assert len(packet.template_sha256) == 64
    template = json.loads(packet.template_json)
    policies, _ = poc_runtime.enrollment_records()
    owned = [p for p in policies if p.arn in (BOUNDARY, GUARD)]
    assert len(template["Resources"]) == 3
    assert [p.arn for p in owned] == [BOUNDARY, GUARD]
    assert packet.absent_policy_arns == tuple(sorted((BOUNDARY, GUARD)))
    assert packet.absent_role_arns == (PUBLISHER.arn,)
    for arn in _ecs_fences():
        assert fences._logical_id(arn) not in template["Resources"]
    assert template["Metadata"] == {
        "Contract": "issue219-test-publisher-seed/v3",
        "AccountId": poc_runtime.ACCOUNT_ID,
        "Region": poc_runtime.REGION,
        "PolicySetSha256": document_hash([(p.arn, p.sha256) for p in owned]),
        "PublisherSubjectSha256": fences.hashlib.sha256(
            poc_runtime.PUBLISHER_SUBJECT.encode("utf-8")
        ).hexdigest(),
    }
    for policy in owned:
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
    publisher = template["Resources"][fences._logical_id(PUBLISHER.arn)]
    assert publisher["Type"] == "AWS::IAM::Role"
    assert publisher["DeletionPolicy"] == "Retain"
    assert publisher["UpdateReplacePolicy"] == "Retain"
    props = publisher["Properties"]
    assert props["RoleName"] == poc_runtime.PUBLISHER_NAME
    assert props["Path"] == "/"
    assert props["AssumeRolePolicyDocument"] == json.loads(
        poc_runtime.publisher_trust(poc_runtime.PUBLISHER_SUBJECT)
    )
    assert props["PermissionsBoundary"] == BOUNDARY
    assert props["ManagedPolicyArns"] == [GUARD]
    assert props["Policies"] == [
        {
            "PolicyName": "Issue219TestImagePush",
            "PolicyDocument": json.loads(poc_runtime.publisher_policy()),
        }
    ]
    assert props["MaxSessionDuration"] == 3600
    assert props["Tags"] == [
        {"Key": "OwnerProject", "Value": "independent-seed"},
        {"Key": "Environment", "Value": "test"},
        {"Key": "Repository", "Value": poc_runtime.APPLICATION_REPOSITORY},
        {"Key": "Purpose", "Value": "publisher"},
    ]
    assert set(publisher["DependsOn"]) == {
        fences._logical_id(BOUNDARY),
        fences._logical_id(GUARD),
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
            tuple(
                replace(p, ownership="foreign") if p.arn == BOUNDARY else p
                for p in policies
            ),
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


def test_publisher_cannot_bind_a_foreign_boundary(monkeypatch):
    policies, principals = poc_runtime.enrollment_records()
    publisher = replace(
        principals[-1],
        boundary_arn=f"arn:aws:iam::{poc_runtime.ACCOUNT_ID}:policy/foreign",
    )
    monkeypatch.setattr(
        fences, "enrollment_records", lambda: (policies, (*principals[:-1], publisher))
    )
    with pytest.raises(RegistryError, match="Publisher fence binding changed"):
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
    _policy_row(changes)["ResourceChange"].update(edit)
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


def test_ecs_fence_records_are_not_owned_by_publisher_stack(monkeypatch):
    baseline = fences.build_fence_stack_packet()
    policies, principals = poc_runtime.enrollment_records()
    ecs = set(_ecs_fences())
    changed = tuple(
        replace(p, ownership="governance", installed_arn=True) if p.arn in ecs else p
        for p in policies
    )
    _use_records(monkeypatch, changed, principals)
    assert fences.build_fence_stack_packet() == baseline


@pytest.mark.parametrize(
    "field,edit",
    [
        ("policies", lambda rows: rows[:-1]),
        ("policies", lambda rows: (*rows, rows[0])),
        ("principals", lambda rows: rows[:-1]),
        ("principals", lambda rows: (*rows, rows[0])),
    ],
    ids=["policy-missing", "policy-extra", "principal-missing", "principal-extra"],
)
def test_stack_packet_rejects_changed_source_inventory(monkeypatch, field, edit):
    records = dict(zip(("policies", "principals"), poc_runtime.enrollment_records()))
    records[field] = edit(records[field])
    _use_records(monkeypatch, records["policies"], records["principals"])
    with pytest.raises(RegistryError, match="inventory changed"):
        fences.build_fence_stack_packet()


@pytest.mark.parametrize(
    "changes",
    [
        {"arn": f"arn:aws:iam::{poc_runtime.ACCOUNT_ID}:role/other-ImagePublisher"},
        {"owner_project": "governance"},
        {"existing": True},
        {"guard_arns": ()},
        {"guard_arns": (GUARD, GUARD), "attachment_arns": (GUARD, GUARD)},
        {"attachment_arns": ()},
        {"attachment_arns": (GUARD, FOREIGN)},
    ],
    ids=[
        "missing",
        "owner",
        "existing",
        "no-guard",
        "two-guards",
        "no-attachment",
        "extra-attachment",
    ],
)
def test_publisher_ownership_fails_closed(monkeypatch, changes):
    _with_publisher(monkeypatch, **changes)
    with pytest.raises(RegistryError, match="Publisher ownership changed"):
        fences.build_fence_stack_packet()


@pytest.mark.parametrize(
    "changes",
    [
        {"boundary_arn": FOREIGN},
        {"boundary_arn": None},
        {"boundary_arn": GUARD},
        {"boundary_arn": EXECUTION.policy_arn("boundary")},
        {"guard_arns": (FOREIGN,), "attachment_arns": (FOREIGN,)},
        {
            "guard_arns": (EXECUTION.policy_arn("guard"),),
            "attachment_arns": (EXECUTION.policy_arn("guard"),),
        },
    ],
)
def test_publisher_fence_binding_fails_closed(monkeypatch, changes):
    _with_publisher(monkeypatch, **changes)
    with pytest.raises(RegistryError, match="Publisher fence binding changed"):
        fences.build_fence_stack_packet()


def test_duplicate_publisher_fence_record_rejected(monkeypatch):
    policies, principals = poc_runtime.enrollment_records()
    boundary = next(p for p in policies if p.arn == BOUNDARY)
    _use_records(monkeypatch, (boundary, *policies[1:]), principals)
    with pytest.raises(RegistryError, match="Publisher fence binding changed"):
        fences.build_fence_stack_packet()


@pytest.mark.parametrize("arn", [BOUNDARY, GUARD])
@pytest.mark.parametrize("changes", [{"ownership": "foreign"}, {"installed_arn": True}])
def test_publisher_fence_ownership_fails_closed(monkeypatch, arn, changes):
    policies, principals = poc_runtime.enrollment_records()
    changed = tuple(replace(p, **changes) if p.arn == arn else p for p in policies)
    _use_records(monkeypatch, changed, principals)
    with pytest.raises(RegistryError, match="Runtime fence ownership changed"):
        fences.build_fence_stack_packet()


def test_non_resource_change_rejected():
    packet = fences.build_fence_stack_packet()
    changes = _changes(packet)
    changes[0]["Type"] = "Other"
    with pytest.raises(RegistryError, match="Unexpected runtime seed change"):
        fences.validate_fence_create_changes(packet, changes)


def test_obsolete_change_sets_rejected():
    packet = fences.build_fence_stack_packet()
    seven = _changes(packet) + [
        {
            "Type": "Resource",
            "ResourceChange": {
                "Action": "Add",
                "LogicalResourceId": fences._logical_id(arn),
                "ResourceType": "AWS::IAM::ManagedPolicy",
            },
        }
        for arn in _ecs_fences()
    ]
    six = [c for c in seven if c["ResourceChange"]["ResourceType"] != "AWS::IAM::Role"]
    assert (len(seven), len(six)) == (7, 6)
    for obsolete in (seven, six):
        with pytest.raises(RegistryError, match="Only exact new"):
            fences.validate_fence_create_changes(packet, obsolete)


def test_break_glass_during_update_policy_is_narrow():
    """Only Modify on the publisher role is allowed; replace/delete are denied."""
    text = fences.break_glass_during_update_policy_json()
    logical = fences._logical_id(fences.PUBLISHER.arn)
    assert json.loads(text) == {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "Update:Modify",
                "Principal": "*",
                "Resource": f"LogicalResourceId/{logical}",
            },
            {
                "Effect": "Deny",
                "Action": ["Update:Replace", "Update:Delete"],
                "Principal": "*",
                "Resource": "*",
            },
        ]
    }
    assert (
        logical
        in json.loads(fences.build_fence_stack_packet().template_json)["Resources"]
    )
    assert text != fences.build_fence_stack_packet().deny_update_policy_json
