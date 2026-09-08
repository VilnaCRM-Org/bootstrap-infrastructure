"""Seed installation artifacts keep independent ownership and closed authority."""

import json
import sys
from dataclasses import replace
from pathlib import Path

import pytest
from seed import policy_registry as registry
from test_seed_policy_registry import key_for

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))

import operator_seed_installation as installation  # noqa: E402
from seed.operator_trust import operator_trust_policy  # noqa: E402


def packet_for(environment="test"):
    """Render offline artifacts with explicitly synthetic test KMS metadata."""
    return installation.build_installation(
        environment,
        account_id=registry.ACCOUNTS[environment],
        seed_key=key_for(environment),
    )


def changes_for(packet, phase):
    """Model complete AWS resource changes without claiming live provenance."""
    imported = json.loads(packet.import_template)["Resources"]
    all_resources = json.loads(packet.enrollment_template)["Resources"]
    identities = {
        p["LogicalResourceId"]: p["ResourceIdentifier"]["PolicyArn"]
        for p in json.loads(packet.resources_to_import)
    }
    selected = (
        imported
        if phase == "import"
        else {key: value for key, value in all_resources.items() if key not in imported}
    )
    return [
        {
            "Type": "Resource",
            "ResourceChange": {
                "Action": "Import" if phase == "import" else "Add",
                "LogicalResourceId": key,
                "ResourceType": value["Type"],
                **(
                    {"PhysicalResourceId": identities[key]} if phase == "import" else {}
                ),
            },
        }
        for key, value in selected.items()
    ]


@pytest.mark.parametrize("environment", ["test", "prod"])
def test_exact_retained_graph_and_import_schema(environment):
    packet = packet_for(environment)
    expected = packet.registry
    installation.validate_installation(packet)
    assert packet == packet_for(environment)
    imported = json.loads(packet.import_template)
    full = json.loads(packet.enrollment_template)
    assert imported["Metadata"] == full["Metadata"]
    assert full["Metadata"]["CatalogSha256"] == registry.CATALOG_HASHES[environment]
    assert full["Metadata"]["RegistrySha256"] == expected.sha256
    assert full["Metadata"]["SeedKmsKeyArn"] == key_for(environment).arn
    assert full["Metadata"]["ActivationAuthorized"] is False
    resources = full["Resources"]
    assert len(resources) == 58
    policy_properties = [
        r["Properties"]
        for r in resources.values()
        if r["Type"] == "AWS::IAM::ManagedPolicy"
    ]
    assert len({p["ManagedPolicyName"].casefold() for p in policy_properties}) == 55
    assert len(imported["Resources"]) == 6
    assert all(resources[key] == value for key, value in imported["Resources"].items())
    for resource in resources.values():
        assert resource["DeletionPolicy"] == resource["UpdateReplacePolicy"] == "Retain"
    imports = json.loads(packet.resources_to_import)
    assert {p["ResourceIdentifier"]["PolicyArn"] for p in imports} == {
        p.arn for p in expected.policies if p.installed_arn
    }
    assert {p["LogicalResourceId"] for p in imports} == set(imported["Resources"])
    for item in imports:
        assert set(item) == {"ResourceType", "LogicalResourceId", "ResourceIdentifier"}
        assert item["ResourceType"] == "AWS::IAM::ManagedPolicy"
        assert set(item["ResourceIdentifier"]) == {"PolicyArn"}
    policies = {
        f"arn:aws:iam::{expected.account_id}:policy"
        f"{r['Properties']['Path']}{r['Properties']['ManagedPolicyName']}": r
        for r in resources.values()
        if r["Type"] == "AWS::IAM::ManagedPolicy"
    }
    assert set(policies) == {p.arn for p in expected.policies}
    for policy in expected.policies:
        properties = policies[policy.arn]["Properties"]
        assert (
            registry.canonical_json(properties["PolicyDocument"])
            == policy.document_json
        )
        assert len(policy.document_json) <= 6144
        assert properties.get("Roles", []) == sorted(
            p.arn.rsplit("/", 1)[1]
            for p in expected.principals
            if p.existing and policy.arn in p.attachment_arns
        )
    assert all("Roles" not in r["Properties"] for r in imported["Resources"].values())


@pytest.mark.parametrize("environment", ["test", "prod"])
def test_only_new_disabled_executors_are_owned_without_attachment_cycles(environment):
    packet = packet_for(environment)
    expected = packet.registry
    resources = json.loads(packet.enrollment_template)["Resources"]
    roles = [
        r["Properties"] for r in resources.values() if r["Type"] == "AWS::IAM::Role"
    ]
    assert len(roles) == 3
    assert {r["RoleName"] for r in roles} == {
        p.arn.rsplit("/", 1)[1] for p in expected.principals if not p.existing
    }
    for role in roles:
        principal = next(
            p for p in expected.principals if p.arn.endswith("/" + role["RoleName"])
        )
        assert role["AssumeRolePolicyDocument"] == registry.DISABLED_TRUST
        assert set(role) == {
            "RoleName",
            "Path",
            "AssumeRolePolicyDocument",
            "PermissionsBoundary",
            "ManagedPolicyArns",
        }
        assert len(role["ManagedPolicyArns"]) == len(principal.attachment_arns) <= 10
        for ref in [role["PermissionsBoundary"], *role["ManagedPolicyArns"]]:
            policy = resources[ref["Ref"]]
            assert policy["Type"] == "AWS::IAM::ManagedPolicy"
            assert role["RoleName"] not in policy["Properties"].get("Roles", [])
        referenced = [
            resources[ref["Ref"]]["Properties"]
            for ref in [role["PermissionsBoundary"], *role["ManagedPolicyArns"]]
        ]
        arns = [
            f"arn:aws:iam::{expected.account_id}:policy"
            f"{p['Path']}{p['ManagedPolicyName']}"
            for p in referenced
        ]
        assert arns == [principal.boundary_arn, *principal.attachment_arns]
    assert json.loads(packet.stack_policy) == {
        "Statement": [
            {"Effect": "Deny", "Action": "Update:*", "Principal": "*", "Resource": "*"}
        ]
    }


@pytest.mark.parametrize("environment", ["test", "prod"])
def test_eight_boundary_additions_leave_config_and_other_existing_roles_untouched(
    environment,
):
    packet = packet_for(environment)
    manifest = json.loads(packet.boundary_manifest)
    operations = manifest["operations"]
    assert len(operations) == 8
    desired = {p.arn: p for p in packet.registry.principals}
    kinds = {p.arn: p.kind for p in packet.registry.policies}
    assert manifest["registry_sha256"] == packet.registry.sha256
    assert manifest["catalog_sha256"] == packet.registry.catalog_sha256
    for operation in operations:
        assert operation["operation"] == "put_role_permissions_boundary"
        role = desired[operation["precondition"]["RoleArn"]]
        assert role.existing and role.frozen_config is None
        assert operation["precondition"]["PermissionsBoundary"] is None
        assert operation["parameters"] == {
            "RoleName": role.arn.rsplit("/", 1)[1],
            "PermissionsBoundary": role.boundary_arn,
        }
        assert kinds[role.boundary_arn] == "purpose_capability_boundary"


@pytest.mark.parametrize(
    "field,value",
    [
        ("aws_account_id", "933245420672"),
        ("key_state", "Disabled"),
        ("key_manager", "AWS"),
        ("key_usage", "SIGN_VERIFY"),
        ("arn", "arn:aws:kms:eu-central-1:891377212104:alias/unverified"),
    ],
)
def test_invalid_key_binding_cannot_generate_artifacts(field, value):
    with pytest.raises(ValueError):
        installation.build_installation(
            "test",
            account_id=registry.ACCOUNTS["test"],
            seed_key=replace(key_for(), **{field: value}),
        )


@pytest.mark.parametrize(
    "field",
    [
        "import_template",
        "resources_to_import",
        "enrollment_template",
        "boundary_manifest",
        "stack_policy",
    ],
)
def test_artifact_edits_are_rejected(field):
    packet = packet_for()
    with pytest.raises(ValueError, match="differs"):
        installation.validate_installation(replace(packet, **{field: "{}"}))


@pytest.mark.parametrize("kind", ["existing_role", "active_trust", "delete_policy"])
def test_plausible_ownership_or_authority_edits_are_rejected(kind):
    packet = packet_for()
    full = json.loads(packet.enrollment_template)
    resources = full["Resources"]
    role = next(r for r in resources.values() if r["Type"] == "AWS::IAM::Role")
    if kind == "existing_role":
        role["Properties"]["RoleName"] = "GitHubCiApply-bootstrap-infrastructure-test"
    elif kind == "active_trust":
        role["Properties"]["AssumeRolePolicyDocument"]["Statement"][0]["Effect"] = (
            "Allow"
        )
    else:
        resources[next(iter(resources))]["DeletionPolicy"] = "Delete"
    edited = replace(packet, enrollment_template=registry.canonical_json(full))
    with pytest.raises(ValueError, match="differs"):
        installation.validate_installation(edited)


def test_forged_registry_and_wrong_packet_type_rejected():
    packet = packet_for()
    with pytest.raises(ValueError, match="packet required"):
        installation.validate_installation(None)
    with pytest.raises(ValueError, match="registry required"):
        installation.validate_installation(replace(packet, registry=None))
    with pytest.raises(ValueError, match="differs"):
        installation.validate_installation(
            replace(packet, registry=replace(packet.registry, policies=()))
        )
    with pytest.raises(ValueError, match="account/environment"):
        installation.build_installation(
            "test", account_id=registry.ACCOUNTS["prod"], seed_key=key_for()
        )


@pytest.mark.parametrize("phase", ["import", "enroll"])
def test_complete_exact_change_set_is_accepted(phase):
    packet = packet_for()
    changes = changes_for(packet, phase)
    installation.validate_change_set(packet, phase=phase, changes=changes)
    assert len(changes) == (6 if phase == "import" else 52)


@pytest.mark.parametrize(
    "field,value,message",
    [
        ("Action", "Modify", "Only exact"),
        ("Action", "Remove", "Only exact"),
        ("Replacement", "True", "Replacement"),
        ("Replacement", "Conditional", "Replacement"),
        ("LogicalResourceId", None, "logical identity"),
        ("LogicalResourceId", "Foreign", "complete installation"),
        ("ResourceType", "AWS::IAM::User", "complete installation"),
        ("PhysicalResourceId", "existing-resource", "Addition already exists"),
        ("PolicyAction", "Delete", "Destructive policy action"),
        ("ChangeSetId", "nested-change-set", "Nested change set"),
    ],
)
def test_change_set_cannot_widen_or_replace(field, value, message):
    packet = packet_for()
    changes = changes_for(packet, "enroll")
    changes[0]["ResourceChange"][field] = value
    with pytest.raises(ValueError, match=message):
        installation.validate_change_set(packet, phase="enroll", changes=changes)


@pytest.mark.parametrize(
    "kind", ["missing", "duplicate", "object", "entry", "type", "resource"]
)
def test_incomplete_or_malformed_changes_fail(kind):
    packet = packet_for()
    changes = changes_for(packet, "enroll")
    edits = {
        "missing": changes[:-1],
        "duplicate": changes + changes[:1],
        "object": {},
        "entry": [None],
        "type": [{"Type": "Output"}],
        "resource": [{"Type": "Resource", "ResourceChange": []}],
    }
    with pytest.raises(ValueError):
        installation.validate_change_set(packet, phase="enroll", changes=edits[kind])


def test_wrong_physical_import_and_unknown_phase_fail():
    packet = packet_for()
    changes = changes_for(packet, "import")
    changes[0]["ResourceChange"]["PhysicalResourceId"] = (
        "arn:aws:iam::933245420672:policy/foreign"
    )
    with pytest.raises(ValueError, match="physical policy"):
        installation.validate_change_set(packet, phase="import", changes=changes)
    with pytest.raises(ValueError, match="Unknown installation phase"):
        installation.validate_change_set(packet, phase="replace", changes=[])


@pytest.mark.parametrize(
    "mutation,message",
    [
        ("imports", "six existing"),
        ("roles", "resource graph"),
        ("boundaries", "eight existing"),
    ],
)
def test_internal_graph_invariants_reject_ownership_drift(mutation, message):
    expected = packet_for().registry
    if mutation == "imports":
        expected = replace(
            expected,
            policies=tuple(replace(p, installed_arn=False) for p in expected.policies),
        )
    elif mutation == "roles":
        expected = replace(
            expected, principals=tuple(p for p in expected.principals if p.existing)
        )
    else:
        expected = replace(
            expected,
            principals=tuple(
                replace(p, boundary_arn=None) if p.existing else p
                for p in expected.principals
            ),
        )
    with pytest.raises(ValueError, match=message):
        installation._render(expected)


def test_executor_cannot_be_rendered_without_boundary():
    executor = next(p for p in packet_for().registry.principals if not p.existing)
    with pytest.raises(ValueError, match="Executor boundary"):
        installation._role_resource(replace(executor, boundary_arn=None))


def activation_changes(packet):
    """Standard API summaries of three direct, non-replacing role trust updates."""
    resources = json.loads(packet.activation_template)["Resources"]
    return [
        {
            "Type": "Resource",
            "ResourceChange": {
                "Action": "Modify",
                "LogicalResourceId": logical,
                "PhysicalResourceId": value["Properties"]["RoleName"],
                "ResourceType": "AWS::IAM::Role",
                "Replacement": "False",
                "Scope": ["Properties"],
                "Details": [
                    {
                        "Evaluation": "Static",
                        "ChangeSource": "DirectModification",
                        "Target": {
                            "Attribute": "Properties",
                            "Name": "AssumeRolePolicyDocument",
                            "RequiresRecreation": "Never",
                        },
                    }
                ],
            },
        }
        for logical, value in resources.items()
        if value["Type"] == "AWS::IAM::Role"
    ]


@pytest.mark.parametrize("environment", ["test", "prod"])
def test_activation_preserves_everything_except_three_exact_trusts(environment):
    disabled = packet_for(environment)
    active = installation.build_activation(disabled)
    assert active == installation.build_activation(disabled)
    installation.validate_activation(active)
    installation.validate_installation(disabled)
    before = json.loads(disabled.enrollment_template)
    after = json.loads(active.activation_template)
    changed = []
    for logical, resource in after["Resources"].items():
        previous = before["Resources"][logical]
        if resource == previous:
            continue
        changed.append(logical)
        name = resource["Properties"]["RoleName"]
        purpose = name.removeprefix("GitHubOperator").split("-")[0].lower()
        trust = resource["Properties"]["AssumeRolePolicyDocument"]
        assert trust == json.loads(
            operator_trust_policy(
                environment, purpose, account_id=registry.ACCOUNTS[environment]
            )
        )
        assert (
            previous["Properties"]["AssumeRolePolicyDocument"]
            == registry.DISABLED_TRUST
        )
        assert len(registry.canonical_json(trust)) <= 2048
        resource["Properties"]["AssumeRolePolicyDocument"] = registry.DISABLED_TRUST
    assert len(changed) == 3
    assert after == before
    assert json.loads(active.temporary_stack_policy) == {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "Update:Modify",
                "Principal": "*",
                "Resource": sorted(f"LogicalResourceId/{key}" for key in changed),
            },
            {
                "Effect": "Deny",
                "Action": ["Update:Replace", "Update:Delete"],
                "Principal": "*",
                "Resource": "*",
            },
        ]
    }
    changes = activation_changes(active)
    installation.validate_activation_change_set(active, changes=changes)
    for change in changes:
        target = change["ResourceChange"]["Details"][0]["Target"]
        target["Path"] = "/Properties/AssumeRolePolicyDocument"
        target["AttributeChangeType"] = "Modify"
    installation.validate_activation_change_set(active, changes=list(reversed(changes)))


@pytest.mark.parametrize(
    "mutation", ["trust", "policy", "boundary", "owner", "retention"]
)
def test_activation_rejects_template_changes_even_with_plausible_summaries(mutation):
    active = installation.build_activation(packet_for())
    template = json.loads(active.activation_template)
    resources = template["Resources"]
    role = next(r for r in resources.values() if r["Type"] == "AWS::IAM::Role")
    if mutation == "trust":
        role["Properties"]["AssumeRolePolicyDocument"] = registry.DISABLED_TRUST
    elif mutation == "policy":
        policy = next(
            r for r in resources.values() if r["Type"] == "AWS::IAM::ManagedPolicy"
        )
        policy["Properties"]["PolicyDocument"] = {}
    elif mutation == "boundary":
        role["Properties"]["PermissionsBoundary"] = "foreign"
    elif mutation == "owner":
        role["Properties"]["RoleName"] = "GitHubCiApply-bootstrap-infrastructure-test"
    else:
        role["DeletionPolicy"] = "Delete"
    forged = replace(active, activation_template=registry.canonical_json(template))
    with pytest.raises(ValueError, match="differs"):
        installation.validate_activation_change_set(
            forged, changes=activation_changes(active)
        )


def test_activation_rejects_forged_parent_policy_and_packet_types():
    packet = packet_for()
    active = installation.build_activation(packet)
    with pytest.raises(ValueError, match="Activation packet required"):
        installation.validate_activation(None)
    with pytest.raises(ValueError, match="differs"):
        installation.build_activation(replace(packet, enrollment_template="{}"))
    with pytest.raises(ValueError, match="differs"):
        installation.validate_activation(replace(active, temporary_stack_policy="{}"))


@pytest.mark.parametrize(
    "field,value",
    [
        ("Action", "Add"),
        ("Action", "Remove"),
        ("ResourceType", "AWS::IAM::ManagedPolicy"),
        ("Replacement", "True"),
        ("Replacement", "Conditional"),
        ("Replacement", None),
        ("Replacement", False),
        ("Scope", ["Properties", "Tags"]),
        ("Scope", []),
        ("ChangeSetId", "nested"),
        ("PolicyAction", "Delete"),
        ("LogicalResourceId", []),
        ("LogicalResourceId", "Foreign"),
        ("PhysicalResourceId", "GitHubOperatorApply-prod"),
        ("Details", []),
        ("Details", None),
        ("Details", [None]),
    ],
)
def test_activation_rejects_other_changes_and_malformed_summaries(field, value):
    active = installation.build_activation(packet_for())
    changes = activation_changes(active)
    changes[0]["ResourceChange"][field] = value
    with pytest.raises(ValueError):
        installation.validate_activation_change_set(active, changes=changes)


@pytest.mark.parametrize(
    "field,value",
    [
        ("Evaluation", "Dynamic"),
        ("ChangeSource", "ResourceReference"),
        ("CausingEntity", "OtherRole"),
        ("Target", None),
    ],
)
def test_activation_rejects_indirect_or_missing_trust_detail(field, value):
    active = installation.build_activation(packet_for())
    changes = activation_changes(active)
    changes[0]["ResourceChange"]["Details"][0][field] = value
    with pytest.raises(ValueError):
        installation.validate_activation_change_set(active, changes=changes)


@pytest.mark.parametrize(
    "field,value",
    [
        ("Attribute", "Metadata"),
        ("Name", "ManagedPolicyArns"),
        ("Name", "PermissionsBoundary"),
        ("Name", "Policies"),
        ("RequiresRecreation", "Conditionally"),
        ("RequiresRecreation", None),
        ("Path", "/Properties/ManagedPolicyArns"),
        ("AttributeChangeType", "Remove"),
    ],
)
def test_activation_rejects_any_other_property_target(field, value):
    active = installation.build_activation(packet_for())
    changes = activation_changes(active)
    changes[0]["ResourceChange"]["Details"][0]["Target"][field] = value
    with pytest.raises(ValueError):
        installation.validate_activation_change_set(active, changes=changes)


@pytest.mark.parametrize(
    "kind", ["missing", "duplicate", "object", "entry", "type", "resource", "extra"]
)
def test_activation_requires_complete_unique_executor_changes(kind):
    active = installation.build_activation(packet_for())
    changes = activation_changes(active)
    edits = {
        "missing": changes[:-1],
        "duplicate": changes + changes[:1],
        "object": {},
        "entry": [None],
        "type": [{"Type": "Output"}],
        "resource": [{"Type": "Resource", "ResourceChange": []}],
        "extra": changes + changes_for(active.installation, "enroll")[:1],
    }
    with pytest.raises(ValueError):
        installation.validate_activation_change_set(active, changes=edits[kind])
