"""TEST PoC seed amendment remains exact, offline and unactivated."""

import copy
import dataclasses
import json
import sys
from pathlib import Path

import pytest
from seed import policy_registry as registry
from seed import test_poc_prerequisite_amendment as capability
from test_governance_test_poc_capability import arguments
from test_operator_seed_installation import packet_for

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))

import operator_seed_installation as installation  # noqa: E402
import test_poc_seed_amendment as amendment  # noqa: E402
from infra.governance import (  # noqa: E402
    _test_poc_capability_statements,
    _TestPocTarget,
)


def activation(environment="test"):
    return installation.build_activation(packet_for(environment))


def changes():
    """Synthetic standard DescribeChangeSet rows, never live evidence."""
    return [
        {
            "Type": "Resource",
            "ResourceChange": {
                "Action": "Modify",
                "LogicalResourceId": installation._logical_id(arn),
                "PhysicalResourceId": arn,
                "ResourceType": "AWS::IAM::ManagedPolicy",
                "Replacement": "False",
                "Scope": ["Properties"],
                "Details": [
                    {
                        "Evaluation": "Static",
                        "ChangeSource": "DirectModification",
                        "Target": {
                            "Attribute": "Properties",
                            "Name": "PolicyDocument",
                            "RequiresRecreation": "Never",
                        },
                    }
                ],
            },
        }
        for arn in sorted(capability.TARGETS)
    ]


def test_catalog_proposes_only_four_test_policy_updates():
    old = registry.load_catalog("test")
    prod = registry.load_catalog("prod")
    candidate = capability.build_catalog()
    assert registry.document_hash(candidate) == capability.RESULT_CATALOG_SHA256
    assert registry.document_hash(old) == registry.CATALOG_HASHES["test"]
    assert registry.document_hash(prod) == registry.CATALOG_HASHES["prod"]
    assert set(candidate["policies"]) == set(old["policies"])
    assert candidate["principals"] == old["principals"]
    assert {
        arn
        for arn in old["policies"]
        if old["policies"][arn] != candidate["policies"][arn]
    } == capability.TARGETS
    assert (
        candidate["provenance"]["test_poc_prerequisites_amendment"][
            "activation_authorized"
        ]
        is False
    )
    for arn in capability.TARGETS:
        doc = amendment._catalog_document(candidate, arn)
        assert (
            registry.document_hash(doc) == candidate["policies"][arn]["template_sha256"]
        )
        assert len(registry.canonical_json(doc)) <= 6144


def test_proposed_boundary_equals_staged_service_capability(monkeypatch):
    read_text = Path.read_text

    def staged(path, *args, **kwargs):
        value = read_text(path, *args, **kwargs)
        if path.name == "test-poc-identity.json":
            identity = json.loads(value)
            identity["enabled"] = True
            return json.dumps(identity)
        return value

    monkeypatch.setattr(Path, "read_text", staged)
    args = arguments()
    proposed = _test_poc_capability_statements(
        _TestPocTarget(
            args.account_id,
            args.partition,
            capability.REPOSITORY,
            args.region,
            capability.REPOSITORY,
        ),
        args.settings,
        write=True,
    )
    assert (
        proposed
        == json.loads(
            Path(capability.__file__)
            .with_name("test_poc_prerequisites.json")
            .read_text()
        )["statements"]
    )
    candidate = capability.build_catalog()
    boundary = amendment._catalog_document(candidate, capability.BOUNDARY)
    assert boundary["Statement"][-6:] == proposed


def test_amendment_rejects_changed_manifest_and_baseline(monkeypatch):
    read_text = Path.read_text

    def changed_manifest(path, *args, **kwargs):
        value = read_text(path, *args, **kwargs)
        if path.name == "test_poc_prerequisites.json":
            return value.replace("test-poc-prerequisites/v1", "unreviewed/v1")
        return value

    monkeypatch.setattr(Path, "read_text", changed_manifest)
    with pytest.raises(ValueError, match="manifest"):
        capability.build_catalog()
    monkeypatch.setattr(Path, "read_text", read_text)
    monkeypatch.setattr(capability, "BASELINE_POLICY_HASHES", {})
    with pytest.raises(ValueError, match="baseline"):
        capability.build_catalog()


def test_packet_changes_only_four_policy_documents_and_keeps_denial():
    source = activation()
    packet = amendment.build_amendment(source)
    baseline = json.loads(packet.baseline_template)
    proposed = json.loads(packet.candidate_template)
    assert proposed["Metadata"]["CatalogSha256"] == capability.RESULT_CATALOG_SHA256
    assert proposed["Metadata"]["RegistrySha256"] == packet.resulting_registry.sha256
    assert proposed["Metadata"]["ActivationAuthorized"] is False
    assert packet.final_stack_policy == source.installation.stack_policy
    assert json.loads(packet.temporary_stack_policy)["Statement"][1]["Action"] == [
        "Update:Replace",
        "Update:Delete",
    ]
    assert len(proposed["Resources"]) == 58
    changed = {
        logical
        for logical in baseline["Resources"]
        if baseline["Resources"][logical] != proposed["Resources"][logical]
    }
    assert changed == {installation._logical_id(arn) for arn in capability.TARGETS}
    for logical in changed:
        before = baseline["Resources"][logical]
        after = proposed["Resources"][logical]
        assert before["Type"] == after["Type"] == "AWS::IAM::ManagedPolicy"
        copy_after = copy.deepcopy(after)
        copy_after["Properties"]["PolicyDocument"] = before["Properties"][
            "PolicyDocument"
        ]
        assert copy_after == before
    assert all(
        p.arn not in capability.TARGETS or p.sha256 != old.sha256
        for p, old in zip(
            packet.resulting_registry.policies, source.installation.registry.policies
        )
    )


def test_change_set_accepts_only_four_exact_in_place_documents():
    source = activation()
    packet = amendment.build_amendment(source)
    amendment.validate_change_set(source, packet, changes())
    with pytest.raises(ValueError, match="Only TEST"):
        amendment.build_amendment(activation("prod"))
    with pytest.raises(ValueError, match="differs"):
        amendment.validate_change_set(
            source,
            dataclasses.replace(packet, temporary_stack_policy="{}"),
            changes(),
        )


@pytest.mark.parametrize(
    "path,value",
    [
        (("Type",), "Parameter"),
        (("ResourceChange", "Action"), "Remove"),
        (("ResourceChange", "Replacement"), "True"),
        (("ResourceChange", "ResourceType"), "AWS::IAM::Role"),
        (("ResourceChange", "PhysicalResourceId"), "other"),
        (("ResourceChange", "Scope"), ["Tags"]),
        (("ResourceChange", "PolicyAction"), "Delete"),
        (("ResourceChange", "Details", 0, "ChangeSource"), "ResourceReference"),
        (("ResourceChange", "Details", 0, "Target", "Name"), "Roles"),
    ],
)
def test_change_set_rejects_other_operations(path, value):
    source = activation()
    packet = amendment.build_amendment(source)
    invalid = changes()
    target = invalid[0]
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    with pytest.raises(ValueError):
        amendment.validate_change_set(source, packet, invalid)


def test_change_set_rejects_incomplete_duplicate_and_malformed_rows():
    source = activation()
    packet = amendment.build_amendment(source)
    for invalid in (
        None,
        changes()[:-1],
        [*changes(), changes()[0]],
        [*changes(), {}],
    ):
        with pytest.raises(ValueError):
            amendment.validate_change_set(source, packet, invalid)
