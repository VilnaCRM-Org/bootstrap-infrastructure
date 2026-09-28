"""Generate an independent seed installation packet; never execute it.

The caller must independently authenticate its nonroot installer and DescribeKey
observation. This pure generator proves neither provenance nor installed state.
Before import, independently reconcile the six boundary ownership records out of
the operator checkpoint without deleting AWS policies, retain all component/role
identities, and reconcile OIDC external reads. Verify live policy documents,
names, paths, attachments and exclusive CloudFormation ownership before import;
CloudFormation import itself does not establish that those properties match.

Import only the six retained policies, verify import drift, then add the remaining
policies and disabled roles. Install the deny-update stack policy before the
second phase; validate the actual complete change set before each execution.
Enroll only the eight listed existing role boundaries after checking their live
preconditions. Finally collect all IAM/KMS metadata using independently authorized
installer credentials and call seed.policy_registry.verify_enrollment. Ordinary
operator credentials cannot perform this transfer or activate executor trust.
Large templates require an independently protected TemplateURL artifact location.
"""

from __future__ import annotations

import copy
import dataclasses
import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, cast

from seed import policy_registry as registry
from seed.operator_trust import operator_trust_policy
from seed.test_poc_prerequisite_amendment import (
    RESULT_CATALOG_SHA256,
    TARGETS,
    build_catalog,
)


@dataclass(frozen=True)
class InstallationPacket:
    """Canonical public artifacts bound to one reviewed, real-key registry."""

    registry: registry.SeedRegistry
    import_template: str
    resources_to_import: str
    enrollment_template: str
    boundary_manifest: str
    stack_policy: str


@dataclass(frozen=True)
class ActivationPacket:
    """Trust-only proposed update; neither authorization nor installed evidence."""

    installation: InstallationPacket
    activation_template: str
    temporary_stack_policy: str


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _logical_id(arn: str) -> str:
    """Keep physical identity stable across import and enrollment templates."""
    return "Seed" + hashlib.sha256(arn.encode()).hexdigest()


def _name_path(arn: str) -> tuple[str, str]:
    """Split a pinned IAM role/policy resource into its friendly name and path."""
    resource = arn.split(":", 5)[5].split("/", 1)[1]
    path, _, name = resource.rpartition("/")
    return name, f"/{path}/" if path else "/"


def _resource(kind: str, properties: dict[str, Any]) -> dict[str, Any]:
    """Retain every independently owned resource on deletion or replacement."""
    return {
        "Type": kind,
        "DeletionPolicy": "Retain",
        "UpdateReplacePolicy": "Retain",
        "Properties": properties,
    }


def _policy_resource(
    policy: registry.PolicyRecord, expected: registry.SeedRegistry
) -> dict[str, Any]:
    """Attach only seed-owned policies to literal existing role names."""
    name, path = _name_path(policy.arn)
    properties = {
        "ManagedPolicyName": name,
        "Path": path,
        "PolicyDocument": json.loads(policy.document_json),
    }
    roles = sorted(
        _name_path(p.arn)[0]
        for p in expected.principals
        if p.existing and policy.arn in p.attachment_arns
    )
    if roles:
        properties["Roles"] = roles
    return _resource("AWS::IAM::ManagedPolicy", properties)


def _role_resource(principal: registry.PrincipalRecord) -> dict[str, Any]:
    """Create only the three bounded executors, with all assumption denied."""
    name, path = _name_path(principal.arn)
    _require(principal.boundary_arn is not None, "Executor boundary missing")
    return _resource(
        "AWS::IAM::Role",
        {
            "RoleName": name,
            "Path": path,
            "AssumeRolePolicyDocument": registry.disabled_trust_policy(
                principal.arn.split(":")[4]
            ),
            "PermissionsBoundary": {
                "Ref": _logical_id(cast(str, principal.boundary_arn))
            },
            "ManagedPolicyArns": [
                {"Ref": _logical_id(arn)} for arn in principal.attachment_arns
            ],
        },
    )


def _template(resources: dict, expected: registry.SeedRegistry) -> str:
    """Bind template provenance claims to explicit catalog and rendered hashes."""
    return registry.canonical_json(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Metadata": {
                "AccountId": expected.account_id,
                "Region": expected.region,
                "CatalogSha256": expected.catalog_sha256,
                "RegistrySha256": expected.sha256,
                "SeedKmsKeyArn": expected.seed_key.arn,
                "ActivationAuthorized": False,
            },
            "Resources": resources,
        }
    )


def _boundary_manifest(expected: registry.SeedRegistry) -> str:
    """Describe exactly eight boundary additions, without adopting their roles."""
    boundaries = {
        p.arn for p in expected.policies if p.kind == "purpose_capability_boundary"
    }
    operations = [
        {
            "operation": "put_role_permissions_boundary",
            "parameters": {
                "RoleName": _name_path(p.arn)[0],
                "PermissionsBoundary": p.boundary_arn,
            },
            "precondition": {"RoleArn": p.arn, "PermissionsBoundary": None},
        }
        for p in expected.principals
        if p.existing and p.boundary_arn in boundaries
    ]
    _require(len(operations) == 8, "Expected eight existing-role boundary additions")
    return registry.canonical_json(
        {
            "account_id": expected.account_id,
            "catalog_sha256": expected.catalog_sha256,
            "registry_sha256": expected.sha256,
            "activation_authorized": False,
            "prerequisites": [
                "Independently authenticate nonroot installer "
                "and live seed KMS metadata.",
                "Reconcile six boundary ownership records and OIDC reads "
                "in operator checkpoint.",
                "Verify import properties and exclusive CloudFormation ownership "
                "from live AWS.",
                "Import six policies only; require drift-free import "
                "before adding resources.",
                "Set deny-update stack policy; require CAPABILITY_NAMED_IAM "
                "and exact change sets.",
                "Keep existing roles owned by their current stacks; "
                "verify each boundary is absent.",
                "Verify complete disabled enrollment with independently "
                "collected IAM metadata.",
                "Trust activation requires separate independent authorization.",
            ],
            "operations": operations,
        }
    )


def _render(expected: registry.SeedRegistry) -> InstallationPacket:
    """Derive both phases from the same validated resource graph."""
    policies = {
        _logical_id(p.arn): _policy_resource(p, expected) for p in expected.policies
    }
    imported = {
        _logical_id(p.arn): policies[_logical_id(p.arn)]
        for p in expected.policies
        if p.installed_arn
    }
    _require(len(imported) == 6, "Expected six existing boundary imports")
    resources = dict(policies)
    for principal in expected.principals:
        if not principal.existing:
            resources[_logical_id(principal.arn)] = _role_resource(principal)
    _require(len(resources) == 58, "Seed resource graph changed")
    # AWS's public CloudformationSchema.zip declares /properties/PolicyArn as
    # AWS::IAM::ManagedPolicy's primaryIdentifier (not ManagedPolicyName).
    imports = [
        {
            "ResourceType": "AWS::IAM::ManagedPolicy",
            "LogicalResourceId": _logical_id(p.arn),
            "ResourceIdentifier": {"PolicyArn": p.arn},
        }
        for p in expected.policies
        if p.installed_arn
    ]
    return InstallationPacket(
        expected,
        _template(imported, expected),
        registry.canonical_json(imports),
        _template(resources, expected),
        _boundary_manifest(expected),
        registry.canonical_json(
            {
                "Statement": [
                    {
                        "Effect": "Deny",
                        "Action": "Update:*",
                        "Principal": "*",
                        "Resource": "*",
                    }
                ]
            }
        ),
    )


def build_installation(
    environment: str, *, account_id: str, seed_key: registry.SeedKeyBinding
) -> InstallationPacket:
    """Render only pinned catalogs using caller-supplied observed key metadata."""
    expected = registry.build_registry(
        environment, account_id=account_id, seed_key=seed_key
    )
    return _render(expected)


def validate_installation(packet: InstallationPacket) -> None:
    """Reject any artifact or registry changes, including ownership broadening."""
    _require(isinstance(packet, InstallationPacket), "Installation packet required")
    expected = packet.registry
    _require(isinstance(expected, registry.SeedRegistry), "Seed registry required")
    canonical = build_installation(
        expected.environment, account_id=expected.account_id, seed_key=expected.seed_key
    )
    _require(packet == canonical, "Installation packet differs from pinned registry")


def validate_change_set(
    packet: InstallationPacket, *, phase: str, changes: object
) -> None:
    """Check complete AWS DescribeChangeSet Changes after caller authentication.

    The caller must exhaust pagination, authenticate stack/account/template and
    change-set identity, require AVAILABLE execution status, and execute that
    exact reviewed change-set ID. This function never authenticates AWS evidence.
    """
    validate_installation(packet)
    _require(phase in {"import", "enroll"}, "Unknown installation phase")
    imported = json.loads(packet.import_template)["Resources"]
    resources = json.loads(packet.enrollment_template)["Resources"]
    targets = (
        imported
        if phase == "import"
        else {key: value for key, value in resources.items() if key not in imported}
    )
    _require(isinstance(changes, list), "Complete change list required")
    actual: dict[str, object] = {}
    for change in cast(list, changes):
        _require(isinstance(change, Mapping), "Malformed change")
        _require(change.get("Type") == "Resource", "Unexpected change type")
        resource = change.get("ResourceChange")
        _require(isinstance(resource, Mapping), "Malformed resource change")
        resource = cast(Mapping, resource)
        _require(
            resource.get("Action") == ("Import" if phase == "import" else "Add"),
            "Only exact import or addition is permitted",
        )
        _require(
            resource.get("Replacement") in (None, "False"), "Replacement forbidden"
        )
        _require(
            resource.get("PolicyAction") in (None, "Retain"),
            "Destructive policy action forbidden",
        )
        _require(resource.get("ChangeSetId") is None, "Nested change set forbidden")
        logical = resource.get("LogicalResourceId")
        _require(isinstance(logical, str), "Malformed logical identity")
        logical = cast(str, logical)
        _require(logical not in actual, "Duplicate resource change")
        if phase == "import":
            identities = {
                item["LogicalResourceId"]: item["ResourceIdentifier"]["PolicyArn"]
                for item in json.loads(packet.resources_to_import)
            }
            _require(
                resource.get("PhysicalResourceId") == identities.get(logical),
                "Import physical policy identity changed",
            )
        else:
            _require(
                resource.get("PhysicalResourceId") is None, "Addition already exists"
            )
        actual[logical] = resource.get("ResourceType")
    _require(
        actual == {key: value["Type"] for key, value in targets.items()},
        "Change set does not match the complete installation phase",
    )


def build_activation(packet: InstallationPacket) -> ActivationPacket:
    """Change only three executor trusts in the canonical disabled template.

    Independently authorize activation and verify disabled enrollment, reconciled
    checkpoints and installed trusted main before executing. Authenticate the
    current stack template against enrollment_template and the proposed template
    against activation_template. The temporary policy permits only role Modify;
    it cannot restrict individual properties or grant IAM authority. Restore the
    installation's deny-update policy after execution, including on failure.
    """
    validate_installation(packet)
    expected = packet.registry
    template = json.loads(packet.enrollment_template)
    targets = []
    for purpose in ("preview", "apply", "drift"):
        arn = (
            f"arn:aws:iam::{expected.account_id}:role/GitHubOperator{purpose.title()}"
            f"-{expected.environment}"
        )
        logical = _logical_id(arn)
        template["Resources"][logical]["Properties"]["AssumeRolePolicyDocument"] = (
            json.loads(
                operator_trust_policy(
                    expected.environment, purpose, account_id=expected.account_id
                )
            )
        )
        targets.append(f"LogicalResourceId/{logical}")
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "Update:Modify",
                "Principal": "*",
                "Resource": sorted(targets),
            },
            {
                "Effect": "Deny",
                "Action": ["Update:Replace", "Update:Delete"],
                "Principal": "*",
                "Resource": "*",
            },
        ]
    }
    return ActivationPacket(
        packet, registry.canonical_json(template), registry.canonical_json(policy)
    )


def validate_activation(packet: ActivationPacket) -> None:
    """Recompute both artifacts so forged trust or unrelated edits fail closed."""
    _require(isinstance(packet, ActivationPacket), "Activation packet required")
    _require(
        packet == build_activation(packet.installation),
        "Activation packet differs from pinned trust update",
    )


def _trust_detail(details: object) -> None:
    """Accept the standard summary for one static direct trust-property edit."""
    _require(isinstance(details, list) and len(details) == 1, "One trust edit required")
    detail = cast(list, details)[0]
    _require(isinstance(detail, Mapping), "Malformed trust edit")
    _require(
        detail.get("Evaluation") == "Static"
        and detail.get("ChangeSource") == "DirectModification"
        and detail.get("CausingEntity") is None,
        "Only a static direct trust edit is permitted",
    )
    target = detail.get("Target")
    _require(isinstance(target, Mapping), "Malformed trust target")
    target = cast(Mapping, target)
    _require(
        target.get("Attribute") == "Properties"
        and target.get("Name") == "AssumeRolePolicyDocument"
        and target.get("RequiresRecreation") == "Never",
        "Only the non-replacing trust property may change",
    )
    _require(
        target.get("Path") in (None, "/Properties/AssumeRolePolicyDocument")
        and target.get("AttributeChangeType") in (None, "Modify"),
        "Unexpected trust property path or operation",
    )


def _activation_resource(change: object) -> Mapping:
    """Reject replacement, removal, nested changes and any non-property scope."""
    _require(isinstance(change, Mapping), "Malformed activation change")
    change = cast(Mapping, change)
    _require(change.get("Type") == "Resource", "Unexpected activation change type")
    resource = change.get("ResourceChange")
    _require(isinstance(resource, Mapping), "Malformed activation resource")
    resource = cast(Mapping, resource)
    _require(
        resource.get("Action") == "Modify"
        and resource.get("ResourceType") == "AWS::IAM::Role"
        and resource.get("Replacement") == "False"
        and resource.get("Scope") == ["Properties"],
        "Only non-replacing role property modification is permitted",
    )
    _require(
        resource.get("ChangeSetId") is None and resource.get("PolicyAction") is None,
        "Nested or policy-action change forbidden",
    )
    _trust_detail(resource.get("Details"))
    return resource


def validate_activation_change_set(
    packet: ActivationPacket, *, changes: object
) -> None:
    """Check complete authenticated standard DescribeChangeSet resource summaries.

    Caller requirements from validate_change_set and build_activation apply. The
    summaries do not prove the proposed trust values: authenticate the exact
    canonical before/after templates too. This is not a drift-reconciliation or
    already-active no-op phase; all three disabled executors must change.
    """
    validate_activation(packet)
    _require(isinstance(changes, list), "Complete activation change list required")
    targets = {
        _logical_id(p.arn): _name_path(p.arn)[0]
        for p in packet.installation.registry.principals
        if not p.existing
    }
    actual = set()
    for change in cast(list, changes):
        resource = _activation_resource(change)
        logical = resource.get("LogicalResourceId")
        _require(isinstance(logical, str), "Malformed activation logical identity")
        logical = cast(str, logical)
        _require(logical in targets and logical not in actual, "Unexpected executor")
        _require(
            resource.get("PhysicalResourceId") == targets[logical],
            "Executor physical identity changed",
        )
        actual.add(logical)
    _require(actual == set(targets), "All three executor trust changes required")


# Closed TEST prerequisite policy amendment. No AWS calls or activation.


@dataclass(frozen=True)
class TestPocSeedAmendment:
    """Pinned before/after artifacts, not authorization to install them."""

    baseline_template: str
    candidate_template: str
    temporary_stack_policy: str
    final_stack_policy: str
    resulting_registry: registry.SeedRegistry


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
    seed_registry = activation.installation.registry
    _require(seed_registry.environment == "test", "Only TEST seed may be amended")
    catalog = build_catalog()
    old = json.loads(activation.activation_template)
    candidate = copy.deepcopy(old)
    _require(len(candidate["Resources"]) == 58, "Seed resource graph changed")
    new_policies = []
    for policy in seed_registry.policies:
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
        desired = registry._bind(
            _catalog_document(catalog, policy.arn), seed_registry.seed_key.arn
        )
        resource["Properties"]["PolicyDocument"] = desired
        new_policies.append(
            dataclasses.replace(
                policy,
                document_json=registry.canonical_json(desired),
                sha256=registry.document_hash(desired),
            )
        )
    _require(len(new_policies) == 55, "TEST policy count changed")
    result_registry = dataclasses.replace(
        seed_registry,
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
        candidate_template=registry.canonical_json(candidate),
        temporary_stack_policy=registry.canonical_json(temporary),
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


def validate_test_poc_change_set(
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
