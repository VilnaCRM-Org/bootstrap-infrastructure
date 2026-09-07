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

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, cast

from seed import policy_registry as registry


@dataclass(frozen=True)
class InstallationPacket:
    """Canonical public artifacts bound to one reviewed, real-key registry."""

    registry: registry.SeedRegistry
    import_template: str
    resources_to_import: str
    enrollment_template: str
    boundary_manifest: str
    stack_policy: str


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
            "AssumeRolePolicyDocument": registry.DISABLED_TRUST,
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
