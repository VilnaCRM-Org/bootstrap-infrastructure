"""Render and verify the reviewed, closed independent IAM enrollment registry.

This module performs no I/O except loading its packaged public policy catalogs.
It cannot install policies, enable trust, or authorize an administrative apply.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping

from .operator_trust import operator_trust_policy

CATALOG_HASHES = {
    "test": "9079c48192d3ebcdbd2dd957cc36138b7f90f80aa7fe22d49a60a56f436a32f7",
    "prod": "544a7c7f5610dc62172debcb16a6dca91c3a36eeb484f8f89b6e20af1c62ffd1",
}
ACCOUNTS = {"test": "891377212104", "prod": "933245420672"}
REGION = "eu-central-1"
_KEY_ID = re.compile(
    r"(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    r"|mrk-[0-9a-f]{32})\Z"
)
_BOUNDARIES = {
    "existing_capability_boundary",
    "purpose_capability_boundary",
    "executor_boundary",
}


class RegistryError(ValueError):
    """An input violates the closed enrollment contract."""


def disabled_trust_policy(account_id: str) -> dict:
    """Use a valid account principal with no Allow for any assumption method."""
    if account_id not in ACCOUNTS.values():
        raise RegistryError("Disabled trust account is outside the closed inventory")
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }


def canonical_json(value: Any) -> str:
    """Serialize public policy/metadata values deterministically."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def document_hash(value: Any) -> str:
    """Hash the complete canonical document, including statement order."""
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class SeedKeyBinding:
    """Public fields obtained from independently observed KMS DescribeKey metadata.

    Offline validation cannot establish that a caller-supplied key exists. The
    hosted installer must obtain these fields from AWS and compare the key ARN.
    """

    arn: str
    key_id: str
    aws_account_id: str
    key_manager: str
    key_state: str
    key_usage: str


@dataclass(frozen=True)
class PolicyRecord:
    """One independently owned managed policy and its exact desired document."""

    arn: str
    kind: str
    ownership: str
    installed_arn: bool
    document_json: str
    sha256: str


@dataclass(frozen=True)
class FrozenConfigGrants:
    """Config's complete frozen trust/inline grants and AWS-managed attachment."""

    trust_json: str
    inline_policies: tuple[tuple[str, str], ...]
    aws_policy_arn: str
    aws_policy_version: str
    aws_policy_sha256: str


@dataclass(frozen=True)
class PrincipalRecord:
    """One existing or proposed principal's complete initial enrollment set."""

    arn: str
    existing: bool
    owner_project: str
    boundary_arn: str | None
    guard_arns: tuple[str, ...]
    attachment_arns: tuple[str, ...]
    frozen_config: FrozenConfigGrants | None


@dataclass(frozen=True)
class SeedRegistry:
    """Immutable desired enrollment data, not an installed/activated deployment."""

    environment: str
    account_id: str
    region: str
    catalog_sha256: str
    seed_key: SeedKeyBinding
    policies: tuple[PolicyRecord, ...]
    principals: tuple[PrincipalRecord, ...]

    @property
    def sha256(self) -> str:
        """Bind the complete rendered registry, including its actual seed key."""
        return document_hash(asdict(self))


@dataclass(frozen=True)
class ObservedPolicy:
    """Public default-version document captured by the independent installer."""

    arn: str
    default_version_id: str
    document_json: str


@dataclass(frozen=True)
class ObservedPrincipal:
    """Complete role metadata relevant to initial enrollment verification."""

    arn: str
    boundary_arn: str | None
    attachment_arns: tuple[str, ...]
    trust_json: str
    inline_policies: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class ObservedAwsManagedPolicy:
    """Complete AWS-managed document digest computed by the metadata collector."""

    arn: str
    default_version_id: str
    document_sha256: str


@dataclass(frozen=True)
class EnrollmentObservation:
    """Read-only evidence; obtaining it from the correct account is external."""

    account_id: str
    seed_key: SeedKeyBinding
    policies: tuple[ObservedPolicy, ...]
    principals: tuple[ObservedPrincipal, ...]
    aws_managed_policies: tuple[ObservedAwsManagedPolicy, ...]


@dataclass(frozen=True)
class EnrollmentVerification:
    """Verified disabled enrollment; never authority to activate or deploy."""

    registry_sha256: str
    policies_verified: int
    principals_verified: int
    disabled_executors_verified: int
    activation_authorized: bool = False


@dataclass(frozen=True)
class ActiveEnrollmentVerification:
    """Verified active metadata, not admission, execution or activation authority."""

    registry_sha256: str
    policies_verified: int
    principals_verified: int
    active_executors_verified: int
    activation_authorized: bool = False


def load_catalog(environment: str) -> dict[str, Any]:
    """Load only a named, hash-pinned public metadata catalog."""
    _require(environment in CATALOG_HASHES, "Unknown seed environment")
    path = Path(__file__).parent / "catalogs" / f"{environment}.json"
    catalog = json.loads(path.read_text(encoding="utf-8"))
    _verify_catalog_hash(environment, catalog)
    return catalog


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RegistryError(message)


def _verify_catalog_hash(environment: str, catalog: Mapping[str, Any]) -> None:
    _require(
        document_hash(catalog) == CATALOG_HASHES[environment],
        "Catalog changed: independent inventory/policy review is required",
    )


def _validate_key(key: SeedKeyBinding, catalog: Mapping[str, Any]) -> None:
    _require(isinstance(key, SeedKeyBinding), "Explicit seed KMS metadata is required")
    account = catalog["account_id"]
    expected = f"arn:aws:kms:{REGION}:{account}:key/{key.key_id}"
    _require(key.arn == expected, "Seed KMS ARN/account/region/key ID mismatch")
    _require(key.aws_account_id == account, "Seed KMS metadata account mismatch")
    _require(bool(_KEY_ID.fullmatch(key.key_id)), "Seed KMS ID must be an exact key ID")
    compact = key.key_id.removeprefix("mrk-").replace("-", "")
    _require(
        not compact.startswith(("00000000", "01234567", "12345678"))
        and len(set(compact)) > 2,
        "Placeholder seed KMS key ID is forbidden",
    )
    _require(
        (key.key_manager, key.key_state, key.key_usage)
        == ("CUSTOMER", "Enabled", "ENCRYPT_DECRYPT"),
        "Seed KMS key must be an enabled customer encryption key",
    )
    bindings = catalog["operator_bindings"]
    routine_keys = {
        bindings["backend_key"],
        bindings["source_alias_metadata_key"],
        bindings["aws_secretsmanager_key"],
    }
    _require(key.arn not in routine_keys, "Seed KMS key cannot reuse a routine key")


def _bind(value: Any, key_arn: str) -> Any:
    """Resolve the one reviewed public-resource reference; reject unknown ones."""
    if isinstance(value, dict):
        if "Ref" in value:
            _require(value == {"Ref": "SeedKmsKeyArn"}, "Unknown seed policy binding")
            return key_arn
        return {k: _bind(v, key_arn) for k, v in value.items()}
    if isinstance(value, list):
        return [_bind(v, key_arn) for v in value]
    return value


def _policy(arn: str, data: Mapping[str, Any], catalog: Mapping, key: str):
    template = {
        "Version": "2012-10-17",
        "Statement": [catalog["statements"][s] for s in data["statement_ids"]],
    }
    _require(document_hash(template) == data["template_sha256"], "Policy template hash")
    document = _bind(template, key)
    encoded = canonical_json(document)
    _require(len(encoded) <= 6144, f"Managed policy exceeds 6144 characters: {arn}")
    return PolicyRecord(
        arn,
        data["kind"],
        data["ownership"],
        data["installed_arn"],
        encoded,
        document_hash(document),
    )


def _frozen_config(value: Mapping[str, Any] | None) -> FrozenConfigGrants | None:
    if value is None:
        return None
    aws_policy = value["aws_managed_policy"]
    return FrozenConfigGrants(
        canonical_json(value["trust"]),
        tuple(
            (k, canonical_json(v)) for k, v in sorted(value["inline_policies"].items())
        ),
        aws_policy["arn"],
        aws_policy["version_id"],
        aws_policy["document_sha256"],
    )


def _principal(data: Mapping[str, Any]) -> PrincipalRecord:
    return PrincipalRecord(
        data["arn"],
        data["existing"],
        data["owner_project"],
        data["boundary_arn"],
        tuple(sorted(data["guard_arns"])),
        tuple(sorted(data["attachment_arns"])),
        _frozen_config(data["frozen_config"]),
    )


def _validate_principal(principal: PrincipalRecord, policies: Mapping) -> None:
    guards = set(principal.guard_arns)
    attachments = set(principal.attachment_arns)
    _require(
        bool(guards) and guards <= attachments, "Missing required guard attachment"
    )
    _require(
        len(attachments) == len(principal.attachment_arns) <= 10, "Attachment quota"
    )
    _require(len(guards) == len(principal.guard_arns), "Duplicate guard")
    _require(
        all(policies[g].kind == "immutable_managed_guard" for g in guards),
        "Guard reference is not a managed deny policy",
    )
    if principal.boundary_arn is None:
        _require(principal.frozen_config is not None, "Unbounded non-Config principal")
    else:
        _require(policies[principal.boundary_arn].kind in _BOUNDARIES, "Boundary kind")


def _validate_policy_inventory(policies: tuple) -> None:
    for kind, count in [
        ("existing_capability_boundary", 6),
        ("purpose_capability_boundary", 8),
        ("executor_boundary", 3),
        ("executor_identity", 3),
    ]:
        _require(
            sum(p.kind == kind for p in policies) == count, "Policy kind inventory"
        )


def _validate_policy_names(policies: tuple) -> None:
    names = [policy.arn.rsplit("/", 1)[-1] for policy in policies]
    _require(
        all(re.fullmatch(r"[A-Za-z0-9_+=,.@-]{1,128}", name) for name in names),
        "Invalid managed policy name",
    )
    _require(
        len({name.casefold() for name in names}) == len(names),
        "Managed policy names must be unique across paths and case",
    )


def _validate_closure(policies: tuple, principals: tuple) -> None:
    policy_map = {p.arn: p for p in policies}
    _require(len(policy_map) == len(policies) == 55, "Expected 55 seed policies")
    _validate_policy_names(policies)
    _require(
        len({p.arn for p in principals}) == len(principals) == 24,
        "Expected 24 principals",
    )
    _require(sum(p.existing for p in principals) == 21, "Expected 21 existing roles")
    _validate_policy_inventory(policies)
    _require(sum(p.frozen_config is not None for p in principals) == 1, "Config freeze")
    for principal in principals:
        _validate_principal(principal, policy_map)
    referenced = {arn for p in principals for arn in p.attachment_arns}
    referenced |= {p.boundary_arn for p in principals}
    _require(set(policy_map) <= referenced, "Unreferenced seed policy")


def build_registry(
    environment: str,
    *,
    account_id: str,
    seed_key: SeedKeyBinding,
    catalog: Mapping[str, Any] | None = None,
) -> SeedRegistry:
    """Render the entire closed enrollment set using an explicit real-key binding."""
    _require(environment in ACCOUNTS, "Unknown seed environment")
    _require(account_id == ACCOUNTS[environment], "Seed account/environment mismatch")
    selected = load_catalog(environment) if catalog is None else catalog
    _verify_catalog_hash(environment, selected)
    _validate_key(seed_key, selected)
    policies = tuple(
        _policy(arn, data, selected, seed_key.arn)
        for arn, data in sorted(selected["policies"].items())
    )
    principals = tuple(_principal(p) for p in selected["principals"])
    _validate_closure(policies, principals)
    return SeedRegistry(
        environment,
        account_id,
        REGION,
        CATALOG_HASHES[environment],
        seed_key,
        policies,
        principals,
    )


def _unique(items: tuple, label: str) -> dict:
    result = {item.arn: item for item in items}
    _require(len(result) == len(items), f"Duplicate observed {label}")
    return result


def _observed_hash(policy: ObservedPolicy) -> str:
    _require(
        bool(re.fullmatch(r"v[1-9][0-9]*", policy.default_version_id)),
        "Invalid observed default policy version",
    )
    return document_hash(json.loads(policy.document_json))


def _verify_config(expected: FrozenConfigGrants, actual: ObservedPrincipal, aws: dict):
    _require(
        canonical_json(json.loads(actual.trust_json)) == expected.trust_json,
        "Config trust changed",
    )
    inline = tuple(
        sorted((k, canonical_json(json.loads(v))) for k, v in actual.inline_policies)
    )
    _require(
        inline == expected.inline_policies, "Config complete inline grants changed"
    )
    policy = aws[expected.aws_policy_arn]
    _require(
        policy.default_version_id == expected.aws_policy_version,
        "Config AWS-managed version requires enrollment review",
    )
    _require(
        policy.document_sha256 == expected.aws_policy_sha256,
        "Config AWS-managed policy document changed",
    )


def _verify_role(expected: PrincipalRecord, actual: ObservedPrincipal, aws: dict):
    _require(actual.boundary_arn == expected.boundary_arn, "Role boundary mismatch")
    _require(
        len(set(actual.attachment_arns)) == len(actual.attachment_arns),
        "Duplicate observed attachment",
    )
    _require(
        set(actual.attachment_arns) == set(expected.attachment_arns),
        "Role attachment set changed or a required guard is missing",
    )
    if not expected.existing:
        _require(
            canonical_json(json.loads(actual.trust_json))
            == canonical_json(disabled_trust_policy(expected.arn.split(":")[4])),
            "New executor trust is not disabled",
        )
        _require(not actual.inline_policies, "Unexpected new executor inline grant")
    if expected.frozen_config is not None:
        _verify_config(expected.frozen_config, actual, aws)


def _verify_observation(registry: SeedRegistry, observation: EnrollmentObservation):
    """Verify the same complete immutable inventory for either lifecycle phase."""
    _require(
        observation.account_id == registry.account_id, "Observation account mismatch"
    )
    _require(
        observation.seed_key == registry.seed_key, "Observed seed KMS binding changed"
    )
    expected = build_registry(
        registry.environment, account_id=registry.account_id, seed_key=registry.seed_key
    )
    _require(registry == expected, "Rendered registry changed")
    policies = _unique(observation.policies, "policy")
    roles = _unique(observation.principals, "principal")
    aws = _unique(observation.aws_managed_policies, "AWS-managed policy")
    _require(
        set(policies) == {p.arn for p in registry.policies}, "Observed policy inventory"
    )
    _require(
        set(roles) == {p.arn for p in registry.principals}, "Observed role inventory"
    )
    _require(
        set(aws)
        == {
            p.frozen_config.aws_policy_arn
            for p in registry.principals
            if p.frozen_config is not None
        },
        "Observed Config AWS policy set",
    )
    for policy in registry.policies:
        _require(
            _observed_hash(policies[policy.arn]) == policy.sha256,
            "Installed default policy document hash mismatch",
        )
    return policies, roles, aws


def verify_enrollment(
    registry: SeedRegistry, observation: EnrollmentObservation
) -> EnrollmentVerification:
    """Check complete metadata while all new executors still have disabled trust.

    This is an initial enrollment check, not a perpetual freeze on the ordinary
    mutable role/policy grants. Config's AWS-managed policy may change externally
    after installation; its version/hash must match the reviewed initial input.
    """
    policies, roles, aws = _verify_observation(registry, observation)
    for principal in registry.principals:
        _verify_role(principal, roles[principal.arn], aws)
    return EnrollmentVerification(registry.sha256, len(policies), len(roles), 3)


def _active_executor_trust(registry: SeedRegistry, principal: PrincipalRecord) -> str:
    purposes = {
        f"arn:aws:iam::{registry.account_id}:role/GitHubOperator{purpose.title()}"
        f"-{registry.environment}": purpose
        for purpose in ("preview", "apply", "drift")
    }
    return operator_trust_policy(
        registry.environment, purposes[principal.arn], account_id=registry.account_id
    )


def _verify_active_executor(
    registry: SeedRegistry, expected: PrincipalRecord, actual: ObservedPrincipal
) -> None:
    _require(actual.boundary_arn == expected.boundary_arn, "Role boundary mismatch")
    _require(
        sorted(actual.attachment_arns) == sorted(expected.attachment_arns),
        "Active executor attachment set changed",
    )
    _require(not actual.inline_policies, "Unexpected active executor inline grant")
    _require(
        canonical_json(json.loads(actual.trust_json))
        == _active_executor_trust(registry, expected),
        "Active executor trust changed",
    )


def _mutable_attachment_sets(registry: SeedRegistry) -> dict[str, set[str]]:
    """Keep operator and governed-service grant identities in separate catalogs."""
    catalog = load_catalog(registry.environment)
    bindings = catalog["operator_bindings"]
    permitted = {arn: set(bindings["policy_write"]) for arn in bindings["role_write"]}
    service_policies = {
        f"arn:aws:iam::{registry.account_id}:policy/GitHubCiApply-"
        f"user-service-infrastructure-{registry.environment}-{suffix}"
        for suffix in ("pulumi-backend", "secret-read-deny")
    }
    # Only the service apply role owns these mutable grants. Read, configuration
    # and replication roles retain their exact enrolled attachment sets.
    service_apply = (
        f"arn:aws:iam::{registry.account_id}:role/GitHubCiApply-"
        f"user-service-infrastructure-{registry.environment}"
    )
    for principal in registry.principals:
        if principal.owner_project == "governance" and principal.arn == service_apply:
            permitted[principal.arn] = service_policies
    return permitted


def _verify_mutable_role(
    expected: PrincipalRecord, actual: ObservedPrincipal, permitted: set[str]
) -> None:
    _require(actual.boundary_arn == expected.boundary_arn, "Role boundary mismatch")
    attachments = set(actual.attachment_arns)
    _require(
        len(attachments) == len(actual.attachment_arns) <= 10,
        "Active attachment duplicate or quota",
    )
    _require(set(expected.guard_arns) <= attachments, "Required active guard missing")
    _require(
        attachments <= set(expected.guard_arns) | permitted,
        "Active attachment is outside the principal's permitted policy identities",
    )


def verify_active_enrollment(
    registry: SeedRegistry, observation: EnrollmentObservation
) -> ActiveEnrollmentVerification:
    """Check current immutable enforcement and exact active operator trust.

    Existing operator/service identity attachments may evolve only inside their
    separate closed grant catalogs. All boundaries/guards remain mandatory;
    Config grants, backup attachments and executor grants/trust remain exact.
    AWS-managed Config changes fail pending independent registry review. This
    pure comparison cannot authenticate observations, admit a PR, or apply it.
    """
    policies, roles, aws = _verify_observation(registry, observation)
    permitted = _mutable_attachment_sets(registry)
    for expected in registry.principals:
        actual = roles[expected.arn]
        if not expected.existing:
            _verify_active_executor(registry, expected, actual)
        elif expected.arn in permitted:
            _verify_mutable_role(expected, actual, permitted[expected.arn])
        else:
            _verify_role(expected, actual, aws)
    return ActiveEnrollmentVerification(registry.sha256, len(policies), len(roles), 3)
