"""Collect complete public IAM enrollment metadata through a trusted AWS reader.

The worker supplies its authenticated, read-only AWS transport. This module
never retrieves secret values, assumes roles, mutates AWS, or grants authority.
An observation must pass the independent active-registry verifier before use.
Reads are not atomic, and a successful collection never authorizes activation or
apply. The caller authenticates the transport and enforces current admission.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping
from typing import Any, cast
from urllib.parse import unquote

from seed import policy_registry as registry

AwsRead = Callable[[str, str, dict[str, Any]], Mapping[str, Any]]
MAX_PAGES = 20
MAX_ITEMS = 1000


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise registry.RegistryError(message)


def _object(value: object) -> Mapping[str, Any]:
    _require(isinstance(value, Mapping), "Invalid AWS metadata object")
    return cast(Mapping[str, Any], value)


def _string(value: object) -> str:
    _require(type(value) is str, "Invalid AWS metadata string")
    return cast(str, value)


def _unique_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        _require(key not in result, "Duplicate AWS policy field")
        result[key] = value
    return result


def _document(value: object) -> str:
    """Normalize complete documents without URL-decoding literal JSON values."""
    try:
        if isinstance(value, str):
            _require(len(value) <= 1024 * 1024, "AWS policy document exceeds bound")
            try:
                value = json.loads(value, object_pairs_hook=_unique_fields)
            except json.JSONDecodeError:
                value = json.loads(unquote(value), object_pairs_hook=_unique_fields)
        document = json.dumps(
            _object(value), sort_keys=True, separators=(",", ":"), allow_nan=False
        )
        _require(len(document) <= 1024 * 1024, "AWS policy document exceeds bound")
        return document
    except registry.RegistryError:
        raise
    except (TypeError, ValueError, RecursionError):
        raise registry.RegistryError("Invalid AWS policy document") from None


def _read(call: AwsRead, service: str, operation: str, **arguments: Any) -> Mapping:
    """Do not include transport errors or response contents in error messages."""
    try:
        value = call(service, operation, arguments)
    except Exception:
        raise registry.RegistryError("AWS enrollment metadata read failed") from None
    return _object(value)


def _list(call: AwsRead, operation: str, field: str, role: str) -> tuple:
    """Exhaust IAM pagination; reject repeated markers and oversized inventories."""
    items: list = []
    markers: set[str] = set()
    arguments: dict[str, Any] = {"RoleName": role, "MaxItems": 100}
    for _ in range(MAX_PAGES):
        page = _read(call, "iam", operation, **arguments)
        entries, truncated = page.get(field), page.get("IsTruncated")
        _require(type(entries) is list, "Invalid IAM metadata page")
        _require(type(truncated) is bool, "Missing IAM pagination state")
        items.extend(cast(list, entries))
        _require(len(items) <= MAX_ITEMS, "IAM inventory exceeds bound")
        if not truncated:
            return tuple(items)
        marker = page.get("Marker")
        _require(
            type(marker) is str and 0 < len(marker) <= 1024 and marker not in markers,
            "Invalid or repeated IAM page marker",
        )
        markers.add(cast(str, marker))
        arguments["Marker"] = marker
    raise registry.RegistryError("IAM metadata pagination exceeds bound")


def _policy(call: AwsRead, arn: str) -> registry.ObservedPolicy:
    metadata = _object(_read(call, "iam", "get_policy", PolicyArn=arn).get("Policy"))
    version = metadata.get("DefaultVersionId")
    _require(metadata.get("Arn") == arn, "AWS policy ARN mismatch")
    _require(
        type(version) is str and re.fullmatch(r"v[1-9][0-9]*", version) is not None,
        "Invalid AWS policy version",
    )
    data = _object(
        _read(call, "iam", "get_policy_version", PolicyArn=arn, VersionId=version).get(
            "PolicyVersion"
        )
    )
    _require(
        data.get("VersionId") == version and data.get("IsDefaultVersion") is True,
        "AWS policy default version changed",
    )
    # Re-read the default pointer after fetching its complete document.
    current = _object(_read(call, "iam", "get_policy", PolicyArn=arn).get("Policy"))
    _require(
        current.get("Arn") == arn and current.get("DefaultVersionId") == version,
        "AWS policy changed during collection",
    )
    return registry.ObservedPolicy(
        arn, cast(str, version), _document(data.get("Document"))
    )


def _role(call: AwsRead, arn: str) -> registry.ObservedPrincipal:
    name = arn.rsplit("/", 1)[-1]
    role = _object(_read(call, "iam", "get_role", RoleName=name).get("Role"))
    _require(role.get("Arn") == arn, "AWS role ARN mismatch")
    boundary = role.get("PermissionsBoundary")
    boundary_arn = None
    if boundary is not None:
        boundary = _object(boundary)
        _require(
            boundary.get("PermissionsBoundaryType") == "Policy",
            "Invalid AWS role boundary type",
        )
        boundary_arn = boundary.get("PermissionsBoundaryArn")
        _require(type(boundary_arn) is str, "Invalid AWS role boundary ARN")
    attached = _list(call, "list_attached_role_policies", "AttachedPolicies", name)
    arns = tuple(_object(item).get("PolicyArn") for item in attached)
    _require(all(type(arn) is str for arn in arns), "Invalid attached policy ARN")
    _require(len(set(arns)) == len(arns), "Duplicate attached policy")
    names = _list(call, "list_role_policies", "PolicyNames", name)
    _require(
        all(
            type(item) is str and re.fullmatch(r"[A-Za-z0-9_+=,.@-]{1,128}", item)
            for item in names
        ),
        "Invalid inline policy name",
    )
    _require(len(set(names)) == len(names), "Duplicate inline policy")
    inline = []
    for policy_name in names:
        policy = _read(
            call, "iam", "get_role_policy", RoleName=name, PolicyName=policy_name
        )
        _require(
            policy.get("RoleName") == name and policy.get("PolicyName") == policy_name,
            "Inline policy identity mismatch",
        )
        inline.append((policy_name, _document(policy.get("PolicyDocument"))))
    return registry.ObservedPrincipal(
        arn,
        boundary_arn,
        cast(tuple[str, ...], arns),
        _document(role.get("AssumeRolePolicyDocument")),
        tuple(inline),
    )


def collect_enrollment(
    expected: registry.SeedRegistry, *, purpose: str, call: AwsRead
) -> registry.EnrollmentObservation:
    """Read only after verifying the exact non-root operator executor identity.

    AWS provides no transaction across these reads. The mandatory active check,
    immutable guards, and fresh pre-apply collection provide the runtime boundary;
    this function alone does not attest that IAM remained unchanged afterwards.
    """
    _require(purpose in ("preview", "apply", "drift"), "Invalid operator purpose")
    _require(
        expected
        == registry.build_registry(
            expected.environment,
            account_id=expected.account_id,
            seed_key=expected.seed_key,
        ),
        "Untrusted enrollment registry",
    )
    caller = _read(call, "sts", "get_caller_identity")
    prefix = (
        f"arn:aws:sts::{expected.account_id}:assumed-role/"
        f"GitHubOperator{purpose.title()}-{expected.environment}/"
    )
    arn = caller.get("Arn")
    _require(
        caller.get("Account") == expected.account_id
        and type(arn) is str
        and arn.startswith(prefix)
        and re.fullmatch(r"[A-Za-z0-9_+=,.@-]{2,64}", arn[len(prefix) :]) is not None,
        "Wrong operator caller; root and foreign roles are rejected",
    )
    return _collect_metadata(expected, call=call)


def _collect_metadata(
    expected: registry.SeedRegistry, *, call: AwsRead
) -> registry.EnrollmentObservation:
    """Shared complete reads after an entry point authenticates its own caller.

    This helper deliberately does not authenticate an operator or an installer.
    Use collect_enrollment for active workers; the independent initial CLI has
    its own STS/immutable RoleId gate. Neither route authorizes trust activation.
    """
    metadata = _object(
        _read(call, "kms", "describe_key", KeyId=expected.seed_key.arn).get(
            "KeyMetadata"
        )
    )
    key = registry.SeedKeyBinding(
        *(
            _string(metadata.get(name))
            for name in (
                "Arn",
                "KeyId",
                "AWSAccountId",
                "KeyManager",
                "KeyState",
                "KeyUsage",
            )
        )
    )
    _require(key == expected.seed_key, "Observed seed key mismatch")
    policies = tuple(_policy(call, item.arn) for item in expected.policies)
    principals = tuple(_role(call, item.arn) for item in expected.principals)
    aws_arns = {
        item.frozen_config.aws_policy_arn
        for item in expected.principals
        if item.frozen_config is not None
    }
    aws = []
    for policy_arn in sorted(aws_arns):
        policy = _policy(call, policy_arn)
        aws.append(
            registry.ObservedAwsManagedPolicy(
                policy.arn,
                policy.default_version_id,
                registry.document_hash(json.loads(policy.document_json)),
            )
        )
    return registry.EnrollmentObservation(
        expected.account_id, key, policies, principals, tuple(aws)
    )
