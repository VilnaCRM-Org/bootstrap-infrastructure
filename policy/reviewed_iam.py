"""Strict, offline matching of reviewed complete IAM policy documents."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from typing import Any, NoReturn, cast

_MANAGED_POLICY = "aws:iam/policy:Policy"
_INLINE_POLICY = "aws:iam/rolePolicy:RolePolicy"
# Pulumi RPC unknown sentinel; it is not a physical IAM name or policy value.
_UNKNOWN = "04da6b54-80e4-46f7-96ec-b56ff0331ba9"
_ADDITIONAL_DOCUMENT_FIELDS = ("policyDocument", "assumeRolePolicy", "inlinePolicies")


def _physical_name(value: object, maximum: int) -> str | None:
    """Accept literal IAM names without coercion, whitespace or key separators."""
    if not isinstance(value, str):
        return None
    if _UNKNOWN in value:
        return None
    if re.fullmatch(r"[A-Za-z0-9_+=,.@-]{1," + str(maximum) + "}", value) is None:
        return None
    return value


def _policy_identity(resource_type: str, props: Mapping[str, Any]) -> str | None:
    """Inline policy names are unique only together with their owning role."""
    if resource_type not in (_MANAGED_POLICY, _INLINE_POLICY):
        return None
    name = _physical_name(props.get("name"), 128)
    if name is None:
        return None
    identity = [resource_type, name]
    if resource_type == _INLINE_POLICY:
        role = _physical_name(props.get("role"), 64)
        if role is None:
            return None
        identity.append(role)
    return "|".join(identity)


def _closed_digests(value: object) -> tuple[str, ...]:
    """Reject malformed pin sets rather than ignoring their invalid members."""
    if isinstance(value, str):
        value = (value,)
    if not isinstance(value, Sequence) or isinstance(value, (bytes, bytearray)):
        return ()
    if not all(
        isinstance(item, str) and re.fullmatch(r"[0-9a-f]{64}", item) for item in value
    ):
        return ()
    return tuple(cast(Sequence[str], value))


def _unique_members(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate JSON members instead of silently choosing one value."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON member")
        result[key] = value
    return result


def _reject_constant(value: str) -> NoReturn:
    """NaN and Infinity are not JSON values and cannot receive reviewed pins."""
    raise ValueError(f"Invalid JSON constant: {value}")


def _json_mapping(value: Mapping[Any, Any]) -> dict[str, Any]:
    """Normalize object members without allowing key coercion."""
    if not all(isinstance(key, str) for key in value):
        raise ValueError("JSON object keys must be strings")
    return _unique_members([(key, _json_value(item)) for key, item in value.items()])


def _json_value(value: Any) -> Any:
    """Normalize mappings while rejecting key coercion and non-JSON values."""
    if isinstance(value, Mapping):
        return _json_mapping(value)
    if isinstance(value, list):
        return [_json_value(item) for item in value]
    if isinstance(value, str):
        if _UNKNOWN in value:
            raise ValueError("Unresolved Pulumi policy value")
        return value
    if value is None or isinstance(value, (bool, int, float)):
        return value
    raise ValueError("Unsupported JSON value")


def _canonical_document(value: object) -> str:
    """Hash the complete strict document, retaining every statement and condition."""
    if isinstance(value, str):
        value = json.loads(
            value, object_pairs_hook=_unique_members, parse_constant=_reject_constant
        )
    if not isinstance(value, Mapping):
        raise ValueError("IAM policy must be an object")
    return json.dumps(
        _json_value(value), sort_keys=True, separators=(",", ":"), allow_nan=False
    )


def reviewed_iam_document_matches(
    resource_type: str,
    props: Mapping[str, Any],
    reviewed_documents: Mapping[str, str | Sequence[str]],
) -> bool:
    """Match exact resource identity plus a closed set of complete-policy digests.

    No cloud lookup occurs. The deployment's separately validated AWS provider
    and entrypoint must enforce the account; a resource-policy body cannot prove
    which account owns a managed policy. Unknown or malformed values fail closed.
    """
    identity = _policy_identity(resource_type, props)
    if identity is None:
        return False
    expected = _closed_digests(reviewed_documents.get(identity))
    if not expected:
        return False
    if any(key in props for key in _ADDITIONAL_DOCUMENT_FIELDS):
        return False
    try:
        canonical = _canonical_document(props.get("policy"))
    except (ValueError, TypeError, RecursionError, OverflowError):
        return False
    actual = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return actual in expected
