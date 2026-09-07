"""Strict JSON decoding for authenticated deployment-contract artifacts.

Decoding checks shape, canonical selector semantics, and content digests only.
The caller must authenticate the artifact's origin and trusted runtime revision;
a matching digest does not establish provenance or authorize execution.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any, TypeVar, cast

from deployment_controller import (
    ControllerMetadata,
    DeploymentContract,
    DeploymentIdentity,
    _validate_contract,
)
from deployment_schedule import DeploymentStep
from deployment_scopes import DeploymentScopes, PathImpact

MAX_CONTRACT_BYTES = 1024 * 1024
T = TypeVar("T")
Parser = Callable[[object], object]


def _primitive(value: object, expected: type[T]) -> T:
    """Require the exact JSON primitive type, including integer/Boolean separation."""
    if type(value) is not expected:
        raise ValueError(f"Expected JSON {expected.__name__}")
    return cast(T, value)


def _string(value: object) -> str:
    """Accept Unicode scalar strings; escaped unpaired surrogates are invalid."""
    result = _primitive(value, str)
    result.encode("utf-8")
    return result


def _integer(value: object) -> int:
    """Decode an integer without accepting a Boolean or coercing strings/floats."""
    return _primitive(value, int)


def _boolean(value: object) -> bool:
    """Decode a Boolean without accepting integers."""
    return _primitive(value, bool)


def _optional_string(value: object) -> str | None:
    """Decode the nullable predecessor field."""
    return None if value is None else _string(value)


def _array(value: object, decode: Callable[[object], T]) -> tuple[T, ...]:
    """Freeze each JSON array after validating all elements."""
    if type(value) is not list:
        raise ValueError("Expected JSON array")
    return tuple(decode(item) for item in value)


def _strings(value: object) -> tuple[str, ...]:
    """Decode immutable string lists; semantic validation checks allowed scopes."""
    return _array(value, _string)


def _fields(value: object, schema: dict[str, Parser]) -> dict[str, Any]:
    """Require the exact object keys and decode every required field."""
    if type(value) is not dict or set(value) != set(schema):
        raise ValueError("Expected object with exactly the required fields")
    fields = cast(dict[str, object], value)
    return {key: decode(fields[key]) for key, decode in schema.items()}


def _controller(value: object) -> ControllerMetadata:
    """Decode the trusted controller-run identity."""
    return ControllerMetadata(
        **_fields(
            value,
            {
                "sha": _string,
                "run_id": _string,
                "run_attempt": _integer,
                "workflow_ref": _string,
            },
        )
    )


def _identity(value: object) -> DeploymentIdentity:
    """Decode the complete original request and repository identity."""
    return DeploymentIdentity(
        **_fields(
            value,
            {
                "repository": _string,
                "repository_id": _integer,
                "owner_id": _integer,
                "pull_request_number": _string,
                "head_sha": _string,
                "base_sha": _string,
                "comment_id": _string,
                "source_run_id": _string,
                "command": _string,
                "target_environment": _string,
                "controller": _controller,
            },
        )
    )


def _reason(value: object) -> PathImpact:
    """Decode one path's complete immutable classification."""
    return PathImpact(
        **_fields(
            value,
            {
                "path": _string,
                "stacks": _strings,
                "scaffold_validation": _boolean,
                "execution_validation": _boolean,
                "catalog_validation": _boolean,
                "reason": _string,
            },
        )
    )


def _selection(value: object) -> DeploymentScopes:
    """Decode every reason and aggregate validation flag without coercion."""
    return DeploymentScopes(
        **_fields(
            value,
            {
                "base_sha": _string,
                "head_sha": _string,
                "stacks": _strings,
                "scaffold_validation": _boolean,
                "execution_validation": _boolean,
                "catalog_validation": _boolean,
                "reasons": lambda items: _array(items, _reason),
            },
        )
    )


def _step(value: object) -> DeploymentStep:
    """Decode one scheduled stage, including its nullable dependency."""
    return DeploymentStep(
        **_fields(
            value,
            {
                "key": _string,
                "environment": _string,
                "scope": _string,
                "operation": _string,
                "predecessor": _optional_string,
            },
        )
    )


def _contract(value: object) -> DeploymentContract:
    """Decode the only supported document kind; receipts/barriers are not inputs."""
    return DeploymentContract(
        **_fields(
            value,
            {
                "schema_version": _integer,
                "identity": _identity,
                "selector_sha256": _string,
                "selection": _selection,
                "selection_digest": _string,
                "schedule": lambda items: _array(items, _step),
                "contract_digest": _string,
            },
        )
    )


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject duplicate keys at every depth instead of keeping the last value."""
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON object key")
        result[key] = value
    return result


def _reject_number(value: str) -> object:
    """Disallow nonfinite constants and floats; this contract has no float fields."""
    raise ValueError("Noninteger JSON numbers are not supported")


def _bounded_text(payload: str | bytes) -> str:
    """Limit the actual UTF-8 payload before parsing and reject other transports."""
    if type(payload) not in (str, bytes):
        raise ValueError("Contract payload must be a JSON string or UTF-8 bytes")
    if len(payload) > MAX_CONTRACT_BYTES:
        raise ValueError("Contract payload exceeds the size limit")
    text = payload.decode("utf-8") if isinstance(payload, bytes) else payload
    if len(text.encode("utf-8")) > MAX_CONTRACT_BYTES:
        raise ValueError("Contract payload exceeds the size limit")
    return text


def decode_deployment_contract(payload: str | bytes) -> DeploymentContract:
    """Decode at most 1 MiB of strict UTF-8 JSON and verify canonical semantics.

    The installed controller validator recomputes scope from the normalized paths
    using its trusted selector, then verifies schedule and content digests. The
    caller must authenticate that these are the original complete artifact facts.
    """
    text = _bounded_text(payload)
    try:
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_number,
            parse_float=_reject_number,
        )
    except RecursionError as error:
        raise ValueError("Contract JSON nesting is too deep") from error
    contract = _contract(value)
    _validate_contract(contract)
    return contract
