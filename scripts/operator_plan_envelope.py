"""In-memory authenticated operator plans bound to trusted caller-supplied facts.

Encryption does not authorize an apply or establish caller provenance. The
worker must recheck current admission, checkpoint version/provider identity and
one-time request consumption before apply. No fixed wall-clock expiry is imposed:
protected-environment approval may legitimately take longer than an hour.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import os
import re
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
from typing import Any, cast

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from deployment_controller import WORKFLOW, DeploymentContract, _validate_contract
from validate_ci_environment import _validate_secrets_provider

MAX_PLAN_BYTES = 32 * 1024 * 1024
MAX_ENVELOPE_BYTES = 48 * 1024 * 1024
MAX_CONTEXT_BYTES = 8192
ACCOUNTS = {
    "test": (
        "891377212104",
        "arn:aws:kms:eu-central-1:891377212104:key/1ab201ad-c498-496d-ad36-a529021da6be",
    ),
    "prod": (
        "933245420672",
        "arn:aws:kms:eu-central-1:933245420672:key/fdba4c44-71b0-4979-b163-4705a91aa29b",
    ),
}
KmsCall = Callable[[dict[str, Any]], Mapping[str, Any]]


class EnvelopeError(ValueError):
    """A bounded error category that contains no plan or KMS response material."""


@dataclass(frozen=True)
class CheckpointBinding:
    """Exact existing canonical S3 checkpoint identity from trusted observations."""

    bucket: str
    key: str
    version_id: str
    etag: str


@dataclass(frozen=True)
class ProviderBinding:
    """Resolved provider/key identity; state_sha256 hashes complete provider state."""

    uri: str
    key_arn: str
    state_sha256: str


@dataclass(frozen=True)
class ExecutionBinding:
    """Pinned execution and observed state facts, never proof of their provenance."""

    environment: str
    account_id: str
    region: str
    project: str
    backend: str
    kms_key_arn: str
    checkpoint: CheckpointBinding
    provider: ProviderBinding


def _require(condition: bool, category: str) -> None:
    if not condition:
        raise EnvelopeError(category)


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _unique(pairs: list[tuple[str, Any]]) -> dict:
    result = {}
    for key, value in pairs:
        _require(key not in result, "duplicate-json-key")
        result[key] = value
    return result


def _finite(value: str) -> float:
    number = float(value)
    _require(math.isfinite(number), "nonfinite-json")
    return number


def _json(raw: bytes) -> Any:
    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique,
            parse_float=_finite,
            parse_constant=_finite,
        )
    except (ValueError, UnicodeError, RecursionError):
        raise EnvelopeError("invalid-json") from None


def _text(value: object, maximum: int = 1024) -> bool:
    return (
        type(value) is str
        and 0 < len(value) <= maximum
        and all(33 <= ord(character) <= 126 for character in value)
    )


def _validate_execution(execution: ExecutionBinding) -> None:
    _require(type(execution) is ExecutionBinding, "execution-type")
    _require(
        type(execution.environment) is str and execution.environment in ACCOUNTS,
        "execution-environment",
    )
    account, key = ACCOUNTS[execution.environment]
    bucket = f"pulumi-bootstrap-infrastructure-{execution.environment}-state"
    _require(
        (
            execution.account_id,
            execution.region,
            execution.project,
            execution.backend,
            execution.kms_key_arn,
        )
        == (account, "eu-central-1", "github-ci-bootstrap", "s3://" + bucket, key),
        "execution-coordinates",
    )
    checkpoint, provider = execution.checkpoint, execution.provider
    _require(type(checkpoint) is CheckpointBinding, "checkpoint-type")
    _require(
        checkpoint.bucket == bucket
        and checkpoint.key
        == f".pulumi/stacks/github-ci-bootstrap/{execution.environment}.json",
        "checkpoint-path",
    )
    _require(
        _text(checkpoint.version_id)
        and checkpoint.version_id != "null"
        and _text(checkpoint.etag),
        "checkpoint-version",
    )
    _require(type(provider) is ProviderBinding, "provider-type")
    _require(
        _text(provider.uri)
        and provider.key_arn == key
        and type(provider.state_sha256) is str
        and re.fullmatch(r"[0-9a-f]{64}", provider.state_sha256) is not None,
        "provider-identity",
    )
    _require(
        _validate_secrets_provider(
            provider.uri,
            {
                "AWS_ACCOUNT_ID": account,
                "AWS_REGION": execution.region,
            },
        )
        is None,
        "provider-uri",
    )


def _binding(contract: DeploymentContract, execution: ExecutionBinding) -> dict:
    try:
        _validate_contract(contract)
    except (ValueError, TypeError, AttributeError):
        raise EnvelopeError("invalid-contract") from None
    _validate_execution(execution)
    _require(
        any(
            step.scope == "operator" and step.environment == execution.environment
            for step in contract.schedule
        ),
        "operator-not-selected",
    )
    identity = contract.identity
    result = {
        "purpose": "operator-saved-plan-v1",
        "repository": identity.repository,
        "repository_id": str(identity.repository_id),
        "repository_owner_id": str(identity.owner_id),
        "account": execution.account_id,
        "project": execution.project,
        "stack": execution.environment,
        "backend": execution.backend,
        "workflow_path": WORKFLOW,
        "controller_sha": identity.controller.sha,
        "head_sha": identity.head_sha,
        "base_sha": identity.base_sha,
        "run_id": identity.controller.run_id,
        "run_attempt": str(identity.controller.run_attempt),
        "pull_request_number": identity.pull_request_number,
        "comment_id": identity.comment_id,
        "source_run_id": identity.source_run_id,
        "command": identity.command,
        "target_environment": identity.target_environment,
        "selector_sha256": contract.selector_sha256,
        "selection_digest": contract.selection_digest,
        "contract_digest": contract.contract_digest,
        "execution_sha256": _digest(_canonical(asdict(execution))),
    }
    _require(len(_canonical(result)) <= MAX_CONTEXT_BYTES, "binding-size")
    return result


def _plan(plan: bytes) -> None:
    _require(type(plan) is bytes and 0 < len(plan) <= MAX_PLAN_BYTES, "plan-size")
    _require(type(_json(plan)) is dict, "plan-object")


def _decode(value: Any, minimum: int, maximum: int) -> bytes:
    _require(
        type(value) is str and len(value) <= 4 * ((maximum + 2) // 3), "encoded-size"
    )
    try:
        raw = base64.b64decode(value, validate=True)
    except ValueError:
        raise EnvelopeError("invalid-base64") from None
    _require(minimum <= len(raw) <= maximum, "decoded-size")
    _require(base64.b64encode(raw).decode("ascii") == value, "noncanonical-base64")
    return raw


def _kms(call: KmsCall, request: dict, key_arn: str) -> tuple[Mapping, bytes]:
    try:
        response = call(request)
    except Exception:
        raise EnvelopeError("kms-failed") from None
    _require(isinstance(response, Mapping), "kms-response")
    _require(response.get("KeyId") == key_arn, "foreign-kms-key")
    key = response.get("Plaintext")
    _require(type(key) is bytes and len(key) == 32, "kms-data-key")
    return response, cast(bytes, key)


def seal_plan(
    plan: bytes,
    *,
    contract: DeploymentContract,
    execution: ExecutionBinding,
    generate_key: KmsCall,
) -> bytes:
    """Return ciphertext bytes only; the KMS callback uses native SDK byte values.

    No file/artifact writes, logging, shell commands or plaintext serialization
    outputs occur. The callback must keep KMS responses and data keys in memory.
    """
    binding = _binding(contract, execution)
    _plan(plan)
    response, key = _kms(
        generate_key,
        {
            "KeyId": execution.kms_key_arn,
            "KeySpec": "AES_256",
            "EncryptionContext": binding,
        },
        execution.kms_key_arn,
    )
    wrapped = response.get("CiphertextBlob")
    _require(type(wrapped) is bytes and 0 < len(wrapped) <= 6144, "wrapped-key-size")
    wrapped = cast(bytes, wrapped)
    nonce = os.urandom(12)
    aad = _canonical({"binding": binding, "wrapped_key_sha256": _digest(wrapped)})
    ciphertext = AESGCM(key).encrypt(nonce, plan, aad)
    result = _canonical(
        {
            "schema": 1,
            "binding": binding,
            "wrapped_key": base64.b64encode(wrapped).decode("ascii"),
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        }
    )
    _require(len(result) <= MAX_ENVELOPE_BYTES, "envelope-size")
    return result


def open_plan(
    raw: bytes,
    *,
    contract: DeploymentContract,
    execution: ExecutionBinding,
    decrypt_key: KmsCall,
) -> bytes:
    """Open only for independently supplied exact expected request/state bindings.

    Matching bindings prevent cross-request/state replay, not repeated use in
    the same context. Admission freshness and one-time apply consumption remain
    caller-owned. Returned plaintext must remain private to the apply process.
    """
    _require(type(raw) is bytes and 0 < len(raw) <= MAX_ENVELOPE_BYTES, "envelope-size")
    binding = _binding(contract, execution)
    envelope = _json(raw)
    _require(
        type(envelope) is dict
        and set(envelope)
        == {
            "schema",
            "binding",
            "wrapped_key",
            "nonce",
            "ciphertext",
        },
        "envelope-fields",
    )
    _require(type(envelope["schema"]) is int and envelope["schema"] == 1, "schema")
    _require(envelope["binding"] == binding, "binding-mismatch")
    wrapped = _decode(envelope["wrapped_key"], 1, 6144)
    nonce = _decode(envelope["nonce"], 12, 12)
    ciphertext = _decode(envelope["ciphertext"], 16, MAX_PLAN_BYTES + 16)
    _, key = _kms(
        decrypt_key,
        {
            "KeyId": execution.kms_key_arn,
            "CiphertextBlob": wrapped,
            "EncryptionContext": binding,
        },
        execution.kms_key_arn,
    )
    aad = _canonical({"binding": binding, "wrapped_key_sha256": _digest(wrapped)})
    try:
        plan = AESGCM(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag:
        raise EnvelopeError("authentication-failed") from None
    _plan(plan)
    return plan
