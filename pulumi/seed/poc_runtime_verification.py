"""Compare complete runtime enrollment metadata; never authorize installation.

The independent installer must authenticate observations, preserve the existing
seed registry and govern every mutable identity with its separately reviewed
governor amendment. This verifier cannot substitute for any of those controls.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass

from . import poc_runtime as runtime
from .policy_registry import (
    ObservedPolicy,
    ObservedPrincipal,
    PolicyRecord,
    PrincipalRecord,
    RegistryError,
    canonical_json,
    document_hash,
)


@dataclass(frozen=True)
class RuntimeVerification:
    """Exact metadata comparison result, carrying no deployment authority."""

    enrollment_sha256: str
    policies_verified: int = 6
    principals_verified: int = 3
    activation_authorized: bool = False


def _require(condition: bool, message: str) -> None:
    """Reject incomplete or altered installer observations."""
    if not condition:
        raise RegistryError(message)


def _grants(purpose: str, publisher_subject: str | None) -> tuple[str, tuple]:
    """Select complete expected trust and inline grants from fixed source policy."""
    if purpose == "execution":
        return runtime.execution_trust(), (
            ("Issue219TestImagePull", runtime.execution_policy()),
        )
    if purpose == "publisher":
        trust = (
            runtime.disabled_trust()
            if publisher_subject is None
            else runtime.publisher_trust(publisher_subject)
        )
        return trust, (("Issue219TestImagePush", runtime.publisher_policy()),)
    return runtime.disabled_trust(), ()


def _inventory(observed: tuple, expected: tuple, label: str) -> dict:
    """Reject missing, duplicate or foreign rows before document verification."""
    rows = {row.arn: row for row in observed}
    _require(
        len(observed) == len(rows) == len(expected)
        and set(rows) == {row.arn for row in expected},
        f"Runtime {label} inventory differs",
    )
    return rows


def _verify_policy(expected: PolicyRecord, actual: ObservedPolicy) -> None:
    """Require the complete expected document at a valid native default version."""
    _require(
        re.fullmatch(r"v[1-9][0-9]*", actual.default_version_id) is not None
        and document_hash(json.loads(actual.document_json)) == expected.sha256,
        "Runtime fence default version or document differs",
    )


def _verify_role(
    expected: PrincipalRecord, actual: ObservedPrincipal, trust: str, inline: tuple
) -> None:
    """Reject changed boundaries, attachments, trust or complete inline grants."""
    _require(
        actual.boundary_arn == expected.boundary_arn
        and sorted(actual.attachment_arns) == sorted(expected.attachment_arns),
        "Runtime boundary or complete attachment set differs",
    )
    _require(
        canonical_json(json.loads(actual.trust_json)) == trust
        and tuple(
            sorted(
                (name, canonical_json(json.loads(document)))
                for name, document in actual.inline_policies
            )
        )
        == inline,
        "Runtime trust or complete inline grants differ",
    )


def verify_runtime_enrollment(
    *,
    account_id: str,
    region: str,
    policies: tuple[ObservedPolicy, ...],
    principals: tuple[ObservedPrincipal, ...],
    publisher_subject: str | None = None,
) -> RuntimeVerification:
    """Require exact six-policy/three-role documents, trusts and complete grants.

    Input metadata is not authenticated here. A successful comparison neither
    verifies governor authority/immutability nor makes observation and use atomic.
    """
    _require(
        (account_id, region) == (runtime.ACCOUNT_ID, runtime.REGION),
        "Runtime enrollment target differs",
    )
    expected_policies, expected_roles = runtime.enrollment_records()
    policy_map = _inventory(policies, expected_policies, "policy")
    role_map = _inventory(principals, expected_roles, "principal")
    for expected in expected_policies:
        _verify_policy(expected, policy_map[expected.arn])
    grants = []
    for identity, expected in zip(runtime.runtime_identities(), expected_roles):
        actual = role_map[expected.arn]
        trust, inline = _grants(identity.purpose, publisher_subject)
        _verify_role(expected, actual, trust, inline)
        grants.append((identity.arn, trust, inline))
    return RuntimeVerification(
        document_hash(
            {
                "policies": [asdict(row) for row in expected_policies],
                "principals": [asdict(row) for row in expected_roles],
                "grants": grants,
            }
        )
    )
