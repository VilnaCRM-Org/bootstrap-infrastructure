"""Uninstalled TEST PassRole proposal for issue 219; no resource registration.

These are amendment fragments, not complete deploy-role policies. The existing
independent boundary and guards must be reconciled and reviewed separately.
Nothing imports this module from a deployment or enrollment entrypoint.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

ACCOUNT_ID = "891377212104"
REGION = "eu-central-1"
REPOSITORY = "VilnaCRM-Org/user-service-infrastructure"
RUNTIME_ROLE_ARNS = tuple(
    f"arn:aws:iam::{ACCOUNT_ID}:role/user-service-infrastructure-test-{suffix}"
    for suffix in ("EcsExecution", "EcsTask")
)
ECS_SERVICE = "ecs-tasks.amazonaws.com"


@dataclass(frozen=True)
class PassRoleProposal:
    """Separate desired identity, boundary and explicit guard amendments."""

    identity_json: str
    boundary_json: str
    guard_json: str
    state: str = "proposed-uninstalled-pass-role-fragments"


def _document(statements: list[dict]) -> str:
    """Render finite fragments deterministically; full-policy quota checks remain."""
    return json.dumps(
        {"Version": "2012-10-17", "Statement": statements},
        sort_keys=True,
        separators=(",", ":"),
    )


def propose_pass_role(
    *, account_id: str, region: str, repository: str, environment: str, purpose: str
) -> PassRoleProposal:
    """Select one exact TEST service; preview and drift explicitly deny PassRole.

    Role names preserve the earlier dormant-runtime proposal, not observed AWS
    identities. Publisher, service-linked and deployment roles are never passed.
    The shared boundary allows only the finite pair; individual identity/guard
    documents keep read roles unable to use that boundary allowance.
    """
    if (account_id, region, repository, environment) != (
        ACCOUNT_ID,
        REGION,
        REPOSITORY,
        "test",
    ):
        raise ValueError("PassRole proposal requires the exact TEST service target")
    if purpose not in {"apply", "preview", "drift"}:
        raise ValueError("PassRole proposal supports apply, preview and drift only")
    allow = {
        "Sid": "PassOnlyTestEcsRuntimeRoles",
        "Effect": "Allow",
        "Action": ["iam:PassRole"],
        "Resource": list(RUNTIME_ROLE_ARNS),
        "Condition": {"StringEquals": {"iam:PassedToService": ECS_SERVICE}},
    }
    guard = [
        {
            "Sid": "DenyPassingOtherRoles",
            "Effect": "Deny",
            "Action": ["iam:PassRole"],
            "NotResource": list(RUNTIME_ROLE_ARNS),
        },
        {
            "Sid": "DenyPassingRolesOutsideEcsTasks",
            "Effect": "Deny",
            "Action": ["iam:PassRole"],
            "Resource": "*",
            # Negated equality also rejects a missing context key.
            "Condition": {"StringNotEquals": {"iam:PassedToService": ECS_SERVICE}},
        },
    ]
    read_deny = {
        "Sid": "DenyReadRolePassRole",
        "Effect": "Deny",
        "Action": ["iam:PassRole"],
        "Resource": "*",
    }
    return PassRoleProposal(
        identity_json=_document([allow] if purpose == "apply" else [read_deny]),
        boundary_json=_document([allow]),
        guard_json=_document(guard if purpose == "apply" else [read_deny]),
    )
