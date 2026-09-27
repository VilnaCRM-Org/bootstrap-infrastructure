"""Closed TEST runtime enrollment records and the finite ECR publisher grant.

No AWS calls or resources live here. Execution receives only bounded ECR pull;
the task role remains disabled until its queue/mail contract is reviewed.
Publisher trust accepts only a complete customized subject, never a default one.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from .poc_pass_role import ACCOUNT_ID, REGION, RUNTIME_ROLE_ARNS
from .policy_registry import (
    PolicyRecord,
    PrincipalRecord,
    RegistryError,
    canonical_json,
    document_hash,
    load_catalog,
)

PUBLISHER_NAME = "user-service-test-ImagePublisher"
APPLICATION_REPOSITORY = "VilnaCRM-Org/user-service"
REPOSITORY_ARNS = tuple(
    f"arn:aws:ecr:{REGION}:{ACCOUNT_ID}:repository/user-service-test-{target}"
    for target in ("web", "worker")
)
PUBLISH_ACTIONS = (
    "ecr:BatchCheckLayerAvailability",
    "ecr:BatchGetImage",
    "ecr:CompleteLayerUpload",
    "ecr:DescribeImages",
    "ecr:InitiateLayerUpload",
    "ecr:PutImage",
    "ecr:UploadLayerPart",
)
PULL_ACTIONS = (
    "ecr:BatchCheckLayerAvailability",
    "ecr:BatchGetImage",
    "ecr:GetDownloadUrlForLayer",
)


@dataclass(frozen=True)
class RuntimeIdentity:
    """Exact governance role name and independently owned fence identities."""

    purpose: str
    name: str

    @property
    def arn(self) -> str:
        """Return the account-local role ARN."""
        return f"arn:aws:iam::{ACCOUNT_ID}:role/{self.name}"

    def policy_arn(self, kind: str) -> str:
        """Return one of the two finite independently owned policy ARNs."""
        if kind not in {"boundary", "guard"}:
            raise RegistryError("Unknown runtime fence kind")
        return (
            f"arn:aws:iam::{ACCOUNT_ID}:policy/issue219/test/{kind}/"
            f"{self.name}-{kind.title()}"
        )


def runtime_identities() -> tuple[RuntimeIdentity, ...]:
    """Preserve the proposed ECS role pair and separate application publisher."""
    return (
        RuntimeIdentity("execution", RUNTIME_ROLE_ARNS[0].rsplit("/", 1)[1]),
        RuntimeIdentity("task", RUNTIME_ROLE_ARNS[1].rsplit("/", 1)[1]),
        RuntimeIdentity("publisher", PUBLISHER_NAME),
    )


def _document(statements: list[dict], limit: int = 6144) -> str:
    """Enforce IAM document quotas before any resource registration."""
    document = canonical_json({"Version": "2012-10-17", "Statement": statements})
    if len(document) > limit:
        raise RegistryError("Runtime policy exceeds IAM document quota")
    return document


def disabled_trust() -> str:
    """Use a valid account principal with no Allow, avoiding wildcard principals."""
    return _document(
        [
            {
                "Effect": "Deny",
                "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT_ID}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
        2048,
    )


def publisher_trust(subject: str) -> str:
    """Validate an exact observed subject; this does not authenticate its source.

    The independent installer must observe GitHub configuration and real claims.
    Only aud/sub are IAM keys; immutable identity/workflow claims belong in sub.
    Preserve the observed key order and either documented repo spelling.
    """
    expected = {
        "repo": APPLICATION_REPOSITORY,
        "repository_id": "646535009",
        "repository_owner_id": "114362548",
        "environment": "poc-test-images",
        "ref": "refs/heads/main",
        "workflow_ref": (
            f"{APPLICATION_REPOSITORY}/.github/workflows/publish-poc-images.yml"
            "@refs/heads/main"
        ),
        "event_name": "workflow_dispatch",
    }
    if not isinstance(subject, str):
        raise RegistryError("Publisher requires an exact customized subject")
    segments = subject.split(":")
    if len(segments) != 2 * len(expected):
        raise RegistryError("Publisher subject lacks the closed claim set")
    actual = dict(zip(segments[::2], segments[1::2]))
    immutable = "VilnaCRM-Org@114362548/user-service@646535009"
    if actual.get("repo") == immutable:
        expected["repo"] = immutable
    if actual != expected:
        raise RegistryError("Publisher subject differs from the TEST contract")
    return _document(
        [
            {
                "Effect": "Allow",
                "Principal": {
                    "Federated": f"arn:aws:iam::{ACCOUNT_ID}:"
                    "oidc-provider/token.actions.githubusercontent.com"
                },
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringEquals": {
                        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
                        "token.actions.githubusercontent.com:sub": subject,
                    }
                },
            }
        ],
        2048,
    )


def publisher_policy() -> str:
    """Grant documented push APIs and the publisher's native digest readback."""
    return _ecr_policy(PUBLISH_ACTIONS)


def execution_policy() -> str:
    """Grant agent image pulls only; application and log/secret grants stay absent."""
    return _ecr_policy(PULL_ACTIONS)


def execution_trust() -> str:
    """Bind ECS assumption to TEST account/region, without unsupported cluster pins."""
    return _document(
        [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ecs-tasks.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": ACCOUNT_ID},
                    "ArnLike": {
                        "aws:SourceArn": f"arn:aws:ecs:{REGION}:{ACCOUNT_ID}:*"
                    },
                },
            }
        ],
        2048,
    )


def _ecr_policy(actions: tuple[str, ...]) -> str:
    """Render a closed regional ECR identity and matching capability boundary."""
    regional = {"StringEquals": {"aws:RequestedRegion": REGION}}
    return _document(
        [
            {"Effect": "Allow", "Action": ["sts:GetCallerIdentity"], "Resource": "*"},
            {
                "Effect": "Allow",
                "Action": ["ecr:GetAuthorizationToken"],
                "Resource": "*",
                "Condition": regional,
            },
            {
                "Effect": "Allow",
                "Action": list(actions),
                "Resource": list(REPOSITORY_ARNS),
                "Condition": regional,
            },
        ]
    )


def _ecr_guard(actions: tuple[str, ...]) -> str:
    """Deny escape through broad identity or role-session repository grants."""
    ecr_actions = [*actions, "ecr:GetAuthorizationToken"]
    return _document(
        [
            {
                "Effect": "Deny",
                "NotAction": [*ecr_actions, "sts:GetCallerIdentity"],
                "Resource": "*",
            },
            {
                "Effect": "Deny",
                "Action": list(actions),
                "NotResource": list(REPOSITORY_ARNS),
            },
            {
                "Effect": "Deny",
                "Action": ecr_actions,
                "Resource": "*",
                "Condition": {"StringNotEquals": {"aws:RequestedRegion": REGION}},
            },
        ]
    )


def _fence_document(role: RuntimeIdentity, kind: str, deny_all: str) -> str:
    """Keep task fences closed; image publication and agent pulls stay separate."""
    if role.purpose == "task":
        return deny_all
    actions = PUBLISH_ACTIONS if role.purpose == "publisher" else PULL_ACTIONS
    return _ecr_policy(actions) if kind == "boundary" else _ecr_guard(actions)


def enrollment_records() -> tuple[
    tuple[PolicyRecord, ...], tuple[PrincipalRecord, ...]
]:
    """Build six fences and three roles without altering the installed catalog.

    Check names against the complete source catalog. Native account-wide name and
    ownership collision checks remain the independent installer's responsibility.
    """
    catalog = load_catalog("test")
    policies, principals = [], []
    occupied = {
        arn.rsplit("/", 1)[1].lower()
        for arn in (
            *catalog["policies"],
            *(row["arn"] for row in catalog["principals"]),
        )
    }
    deny_all = _document([{"Effect": "Deny", "Action": "*", "Resource": "*"}])
    for role in runtime_identities():
        names = [
            role.name,
            *(role.policy_arn(k).rsplit("/", 1)[1] for k in ("boundary", "guard")),
        ]
        if any(name.lower() in occupied for name in names):
            raise RegistryError(
                "Runtime role or policy name collides with seed catalog"
            )
        occupied.update(name.lower() for name in names)
        for kind in ("boundary", "guard"):
            document = _fence_document(role, kind, deny_all)
            policies.append(
                PolicyRecord(
                    role.policy_arn(kind),
                    "purpose_capability_boundary"
                    if kind == "boundary"
                    else "immutable_managed_guard",
                    "independent-seed",
                    False,
                    document,
                    document_hash(json.loads(document)),
                )
            )
        principals.append(
            PrincipalRecord(
                role.arn,
                False,
                "governance",
                role.policy_arn("boundary"),
                (role.policy_arn("guard"),),
                (role.policy_arn("guard"),),
                None,
            )
        )
    return tuple(policies), tuple(principals)
