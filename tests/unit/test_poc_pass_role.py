"""Finite offline intersection checks; these do not simulate AWS authorization."""

from __future__ import annotations

import json

import pytest
from iam_statement_matcher import iam_statement_matches
from seed.poc_pass_role import (
    ACCOUNT_ID,
    ECS_SERVICE,
    REGION,
    REPOSITORY,
    RUNTIME_ROLE_ARNS,
    propose_pass_role,
)


def _proposal(purpose="apply", **overrides):
    target = dict(
        account_id=ACCOUNT_ID,
        region=REGION,
        repository=REPOSITORY,
        environment="test",
        purpose=purpose,
    )
    return propose_pass_role(**(target | overrides))


def _decision(document, resource, service, action="iam:PassRole"):
    """Evaluate only this proposal's exact equality/negated equality conditions."""
    allowed = False
    for row in json.loads(document)["Statement"]:
        if not iam_statement_matches(row, action, resource):
            continue
        conditions = row.get("Condition", {})
        assert set(conditions) <= {"StringEquals", "StringNotEquals"}
        matches = True
        for operator, entries in conditions.items():
            assert set(entries) == {"iam:PassedToService"}
            equal = service == entries["iam:PassedToService"]
            matches &= equal if operator == "StringEquals" else not equal
        if matches:
            if row["Effect"] == "Deny":
                return "explicit-deny"
            allowed = True
    return "allow" if allowed else "implicit-deny"


def _effective(proposal, resource, service, identity=None, boundary=None):
    decisions = [
        _decision(identity or proposal.identity_json, resource, service),
        _decision(boundary or proposal.boundary_json, resource, service),
        _decision(proposal.guard_json, resource, service),
    ]
    if "explicit-deny" in decisions:
        return "explicit-deny"
    return "allow" if decisions[:2] == ["allow", "allow"] else "implicit-deny"


@pytest.mark.parametrize("role", RUNTIME_ROLE_ARNS)
def test_apply_requires_matching_identity_and_boundary(role):
    proposal = _proposal()
    empty = '{"Statement":[]}'
    assert _effective(proposal, role, ECS_SERVICE) == "allow"
    assert _effective(proposal, role, ECS_SERVICE, identity=empty) == "implicit-deny"
    assert _effective(proposal, role, ECS_SERVICE, boundary=empty) == "implicit-deny"
    assert proposal.state == "proposed-uninstalled-pass-role-fragments"
    for document in (
        proposal.identity_json,
        proposal.boundary_json,
        proposal.guard_json,
    ):
        assert len(document) < 6144
        assert all(
            row["Action"] == ["iam:PassRole"]
            for row in json.loads(document)["Statement"]
        )


@pytest.mark.parametrize("purpose", ["apply", "preview", "drift"])
@pytest.mark.parametrize("service", [None, "lambda.amazonaws.com", "ecs.amazonaws.com"])
@pytest.mark.parametrize("role", RUNTIME_ROLE_ARNS)
def test_wrong_or_missing_service_is_explicitly_denied(purpose, service, role):
    assert _effective(_proposal(purpose), role, service) == "explicit-deny"


@pytest.mark.parametrize("purpose", ["preview", "drift"])
@pytest.mark.parametrize("role", RUNTIME_ROLE_ARNS)
def test_read_roles_cannot_use_shared_boundary_allow(purpose, role):
    proposal = _proposal(purpose)
    assert _decision(proposal.boundary_json, role, ECS_SERVICE) == "allow"
    assert _effective(proposal, role, ECS_SERVICE) == "explicit-deny"


@pytest.mark.parametrize(
    "role",
    [
        f"arn:aws:iam::{ACCOUNT_ID}:role/user-service-test-ImagePublisher",
        f"arn:aws:iam::{ACCOUNT_ID}:role/GitHubCiApply-user-service-infrastructure-test",
        f"arn:aws:iam::{ACCOUNT_ID}:role/user-service-infrastructure-prod-EcsTask",
        f"arn:aws:iam::{ACCOUNT_ID}:role/other-service-test-EcsTask",
        "arn:aws:iam::123456789012:role/user-service-infrastructure-test-EcsTask",
        f"arn:aws:iam::{ACCOUNT_ID}:role/user-service-infrastructure-test-EcsTask-extra",
        f"arn:aws:iam::{ACCOUNT_ID}:role/aws-service-role/ecs.amazonaws.com/"
        "AWSServiceRoleForECS",
    ],
)
def test_broad_identity_cannot_pass_other_roles(role):
    broad = '{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
    assert _effective(_proposal(), role, ECS_SERVICE, identity=broad) == "explicit-deny"


@pytest.mark.parametrize(
    "override",
    [
        {"account_id": "123456789012"},
        {"region": "us-east-1"},
        {"repository": "VilnaCRM-Org/other-service-infrastructure"},
        {"environment": "prod"},
        {"purpose": "config"},
    ],
)
def test_foreign_target_or_unknown_purpose_is_rejected(override):
    with pytest.raises(ValueError, match="PassRole proposal"):
        _proposal(**override)


def test_generation_is_deterministic_and_does_not_grant_iam_management():
    first = _proposal()
    assert first == _proposal()
    assert (
        _decision(
            first.identity_json, RUNTIME_ROLE_ARNS[0], ECS_SERVICE, "iam:PutRolePolicy"
        )
        == "implicit-deny"
    )
