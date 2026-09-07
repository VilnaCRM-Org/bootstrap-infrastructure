"""Exact operator trust keeps every account, repository and workflow claim pinned."""

import json

import pytest
from seed.operator_trust import operator_trust_policy
from seed.policy_registry import ACCOUNTS


@pytest.mark.parametrize("environment", ["test", "prod"])
@pytest.mark.parametrize("purpose", ["preview", "apply", "drift"])
def test_exact_active_operator_trust_claims_and_subjects(environment, purpose):
    account = ACCOUNTS[environment]
    raw = operator_trust_policy(environment, purpose, account_id=account)
    assert raw == operator_trust_policy(environment, purpose, account_id=account)
    assert len(raw) <= 2048
    assert "*" not in raw
    policy = json.loads(raw)
    github_environment = {
        "preview": "operator-preview",
        "apply": "operator",
        "drift": "operator-drift",
    }[purpose]
    expected_claims = {
        "aud": "sts.amazonaws.com",
        "sub": [
            "repo:VilnaCRM-Org/bootstrap-infrastructure:environment:"
            + github_environment,
            "repo:VilnaCRM-Org@114362548/bootstrap-infrastructure@1098568429:environment:"
            + github_environment,
        ],
        "repository": "VilnaCRM-Org/bootstrap-infrastructure",
        "repository_id": "1098568429",
        "repository_owner_id": "114362548",
        "ref": "refs/heads/main",
        "job_workflow_ref": "VilnaCRM-Org/bootstrap-infrastructure/"
        ".github/workflows/pulumi-operator-account.yml@refs/heads/main",
        "environment": github_environment,
    }
    assert policy == {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Federated": f"arn:aws:iam::{account}:oidc-provider/"
                    "token.actions.githubusercontent.com"
                },
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringEquals": {
                        f"token.actions.githubusercontent.com:{key}": value
                        for key, value in expected_claims.items()
                    }
                },
            }
        ],
    }
    assert "token.actions.githubusercontent.com:workflow_ref" not in raw


@pytest.mark.parametrize(
    "environment,account",
    [
        ("test", ACCOUNTS["prod"]),
        ("prod", ACCOUNTS["test"]),
        ("other", ACCOUNTS["test"]),
        ("TEST", ACCOUNTS["test"]),
        ("test", "111122223333"),
        ("test", "891377212104\n"),
    ],
)
def test_trust_account_or_environment_substitution_fails(environment, account):
    with pytest.raises(ValueError, match="account/environment"):
        operator_trust_policy(environment, "apply", account_id=account)


@pytest.mark.parametrize("purpose", ["", "operator", "Apply", "preview*", "admin"])
def test_unknown_purpose_never_generates_trust(purpose):
    with pytest.raises(ValueError, match="executor purpose"):
        operator_trust_policy("test", purpose, account_id=ACCOUNTS["test"])


@pytest.mark.parametrize("environment", ["test", "prod"])
def test_executor_subjects_are_disjoint(environment):
    claims = {}
    for purpose in ("preview", "apply", "drift"):
        document = json.loads(
            operator_trust_policy(
                environment, purpose, account_id=ACCOUNTS[environment]
            )
        )
        claims[purpose] = document["Statement"][0]["Condition"]["StringEquals"]
    issuer = "token.actions.githubusercontent.com:"
    for source in claims:
        for target in claims:
            if source == target:
                continue
            assert (
                claims[source][issuer + "environment"]
                != claims[target][issuer + "environment"]
            )
            assert not set(claims[source][issuer + "sub"]) & set(
                claims[target][issuer + "sub"]
            )


@pytest.mark.parametrize("environment", ["test", "prod"])
def test_drift_token_cannot_match_apply_trust(environment):
    policy = json.loads(
        operator_trust_policy(environment, "apply", account_id=ACCOUNTS[environment])
    )
    conditions = policy["Statement"][0]["Condition"]["StringEquals"]
    assert conditions["token.actions.githubusercontent.com:environment"] == "operator"
    for repository in (
        "VilnaCRM-Org/bootstrap-infrastructure",
        "VilnaCRM-Org@114362548/bootstrap-infrastructure@1098568429",
    ):
        drift_subject = f"repo:{repository}:environment:operator-drift"
        assert (
            drift_subject not in conditions["token.actions.githubusercontent.com:sub"]
        )
