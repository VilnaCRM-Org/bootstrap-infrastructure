"""Unattended service drift is a distinct, bounded OIDC trust path."""

import json
from dataclasses import replace

import pytest
from infra import ci_bootstrap, ci_config, github_identity, governance
from test_secret_read_deny import _settings

PREFIX = "token.actions.githubusercontent.com:"
REPO = "VilnaCRM-Org/user-service-infrastructure"


def settings(environment):
    return replace(
        _settings(environment),
        repo="user-service-infrastructure",
        github_branch="main",
        github_repository_id="911736693",
        github_repository_owner_id="114362548",
    )


def documents(environment):
    configured = settings(environment)
    account = "891377212104" if environment == "test" else "933245420672"
    provider = (
        f"arn:aws:iam::{account}:oidc-provider/token.actions.githubusercontent.com"
    )
    suffix = "test" if environment == "test" else "prod-preview"
    config = ci_config._ci_config_read_assume_role_policy(
        provider, configured, suffix, governed_service_workflows=True
    )
    drift = ci_bootstrap._deployment_assume_role_policy(
        provider,
        REPO,
        ci_bootstrap._deployment_role_subjects(configured, "drift"),
        repository_id=configured.github_repository_id,
        owner_id=configured.github_repository_owner_id,
        branch_ref="refs/heads/main",
        scheduled_drift_environment=environment,
    )
    return config, drift


def permits(document, claims):
    return any(
        all(
            claims.get(key) in (value if isinstance(value, list) else [value])
            for key, value in row["Condition"]["StringEquals"].items()
        )
        for row in json.loads(document)["Statement"]
    )


@pytest.mark.parametrize(
    "environment,sizes", [("test", (2017, 1919)), ("prod", (1840, 1769))]
)
def test_current_exact_policies_fit_default_quota_and_both_subject_formats(
    environment, sizes
):
    for document, size in zip(documents(environment), sizes, strict=True):
        assert len(json.dumps(json.loads(document), separators=(",", ":"))) == size
        rows = json.loads(document)["Statement"]
        assert len(rows) == 2
        conditions = rows[1]["Condition"]["StringEquals"]
        assert conditions[PREFIX + "ref"] == "refs/heads/main"
        assert conditions[PREFIX + "workflow"] == "Service Scheduled Drift"
        assert len(conditions[PREFIX + "sub"]) == 2
        for subject in conditions[PREFIX + "sub"]:
            assert permits(document, {**conditions, PREFIX + "sub": subject})


@pytest.mark.parametrize("environment", ["test", "prod"])
@pytest.mark.parametrize(
    "field,value",
    [
        ("aud", "other"),
        ("ref", "refs/heads/feature"),
        ("ref", "refs/tags/main"),
        ("workflow", "Service Self Deploy"),
        ("repository", "foreign/service"),
        ("repository_id", "1"),
        ("repository_owner_id", "1"),
        ("sub", "repo:foreign/service:environment:test-drift"),
        ("sub", f"repo:{REPO}:environment:wrong-drift"),
    ],
)
def test_scheduled_credentials_reject_wrong_identity_or_context(
    environment, field, value
):
    for document in documents(environment):
        condition = json.loads(document)["Statement"][1]["Condition"]["StringEquals"]
        claims = {**condition, PREFIX + "sub": condition[PREFIX + "sub"][0]}
        assert not permits(document, {**claims, PREFIX + field: value})
        missing = dict(claims)
        missing.pop(PREFIX + field)
        assert not permits(document, missing)


@pytest.mark.parametrize("environment", ["test", "prod"])
def test_governance_opts_in_only_drift_and_preserves_config_apply_subjects(environment):
    configured = settings(environment)
    specs = governance._governance_role_specs(
        account_id="123456789012",
        partition="aws",
        settings=configured,
        region="eu-central-1",
        repo=configured.repo,
        project=configured.repo,
    )
    assert {s.purpose: s.scheduled_drift_environment for s in specs} == {
        "preview": None,
        "apply": None,
        "drift": environment,
    }
    for suffix in ci_config.CI_CONFIG_SECRET_SUFFIXES_BY_STACK[environment]:
        document = ci_config._ci_config_read_assume_role_policy(
            "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com",
            configured,
            suffix,
            governed_service_workflows=True,
        )
        expected = (
            2 if suffix == {"test": "test", "prod": "prod-preview"}[environment] else 1
        )
        assert len(json.loads(document)["Statement"]) == expected
    assert next(s for s in specs if s.purpose == "apply").subjects == [
        f"repo:{REPO}:environment:{environment}"
    ]


def test_long_future_identity_fails_quota_without_dropping_claims():
    configured = replace(settings("test"), repo="long-service-infrastructure-name")
    with pytest.raises(ValueError, match="supported default IAM quota is 2048"):
        ci_config._ci_config_read_assume_role_policy(
            "arn:aws:iam::891377212104:oidc-provider/token.actions.githubusercontent.com",
            configured,
            "test",
            governed_service_workflows=True,
        )


def test_invalid_scheduled_environment_is_rejected():
    with pytest.raises(ValueError, match="only test and prod"):
        github_identity.scheduled_drift_trust_statement(
            "provider", REPO, "stage", None, None
        )


def test_non_drift_role_cannot_receive_scheduled_trust():
    spec = ci_bootstrap._CiRoleSpec(
        "apply", "example", [], [], scheduled_drift_environment="test"
    )
    with pytest.raises(ValueError, match="restricted to drift roles"):
        ci_bootstrap._create_role(None, spec)
