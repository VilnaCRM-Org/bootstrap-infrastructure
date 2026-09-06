"""Regression checks for the managed-service delegation boundary."""

from __future__ import annotations

import json
from fnmatch import fnmatchcase

import pytest
from iam_statement_matcher import iam_statement_matches
from infra import ci_bootstrap, governance
from infra.bootstrap_settings import BootstrapSettings


def _service_role_specs(environment: str):
    """Render test-account service roles without creating AWS resources."""
    settings = BootstrapSettings(
        org="VilnaCRM-Org",
        repo="user-service-infrastructure",
        environment=environment,
        github_branch="main",
        owner="platform",
        cost_center="core",
        data_classification="internal",
        criticality="high",
        retention_class="standard",
        logging_prefix="company",
        replication_region=None,
        github_token=None,
        github_oidc_provider_arn=None,
    )
    return governance._governance_role_specs(
        account_id="123456789012",
        partition="aws",
        settings=settings,
        region="us-east-1",
        repo="user-service-infrastructure",
        project="user-service-infrastructure",
    )


@pytest.mark.parametrize("environment", ["test", "prod"])
def test_service_apply_cannot_escalate_or_modify_other_repositories(environment):
    """Apply has no IAM escalation, shared-control, or foreign-state grants."""
    spec = next(
        spec for spec in _service_role_specs(environment) if spec.purpose == "apply"
    )
    statements = [
        statement
        for _, document in spec.policy_documents
        for statement in json.loads(document)["Statement"]
        if statement["Effect"] == "Allow"
    ]
    actions = [action for statement in statements for action in statement["Action"]]
    forbidden_actions = (
        "iam:CreateRole",
        "iam:PutRolePolicy",
        "iam:AttachRolePolicy",
        "iam:UpdateAssumeRolePolicy",
        "iam:CreatePolicyVersion",
        "iam:PassRole",
        "iam:CreateOpenIDConnectProvider",
        "sts:AssumeRole",
        "kms:PutKeyPolicy",
        "kms:CreateGrant",
        "kms:UpdateAlias",
        "s3:PutBucketPolicy",
        "s3:PutReplicationConfiguration",
        "secretsmanager:PutSecretValue",
        "cloudtrail:StopLogging",
        "guardduty:DeleteDetector",
    )
    for forbidden in forbidden_actions:
        assert not any(fnmatchcase(forbidden, action) for action in actions)

    state = next(
        statement
        for statement in statements
        if statement["Sid"] == "UsePulumiStateBucket"
    )
    own_bucket = f"arn:aws:s3:::pulumi-user-service-infrastructure-{environment}-state"
    foreign_bucket = (
        f"arn:aws:s3:::pulumi-other-service-infrastructure-{environment}-state"
    )
    assert own_bucket in state["Resource"]
    assert "s3:PutObject" in state["Action"]
    assert not any(
        fnmatchcase(foreign_bucket + "/.pulumi/state.json", resource)
        for resource in state["Resource"]
    )

    key = next(
        statement
        for statement in statements
        if statement["Sid"] == "UsePulumiSecretsProviderKey"
    )
    assert key["Resource"] == "arn:aws:kms:us-east-1:123456789012:key/*"
    assert key["Condition"]["ForAnyValue:StringLike"]["kms:ResourceAliases"] == [
        f"alias/pulumi-user-service-infrastructure-{environment}-secrets"
    ]


@pytest.mark.parametrize("environment", ["test", "prod"])
def test_service_roles_do_not_construct_platform_permission_specs(
    monkeypatch, environment
):
    """Future broadening of platform specs cannot silently affect services."""

    def reject_platform_specs(**_kwargs):
        raise AssertionError("managed services must not inherit platform role policies")

    monkeypatch.setattr(ci_bootstrap, "_role_specs", reject_platform_specs)
    monkeypatch.setattr(
        ci_bootstrap, "_automation_policy_documents", reject_platform_specs
    )
    specs = _service_role_specs(environment)
    apply = next(spec for spec in specs if spec.purpose == "apply")
    assert apply.subjects == [
        f"repo:VilnaCRM-Org/user-service-infrastructure:environment:{environment}"
    ]
    assert all(
        "-preview" not in subject and ":ref:" not in subject
        for subject in apply.subjects
    )


@pytest.mark.parametrize("environment", ["test", "prod"])
def test_service_preview_and_drift_cannot_mutate_platform(environment):
    """Read roles retain metadata access without any IAM management grants."""
    for spec in _service_role_specs(environment):
        if spec.purpose == "apply":
            continue
        statements = [
            statement
            for _, document in spec.policy_documents
            for statement in json.loads(document)["Statement"]
        ]
        actions = [
            action
            for statement in statements
            if statement["Effect"] == "Allow"
            for action in statement["Action"]
        ]
        assert "s3:GetBucketLocation" in actions
        assert "kms:DescribeKey" in actions
        assert not any(action.startswith("iam:") for action in actions)
        assert not any(fnmatchcase("iam:PutRolePolicy", action) for action in actions)
        assert any(
            statement["Effect"] == "Deny"
            and "secretsmanager:GetSecretValue" in statement["Action"]
            for statement in statements
        )


def _s3_decision(spec, action: str, resource: str) -> str:
    """Evaluate S3 action/resource grants and denies in these identity policies."""
    decision = "implicit-deny"
    for _, document in spec.policy_documents:
        for statement in json.loads(document)["Statement"]:
            if not iam_statement_matches(statement, action, resource):
                continue
            if statement["Effect"] == "Deny":
                return "explicit-deny"
            decision = "allow"
    return decision


@pytest.mark.parametrize("environment", ["test", "prod"])
@pytest.mark.parametrize("purpose", ["preview", "drift"])
def test_service_metadata_is_exact_repo_account_region_and_environment(
    environment, purpose
):
    """Read policies contain no global inventory or cross-repository grants."""
    spec = next(
        spec for spec in _service_role_specs(environment) if spec.purpose == purpose
    )
    document = json.loads(dict(spec.policy_documents)["read-only"])
    statements = {item["Sid"]: item for item in document["Statement"]}
    assert set(statements) == {
        "ReadOwnStateBucketMetadata",
        "ReadOwnPulumiKeyMetadata",
        "ReadOwnCiConfigurationMetadata",
        "DenySecretLeakingReads",
    }
    bucket = statements["ReadOwnStateBucketMetadata"]
    assert bucket["Action"] == ["s3:GetBucketLocation"]
    assert bucket["Resource"] == (
        f"arn:aws:s3:::pulumi-user-service-infrastructure-{environment}-state"
    )
    key = statements["ReadOwnPulumiKeyMetadata"]
    assert key["Action"] == ["kms:DescribeKey"]
    assert key["Resource"] == "arn:aws:kms:us-east-1:123456789012:key/*"
    assert key["Condition"] == {
        "ForAnyValue:StringEquals": {
            "kms:ResourceAliases": [
                f"alias/pulumi-user-service-infrastructure-{environment}-secrets"
            ]
        }
    }
    secret = statements["ReadOwnCiConfigurationMetadata"]
    assert secret["Action"] == [
        "secretsmanager:DescribeSecret",
        "secretsmanager:GetResourcePolicy",
        "secretsmanager:ListSecretVersionIds",
    ]
    suffixes = (
        ("test-pr", "test") if environment == "test" else ("prod-preview", "prod")
    )
    assert secret["Resource"] == [
        "arn:aws:secretsmanager:us-east-1:123456789012:"
        f"secret:/user-service-infrastructure/ci/{suffix}-??????"
        for suffix in suffixes
    ]
    deny = statements["DenySecretLeakingReads"]
    assert deny["Effect"] == "Deny"
    assert deny["Resource"] == "*"
    assert deny["Action"] == list(ci_bootstrap._READ_ONLY_SECRET_DENY_ACTIONS)
    for owner in ("bootstrap-infrastructure", "other-service-infrastructure"):
        foreign = f"arn:aws:s3:::pulumi-{owner}-{environment}-state"
        assert _s3_decision(spec, "s3:GetBucketLocation", foreign) == "implicit-deny"
        assert (
            _s3_decision(spec, "iam:GetRole", "arn:aws:iam::123456789012:role/any")
            == "implicit-deny"
        )


@pytest.mark.parametrize("environment", ["test", "prod"])
@pytest.mark.parametrize("purpose", ["preview", "drift"])
def test_read_roles_can_lock_but_cannot_mutate_checkpoints(environment, purpose):
    """Preview/drift preserve checkpoint integrity, including object versions."""
    spec = next(
        spec for spec in _service_role_specs(environment) if spec.purpose == purpose
    )
    bucket = f"arn:aws:s3:::pulumi-user-service-infrastructure-{environment}-state"
    lock = (
        f"{bucket}/.pulumi/locks/organization/"
        f"user-service-infrastructure/{environment}/run.json"
    )
    assert _s3_decision(spec, "s3:PutObject", lock) == "allow"
    assert _s3_decision(spec, "s3:DeleteObject", lock) == "allow"
    assert _s3_decision(spec, "s3:DeleteObjectVersion", lock) == "explicit-deny"
    for key in (
        ".pulumi/meta.yaml",
        ".pulumi/stacks/user-service-infrastructure/test.json",
        ".pulumi/history/user-service-infrastructure/test/update.json",
        "state/test.json",
        ".pulumi/locks-other/checkpoint.json",
    ):
        resource = f"{bucket}/{key}"
        assert _s3_decision(spec, "s3:GetObject", resource) == "allow"
        assert _s3_decision(spec, "s3:GetObjectVersion", resource) == "allow"
        for action in ("s3:PutObject", "s3:DeleteObject", "s3:DeleteObjectVersion"):
            assert _s3_decision(spec, action, resource) == "explicit-deny"
    foreign_lock = (
        f"arn:aws:s3:::pulumi-other-service-{environment}-state/.pulumi/locks/run.json"
    )
    assert _s3_decision(spec, "s3:PutObject", foreign_lock) == "explicit-deny"
    assert _s3_decision(spec, "s3:GetObject", foreign_lock) == "implicit-deny"


@pytest.mark.parametrize("environment", ["test", "prod"])
def test_apply_retains_checkpoint_write_access(environment):
    """Only the protected apply role may persist actual Pulumi updates."""
    spec = next(
        spec for spec in _service_role_specs(environment) if spec.purpose == "apply"
    )
    checkpoint = (
        f"arn:aws:s3:::pulumi-user-service-infrastructure-{environment}-state/"
        f".pulumi/stacks/user-service-infrastructure/{environment}.json"
    )
    for action in ("s3:PutObject", "s3:DeleteObject", "s3:DeleteObjectVersion"):
        assert _s3_decision(spec, action, checkpoint) == "allow"
