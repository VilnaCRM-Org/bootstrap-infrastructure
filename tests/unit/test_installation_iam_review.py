"""Concrete IAM regressions from the installation security review."""

import json
from dataclasses import replace

import pytest
from infra import automation, ci_bootstrap, ci_config, operations_monitoring
from infra.github_identity import validate_trust_policy_size
from pulumi.runtime.stack import wait_for_rpcs
from pulumi.runtime.sync_await import _sync_await
from test_platform_iam import ACCOUNT, REPO, settings


def sized_document(size):
    document = json.dumps({"Statement": [], "Sid": ""}, separators=(",", ":"))
    return document.replace('"Sid":""', '"Sid":"' + "x" * (size - len(document)) + '"')


@pytest.mark.parametrize("size", [6144, 6145, 10239, 10240])
def test_inline_policy_uses_its_own_limit(size):
    automation._validate_automation_policy_documents(
        [("policy", sized_document(size)), ("managed", sized_document(6144))]
    )


def test_inline_and_managed_overflow_remain_closed():
    with pytest.raises(ValueError, match="inline policy document exceeds"):
        automation._validate_automation_policy_documents(
            [("policy", sized_document(10241))]
        )
    with pytest.raises(ValueError, match="managed policy document exceeds"):
        automation._validate_automation_policy_documents(
            [("policy", sized_document(100)), ("managed", sized_document(6145))]
        )


def test_operator_guard_counts_towards_inline_aggregate():
    docs = [("policy", sized_document(6000))]
    automation._validate_automation_policy_documents(
        docs, additional_inline_documents=(sized_document(4240),)
    )
    with pytest.raises(ValueError, match="aggregate inline policies exceed"):
        automation._validate_automation_policy_documents(
            docs, additional_inline_documents=(sized_document(4241),)
        )


@pytest.mark.parametrize("environment", ["test", "prod"])
@pytest.mark.parametrize("repo", [None, REPO.name, "foreign-infrastructure"])
def test_generic_backend_alias_is_owned_by_the_primary_repository(environment, repo):
    configured = settings(environment)
    document = json.loads(
        ci_bootstrap._pulumi_backend_policy_document(
            ACCOUNT, "aws", configured, repo, read_only=True
        )
    )
    statement = next(
        item
        for item in document["Statement"]
        if item["Sid"] == "UsePulumiSecretsProviderKey"
    )
    aliases = statement["Condition"]["ForAnyValue:StringLike"]["kms:ResourceAliases"]
    expected = [f"alias/pulumi-{repo or REPO.name}-{environment}-secrets"]
    if repo in (None, REPO.name):
        expected.append(f"alias/pulumi-platform-bootstrap-{environment}")
    assert aliases == expected


@pytest.mark.parametrize("environment", ["test", "prod"])
def test_key_creation_requires_exact_repository_environment_and_purpose(environment):
    policy = json.loads(
        automation._automation_policy(ACCOUNT, settings(environment), REPO.name)
    )
    create = next(
        item for item in policy["Statement"] if item["Sid"] == "CreateBootstrapKmsKeys"
    )
    condition = create["Condition"]["StringEquals"]
    assert condition == {
        "aws:RequestTag/Environment": environment,
        "aws:RequestTag/Purpose": [
            "pulumi-secrets",
            "operations-alerting",
            "operations-cloudtrail",
        ],
        "aws:RequestTag/Repository": REPO.name,
    }
    for missing in condition:
        request = {
            key: (value[0] if isinstance(value, list) else value)
            for key, value in condition.items()
        }
        del request[missing]
        assert not all(
            request.get(key) in (value if isinstance(value, list) else [value])
            for key, value in condition.items()
        )
    for wrong in condition:
        request = {
            key: (value[0] if isinstance(value, list) else value)
            for key, value in condition.items()
        }
        request[wrong] = "foreign"
        assert not all(
            request.get(key) in (value if isinstance(value, list) else [value])
            for key, value in condition.items()
        )


@pytest.mark.parametrize("environment", ["test", "prod"])
@pytest.mark.parametrize("repo", [REPO.name, None])
def test_monitoring_keys_send_the_required_repository_tag(
    pulumi_mocks, environment, repo
):
    configured = replace(
        settings(environment), repo=repo, operations_cloudtrail_name=None
    )
    monitoring = operations_monitoring.OperationsMonitoring(
        "review-tagging", settings=configured
    )
    _sync_await(wait_for_rpcs())
    keys = [
        state
        for kind, name, state in pulumi_mocks.resources
        if kind == "aws:kms/key:Key"
    ]
    assert len(keys) == 2
    assert {key["tags"]["Purpose"] for key in keys} == {
        "operations-alerting",
        "operations-cloudtrail",
    }
    assert all(key["tags"]["Repository"] == (repo or "bootstrap") for key in keys)
    assert all(key["tags"]["Environment"] == environment for key in keys)
    assert monitoring.cloudtrail_key is not None


@pytest.mark.parametrize("size", [2047, 2048])
def test_trust_size_excludes_serialization_whitespace_without_changing_bytes(size):
    document = json.dumps(json.loads(sized_document(size)), indent=4)
    assert len(document) > 2048
    assert validate_trust_policy_size(document) == document


def test_oversized_trust_fails_with_an_explicit_supported_quota():
    with pytest.raises(ValueError, match="supported default IAM quota is 2048"):
        validate_trust_policy_size(sized_document(2049))


@pytest.mark.parametrize("environment", ["test", "prod"])
def test_actual_identity_trust_fits_and_preserves_both_subject_formats(environment):
    configured = replace(
        settings(environment),
        org="VilnaCRM-Org",
        github_branch="main",
        github_repository_id="1098568429",
        github_repository_owner_id="114362548",
    )
    provider = (
        f"arn:aws:iam::{ACCOUNT}:oidc-provider/token.actions.githubusercontent.com"
    )
    for purpose in ("preview", "drift", "apply"):
        subjects = ci_bootstrap._deployment_role_subjects(configured, purpose)
        document = ci_bootstrap._deployment_assume_role_policy(
            provider,
            f"{configured.org}/{REPO.name}",
            subjects,
            repository_id=configured.github_repository_id,
            owner_id=configured.github_repository_owner_id,
            branch_ref=None if purpose == "preview" else "refs/heads/main",
        )
        assert len(json.dumps(json.loads(document), separators=(",", ":"))) <= 2048
        assert len(
            json.loads(document)["Statement"][0]["Condition"]["StringEquals"][
                "token.actions.githubusercontent.com:sub"
            ]
        ) == 2 * len(subjects)


def test_long_valid_identity_does_not_silently_drop_subjects_to_fit():
    configured = replace(
        settings(),
        org="o" * 39,
        repo="r" * 100,
        github_branch="main",
        github_repository_id="1098568429",
        github_repository_owner_id="114362548",
    )
    provider = (
        f"arn:aws:iam::{ACCOUNT}:oidc-provider/token.actions.githubusercontent.com"
    )
    with pytest.raises(ValueError, match="2084 characters"):
        ci_bootstrap._deployment_assume_role_policy(
            provider,
            f"{configured.org}/{configured.repo}",
            ci_bootstrap._deployment_role_subjects(configured, "preview"),
            repository_id=configured.github_repository_id,
            owner_id=configured.github_repository_owner_id,
        )
    with pytest.raises(ValueError, match="supported default IAM quota"):
        ci_config._ci_config_read_assume_role_policy(
            provider, replace(configured, github_branch="b" * 1000), "test"
        )


def test_ci_apply_rejects_oversized_managed_first_document_before_registration(
    monkeypatch,
):
    spec = ci_bootstrap._CiRoleSpec(
        purpose="apply",
        role_name="ReviewApply",
        subjects=[],
        policy_documents=[("policy", sized_document(6145))],
    )

    def forbidden(*args, **kwargs):
        raise AssertionError("oversized policy reached role registration")

    monkeypatch.setattr(ci_bootstrap.aws.iam, "Role", forbidden)
    with pytest.raises(ValueError, match="managed policy document exceeds"):
        ci_bootstrap._create_role(None, spec)
