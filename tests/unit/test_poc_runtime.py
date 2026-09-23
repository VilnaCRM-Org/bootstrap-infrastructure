"""Finite runtime enrollment and publisher trust/capability regressions."""

from __future__ import annotations

import copy
import json
from fnmatch import fnmatchcase

import pytest
from seed import poc_runtime as runtime
from seed.policy_registry import RegistryError


def subject(**overrides):
    """Synthetic exact claims; never authenticated token evidence."""
    claims = {
        "repo": runtime.APPLICATION_REPOSITORY,
        "repository_id": "646535009",
        "repository_owner_id": "114362548",
        "environment": "poc-test-images",
        "ref": "refs/heads/main",
        "workflow_ref": f"{runtime.APPLICATION_REPOSITORY}/.github/workflows/"
        "publish-poc-images.yml@refs/heads/main",
        "event_name": "workflow_dispatch",
    } | overrides
    return ":".join(f"{key}:{value}" for key, value in claims.items())


def _action_matches(row, action):
    selector = "NotAction" if "NotAction" in row else "Action"
    values = row[selector]
    values = [values] if isinstance(values, str) else values
    matches = any(fnmatchcase(action.lower(), item.lower()) for item in values)
    return matches != (selector == "NotAction")


def _resource_matches(row, resource):
    selector = "NotResource" if "NotResource" in row else "Resource"
    values = row[selector]
    values = [values] if isinstance(values, str) else values
    matches = any(fnmatchcase(resource, item) for item in values)
    return matches != (selector == "NotResource")


def _conditions_match(row, region):
    condition = row.get("Condition", {})
    assert set(condition) <= {"StringEquals", "StringNotEquals"}
    return not any(
        (region == entries["aws:RequestedRegion"]) != (operator == "StringEquals")
        for operator, entries in condition.items()
    )


def decision(document, action, resource, region=runtime.REGION):
    """Evaluate this finite policy dialect, including its explicit guard denials."""
    result = "implicit-deny"
    for row in json.loads(document)["Statement"]:
        if not _action_matches(row, action):
            continue
        if not _resource_matches(row, resource):
            continue
        if not _conditions_match(row, region):
            continue
        if row["Effect"] == "Deny":
            return "explicit-deny"
        result = "allow"
    return result


def test_enrollment_has_closed_owner_and_attachment_inventory():
    policies, principals = runtime.enrollment_records()
    assert len(policies) == 6
    assert len(principals) == 3
    assert len({row.arn for row in policies}) == 6
    assert {row.owner_project for row in principals} == {"governance"}
    assert {row.ownership for row in policies} == {"independent-seed"}
    for row in principals:
        assert row.existing is False
        assert row.attachment_arns == row.guard_arns
        assert len(row.attachment_arns) == 1
        assert row.boundary_arn in {policy.arn for policy in policies}
    for row in policies:
        assert len(row.document_json) < 6144
        assert row.sha256 == runtime.document_hash(json.loads(row.document_json))
        if "EcsTask" in row.arn:
            assert json.loads(row.document_json)["Statement"] == [
                {"Effect": "Deny", "Action": "*", "Resource": "*"}
            ]
    assert len(runtime.publisher_policy()) < 10240
    assert all(
        row["Effect"] == "Deny"
        for row in json.loads(runtime.disabled_trust())["Statement"]
    )


@pytest.mark.parametrize(
    "spelling",
    [
        runtime.APPLICATION_REPOSITORY,
        "VilnaCRM-Org@114362548/user-service@646535009",
    ],
)
def test_publisher_trust_uses_only_supported_iam_keys_and_exact_subject(spelling):
    supplied = subject(repo=spelling)
    document = runtime.publisher_trust(supplied)
    assert len(document) < 2048
    statement = json.loads(document)["Statement"][0]
    assert statement["Condition"] == {
        "StringEquals": {
            "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
            "token.actions.githubusercontent.com:sub": supplied,
        }
    }
    segments = supplied.split(":")
    reordered = ":".join(
        sum(
            [
                segments[index : index + 2]
                for index in reversed(range(0, len(segments), 2))
            ],
            [],
        )
    )
    assert reordered in runtime.publisher_trust(reordered)


@pytest.mark.parametrize(
    "bad",
    [
        None,
        "",
        "repo:VilnaCRM-Org/user-service:environment:poc-test-images",
        subject(repo="VilnaCRM-Org/other-service"),
        subject(repository_id="1"),
        subject(repository_owner_id="1"),
        subject(environment="prod"),
        subject(ref="refs/heads/feature"),
        subject(
            workflow_ref="VilnaCRM-Org/user-service/.github/workflows/other.yml@refs/heads/main"
        ),
        subject(event_name="pull_request"),
        subject().replace("workflow_ref:", "job_workflow_ref:"),
        subject().replace("repository_id:646535009", "repo:VilnaCRM-Org/user-service"),
        subject() + ":actor:someone",
    ],
)
def test_publisher_trust_rejects_default_foreign_incomplete_or_duplicate_claims(bad):
    with pytest.raises(RegistryError, match="Publisher"):
        runtime.publisher_trust(bad)


@pytest.mark.parametrize("action", runtime.PUBLISH_ACTIONS)
@pytest.mark.parametrize("resource", runtime.REPOSITORY_ARNS)
def test_publisher_identity_and_boundary_intersection(action, resource):
    policies, _ = runtime.enrollment_records()
    boundary, guard = [
        row.document_json for row in policies if runtime.PUBLISHER_NAME in row.arn
    ]
    assert decision(runtime.publisher_policy(), action, resource) == "allow"
    assert decision(boundary, action, resource) == "allow"
    assert decision(guard, action, resource) == "implicit-deny"
    assert decision('{"Statement":[]}', action, resource) == "implicit-deny"
    assert decision(guard, action, resource, None) == "explicit-deny"
    assert decision(guard, action, resource, "us-east-1") == "explicit-deny"
    # Explicit denial also defeats a repository-policy grant to the role session.
    foreign = resource.replace("user-service-test-", "other-service-test-")
    assert decision(guard, action, foreign) == "explicit-deny"


@pytest.mark.parametrize(
    "action,resource",
    [
        ("iam:PassRole", "arn:aws:iam::891377212104:role/anything"),
        (
            "iam:PutRolePolicy",
            "arn:aws:iam::891377212104:role/user-service-test-ImagePublisher",
        ),
        ("sts:AssumeRole", "arn:aws:iam::891377212104:role/administrator"),
        ("ecr:DeleteRepository", runtime.REPOSITORY_ARNS[0]),
        ("ecr:BatchDeleteImage", runtime.REPOSITORY_ARNS[0]),
        ("ecr:SetRepositoryPolicy", runtime.REPOSITORY_ARNS[0]),
        (
            "s3:GetObject",
            "arn:aws:s3:::pulumi-user-service-infrastructure-test-state/state",
        ),
        ("secretsmanager:GetSecretValue", "*"),
        ("kms:Decrypt", "*"),
    ],
)
def test_publisher_guard_denies_unreviewed_apis_even_with_broad_grants(
    action, resource
):
    policies, _ = runtime.enrollment_records()
    guard = next(
        row.document_json
        for row in policies
        if row.arn.endswith(f"{runtime.PUBLISHER_NAME}-Guard")
    )
    assert decision(guard, action, resource) == "explicit-deny"


def test_only_authorization_token_and_caller_identity_have_global_allow():
    document = json.loads(runtime.publisher_policy())
    assert [
        row["Action"] for row in document["Statement"] if row["Resource"] == "*"
    ] == [["sts:GetCallerIdentity"], ["ecr:GetAuthorizationToken"]]
    assert (
        decision(runtime.publisher_policy(), "ecr:GetAuthorizationToken", "*")
        == "allow"
    )
    assert (
        decision(runtime.publisher_policy(), "ecr:GetAuthorizationToken", "*", None)
        == "implicit-deny"
    )


@pytest.mark.parametrize("kind", ["role", "policy"])
def test_case_insensitive_catalog_collision_rejected(monkeypatch, kind):
    catalog = copy.deepcopy(runtime.load_catalog("test"))
    identity = runtime.runtime_identities()[0]
    if kind == "role":
        catalog["principals"].append({"arn": identity.arn.upper()})
    else:
        catalog["policies"][identity.policy_arn("boundary").upper()] = {}
    monkeypatch.setattr(runtime, "load_catalog", lambda _: catalog)
    with pytest.raises(RegistryError, match="collides"):
        runtime.enrollment_records()


def test_policy_size_and_unknown_fence_rejected():
    with pytest.raises(RegistryError, match="quota"):
        runtime._document([{"oversized": "a" * 6144}])
    with pytest.raises(RegistryError, match="kind"):
        runtime.runtime_identities()[0].policy_arn("identity")


@pytest.mark.parametrize("action", (*runtime.PULL_ACTIONS, "ecr:GetAuthorizationToken"))
@pytest.mark.parametrize("resource", runtime.REPOSITORY_ARNS)
def test_execution_pull_intersection_and_regional_denials(action, resource):
    policies, _ = runtime.enrollment_records()
    boundary, guard = [
        row.document_json for row in policies if "EcsExecution" in row.arn
    ]
    assert decision(runtime.execution_policy(), action, resource) == "allow"
    assert decision(boundary, action, resource) == "allow"
    assert decision(guard, action, resource) == "implicit-deny"
    for region in (None, "us-east-1"):
        assert decision(guard, action, resource, region) == "explicit-deny"
    if action != "ecr:GetAuthorizationToken":
        for foreign in (
            resource.replace("user-service-test-", "foreign-"),
            resource.replace(runtime.ACCOUNT_ID, "933245420672"),
        ):
            assert decision(guard, action, foreign) == "explicit-deny"


@pytest.mark.parametrize(
    "action",
    [
        "ecr:PutImage",
        "ecr:DeleteRepository",
        "ecr:SetRepositoryPolicy",
        "ecr:DescribeImages",
        "iam:PassRole",
        "iam:PutRolePolicy",
        "sts:AssumeRole",
        "logs:PutLogEvents",
        "secretsmanager:GetSecretValue",
        "kms:Decrypt",
        "sqs:ReceiveMessage",
        "ses:SendEmail",
    ],
)
def test_execution_guard_denies_every_non_pull_capability(action):
    guard = next(
        row.document_json
        for row in runtime.enrollment_records()[0]
        if row.arn.endswith("EcsExecution-Guard")
    )
    assert decision(guard, action, runtime.REPOSITORY_ARNS[0]) == "explicit-deny"
    assert decision(runtime.execution_policy(), action, "*") == "implicit-deny"


def test_execution_trust_only_admits_test_ecs_service():
    assert json.loads(runtime.execution_trust())["Statement"] == [
        {
            "Effect": "Allow",
            "Principal": {"Service": "ecs-tasks.amazonaws.com"},
            "Action": "sts:AssumeRole",
            "Condition": {
                "StringEquals": {"aws:SourceAccount": "891377212104"},
                "ArnLike": {"aws:SourceArn": "arn:aws:ecs:eu-central-1:891377212104:*"},
            },
        }
    ]
