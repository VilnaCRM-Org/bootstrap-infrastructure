"""The shared CE/GD ceiling preserves exact identity-purpose restrictions."""

import json
from copy import deepcopy
from fnmatch import fnmatchcase

import pytest
from infra import automation, ci_bootstrap, platform_iam
from infra.iam import github_oidc
from test_platform_iam import ACCOUNT, REPO, settings, values

TARGETS = [
    ("ce", "anomalymonitor", "cost-anomaly-monitor", "DeleteAnomalyMonitor"),
    (
        "ce",
        "anomalysubscription",
        "cost-anomaly-subscription",
        "DeleteAnomalySubscription",
    ),
    ("guardduty", "detector", "security-detection", "DeleteDetector"),
]


def documents(environment, role, account_id=ACCOUNT):
    configured = settings(environment)
    if role == "ci":
        return [
            json.loads(doc)
            for _, doc in ci_bootstrap._role_policy_documents(
                account_id, "aws", configured, "apply", REPO.name
            )
        ]
    if role == "automation":
        return [
            json.loads(automation._automation_policy(account_id, configured, REPO.name))
        ]
    return [
        json.loads(
            github_oidc._deploy_policy_from_values(
                ["arn:aws:s3:::state", "arn:aws:s3:::state/state/*", None]
            )
        )
    ]


def allows(documents, action, resource, context):
    for document in documents:
        for statement in document["Statement"]:
            assert "NotAction" not in statement
            if statement["Effect"] != "Allow" or not any(
                fnmatchcase(action.lower(), pattern.lower())
                for pattern in values(statement["Action"])
            ):
                continue
            if not any(
                fnmatchcase(resource, arn) for arn in values(statement["Resource"])
            ):
                continue
            condition = statement.get("Condition", {})
            assert set(condition) <= {"StringEquals"}
            if all(
                context.get(key) in values(expected)
                for key, expected in condition.get("StringEquals", {}).items()
            ):
                return True
    return False


@pytest.mark.parametrize("environment", ["test", "prod"])
@pytest.mark.parametrize("role", ["ci", "automation", "deploy"])
@pytest.mark.parametrize("service,kind,purpose,verb", TARGETS)
@pytest.mark.parametrize(
    "wrong", [None, "Project", "Environment", "Purpose", "account"]
)
def test_effective_management_union_rejects_every_scope_escape(
    environment, role, service, kind, purpose, verb, wrong
):
    context = {
        "aws:ResourceTag/Project": REPO.name,
        "aws:ResourceTag/Environment": environment,
        "aws:ResourceTag/Purpose": purpose,
    }
    if wrong in {"Project", "Environment", "Purpose"}:
        context[f"aws:ResourceTag/{wrong}"] = "foreign"
    account = "999999999999" if wrong == "account" else ACCOUNT
    region = "eu-central-1" if service == "guardduty" else ""
    arn = f"arn:aws:{service}:{region}:{account}:{kind}/sample"
    boundary = json.loads(
        platform_iam.platform_control_boundary(
            ACCOUNT, settings(environment), REPO.name
        )
    )
    effective = allows(
        documents(environment, role), f"{service}:{verb}", arn, context
    ) and allows([boundary], f"{service}:{verb}", arn, context)
    assert effective is (wrong is None and role != "deploy")


@pytest.mark.parametrize(
    "environment,account_id", [("test", "891377212104"), ("prod", "933245420672")]
)
@pytest.mark.parametrize("role", ["ci", "automation", "deploy"])
@pytest.mark.parametrize("wrong", [None, "Project", "Environment", "Purpose"])
@pytest.mark.parametrize("service,kind,purpose,verb", TARGETS)
def test_effective_creation_preserves_request_purpose(
    environment, account_id, role, wrong, service, kind, purpose, verb
):
    context = {
        "aws:RequestTag/Project": REPO.name,
        "aws:RequestTag/Environment": environment,
        "aws:RequestTag/Purpose": purpose,
    }
    if wrong:
        context[f"aws:RequestTag/{wrong}"] = "foreign"
    action = f"{service}:{verb.replace('Delete', 'Create')}"
    boundary = json.loads(
        platform_iam.platform_control_boundary(
            account_id, settings(environment), REPO.name
        )
    )
    assert (
        allows(documents(environment, role, account_id), action, "*", context)
        and allows([boundary], action, "*", context)
    ) is (wrong is None and role != "deploy")


def test_exact_iam_denials_move_to_guard_and_runtime_queue_denials_stay():
    configured = settings()
    boundary = json.loads(
        platform_iam.platform_control_boundary(ACCOUNT, configured, REPO.name)
    )
    guard = json.loads(platform_iam.platform_control_state_guard(ACCOUNT, configured))
    expected = platform_iam.platform_control_denies(ACCOUNT, configured)
    platform_iam._compress_sensitive_statements(expected)
    for statement in expected:
        if statement["Sid"] in platform_iam._GUARD_ONLY_IAM_DENIALS:
            assert statement in guard["Statement"]
            assert not any(
                item["Action"] == statement["Action"] for item in boundary["Statement"]
            )
    denials = [item for item in boundary["Statement"] if item["Effect"] == "Deny"]
    assert any(
        "secretsmanager:*GetSecretValue" in values(item["Action"]) for item in denials
    )
    assert any(
        any(action.startswith("sqs:") for action in values(item["Action"]))
        for item in denials
    )


@pytest.mark.parametrize("creation", [False, True])
@pytest.mark.parametrize(
    "mutation", ["extra-condition", "wrong-environment", "foreign-service", "deny"]
)
def test_compaction_never_discards_unreviewed_restrictions(creation, mutation):
    configured = settings()
    source = json.loads(automation._automation_policy(ACCOUNT, configured, REPO.name))
    predicate = (
        platform_iam._is_tagged_creation
        if creation
        else platform_iam._is_tagged_management
    )
    combine = (
        platform_iam._coalesce_tagged_creation
        if creation
        else platform_iam._coalesce_tagged_management
    )
    statement = deepcopy(
        next(item for item in source["Statement"] if predicate(item, configured))
    )
    if mutation == "extra-condition":
        statement["Condition"]["StringNotEquals"] = {"aws:PrincipalTag/Blocked": "true"}
    elif mutation == "wrong-environment":
        tag = "RequestTag" if creation else "ResourceTag"
        statement["Condition"]["StringEquals"][f"aws:{tag}/Environment"] = "foreign"
    elif mutation == "foreign-service":
        statement["Action"] = ["iam:DeleteRole"]
    else:
        statement["Effect"] = "Deny"
    assert combine([statement], configured) == [statement]
    assert combine([], configured) == []
