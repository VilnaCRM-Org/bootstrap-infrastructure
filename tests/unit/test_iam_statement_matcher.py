"""Prevent scalar IAM fields or malformed statements from hiding scope defects."""

import json

import pytest
from iam_statement_matcher import iam_statement_matches
from test_governance_automation import allows


@pytest.mark.parametrize("effect", ["Allow", "Deny"])
@pytest.mark.parametrize("action_list", [False, True])
@pytest.mark.parametrize("resource_list", [False, True])
@pytest.mark.parametrize("field", ["Resource", "NotResource"])
def test_scalar_and_list_shapes_match_identically(
    effect, action_list, resource_list, field
):
    action = "s3:Put*"
    resource = "arn:aws:s3:::own/*"
    statement = {
        "Effect": effect,
        "Action": [action] if action_list else action,
        field: [resource] if resource_list else resource,
    }
    assert iam_statement_matches(statement, "S3:PUTOBJECT", "arn:aws:s3:::own/key") is (
        field == "Resource"
    )
    assert iam_statement_matches(
        statement, "s3:PutObject", "arn:aws:s3:::foreign/key"
    ) is (field == "NotResource")
    assert not iam_statement_matches(statement, "s3:GetObject", "arn:aws:s3:::own/key")


@pytest.mark.parametrize("missing", ["Effect", "Action", "Resource"])
def test_missing_fields_raise_before_negative_assertions(missing):
    statement = {"Effect": "Allow", "Action": "s3:PutObject", "Resource": "*"}
    del statement[missing]
    with pytest.raises(ValueError, match="IAM"):
        allows(json.dumps({"Statement": [statement]}), "unmatched:Action", "resource")


@pytest.mark.parametrize("field", ["Action", "Resource", "NotResource"])
@pytest.mark.parametrize("value", [None, 2, [], "", " ", [""], [2], ["valid", None]])
def test_malformed_pattern_fields_raise(field, value):
    statement = {"Effect": "Allow", "Action": "s3:PutObject", "Resource": "*"}
    if field == "NotResource":
        del statement["Resource"]
    statement[field] = value
    with pytest.raises(ValueError, match="IAM"):
        iam_statement_matches(statement, "s3:GetObject", "resource")


@pytest.mark.parametrize(
    "extra",
    [{"NotResource": "other"}, {"NotAction": "s3:GetObject"}, {"Effect": "maybe"}],
)
def test_unsupported_or_ambiguous_statements_raise(extra):
    statement = {"Effect": "Allow", "Action": "s3:PutObject", "Resource": "*", **extra}
    with pytest.raises(ValueError):
        iam_statement_matches(statement, "s3:PutObject", "resource")


def test_allows_preserves_effect_and_case_sensitive_resource_scope():
    allow = {"Effect": "Allow", "Action": "s3:PutObject", "Resource": "bucket/Key"}
    deny = {**allow, "Effect": "Deny"}
    document = json.dumps({"Statement": [allow, deny]})
    assert allows(document, "s3:putobject", "bucket/Key") == [allow]
    assert allows(document, "s3:PutObject", "bucket/key") == []


def test_conditions_remain_separate_from_statement_scope_matching():
    statement = {
        "Effect": "Allow",
        "Action": ["iam:GetRole", "s3:PutObject"],
        "Resource": ["first", "second"],
        "Condition": {"StringEquals": {"aws:SourceAccount": "123456789012"}},
    }
    assert iam_statement_matches(statement, "s3:PutObject", "second")
