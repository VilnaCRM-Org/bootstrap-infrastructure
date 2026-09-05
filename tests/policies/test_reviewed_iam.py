"""Adversarial tests for complete-document IAM digest exceptions."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
from types import MappingProxyType

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "reviewed_iam_test_module",
    Path(__file__).resolve().parents[2] / "policy" / "reviewed_iam.py",
)
assert _SPEC is not None and _SPEC.loader is not None
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)
reviewed_iam_document_matches = _MODULE.reviewed_iam_document_matches

MANAGED = "aws:iam/policy:Policy"
INLINE = "aws:iam/rolePolicy:RolePolicy"
UNKNOWN = "04da6b54-80e4-46f7-96ec-b56ff0331ba9"
DOCUMENT = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "ReadMetadata",
            "Effect": "Allow",
            "Action": ["iam:GetRole"],
            "Resource": "*",
            "Condition": {"StringEquals": {"aws:PrincipalAccount": "123456789012"}},
        },
        {
            "Sid": "ImmutableControls",
            "Effect": "Deny",
            "Action": ["iam:PutRolePolicy"],
            "Resource": "*",
        },
    ],
}


def digest(document=DOCUMENT):
    """Use an independent standard JSON serialization for reviewed fixture pins."""
    return hashlib.sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def props(document=DOCUMENT):
    """Return fresh resource properties to keep mutation cases independent."""
    return {"name": "reviewed-policy", "policy": copy.deepcopy(document)}


@pytest.mark.parametrize(
    "encoding", ["mapping", "json", "whitespace", "reordered", "mapping-proxy"]
)
def test_reviewed_full_document_accepts_only_serialization_equivalence(encoding):
    resource = props()
    if encoding == "json":
        resource["policy"] = json.dumps(DOCUMENT)
    elif encoding == "whitespace":
        resource["policy"] = json.dumps(DOCUMENT, indent=4)
    elif encoding == "reordered":
        resource["policy"] = {key: DOCUMENT[key] for key in reversed(DOCUMENT)}
    elif encoding == "mapping-proxy":
        resource["policy"] = MappingProxyType(DOCUMENT)
    assert reviewed_iam_document_matches(
        MANAGED, resource, {MANAGED + "|reviewed-policy": digest()}
    )


@pytest.mark.parametrize("pins", ["single", "tuple", "list"])
def test_closed_digest_set_allows_two_account_documents(pins):
    second = copy.deepcopy(DOCUMENT)
    second["Statement"][0]["Condition"]["StringEquals"]["aws:PrincipalAccount"] = (
        "987654321098"
    )
    values = {
        "single": digest(second),
        "tuple": (digest(), digest(second)),
        "list": [digest(), digest(second)],
    }[pins]
    assert reviewed_iam_document_matches(
        MANAGED, props(second), {MANAGED + "|reviewed-policy": values}
    )
    assert not reviewed_iam_document_matches(
        MANAGED,
        props({**second, "Unexpected": True}),
        {MANAGED + "|reviewed-policy": values},
    )


def test_inline_identity_requires_both_policy_name_and_owner_role():
    resource = {**props(), "role": "controller-test"}
    pins = {INLINE + "|reviewed-policy|controller-test": digest()}
    assert reviewed_iam_document_matches(INLINE, resource, pins)
    assert not reviewed_iam_document_matches(
        INLINE, {**resource, "role": "other-role"}, pins
    )
    assert not reviewed_iam_document_matches(
        INLINE, {**resource, "name": "other-policy"}, pins
    )
    assert not reviewed_iam_document_matches(MANAGED, resource, pins)


@pytest.mark.parametrize(
    "resource_type,field,value",
    [
        ("aws:iam/role:Role", "name", "reviewed-policy"),
        ("aws:iam/policy:Policy:v2", "name", "reviewed-policy"),
        (MANAGED, "name", None),
        (MANAGED, "name", 42),
        (MANAGED, "name", ""),
        (MANAGED, "name", " reviewed-policy"),
        (MANAGED, "name", "reviewed|policy"),
        (MANAGED, "name", "x" * 129),
        (MANAGED, "name", UNKNOWN),
        (INLINE, "role", UNKNOWN),
        (INLINE, "role", None),
        (INLINE, "role", 42),
        (INLINE, "role", "role|name"),
        (INLINE, "role", "x" * 65),
    ],
)
def test_invalid_or_unknown_identity_fails_even_with_matching_digest(
    resource_type, field, value
):
    resource = {**props(), "role": "controller-test", field: value}
    key = resource_type + "|" + str(resource["name"])
    if resource_type == INLINE:
        key += "|" + str(resource["role"])
    assert not reviewed_iam_document_matches(resource_type, resource, {key: digest()})


@pytest.mark.parametrize(
    "expected",
    [
        None,
        "",
        "*",
        "f" * 63,
        "F" * 64,
        b"f" * 64,
        bytearray(b"f" * 64),
        42,
        {},
        [],
        (),
        [digest(), "bad"],
        [digest(), None],
    ],
)
def test_unreviewed_or_malformed_digest_sets_fail_closed(expected):
    assert not reviewed_iam_document_matches(
        MANAGED, props(), {MANAGED + "|reviewed-policy": expected}
    )


@pytest.mark.parametrize(
    "field", ["policyDocument", "assumeRolePolicy", "inlinePolicies"]
)
@pytest.mark.parametrize("value", [None, {}, []])
def test_extra_embedded_document_fields_never_inherit_an_exception(field, value):
    assert not reviewed_iam_document_matches(
        MANAGED, {**props(), field: value}, {MANAGED + "|reviewed-policy": digest()}
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "action",
        "resource",
        "condition",
        "effect",
        "remove-deny",
        "change-deny",
        "extra-statement",
        "not-action",
        "not-resource",
    ],
)
def test_any_authorization_change_invalidates_review(mutation):
    resource = props()
    document = resource["policy"]
    statement = document["Statement"][0]
    if mutation == "action":
        statement["Action"] = ["iam:*"]
    elif mutation == "resource":
        statement["Resource"] = "arn:aws:iam::987654321098:role/*"
    elif mutation == "condition":
        statement.pop("Condition")
    elif mutation == "effect":
        document["Statement"][1]["Effect"] = "Allow"
    elif mutation == "remove-deny":
        document["Statement"].pop()
    elif mutation == "change-deny":
        document["Statement"][1]["Action"] = ["iam:GetRole"]
    elif mutation == "extra-statement":
        document["Statement"].append(
            {"Effect": "Allow", "Action": "*", "Resource": "*"}
        )
    elif mutation == "not-action":
        statement["NotAction"] = "iam:GetRole"
    elif mutation == "not-resource":
        statement["NotResource"] = "arn:aws:iam::123456789012:role/ignored"
    assert not reviewed_iam_document_matches(
        MANAGED, resource, {MANAGED + "|reviewed-policy": digest()}
    )


@pytest.mark.parametrize(
    "value",
    [
        None,
        [],
        4,
        True,
        "null",
        "[]",
        "4",
        "true",
        "not-json",
        "{",
        UNKNOWN,
        '{"Statement":[],"Statement":[]}',
        '{"Statement":[{"Effect":"Allow","Effect":"Deny"}]}',
        '{"Statement":[],"Value":NaN}',
        '{"Statement":[],"Value":Infinity}',
        '{"Statement":[],"Value":-Infinity}',
        {"Statement": [], "Value": float("nan")},
        {"Statement": [], "Value": float("inf")},
        {"Statement": [], "Value": float("-inf")},
        {"Statement": [], "Value": (1, 2)},
        {"Statement": [], "Value": {1: "coerced-key"}},
        {"Statement": [], "Value": {"invalid"}},
        {"Statement": [], "Value": UNKNOWN},
        {"Statement": [], "Value": "arn:aws:iam::" + UNKNOWN},
    ],
)
def test_strict_json_rejects_ambiguous_unknown_or_non_json_documents(value):
    # Even pinning Python's permissive representation must not authorize invalid JSON.
    try:
        permissive = digest(value)
    except (TypeError, ValueError):
        permissive = digest()
    assert not reviewed_iam_document_matches(
        MANAGED, props(value), {MANAGED + "|reviewed-policy": permissive}
    )


def test_duplicate_key_cannot_hide_a_widening_statement_behind_approved_content():
    encoded = json.dumps(DOCUMENT)
    malicious = (
        '{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}],' + encoded[1:]
    )
    assert json.loads(malicious) == DOCUMENT
    assert not reviewed_iam_document_matches(
        MANAGED, props(malicious), {MANAGED + "|reviewed-policy": digest()}
    )


def test_finite_json_scalars_remain_part_of_the_complete_hash():
    document = {
        **DOCUMENT,
        "Metadata": {
            "text": "é",
            "flag": True,
            "null": None,
            "integer": 3,
            "number": 1.5,
        },
    }
    assert reviewed_iam_document_matches(
        MANAGED, props(document), {MANAGED + "|reviewed-policy": digest(document)}
    )


def test_cyclic_mapping_fails_closed():
    document = {"Statement": []}
    document["cycle"] = document
    assert not reviewed_iam_document_matches(
        MANAGED, props(document), {MANAGED + "|reviewed-policy": digest()}
    )


@pytest.mark.parametrize(
    "key,value", [("Version", "2008-10-17"), ("Extra", "unreviewed")]
)
def test_top_level_policy_changes_also_require_review(key, value):
    resource = props()
    resource["policy"][key] = value
    assert not reviewed_iam_document_matches(
        MANAGED, resource, {MANAGED + "|reviewed-policy": digest()}
    )
