"""Exercise complete enrollment collection with synthetic, offline AWS metadata."""

import copy
import hashlib
import json
import sys
from collections import Counter
from dataclasses import asdict, replace
from pathlib import Path
from urllib.parse import quote

import pytest
from seed import policy_registry as registry
from seed.operator_trust import operator_trust_policy

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))

import operator_enrollment_runtime as runtime  # noqa: E402

# Synthetic public metadata only: neither an installed key nor Config policy.
KEY_ID = "9f610284-127a-4abc-a612-8d638bec729a"
AWS_DOCUMENT = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "config:Describe*", "Resource": "*"}],
}
PERCENT_DOCUMENT = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::synthetic/a%2Fb+literal",
        }
    ],
}


def build(environment="test"):
    """Build the real closed catalog with explicit synthetic key metadata."""
    account = registry.ACCOUNTS[environment]
    key = registry.SeedKeyBinding(
        f"arn:aws:kms:{registry.REGION}:{account}:key/{KEY_ID}",
        KEY_ID,
        account,
        "CUSTOMER",
        "Enabled",
        "ENCRYPT_DECRYPT",
    )
    return registry.build_registry(environment, account_id=account, seed_key=key)


class Reader:
    """Serve only the collector's explicitly allowed metadata operations."""

    def __init__(self, expected, purpose="preview", encoding="object"):
        self.expected = expected
        self.encoding = encoding
        self.calls = []
        self.caller = {
            "Account": expected.account_id,
            "UserId": self.role_id(
                f"GitHubOperator{purpose.title()}-{expected.environment}"
            )
            + ":session-1",
            "Arn": f"arn:aws:sts::{expected.account_id}:assumed-role/"
            f"GitHubOperator{purpose.title()}-{expected.environment}/session-1",
        }
        self.key = dict(
            zip(
                ("Arn", "KeyId", "AWSAccountId", "KeyManager", "KeyState", "KeyUsage"),
                asdict(expected.seed_key).values(),
                strict=True,
            )
        )
        self.policies = {
            p.arn: ("v3", json.loads(p.document_json)) for p in expected.policies
        }
        self.roles = {p.arn.rsplit("/", 1)[-1]: p for p in expected.principals}
        frozen = next(p.frozen_config for p in expected.principals if p.frozen_config)
        self.policies[frozen.aws_policy_arn] = (frozen.aws_policy_version, AWS_DOCUMENT)
        self.inline = {
            name: dict(p.frozen_config.inline_policies)
            if p.frozen_config
            else {"synthetic-inline": json.dumps(PERCENT_DOCUMENT)}
            if p.existing
            else {}
            for name, p in self.roles.items()
        }

    @staticmethod
    def role_id(name):
        """Deterministic synthetic IAM metadata, never an enrollment baseline."""
        return "AROA" + hashlib.sha256(name.encode()).hexdigest()[:17].upper()

    def encode(self, document):
        """Model boto3 mappings, raw JSON and IAM's RFC3986-encoded JSON."""
        if self.encoding == "object":
            return copy.deepcopy(document)
        text = json.dumps(document)
        return quote(text, safe="") if self.encoding == "encoded" else text

    def page(self, field, items, arguments):
        """Exercise real multi-page reads, including an empty truncated first page."""
        if "Marker" not in arguments:
            return {field: [], "IsTruncated": True, "Marker": "page-2"}
        assert arguments["Marker"] == "page-2"
        return {field: items, "IsTruncated": False}

    def policy_response(self, operation, arguments):
        """Supply complete policy identity, pointer and version metadata."""
        arn = arguments["PolicyArn"]
        version, document = self.policies[arn]
        if operation == "get_policy":
            return {"Policy": {"Arn": arn, "DefaultVersionId": version}}
        assert arguments["VersionId"] == version
        return {
            "PolicyVersion": {
                "VersionId": version,
                "IsDefaultVersion": True,
                "Document": self.encode(document),
            }
        }

    def role_response(self, operation, arguments):
        """Serve complete role, attachment and inline policy metadata."""
        name = arguments["RoleName"]
        principal = self.roles[name]
        if operation == "get_role":
            return {"Role": self.role_metadata(principal)}
        if operation == "list_attached_role_policies":
            items = [{"PolicyArn": arn} for arn in principal.attachment_arns]
            return self.page("AttachedPolicies", items, arguments)
        if operation == "list_role_policies":
            return self.page("PolicyNames", list(self.inline[name]), arguments)
        assert operation == "get_role_policy"
        policy_name = arguments["PolicyName"]
        return {
            "RoleName": name,
            "PolicyName": policy_name,
            "PolicyDocument": self.encode(json.loads(self.inline[name][policy_name])),
        }

    def role_metadata(self, principal):
        """Return active executor trust without pretending it is installed."""
        trust = registry.DISABLED_TRUST
        if not principal.existing:
            purpose = principal.arn.rsplit("/", 1)[-1][len("GitHubOperator") :]
            purpose = purpose.split("-", 1)[0].lower()
            trust = json.loads(
                operator_trust_policy(
                    self.expected.environment,
                    purpose,
                    account_id=self.expected.account_id,
                )
            )
        if principal.frozen_config:
            trust = json.loads(principal.frozen_config.trust_json)
        name = principal.arn.rsplit("/", 1)[-1]
        role = {
            "Arn": principal.arn,
            "RoleName": name,
            "RoleId": self.role_id(name),
            "AssumeRolePolicyDocument": self.encode(trust),
        }
        if principal.boundary_arn:
            role["PermissionsBoundary"] = {
                "PermissionsBoundaryType": "Policy",
                "PermissionsBoundaryArn": principal.boundary_arn,
            }
        return role

    def __call__(self, service, operation, arguments):
        """Reject any operation outside this explicit metadata-only API set."""
        self.calls.append((service, operation, copy.deepcopy(arguments)))
        if (service, operation) == ("sts", "get_caller_identity"):
            assert not arguments
            return copy.deepcopy(self.caller)
        if (service, operation) == ("kms", "describe_key"):
            assert arguments == {"KeyId": self.expected.seed_key.arn}
            return {"KeyMetadata": copy.deepcopy(self.key)}
        assert service == "iam"
        if operation in ("get_policy", "get_policy_version"):
            return self.policy_response(operation, arguments)
        return self.role_response(operation, arguments)


def test_shared_collector_does_not_admit_installer_through_operator_gate():
    """Independent initial authentication must never widen active worker identity."""
    expected = build()
    reader = Reader(expected)
    reader.caller["Arn"] = (
        f"arn:aws:sts::{expected.account_id}:assumed-role/IndependentInstaller/session-1"
    )
    with pytest.raises(ValueError, match="Wrong operator caller"):
        runtime.collect_enrollment(expected, purpose="preview", call=reader)
    assert reader.calls == [("sts", "get_caller_identity", {})]


@pytest.mark.parametrize("environment", ["test", "prod"])
@pytest.mark.parametrize("purpose", ["preview", "apply", "drift"])
@pytest.mark.parametrize("encoding", ["object", "json", "encoded"])
def test_complete_collection_all_accounts_and_modes(environment, purpose, encoding):
    expected = build(environment)
    reader = Reader(expected, purpose, encoding)
    actual = runtime.collect_enrollment(expected, purpose=purpose, call=reader)
    assert actual.account_id == expected.account_id
    assert actual.seed_key == expected.seed_key
    assert len(actual.policies) == 55
    assert len(actual.principals) == 24
    for policy, observed in zip(expected.policies, actual.policies, strict=True):
        assert observed == registry.ObservedPolicy(
            policy.arn, "v3", policy.document_json
        )
    executor_trust = {
        f"arn:aws:iam::{expected.account_id}:role/"
        f"GitHubOperator{role_purpose.title()}-{environment}": json.loads(
            operator_trust_policy(
                environment, role_purpose, account_id=expected.account_id
            )
        )
        for role_purpose in ("preview", "apply", "drift")
    }
    for principal, observed in zip(expected.principals, actual.principals, strict=True):
        assert observed.arn == principal.arn
        assert observed.boundary_arn == principal.boundary_arn
        assert observed.attachment_arns == principal.attachment_arns
        if principal.frozen_config:
            expected_trust = json.loads(principal.frozen_config.trust_json)
        elif principal.existing:
            expected_trust = registry.DISABLED_TRUST
        else:
            expected_trust = executor_trust[principal.arn]
        assert json.loads(observed.trust_json) == expected_trust
        name = principal.arn.rsplit("/", 1)[-1]
        assert dict(observed.inline_policies) == {
            key: json.dumps(json.loads(value), sort_keys=True, separators=(",", ":"))
            for key, value in reader.inline[name].items()
        }
    aws_bytes = json.dumps(AWS_DOCUMENT, sort_keys=True, separators=(",", ":")).encode()
    assert (
        actual.aws_managed_policies[0].document_sha256
        == hashlib.sha256(aws_bytes).hexdigest()
    )
    assert reader.calls[0] == ("sts", "get_caller_identity", {})
    assert reader.calls[1] == (
        "iam",
        "get_role",
        {"RoleName": f"GitHubOperator{purpose.title()}-{environment}"},
    )
    assert reader.calls[2][0:2] == ("kms", "describe_key")
    pointers = Counter(
        args["PolicyArn"]
        for _, operation, args in reader.calls
        if operation == "get_policy"
    )
    assert set(pointers) == set(reader.policies)
    assert set(pointers.values()) == {2}
    # Synthetic Config document hashes prove collector behavior, never enrollment.
    with pytest.raises(
        registry.RegistryError, match="Config AWS-managed policy document"
    ):
        registry.verify_active_enrollment(expected, actual)


@pytest.mark.parametrize(
    "arn",
    [
        "arn:aws:iam::891377212104:root",
        "arn:aws:iam::891377212104:user/admin",
        "arn:aws:sts::933245420672:assumed-role/GitHubOperatorPreview-test/session",
        "arn:aws:sts::891377212104:assumed-role/GitHubOperatorApply-test/session",
        "arn:aws:sts::891377212104:assumed-role/GitHubOperatorPreview-test-evil/session",
        "arn:aws:sts::891377212104:assumed-role/GitHubOperatorPreview-test/",
        "arn:aws:sts::891377212104:assumed-role/GitHubOperatorPreview-test/x",
        "arn:aws:sts::891377212104:assumed-role/GitHubOperatorPreview-test/аbc",
        "arn:aws:sts::891377212104:assumed-role/GitHubOperatorPreview-test/extra/path",
        "arn:aws:sts::891377212104:assumed-role/GitHubOperatorPreview-test/" + "a" * 65,
        None,
    ],
)
def test_wrong_caller_rejected_before_iam_or_kms(arn):
    expected = build()
    reader = Reader(expected)
    reader.caller["Arn"] = arn
    with pytest.raises(registry.RegistryError, match="Wrong operator caller"):
        runtime.collect_enrollment(expected, purpose="preview", call=reader)
    assert reader.calls == [("sts", "get_caller_identity", {})]


def test_wrong_caller_account_rejected_before_iam_or_kms():
    expected = build()
    reader = Reader(expected)
    reader.caller["Account"] = "933245420672"
    with pytest.raises(registry.RegistryError, match="Wrong operator caller"):
        runtime.collect_enrollment(expected, purpose="preview", call=reader)
    assert len(reader.calls) == 1


def test_invalid_purpose_and_forged_registry_fail_before_any_aws_read():
    expected = build()
    reader = Reader(expected)
    with pytest.raises(registry.RegistryError, match="Invalid operator purpose"):
        runtime.collect_enrollment(expected, purpose="admin", call=reader)
    with pytest.raises(registry.RegistryError, match="Untrusted enrollment registry"):
        runtime.collect_enrollment(
            replace(expected, policies=expected.policies[:-1]),
            purpose="preview",
            call=reader,
        )
    assert not reader.calls


@pytest.mark.parametrize("value", [None, 123, "foreign-key"])
def test_invalid_key_stops_before_broad_metadata(value):
    expected = build()
    reader = Reader(expected)
    reader.key["Arn"] = value
    with pytest.raises(
        registry.RegistryError, match="metadata string|seed key mismatch"
    ):
        runtime.collect_enrollment(expected, purpose="preview", call=reader)
    assert [service for service, _, _ in reader.calls] == ["sts", "iam", "kms"]


@pytest.mark.parametrize("encoding", ["object", "json", "encoded"])
def test_literal_percent_and_plus_never_decoded_inside_policy_values(encoding):
    reader = Reader(build(), encoding=encoding)
    result = runtime._document(reader.encode(PERCENT_DOCUMENT))
    assert json.loads(result) == PERCENT_DOCUMENT


@pytest.mark.parametrize(
    "value,match",
    [
        (None, "metadata object"),
        ([], "metadata object"),
        ("[]", "metadata object"),
        ("not-json private-response-text", "Invalid AWS policy document"),
        ("%7Bnot-json%7D", "Invalid AWS policy document"),
        ('{"Statement":NaN}', "Invalid AWS policy document"),
        ({"Statement": float("inf")}, "Invalid AWS policy document"),
        ({"Statement": object()}, "Invalid AWS policy document"),
        ('{"Statement":[],"Statement":[]}', "Duplicate AWS policy field"),
        (
            '{"Statement":[{"Effect":"Allow","Effect":"Deny"}]}',
            "Duplicate AWS policy field",
        ),
        (
            quote('{"Statement":[],"Statement":[]}', safe=""),
            "Duplicate AWS policy field",
        ),
        (" " * (1024 * 1024 + 1), "exceeds bound"),
        ({"large": "x" * (1024 * 1024)}, "exceeds bound"),
        ("[" * 2000 + "]" * 2000, "Invalid AWS policy document"),
    ],
)
def test_invalid_or_oversized_documents_fail_closed(value, match):
    with pytest.raises(registry.RegistryError, match=match) as error:
        runtime._document(value)
    assert "private-response-text" not in str(error.value)


@pytest.mark.parametrize("operation", ["get_caller_identity", "get_policy"])
def test_transport_exception_redacts_response_and_exception_chain(operation):
    def failed(*_arguments):
        raise RuntimeError("private-response-text")

    with pytest.raises(registry.RegistryError, match="metadata read failed") as error:
        runtime._read(failed, "iam", operation)
    assert "private-response-text" not in str(error.value)
    assert error.value.__suppress_context__ is True


def test_nonobject_transport_response_rejected():
    with pytest.raises(registry.RegistryError, match="metadata object"):
        runtime._read(lambda *_: [], "sts", "get_caller_identity")


@pytest.mark.parametrize(
    "page,match",
    [
        ({"Items": None, "IsTruncated": False}, "Invalid IAM metadata page"),
        ({"Items": [], "IsTruncated": 0}, "Missing IAM pagination state"),
        ({"Items": []}, "Missing IAM pagination state"),
        ({"Items": [], "IsTruncated": True}, "page marker"),
        ({"Items": [], "IsTruncated": True, "Marker": ""}, "page marker"),
        ({"Items": [], "IsTruncated": True, "Marker": 3}, "page marker"),
        ({"Items": [], "IsTruncated": True, "Marker": "x" * 1025}, "page marker"),
        ({"Items": list(range(1001)), "IsTruncated": False}, "inventory exceeds"),
    ],
)
def test_malformed_or_incomplete_pagination_rejected(page, match):
    with pytest.raises(registry.RegistryError, match=match):
        runtime._list(lambda *_: page, "list_role_policies", "Items", "Role")


def test_repeated_marker_and_unending_pagination_rejected():
    repeated = {"Items": [], "IsTruncated": True, "Marker": "same"}
    with pytest.raises(registry.RegistryError, match="repeated IAM page marker"):
        runtime._list(lambda *_: repeated, "list_role_policies", "Items", "Role")
    calls = []

    def unending(*args):
        calls.append(args)
        return {"Items": [], "IsTruncated": True, "Marker": str(len(calls))}

    with pytest.raises(registry.RegistryError, match="pagination exceeds bound"):
        runtime._list(unending, "list_role_policies", "Items", "Role")
    assert len(calls) == runtime.MAX_PAGES


def test_aggregate_item_bound_and_exact_maximum():
    calls = []

    def page(*_args):
        calls.append(1)
        return {"Items": [0] * 501, "IsTruncated": True, "Marker": str(len(calls))}

    with pytest.raises(registry.RegistryError, match="inventory exceeds bound"):
        runtime._list(page, "list_role_policies", "Items", "Role")
    assert len(calls) == 2
    result = runtime._list(
        lambda *_: {"Items": [0] * 1000, "IsTruncated": False},
        "list_role_policies",
        "Items",
        "Role",
    )
    assert len(result) == 1000


@pytest.mark.parametrize(
    "response_index,field,value,match",
    [
        (0, "Arn", "foreign-arn", "policy ARN mismatch"),
        (0, "DefaultVersionId", "v0", "Invalid AWS policy version"),
        (0, "DefaultVersionId", None, "Invalid AWS policy version"),
        (1, "VersionId", "v2", "default version changed"),
        (1, "IsDefaultVersion", False, "default version changed"),
        (1, "IsDefaultVersion", 1, "default version changed"),
        (2, "DefaultVersionId", "v2", "changed during collection"),
        (2, "Arn", "foreign-arn", "changed during collection"),
    ],
)
def test_policy_identity_and_default_pointer_races_fail(
    response_index, field, value, match
):
    arn = "arn:aws:iam::891377212104:policy/exact"
    responses = [
        {"Policy": {"Arn": arn, "DefaultVersionId": "v1"}},
        {
            "PolicyVersion": {
                "VersionId": "v1",
                "IsDefaultVersion": True,
                "Document": {},
            }
        },
        {"Policy": {"Arn": arn, "DefaultVersionId": "v1"}},
    ]
    next(iter(responses[response_index].values()))[field] = value
    with pytest.raises(registry.RegistryError, match=match):
        runtime._policy(lambda *_: responses.pop(0), arn)


@pytest.mark.parametrize(
    "operation,field,value,match",
    [
        ("get_role", "Arn", "foreign-role", "role ARN mismatch"),
        ("get_role", "PermissionsBoundary", [], "metadata object"),
        (
            "get_role",
            "PermissionsBoundary",
            {"PermissionsBoundaryType": "Inline"},
            "boundary type",
        ),
        (
            "get_role",
            "PermissionsBoundary",
            {"PermissionsBoundaryType": "Policy"},
            "boundary ARN",
        ),
        ("list_attached_role_policies", "AttachedPolicies", [None], "metadata object"),
        (
            "list_attached_role_policies",
            "AttachedPolicies",
            [{}],
            "attached policy ARN",
        ),
        (
            "list_attached_role_policies",
            "AttachedPolicies",
            [{"PolicyArn": "x"}] * 2,
            "Duplicate attached policy",
        ),
        ("list_role_policies", "PolicyNames", [None], "inline policy name"),
        ("list_role_policies", "PolicyNames", ["bad/name"], "inline policy name"),
        ("list_role_policies", "PolicyNames", ["аbc"], "inline policy name"),
        (
            "list_role_policies",
            "PolicyNames",
            ["same", "same"],
            "Duplicate inline policy",
        ),
        ("get_role_policy", "RoleName", "foreign-role", "Inline policy identity"),
        ("get_role_policy", "PolicyName", "foreign-policy", "Inline policy identity"),
    ],
)
def test_bad_role_metadata(operation, field, value, match):
    expected = build()
    reader = Reader(expected)
    principal = next(p for p in expected.principals if p.existing and p.boundary_arn)

    def modified(service, actual_operation, arguments):
        response = reader(service, actual_operation, arguments)
        if actual_operation == operation:
            target = response["Role"] if operation == "get_role" else response
            target[field] = value
        return response

    with pytest.raises(registry.RegistryError, match=match):
        runtime._role(modified, principal.arn)


@pytest.mark.parametrize(
    "user_id",
    [None, 123, "", "AROA" + "Z" * 17 + ":session-1", "session-1"],
)
def test_caller_requires_live_role_id(user_id):
    expected = build()
    reader = Reader(expected)
    reader.caller["UserId"] = user_id
    with pytest.raises(registry.RegistryError, match="immutable role identity"):
        runtime.collect_enrollment(expected, purpose="preview", call=reader)
    assert [operation for _, operation, _ in reader.calls] == [
        "get_caller_identity",
        "get_role",
    ]


def test_caller_requires_same_session():
    expected = build()
    reader = Reader(expected)
    reader.caller["UserId"] = reader.role_id("GitHubOperatorPreview-test") + ":other"
    with pytest.raises(registry.RegistryError, match="immutable role identity"):
        runtime.collect_enrollment(expected, purpose="preview", call=reader)
    assert len(reader.calls) == 2


@pytest.mark.parametrize(
    "field,value",
    [
        ("Arn", "arn:aws:iam::891377212104:role/foreign"),
        ("RoleName", "GitHubOperatorApply-test"),
        ("RoleId", None),
        ("RoleId", 123),
        ("RoleId", "AIDA" + "A" * 17),
        ("RoleId", "AROAshort"),
        ("RoleId", "AROA" + "a" * 17),
    ],
)
def test_caller_role_metadata_is_bound(field, value):
    expected = build()
    reader = Reader(expected)

    def read(service, operation, arguments):
        result = reader(service, operation, arguments)
        if operation == "get_role":
            result["Role"][field] = value
        return result

    with pytest.raises(registry.RegistryError, match="Live operator role metadata"):
        runtime.collect_enrollment(expected, purpose="preview", call=read)
    assert len(reader.calls) == 2


def test_same_name_replacement_rejects_stale_session():
    expected = build()
    reader = Reader(expected)

    def read(service, operation, arguments):
        result = reader(service, operation, arguments)
        if operation == "get_role":
            result["Role"]["RoleId"] = "AROA" + "Z" * 17
        return result

    with pytest.raises(registry.RegistryError, match="immutable role identity"):
        runtime.collect_enrollment(expected, purpose="preview", call=read)
    assert len(reader.calls) == 2
