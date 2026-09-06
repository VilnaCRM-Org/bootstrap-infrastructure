"""Config readers retain only service-mediated decryption of their exact secret."""

import json

import pytest
from infra import ci_config
from test_secret_read_deny import _settings

SECRET = (
    "arn:aws:secretsmanager:eu-central-1:891377212104:secret:"
    "/bootstrap-infrastructure/ci/test-pr-eXoDBk"
)
SERVICE = "secretsmanager.eu-central-1.amazonaws.com"
VIA = "kms:ViaService"
CONTEXT = "kms:EncryptionContext:SecretARN"


def policy(secret=SECRET, region="eu-central-1"):
    return json.loads(
        ci_config._ci_config_read_policy(
            account_id="891377212104",
            partition="aws",
            settings=_settings(),
            suffixes=("test-pr",),
            secret_arns=(secret,),
            region=region,
        )
    )


def decrypt_denied(document, context):
    """Evaluate only these single-valued StringNotEquals Denies (missing matches).

    This is an offline clause regression, not an AWS authorization simulator.
    Statements are ORed; distinct keys inside a statement would instead AND.
    """
    for statement in document["Statement"]:
        if statement["Action"] != "kms:Decrypt":
            continue
        assert statement["Effect"] == "Deny"
        assert statement["Resource"] == "*"
        assert set(statement["Condition"]) == {"StringNotEquals"}
        conditions = statement["Condition"]["StringNotEquals"]
        if all(
            context.get(key) not in (value if isinstance(value, list) else [value])
            for key, value in conditions.items()
        ):
            return True
    return False


@pytest.mark.parametrize(
    "context",
    [
        {},
        {VIA: SERVICE},
        {CONTEXT: SECRET},
        {VIA: "s3.eu-central-1.amazonaws.com", CONTEXT: SECRET},
        {VIA: "secretsmanager.us-east-1.amazonaws.com", CONTEXT: SECRET},
        {VIA: SERVICE, CONTEXT: SECRET.replace("test-pr-", "test-")},
        {VIA: SERVICE, CONTEXT: SECRET.replace("test-pr-", "prod-")},
        {VIA: SERVICE, CONTEXT: SECRET.replace("891377212104", "933245420672")},
        {VIA: SERVICE, CONTEXT: SECRET.replace("eu-central-1", "us-east-1")},
        {VIA: SERVICE, CONTEXT: SECRET.replace("bootstrap-infrastructure", "other")},
        {VIA: SERVICE, CONTEXT: SECRET.replace("eXoDBk", "other1")},
        {VIA: SERVICE, CONTEXT: ""},
        {VIA: "", CONTEXT: SECRET},
        {"kms:EncryptionContext:pulumi:stack": "test"},
        {VIA: SERVICE, "kms:EncryptionContext:pulumi:stack": "test"},
    ],
)
def test_wrong_or_missing_context_remains_explicitly_denied(context):
    assert decrypt_denied(policy(), context)


def test_owned_context_is_not_denied_and_adds_no_kms_allow():
    document = policy()
    assert not decrypt_denied(document, {VIA: SERVICE, CONTEXT: SECRET})
    allows = [item for item in document["Statement"] if item["Effect"] == "Allow"]
    assert len(allows) == 1
    assert allows[0]["Action"] == [
        "secretsmanager:DescribeSecret",
        "secretsmanager:GetSecretValue",
    ]
    decrypt = [
        item for item in document["Statement"] if item["Action"] == "kms:Decrypt"
    ]
    assert len(decrypt) == 2
    assert all(len(item["Condition"]["StringNotEquals"]) == 1 for item in decrypt)


@pytest.mark.parametrize("region", ["eu-central-1", "us-east-1"])
@pytest.mark.parametrize("suffix", ["test-pr", "test", "prod-preview", "prod"])
def test_exact_owned_context_for_each_role_and_region(region, suffix):
    secret = SECRET.replace("eu-central-1", region).replace("test-pr-", suffix + "-")
    assert not decrypt_denied(
        policy(secret, region),
        {VIA: f"secretsmanager.{region}.amazonaws.com", CONTEXT: secret},
    )
