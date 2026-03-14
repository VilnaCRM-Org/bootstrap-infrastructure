import json

from infra.automation import _automation_assume_role_policy, _automation_policy
from infra.iam.github_oidc import _assume_role_policy, _deploy_policy
from infra.logging_bucket import _log_bucket_policy
from infra.pulumi_state import _bucket_policy


def test_assume_role_policy_shape():
    policy = json.loads(_assume_role_policy("arn:oidc", "org", "repo", "main"))
    statement = policy["Statement"][0]
    assert policy["Version"] == "2012-10-17"  # nosec B101
    assert statement["Effect"] == "Allow"  # nosec B101
    assert statement["Principal"]["Federated"] == "arn:oidc"  # nosec B101
    assert statement["Action"] == "sts:AssumeRoleWithWebIdentity"  # nosec B101
    assert (
        statement["Condition"]["StringEquals"][
            "token.actions.githubusercontent.com:aud"
        ]
        == "sts.amazonaws.com"
    )  # nosec B101
    assert (
        statement["Condition"]["StringLike"]["token.actions.githubusercontent.com:sub"]
        == "repo:org/repo:ref:refs/heads/main"
    )  # nosec B101


def test_deploy_policy_shape():
    policy = json.loads(_deploy_policy("arn:bucket", "arn:objects"))
    assert policy["Version"] == "2012-10-17"  # nosec B101
    assert policy["Statement"][0]["Effect"] == "Allow"  # nosec B101
    assert policy["Statement"][0]["Action"] == ["s3:ListBucket"]  # nosec B101
    assert policy["Statement"][0]["Resource"] == "arn:bucket"  # nosec B101
    assert policy["Statement"][0]["Condition"]["StringLike"] == {  # nosec B101
        "s3:prefix": "state/*"
    }
    assert policy["Statement"][1]["Effect"] == "Allow"  # nosec B101
    assert policy["Statement"][1]["Action"] == [  # nosec B101
        "s3:GetObject",
        "s3:GetObjectVersion",
        "s3:PutObject",
        "s3:DeleteObject",
        "s3:DeleteObjectVersion",
    ]
    assert policy["Statement"][1]["Resource"] == "arn:objects"  # nosec B101


def test_deploy_policy_includes_kms_permissions():
    policy = json.loads(_deploy_policy("arn:bucket", "arn:objects", "arn:kms"))
    assert policy["Statement"][2]["Effect"] == "Allow"  # nosec B101
    assert policy["Statement"][2]["Action"] == [  # nosec B101
        "kms:Decrypt",
        "kms:Encrypt",
        "kms:GenerateDataKey",
        "kms:DescribeKey",
        "kms:ReEncrypt*",
    ]
    assert policy["Statement"][2]["Resource"] == "arn:kms"  # nosec B101


def test_automation_assume_role_policy_uses_environment_subject():
    policy = json.loads(
        _automation_assume_role_policy("arn:oidc", "org", "repo", "test")
    )
    statement = policy["Statement"][0]
    assert statement["Principal"]["Federated"] == "arn:oidc"  # nosec B101
    assert statement["Action"] == "sts:AssumeRoleWithWebIdentity"  # nosec B101
    assert statement["Condition"]["StringEquals"] == {  # nosec B101
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
        "token.actions.githubusercontent.com:sub": "repo:org/repo:environment:test",
    }


def test_automation_policy_scopes_to_bootstrap_services():
    policy = json.loads(_automation_policy("123456789012"))
    statements = {statement["Sid"]: statement for statement in policy["Statement"]}
    assert statements["ReadIdentity"]["Action"] == ["sts:GetCallerIdentity"]  # nosec B101
    assert statements["ManageBootstrapS3"]["Action"] == ["s3:*"]  # nosec B101
    assert statements["ManageBootstrapKms"]["Action"] == ["kms:*"]  # nosec B101
    assert "iam:CreateRole" in statements["ManageBootstrapIam"]["Action"]  # nosec B101
    assert "iam:UpdateAssumeRolePolicy" in statements["ManageBootstrapIam"]["Action"]  # nosec B101
    assert statements["ManageBootstrapIam"]["Resource"] == [  # nosec B101
        "arn:aws:iam::123456789012:role/*",
        "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com",
    ]
    assert statements["CreateBootstrapOidcProvider"]["Resource"] == "*"  # nosec B101
    assert statements["PassBootstrapRolesToBackup"]["Condition"]["StringEquals"] == {  # nosec B101
        "iam:PassedToService": "backup.amazonaws.com"
    }
    assert statements["ManageBootstrapBackup"]["Action"] == ["backup:*"]  # nosec B101
    assert statements["ManageBootstrapEcr"]["Action"] == ["ecr:*"]  # nosec B101


def test_log_bucket_policy_contains_required_statements():
    policy = json.loads(_log_bucket_policy("arn:bucket", "123456789012"))
    statements = {statement["Sid"]: statement for statement in policy["Statement"]}
    sids = set(statements)
    assert "RequireTLS" in sids  # nosec B101
    assert "AllowCloudTrailAclCheck" in sids  # nosec B101
    assert "AllowCloudTrailPutObject" in sids  # nosec B101
    assert "AllowLogDelivery" in sids  # nosec B101
    assert "AllowLogDeliveryAclCheck" in sids  # nosec B101
    assert statements["AllowCloudTrailAclCheck"]["Condition"]["StringEquals"] == {  # nosec B101
        "aws:SourceAccount": "123456789012"
    }
    assert statements["AllowLogDeliveryAclCheck"]["Condition"]["StringEquals"] == {  # nosec B101
        "aws:SourceAccount": "123456789012"
    }
    assert statements["AllowCloudTrailPutObject"]["Condition"]["StringEquals"] == {  # nosec B101
        "s3:x-amz-acl": "bucket-owner-full-control",
        "aws:SourceAccount": "123456789012",
    }


def test_state_bucket_policy_targets_state_prefix():
    policy = json.loads(_bucket_policy("arn:bucket"))
    resources = policy["Statement"][0]["Resource"]
    assert "arn:bucket" in resources  # nosec B101
    assert "arn:bucket/*" in resources  # nosec B101
