"""S3 replication trusts require the exact bucket owner and service."""

import json

import pytest
from infra import logging_bucket, pulumi_state


@pytest.mark.parametrize("module", [logging_bucket, pulumi_state])
@pytest.mark.parametrize("account", ["891377212104", "933245420672"])
def test_replication_trust_requires_exact_bucket_account_and_service(module, account):
    bucket = "arn:aws:s3:::exact-replication-source"
    statement = json.loads(module._replication_assume_role_policy(bucket, account))[
        "Statement"
    ][0]
    assert statement == {
        "Effect": "Allow",
        "Principal": {"Service": "s3.amazonaws.com"},
        "Action": "sts:AssumeRole",
        "Condition": {
            "StringEquals": {"aws:SourceArn": bucket, "aws:SourceAccount": account}
        },
    }

    def accepts(service, claims):
        return service == statement["Principal"]["Service"] and all(
            claims.get(key) == value
            for key, value in statement["Condition"]["StringEquals"].items()
        )

    claims = {"aws:SourceArn": bucket, "aws:SourceAccount": account}
    assert accepts("s3.amazonaws.com", claims)
    assert not accepts("ec2.amazonaws.com", claims)
    assert not accepts("s3.amazonaws.com", {"aws:SourceArn": bucket})
    assert not accepts(
        "s3.amazonaws.com", {**claims, "aws:SourceAccount": "000000000000"}
    )
    assert not accepts(
        "s3.amazonaws.com", {**claims, "aws:SourceArn": bucket + "-foreign"}
    )
