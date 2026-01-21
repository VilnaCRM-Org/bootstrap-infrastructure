import json

from infra.iam.github_oidc import _assume_role_policy, _deploy_policy
from infra.logging_bucket import _log_bucket_policy
from infra.pulumi_state import _bucket_policy


def test_assume_role_policy_shape():
  policy = json.loads(_assume_role_policy("arn:oidc", "org", "repo", "main"))
  statement = policy["Statement"][0]
  assert statement["Principal"]["Federated"] == "arn:oidc"  # nosec B101
  assert statement["Condition"]["StringLike"]["token.actions.githubusercontent.com:sub"] == "repo:org/repo:ref:refs/heads/main"  # nosec B101


def test_deploy_policy_shape():
  policy = json.loads(_deploy_policy("arn:bucket", "arn:objects"))
  assert policy["Statement"][0]["Action"] == ["s3:ListBucket", "s3:CreateBucket"]  # nosec B101
  assert policy["Statement"][1]["Resource"] == "arn:objects"  # nosec B101


def test_log_bucket_policy_contains_required_statements():
  policy = json.loads(_log_bucket_policy("arn:bucket", "123456789012"))
  sids = {statement["Sid"] for statement in policy["Statement"]}
  assert "RequireTLS" in sids  # nosec B101
  assert "AllowCloudTrailWrites" in sids  # nosec B101
  assert "AllowCloudTrailPutObject" in sids  # nosec B101
  assert "AllowLogDelivery" in sids  # nosec B101
  assert "AllowLogDeliveryAclCheck" in sids  # nosec B101


def test_state_bucket_policy_targets_state_prefix():
  policy = json.loads(_bucket_policy("arn:bucket"))
  resources = policy["Statement"][0]["Resource"]
  assert "arn:bucket" in resources  # nosec B101
  assert "arn:bucket/*" in resources  # nosec B101
