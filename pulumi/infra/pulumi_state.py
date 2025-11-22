from __future__ import annotations

from typing import Dict

import pulumi
import pulumi_aws as aws

from .config import managed_repositories, state_bucket_name_for_repo, _sanitize_bucket_component
from .utils.tags import base_tags


def _bucket_exists(name: str) -> bool:
  try:
    aws.s3.get_bucket(bucket=name)
    return True
  except Exception:
    return False


def _resource_suffix(repo_name: str) -> str:
  return _sanitize_bucket_component(repo_name, "repoSlug").replace(".", "-")


state_buckets: Dict[str, pulumi.Output[str]] = {}
backend_urls: Dict[str, pulumi.Output[str]] = {}

for repo in managed_repositories():
  bucket_name = state_bucket_name_for_repo(repo.name)
  suffix = _resource_suffix(repo.name)
  import_id = bucket_name if _bucket_exists(bucket_name) else None
  bucket = aws.s3.Bucket(
    f"pulumiState-{suffix}",
    bucket=bucket_name,
    versioning=aws.s3.BucketVersioningArgs(enabled=True),
    lifecycle_rules=[
      aws.s3.BucketLifecycleRuleArgs(
        id="expire-old-versions",
        enabled=True,
        noncurrent_version_expiration=aws.s3.BucketLifecycleRuleNoncurrentVersionExpirationArgs(
          days=365
        ),
      )
    ],
    server_side_encryption_configuration=aws.s3.BucketServerSideEncryptionConfigurationArgs(
      rule=aws.s3.BucketServerSideEncryptionConfigurationRuleArgs(
        apply_server_side_encryption_by_default=aws.s3.BucketServerSideEncryptionConfigurationRuleApplyServerSideEncryptionByDefaultArgs(
          sse_algorithm="AES256"
        )
      )
    ),
    tags=base_tags({"Purpose": "pulumi-state", "Repository": repo.name, "App": repo.name}),
    opts=pulumi.ResourceOptions(import_=import_id) if import_id else None,
  )

  aws.s3.BucketPublicAccessBlock(
    f"pulumiStatePab-{suffix}",
    bucket=bucket.id,
    block_public_acls=True,
    block_public_policy=True,
    ignore_public_acls=True,
    restrict_public_buckets=True,
  )

  def _bucket_policy(arn: str) -> str:
    return f"""
{{
  "Version": "2012-10-17",
  "Statement": [
    {{
      "Sid": "RequireTLS",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["{arn}", "{arn}/state/*"],
      "Condition": {{
        "Bool": {{"aws:SecureTransport": "false"}}
      }}
    }}
  ]
}}
"""

  aws.s3.BucketPolicy(
    f"pulumiStatePolicy-{suffix}",
    bucket=bucket.id,
    policy=bucket.arn.apply(_bucket_policy),
  )

  state_buckets[repo.name] = bucket.bucket
  backend_urls[repo.name] = pulumi.Output.concat("s3://", bucket.bucket, "/state/<stack>")

pulumi.export("pulumiStateBuckets", state_buckets)
pulumi.export("pulumiBackendUrls", backend_urls)
