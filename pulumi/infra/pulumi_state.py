from __future__ import annotations

import json
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
state_bucket_resources: Dict[str, aws.s3.Bucket] = {}
replica_provider = aws.Provider("pulumiStateReplicaProvider", region="us-east-1")

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

  replica_bucket = aws.s3.Bucket(
    f"pulumiStateReplica-{suffix}",
    bucket=f"{bucket_name}-replication",
    versioning=aws.s3.BucketVersioningArgs(enabled=True),
    server_side_encryption_configuration=aws.s3.BucketServerSideEncryptionConfigurationArgs(
      rule=aws.s3.BucketServerSideEncryptionConfigurationRuleArgs(
        apply_server_side_encryption_by_default=aws.s3.BucketServerSideEncryptionConfigurationRuleApplyServerSideEncryptionByDefaultArgs(
          sse_algorithm="AES256"
        )
      )
    ),
    tags=base_tags({"Purpose": "pulumi-state-replica", "Repository": repo.name, "App": repo.name}),
    opts=pulumi.ResourceOptions(provider=replica_provider),
  )

  aws.s3.BucketPublicAccessBlock(
    f"pulumiStateReplicaPab-{suffix}",
    bucket=replica_bucket.id,
    block_public_acls=True,
    block_public_policy=True,
    ignore_public_acls=True,
    restrict_public_buckets=True,
    opts=pulumi.ResourceOptions(provider=replica_provider),
  )

  replication_role = aws.iam.Role(
    f"pulumiStateReplicationRole-{suffix}",
    assume_role_policy=bucket.arn.apply(
      lambda arn: json.dumps(
        {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Principal": {"Service": "s3.amazonaws.com"},
              "Action": "sts:AssumeRole",
              "Condition": {"StringEquals": {"aws:SourceArn": arn}},
            }
          ],
        }
      )
    ),
  )

  replication_role_policy = aws.iam.RolePolicy(
    f"pulumiStateReplicationRolePolicy-{suffix}",
    role=replication_role.id,
    policy=pulumi.Output.all(bucket.arn, replica_bucket.arn).apply(
      lambda arns: json.dumps(
        {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Action": [
                "s3:GetReplicationConfiguration",
                "s3:ListBucket",
                "s3:GetObjectVersion",
                "s3:GetObjectVersionAcl",
                "s3:GetObjectVersionForReplication",
                "s3:GetObjectVersionTagging",
              ],
              "Resource": [arns[0], f"{arns[0]}/*"],
            },
            {
              "Effect": "Allow",
              "Action": [
                "s3:ReplicateObject",
                "s3:ReplicateDelete",
                "s3:ReplicateTags",
                "s3:GetObjectVersionTagging",
                "s3:PutObject",
              ],
              "Resource": [arns[1], f"{arns[1]}/*"],
            },
          ],
        }
      )
    ),
  )

  aws.s3.BucketReplicationConfig(
    f"pulumiStateReplicationConfiguration-{suffix}",
    bucket=bucket.id,
    role=replication_role.arn,
    rules=[
      aws.s3.BucketReplicationConfigRuleArgs(
        id=f"{suffix}-to-useast1",
        status="Enabled",
        destination=aws.s3.BucketReplicationConfigRuleDestinationArgs(
          bucket=replica_bucket.arn,
          storage_class="STANDARD",
        ),
      )
    ],
    opts=pulumi.ResourceOptions(depends_on=[replication_role_policy]),
  )

  state_buckets[repo.name] = bucket.bucket
  backend_urls[repo.name] = pulumi.Output.concat("s3://", bucket.bucket, "/state/<stack>")
  state_bucket_resources[repo.name] = bucket

pulumi.export("pulumiStateBuckets", state_buckets)
pulumi.export("pulumiBackendUrls", backend_urls)
