"""Per-repository Pulumi state buckets and backend URLs."""

from __future__ import annotations

import json
from typing import Dict, Sequence

import pulumi
import pulumi_aws as aws

from .config import ManagedRepository, managed_repositories, state_bucket_name_for_repo, _sanitize_bucket_component
from .utils.tags import base_tags


def _bucket_exists(name: str) -> bool:
  """Return True when the S3 bucket already exists."""
  try:
    aws.s3.get_bucket(bucket=name)
    return True
  except Exception as exc:  # noqa: BLE001
    message = str(exc)
    if "NotFound" in message or "NoSuchBucket" in message or "404" in message:
      return False
    raise


def _resource_suffix(repo_name: str) -> str:
  """Convert a repo name into a safe Pulumi resource suffix."""
  return _sanitize_bucket_component(repo_name, "repoSlug").replace(".", "-")


def _bucket_policy(arn: str) -> str:
  """Return a bucket policy that enforces TLS for Pulumi state objects."""
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


class PulumiStateBuckets(pulumi.ComponentResource):
  """Create primary and replica S3 buckets to store Pulumi state per repository."""

  def __init__(
    self,
    name: str,
    *,
    repositories: Sequence[ManagedRepository] | None = None,
    replication_region: str = "us-east-1",
    opts: pulumi.ResourceOptions | None = None,
  ) -> None:
    super().__init__("bootstrap:pulumi:PulumiStateBuckets", name, None, opts)

    repos = list(repositories) if repositories is not None else managed_repositories()
    self.state_buckets: Dict[str, pulumi.Output[str]] = {}
    self.backend_urls: Dict[str, pulumi.Output[str]] = {}
    self.bucket_resources: Dict[str, aws.s3.Bucket] = {}
    self.bucket_arns: Dict[str, pulumi.Output[str]] = {}

    replica_provider = aws.Provider(
      f"{name}-replica-provider",
      region=replication_region,
      opts=pulumi.ResourceOptions(parent=self),
    )

    for repo in repos:
      bucket_name = state_bucket_name_for_repo(repo.name)
      suffix = _resource_suffix(repo.name)
      import_id = bucket_name if _bucket_exists(bucket_name) else None

      bucket_opts = (
        pulumi.ResourceOptions(parent=self, import_=import_id)
        if import_id
        else pulumi.ResourceOptions(parent=self)
      )
      bucket = aws.s3.Bucket(
        f"{name}-{suffix}",
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
        opts=bucket_opts,
      )

      aws.s3.BucketPublicAccessBlock(
        f"{name}-pab-{suffix}",
        bucket=bucket.id,
        block_public_acls=True,
        block_public_policy=True,
        ignore_public_acls=True,
        restrict_public_buckets=True,
        opts=pulumi.ResourceOptions(parent=self),
      )

      aws.s3.BucketPolicy(
        f"{name}-policy-{suffix}",
        bucket=bucket.id,
        policy=bucket.arn.apply(_bucket_policy),
        opts=pulumi.ResourceOptions(parent=self),
      )

      replica_bucket = aws.s3.Bucket(
        f"{name}-replica-{suffix}",
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
        opts=pulumi.ResourceOptions(parent=self, provider=replica_provider),
      )

      aws.s3.BucketPublicAccessBlock(
        f"{name}-replica-pab-{suffix}",
        bucket=replica_bucket.id,
        block_public_acls=True,
        block_public_policy=True,
        ignore_public_acls=True,
        restrict_public_buckets=True,
        opts=pulumi.ResourceOptions(parent=self, provider=replica_provider),
      )

      replication_role = aws.iam.Role(
        f"{name}-replication-role-{suffix}",
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
        opts=pulumi.ResourceOptions(parent=self),
      )

      replication_role_policy = aws.iam.RolePolicy(
        f"{name}-replication-role-policy-{suffix}",
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
        opts=pulumi.ResourceOptions(parent=self),
      )

      aws.s3.BucketReplicationConfig(
        f"{name}-replication-config-{suffix}",
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
        opts=pulumi.ResourceOptions(parent=self, depends_on=[replication_role_policy]),
      )

      self.state_buckets[repo.name] = bucket.bucket
      self.backend_urls[repo.name] = pulumi.Output.concat("s3://", bucket.bucket, "/state/<stack>")
      self.bucket_resources[repo.name] = bucket
      self.bucket_arns[repo.name] = bucket.arn

    self.register_outputs(
      {
        "state_buckets": self.state_buckets,
        "backend_urls": self.backend_urls,
      }
    )
