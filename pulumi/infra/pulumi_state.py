"""Per-repository Pulumi state buckets and backend URLs."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from typing import cast

import pulumi_aws as aws

import pulumi

from .config import (
    ManagedRepository,
    managed_repositories,
    sanitize_bucket_component,
    settings,
    state_bucket_name_for_repo,
)
from .utils.outputs import apply_output
from .utils.tags import base_tags

_REPLICATION_ROLE_NAME_PREFIX = "PulumiStateRepl-"
_MAX_IAM_ROLE_NAME_LENGTH = 64


def _bucket_exists(name: str) -> bool:
    """Return True when the S3 bucket already exists."""
    try:
        aws.s3.get_bucket(bucket=name)
    except Exception as exc:
        message = str(exc)
        if (
            "NotFound" in message
            or "NoSuchBucket" in message
            or "404" in message
            or "couldn't find resource" in message
        ):
            return False
        raise
    else:
        return True


def _resource_suffix(repo_name: str) -> str:
    """Convert a repo name into a safe Pulumi resource suffix."""
    base = sanitize_bucket_component(repo_name, "repoSlug").replace(".", "-")
    normalized = repo_name.strip().lower()
    if normalized == base:
        return base
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:8]
    return f"{base}-{digest}"


def _truncate_role_suffix(role_suffix: str) -> str:
    """Ensure IAM role suffixes fit within AWS's 64-character limit."""
    max_suffix_len = _MAX_IAM_ROLE_NAME_LENGTH - len(_REPLICATION_ROLE_NAME_PREFIX)
    if len(role_suffix) <= max_suffix_len:
        return role_suffix
    digest = hashlib.sha256(role_suffix.encode("utf-8")).hexdigest()[:8]
    truncated_len = max(max_suffix_len - len(digest) - 1, 1)
    return f"{role_suffix[:truncated_len]}-{digest}"


def _replication_role_name(role_suffix: str) -> str:
    """Build a deterministic IAM role name for S3 replication."""
    return f"{_REPLICATION_ROLE_NAME_PREFIX}{_truncate_role_suffix(role_suffix)}"


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
      "Resource": ["{arn}", "{arn}/*"],
      "Condition": {{
        "Bool": {{"aws:SecureTransport": "false"}}
      }}
    }}
  ]
}}
"""


def _replication_assume_role_policy(arn: str) -> str:
    """Build the S3 replication trust policy for a state bucket."""
    return json.dumps(
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


def _replication_role_policy(arns: Sequence[str]) -> str:
    """Build the S3 replication permissions policy for state buckets."""
    return json.dumps(
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


class PulumiStateBuckets(pulumi.ComponentResource):
    """Create primary and replica S3 buckets to store Pulumi state per repository."""

    def __init__(
        self,
        name: str,
        *,
        repositories: Sequence[ManagedRepository] | None = None,
        replication_region: str | None = None,
        opts: pulumi.ResourceOptions | None = None,
    ) -> None:
        """Initialize state buckets for all managed repositories."""
        super().__init__("bootstrap:pulumi:PulumiStateBuckets", name, None, opts)

        repos = (
            list(repositories) if repositories is not None else managed_repositories()
        )
        self.state_buckets: dict[str, pulumi.Output[str]] = {}
        self.backend_urls: dict[str, pulumi.Output[str]] = {}
        self.bucket_resources: dict[str, aws.s3.Bucket] = {}
        self.bucket_arns: dict[str, pulumi.Output[str]] = {}

        resolved_region = (
            replication_region
            if replication_region
            else (settings.replication_region or "us-east-1")
        )
        primary_region = aws.get_region().name
        if resolved_region == primary_region:
            raise ValueError(
                "replication_region "
                f"'{resolved_region}' must differ from primary region "
                f"'{primary_region}'."
            )

        replica_provider = aws.Provider(
            f"{name}-replica-provider",
            region=resolved_region,
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
                        abort_incomplete_multipart_upload_days=7,
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
                tags=base_tags(
                    {
                        "Purpose": "pulumi-state",
                        "Repository": repo.name,
                        "App": repo.name,
                    }
                ),
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

            aws.s3.BucketOwnershipControls(
                f"{name}-ownership-{suffix}",
                bucket=bucket.id,
                rule=aws.s3.BucketOwnershipControlsRuleArgs(
                    object_ownership="BucketOwnerEnforced"
                ),
                opts=pulumi.ResourceOptions(parent=self),
            )

            aws.s3.BucketPolicy(
                f"{name}-policy-{suffix}",
                bucket=bucket.id,
                policy=apply_output(bucket.arn, _bucket_policy),
                opts=pulumi.ResourceOptions(parent=self),
            )

            replica_bucket_name = f"{bucket_name}-replication"
            if len(replica_bucket_name) > 63:
                raise ValueError(
                    "Replica bucket name "
                    f"'{replica_bucket_name}' exceeds 63 characters."
                )
            replica_import_id = (
                replica_bucket_name if _bucket_exists(replica_bucket_name) else None
            )
            replica_bucket_opts = (
                pulumi.ResourceOptions(
                    parent=self,
                    provider=replica_provider,
                    import_=replica_import_id,
                )
                if replica_import_id
                else pulumi.ResourceOptions(parent=self, provider=replica_provider)
            )

            replica_bucket = aws.s3.Bucket(
                f"{name}-replica-{suffix}",
                bucket=replica_bucket_name,
                versioning=aws.s3.BucketVersioningArgs(enabled=True),
                lifecycle_rules=[
                    aws.s3.BucketLifecycleRuleArgs(
                        id="replica-expire-old-versions",
                        enabled=True,
                        abort_incomplete_multipart_upload_days=7,
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
                tags=base_tags(
                    {
                        "Purpose": "pulumi-state-replica",
                        "Repository": repo.name,
                        "App": repo.name,
                    }
                ),
                opts=replica_bucket_opts,
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

            aws.s3.BucketOwnershipControls(
                f"{name}-replica-ownership-{suffix}",
                bucket=replica_bucket.id,
                rule=aws.s3.BucketOwnershipControlsRuleArgs(
                    object_ownership="BucketOwnerEnforced"
                ),
                opts=pulumi.ResourceOptions(parent=self, provider=replica_provider),
            )

            aws.s3.BucketPolicy(
                f"{name}-replica-policy-{suffix}",
                bucket=replica_bucket.id,
                policy=apply_output(replica_bucket.arn, _bucket_policy),
                opts=pulumi.ResourceOptions(parent=self, provider=replica_provider),
            )

            replication_role = aws.iam.Role(
                f"{name}-replication-role-{suffix}",
                name=_replication_role_name(suffix),
                assume_role_policy=apply_output(
                    bucket.arn, _replication_assume_role_policy
                ),
                tags=base_tags(
                    {
                        "Purpose": "pulumi-state-replication",
                        "Repository": repo.name,
                        "App": repo.name,
                    }
                ),
                opts=pulumi.ResourceOptions(parent=self),
            )

            replication_role_policy = aws.iam.RolePolicy(
                f"{name}-replication-role-policy-{suffix}",
                role=replication_role.id,
                policy=apply_output(
                    cast(
                        pulumi.Output[Sequence[str]],
                        pulumi.Output.all(bucket.arn, replica_bucket.arn),
                    ),
                    _replication_role_policy,
                ),
                opts=pulumi.ResourceOptions(parent=self),
            )

            aws.s3.BucketReplicationConfig(
                f"{name}-replication-config-{suffix}",
                bucket=bucket.id,
                role=replication_role.arn,
                rules=[
                    aws.s3.BucketReplicationConfigRuleArgs(
                        id=f"{suffix}-to-{resolved_region.replace('-', '')}",
                        status="Enabled",
                        destination=aws.s3.BucketReplicationConfigRuleDestinationArgs(
                            bucket=replica_bucket.arn,
                            storage_class="STANDARD",
                        ),
                    )
                ],
                opts=pulumi.ResourceOptions(
                    parent=self, depends_on=[replication_role_policy]
                ),
            )

            self.state_buckets[repo.name] = bucket.bucket
            self.backend_urls[repo.name] = pulumi.Output.concat(
                "s3://", bucket.bucket, "/state/<stack>"
            )
            self.bucket_resources[repo.name] = bucket
            self.bucket_arns[repo.name] = bucket.arn

        self.register_outputs(
            {
                "state_buckets": self.state_buckets,
                "backend_urls": self.backend_urls,
            }
        )
