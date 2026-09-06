"""Per-repository Pulumi state buckets and backend URLs."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from typing import cast

import pulumi_aws as aws

import pulumi

from .bootstrap_settings import BootstrapSettings
from .config import managed_repositories, settings
from .managed_repository import ManagedRepository
from .platform_iam import platform_boundary_arn
from .utils.outputs import apply_output
from .utils.tags import base_tags

_REPLICATION_ROLE_NAME_PREFIX = "PulumiStateRepl-"
_MAX_IAM_ROLE_NAME_LENGTH = 64
DEFAULT_REPLICATION_REGION = "eu-west-1"


def central_logging_bucket_name(region: str) -> str:
    """Compatibility wrapper for log-bucket naming."""
    return settings.central_logging_bucket_name(region)


def state_bucket_name_for_repo(repo_name: str) -> str:
    """Compatibility wrapper for state-bucket naming."""
    return settings.state_bucket_name_for_repo(repo_name)


def _bucket_exists(name: str, *, provider: aws.Provider | None = None) -> bool:
    """Return True when the S3 bucket already exists."""
    try:
        invoke_opts = (
            pulumi.InvokeOptions(provider=provider) if provider is not None else None
        )
        aws.s3.get_bucket(bucket=name, opts=invoke_opts)
    except Exception as exc:
        message = str(exc)
        if (
            "NotFound" in message
            or "NoSuchBucket" in message
            or "404" in message
            or "empty result" in message
            or "couldn't find resource" in message
        ):
            return False
        raise
    else:
        return True


def _resource_suffix(
    repo_name: str, settings_obj: BootstrapSettings | None = None
) -> str:
    """Convert a repo name into a safe Pulumi resource suffix."""
    active_settings = settings_obj or globals()["settings"]
    base = active_settings.sanitize_bucket_component(repo_name, "repoSlug").replace(
        ".",
        "-",
    )
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


def _replication_role_suffix(
    repo_name: str,
    environment: str | None = None,
    settings_obj: BootstrapSettings | None = None,
) -> str:
    """Build an environment-scoped suffix for S3 replication IAM roles."""
    active_settings = settings_obj or globals()["settings"]
    env = active_settings.sanitize_bucket_component(
        environment or active_settings.environment, "environment"
    ).replace(".", "-")
    return f"{_resource_suffix(repo_name, active_settings)}-{env}"


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


def _replication_assume_role_policy(arn: str, account_id: str) -> str:
    """Build the S3 replication trust policy for a state bucket."""
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "s3.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                    "Condition": {
                        "StringEquals": {
                            "aws:SourceArn": arn,
                            "aws:SourceAccount": account_id,
                        }
                    },
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


def _resolved_replication_region(
    replication_region: str | None,
    primary_region: str,
    settings_obj: BootstrapSettings | None = None,
) -> str:
    """Resolve and validate the replica region for state buckets."""
    active_settings = settings_obj or globals()["settings"]
    resolved_region = (
        replication_region
        or active_settings.replication_region
        or DEFAULT_REPLICATION_REGION
    )
    if resolved_region == primary_region:
        raise ValueError(
            "replication_region "
            f"'{resolved_region}' must differ from primary region "
            f"'{primary_region}'."
        )
    return resolved_region


def _resource_options(
    parent: pulumi.Resource,
    *,
    provider: aws.Provider | None = None,
    import_id: str | None = None,
    depends_on: Sequence[pulumi.Resource] | None = None,
) -> pulumi.ResourceOptions:
    """Build consistent Pulumi resource options for state infrastructure."""
    kwargs: dict[str, object] = {"parent": parent}
    if provider is not None:
        kwargs["provider"] = provider
    if import_id is not None:
        kwargs["import_"] = import_id
    if depends_on is not None:
        kwargs["depends_on"] = list(depends_on)
    return pulumi.ResourceOptions(**kwargs)


def _state_bucket_lifecycle_rule(
    rule_id: str,
) -> aws.s3.BucketLifecycleConfigurationRuleArgs:
    """Return the shared lifecycle rule for Pulumi state buckets."""
    return aws.s3.BucketLifecycleConfigurationRuleArgs(
        id=rule_id,
        status="Enabled",
        abort_incomplete_multipart_upload=aws.s3.BucketLifecycleConfigurationRuleAbortIncompleteMultipartUploadArgs(
            days_after_initiation=7
        ),
        noncurrent_version_expiration=aws.s3.BucketLifecycleConfigurationRuleNoncurrentVersionExpirationArgs(
            noncurrent_days=365
        ),
    )


def _state_bucket_encryption_rules() -> list[
    aws.s3.BucketServerSideEncryptionConfigurationRuleArgs
]:
    """Return the shared AES256 bucket encryption policy."""
    return [
        aws.s3.BucketServerSideEncryptionConfigurationRuleArgs(
            blocked_encryption_types=["SSE-C"],
            bucket_key_enabled=False,
            apply_server_side_encryption_by_default=aws.s3.BucketServerSideEncryptionConfigurationRuleApplyServerSideEncryptionByDefaultArgs(
                sse_algorithm="AES256"
            ),
        )
    ]


def _state_bucket_tags(
    purpose: str,
    repo: ManagedRepository,
    settings_obj: BootstrapSettings | None = None,
) -> dict[str, str]:
    """Return standard tags for state-bucket resources."""
    return base_tags(
        {
            "Purpose": purpose,
            "Repository": repo.name,
            "App": repo.name,
            "RepositoryProject": repo.project_name,
            **repo.tag_metadata(),
        },
        settings=settings_obj,
    )


def _replica_bucket_name(bucket_name: str, replication_region: str) -> str:
    """Return the replica bucket name while enforcing S3 limits."""
    suffix = f"-{replication_region}-replication"
    max_prefix_length = 63 - len(suffix)
    if len(bucket_name) <= max_prefix_length:
        return f"{bucket_name}{suffix}"
    digest = hashlib.sha256(bucket_name.encode("utf-8")).hexdigest()[:8]
    truncated_length = max(max_prefix_length - len(digest) - 1, 1)
    return f"{bucket_name[:truncated_length]}-{digest}{suffix}"


def _state_access_log_bucket_names(
    primary_region: str,
    replication_region: str,
    settings_obj: BootstrapSettings | None = None,
) -> tuple[str, str]:
    """Return deterministic primary/replica log-bucket names for state buckets."""
    active_settings = settings_obj or globals()["settings"]
    primary_logs_bucket = (
        central_logging_bucket_name(primary_region)
        if active_settings is globals()["settings"]
        else active_settings.central_logging_bucket_name(primary_region)
    )
    return primary_logs_bucket, _replica_bucket_name(
        primary_logs_bucket, replication_region
    )


class PulumiStateBuckets(pulumi.ComponentResource):
    """Create primary and replica S3 buckets to store Pulumi state per repository."""

    def __init__(
        self,
        name: str,
        *,
        repositories: Sequence[ManagedRepository] | None = None,
        log_delivery_dependencies: Sequence[pulumi.Resource] | None = None,
        access_log_prefix: str = "server-access/",
        settings: BootstrapSettings | None = None,
        replication_region: str | None = None,
        replication_permissions_boundary: str | None = None,
        manage_replication_role: bool = True,
        opts: pulumi.ResourceOptions | None = None,
    ) -> None:
        """Initialize state buckets for all managed repositories."""
        super().__init__("bootstrap:pulumi:PulumiStateBuckets", name, None, opts)

        self._settings = settings or globals()["settings"]
        self._access_log_prefix = access_log_prefix
        self._replication_permissions_boundary = replication_permissions_boundary
        self._manage_replication_role = manage_replication_role
        self.state_buckets: dict[str, pulumi.Output[str]] = {}
        self.backend_urls: dict[str, pulumi.Output[str]] = {}
        self.bucket_resources: dict[str, aws.s3.Bucket] = {}
        self.bucket_arns: dict[str, pulumi.Output[str]] = {}
        self._log_delivery_dependencies = (
            list(log_delivery_dependencies) if log_delivery_dependencies else None
        )

        primary_region = aws.get_region().region
        resolved_region = _resolved_replication_region(
            replication_region, primary_region, self._settings
        )
        primary_logs_bucket, replica_logs_bucket = _state_access_log_bucket_names(
            primary_region, resolved_region, self._settings
        )
        replica_provider = aws.Provider(
            f"{name}-replica-provider",
            region=resolved_region,
            opts=_resource_options(self),
        )

        repos = (
            list(repositories) if repositories is not None else managed_repositories()
        )
        for repo in repos:
            self._register_repository(
                name,
                repo,
                primary_logs_bucket=primary_logs_bucket,
                replica_logs_bucket=replica_logs_bucket,
                resolved_region=resolved_region,
                replica_provider=replica_provider,
            )

        self.register_outputs(
            {
                "state_buckets": self.state_buckets,
                "backend_urls": self.backend_urls,
            }
        )

    def _register_repository(
        self,
        component_name: str,
        repo: ManagedRepository,
        *,
        primary_logs_bucket: str,
        replica_logs_bucket: str,
        resolved_region: str,
        replica_provider: aws.Provider,
    ) -> None:
        """Create state bucket resources for one managed repository."""
        bucket_name = (
            state_bucket_name_for_repo(repo.name)
            if self._settings is globals()["settings"]
            else self._settings.state_bucket_name_for_repo(repo.name)
        )
        suffix = _resource_suffix(repo.name, self._settings)
        role_suffix = _replication_role_suffix(repo.name, settings_obj=self._settings)
        bucket, bucket_versioning = self._create_bucket(
            f"{component_name}-{suffix}",
            bucket_name=bucket_name,
            lifecycle_rule_id="expire-old-versions",
            purpose="pulumi-state",
            repo=repo,
            logging_target_bucket=primary_logs_bucket,
            access_block_name=f"{component_name}-pab-{suffix}",
            ownership_name=f"{component_name}-ownership-{suffix}",
            policy_name=f"{component_name}-policy-{suffix}",
            import_id=bucket_name if _bucket_exists(bucket_name) else None,
        )
        replica_bucket, replica_bucket_versioning = self._create_bucket(
            f"{component_name}-replica-{suffix}",
            bucket_name=_replica_bucket_name(bucket_name, resolved_region),
            lifecycle_rule_id="replica-expire-old-versions",
            purpose="pulumi-state-replica",
            repo=repo,
            logging_target_bucket=replica_logs_bucket,
            access_block_name=f"{component_name}-replica-pab-{suffix}",
            ownership_name=f"{component_name}-replica-ownership-{suffix}",
            policy_name=f"{component_name}-replica-policy-{suffix}",
            provider=replica_provider,
            import_id=self._replica_import_id(
                bucket_name, resolved_region, replica_provider
            ),
        )
        replication_role, replication_role_policy = self._create_replication_role(
            component_name,
            repo=repo,
            suffix=suffix,
            role_suffix=role_suffix,
            bucket=bucket,
            replica_bucket=replica_bucket,
        )
        aws.s3.BucketReplicationConfig(
            f"{component_name}-replication-config-{suffix}",
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
            opts=_resource_options(
                self,
                depends_on=[
                    *([replication_role_policy] if replication_role_policy else []),
                    bucket_versioning,
                    replica_bucket_versioning,
                ],
            ),
        )
        self._record_repo_outputs(repo.name, bucket)

    def _create_bucket(
        self,
        resource_name: str,
        *,
        bucket_name: str,
        lifecycle_rule_id: str,
        purpose: str,
        repo: ManagedRepository,
        logging_target_bucket: str,
        access_block_name: str,
        ownership_name: str,
        policy_name: str,
        provider: aws.Provider | None = None,
        import_id: str | None = None,
    ) -> tuple[aws.s3.Bucket, aws.s3.BucketVersioning]:
        """Create one managed Pulumi state bucket and baseline safeguards."""
        bucket = aws.s3.Bucket(
            resource_name,
            bucket=bucket_name,
            tags=_state_bucket_tags(purpose, repo, self._settings),
            opts=_resource_options(
                self,
                provider=provider,
                import_id=import_id,
                depends_on=self._log_delivery_dependencies,
            ),
        )
        versioning = self._configure_bucket_settings(
            resource_name,
            bucket=bucket,
            lifecycle_rule_id=lifecycle_rule_id,
            logging_target_bucket=logging_target_bucket,
            provider=provider,
        )
        self._configure_bucket_safeguards(
            access_block_name,
            ownership_name,
            policy_name,
            bucket=bucket,
            provider=provider,
        )
        return bucket, versioning

    def _configure_bucket_settings(
        self,
        resource_name: str,
        *,
        bucket: aws.s3.Bucket,
        lifecycle_rule_id: str,
        logging_target_bucket: str,
        provider: aws.Provider | None = None,
    ) -> aws.s3.BucketVersioning:
        """Attach versioning, logging, lifecycle, and encryption resources."""
        versioning = aws.s3.BucketVersioning(
            f"{resource_name}-versioning",
            bucket=bucket.id,
            versioning_configuration=aws.s3.BucketVersioningVersioningConfigurationArgs(
                status="Enabled"
            ),
            opts=_resource_options(self, provider=provider, depends_on=[bucket]),
        )
        aws.s3.BucketLogging(
            f"{resource_name}-logging",
            bucket=bucket.id,
            target_bucket=logging_target_bucket,
            target_prefix=pulumi.Output.format(
                "{}{}/", self._access_log_prefix, bucket.bucket
            ),
            opts=_resource_options(
                self,
                provider=provider,
                depends_on=[bucket, *(self._log_delivery_dependencies or [])],
            ),
        )
        aws.s3.BucketLifecycleConfiguration(
            f"{resource_name}-lifecycle",
            bucket=bucket.id,
            rules=[_state_bucket_lifecycle_rule(lifecycle_rule_id)],
            opts=_resource_options(self, provider=provider, depends_on=[bucket]),
        )
        aws.s3.BucketServerSideEncryptionConfiguration(
            f"{resource_name}-encryption",
            bucket=bucket.id,
            rules=_state_bucket_encryption_rules(),
            opts=_resource_options(self, provider=provider, depends_on=[bucket]),
        )
        return versioning

    def _configure_bucket_safeguards(
        self,
        access_block_name: str,
        ownership_name: str,
        policy_name: str,
        *,
        bucket: aws.s3.Bucket,
        provider: aws.Provider | None = None,
    ) -> None:
        """Attach public-access, ownership, and TLS guards to a bucket."""
        aws.s3.BucketPublicAccessBlock(
            access_block_name,
            bucket=bucket.id,
            block_public_acls=True,
            block_public_policy=True,
            ignore_public_acls=True,
            restrict_public_buckets=True,
            opts=_resource_options(self, provider=provider),
        )
        aws.s3.BucketOwnershipControls(
            ownership_name,
            bucket=bucket.id,
            rule=aws.s3.BucketOwnershipControlsRuleArgs(
                object_ownership="BucketOwnerEnforced"
            ),
            opts=_resource_options(self, provider=provider),
        )
        aws.s3.BucketPolicy(
            policy_name,
            bucket=bucket.id,
            policy=apply_output(bucket.arn, _bucket_policy),
            opts=_resource_options(self, provider=provider),
        )

    def _replica_import_id(
        self,
        bucket_name: str,
        replication_region: str,
        replica_provider: aws.Provider,
    ) -> str | None:
        """Return the import ID for an existing replica bucket, if present."""
        replica_name = _replica_bucket_name(bucket_name, replication_region)
        if _bucket_exists(replica_name, provider=replica_provider):
            return replica_name
        return None

    def _create_replication_role(
        self,
        component_name: str,
        *,
        repo: ManagedRepository,
        suffix: str,
        role_suffix: str,
        bucket: aws.s3.Bucket,
        replica_bucket: aws.s3.Bucket,
    ) -> tuple[aws.iam.Role, aws.iam.RolePolicy | None]:
        """Create the replication IAM role and inline policy for one bucket pair."""
        if not self._manage_replication_role:
            return aws.iam.Role.get(
                f"{component_name}-replication-role-{suffix}",
                _replication_role_name(role_suffix),
                opts=_resource_options(self),
            ), None
        invoke_options = pulumi.InvokeOptions(parent=self)
        account_id = aws.get_caller_identity(opts=invoke_options).account_id
        replication_role = aws.iam.Role(
            f"{component_name}-replication-role-{suffix}",
            name=_replication_role_name(role_suffix),
            permissions_boundary=(
                self._replication_permissions_boundary
                or platform_boundary_arn(
                    account_id,
                    self._settings,
                    "state-replication",
                    partition=aws.get_partition(opts=invoke_options).partition,
                )
            ),
            assume_role_policy=apply_output(
                bucket.arn,
                lambda arn: _replication_assume_role_policy(arn, account_id),
            ),
            tags=_state_bucket_tags(
                "pulumi-state-replication",
                repo,
                self._settings,
            ),
            opts=_resource_options(self),
        )
        replication_role_policy = aws.iam.RolePolicy(
            f"{component_name}-replication-role-policy-{suffix}",
            role=replication_role.id,
            policy=apply_output(
                cast(
                    pulumi.Output[Sequence[str]],
                    pulumi.Output.all(bucket.arn, replica_bucket.arn),
                ),
                _replication_role_policy,
            ),
            opts=_resource_options(self),
        )
        return replication_role, replication_role_policy

    def _record_repo_outputs(self, repo_name: str, bucket: aws.s3.Bucket) -> None:
        """Store bucket outputs on the component for downstream exports."""
        self.state_buckets[repo_name] = bucket.bucket
        self.backend_urls[repo_name] = pulumi.Output.concat(
            "s3://", bucket.bucket, "/state/<stack>"
        )
        self.bucket_resources[repo_name] = bucket
        self.bucket_arns[repo_name] = bucket.arn
