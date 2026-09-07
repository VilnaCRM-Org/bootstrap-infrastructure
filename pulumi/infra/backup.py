"""AWS Backup plan for centralized logging and Pulumi state buckets."""

import json
from collections.abc import Sequence

import pulumi_aws as aws

import pulumi

from .bootstrap_settings import BootstrapSettings
from .config import settings as default_settings
from .platform_iam import platform_boundary_arn, platform_role_name
from .utils.tags import base_tags


def _environment_part(settings: BootstrapSettings | None) -> str:
    """Return the resource-name-safe environment segment."""
    configured_settings = settings or default_settings
    return configured_settings.sanitize_bucket_component(
        configured_settings.environment, "environment"
    )


def _restore_drill_bucket_pattern(
    account_id: str,
    partition: str,
    settings: BootstrapSettings | None,
) -> str:
    """Return the isolated AWS Backup restore-drill bucket ARN pattern."""
    environment = _environment_part(settings).replace(".", "-")
    return (
        f"arn:{partition}:s3:::awsbackup-restore-{environment}-bootstrap-{account_id}-*"
    )


def _restore_drill_policy(
    account_id: str,
    partition: str,
    settings: BootstrapSettings | None,
) -> str:
    """Return a scoped restore policy for isolated non-production drill buckets."""
    bucket_pattern = _restore_drill_bucket_pattern(account_id, partition, settings)
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "UseS3KmsKeysForIsolatedRestoreDrills",
                    "Effect": "Allow",
                    "Action": [
                        "kms:Decrypt",
                        "kms:DescribeKey",
                        "kms:GenerateDataKey",
                    ],
                    "Resource": f"arn:{partition}:kms:*:{account_id}:key/*",
                    "Condition": {
                        "ForAnyValue:StringLike": {
                            "kms:ResourceAliases": [
                                "alias/pulumi-*-secrets",
                                "alias/bootstrap-*-operations-cloudtrail",
                            ]
                        },
                        "StringLike": {
                            "kms:ViaService": [
                                "s3.*.amazonaws.com",
                            ]
                        },
                    },
                },
                {
                    "Sid": "RestoreToIsolatedDrillBuckets",
                    "Effect": "Allow",
                    "Action": [
                        "s3:CreateBucket",
                        "s3:GetBucketLocation",
                        "s3:GetBucketOwnershipControls",
                        "s3:GetBucketVersioning",
                        "s3:ListBucket",
                        "s3:ListBucketVersions",
                        "s3:PutBucketOwnershipControls",
                        "s3:PutBucketVersioning",
                    ],
                    "Resource": bucket_pattern,
                },
                {
                    "Sid": "RestoreObjectsToIsolatedDrillBuckets",
                    "Effect": "Allow",
                    "Action": [
                        "s3:DeleteObject",
                        "s3:GetObject",
                        "s3:GetObjectAcl",
                        "s3:GetObjectTagging",
                        "s3:GetObjectVersion",
                        "s3:GetObjectVersionAcl",
                        "s3:ListMultipartUploadParts",
                        "s3:PutObject",
                        "s3:PutObjectAcl",
                        "s3:PutObjectTagging",
                        "s3:PutObjectVersionAcl",
                    ],
                    "Resource": f"{bucket_pattern}/*",
                },
            ],
        },
        sort_keys=True,
    )


class S3BackupPlan(pulumi.ComponentResource):
    """Provision AWS Backup vault, plan, and selection for S3 buckets."""

    def __init__(
        self,
        name: str,
        *,
        settings: BootstrapSettings | None = None,
        backup_target_arns: Sequence[pulumi.Input[str]],
        opts: pulumi.ResourceOptions | None = None,
    ) -> None:
        """Initialize the AWS Backup plan for S3 resources."""
        super().__init__("bootstrap:backup:S3BackupPlan", name, None, opts)

        configured_settings = settings or default_settings
        base_opts = pulumi.ResourceOptions(parent=self)
        account_id = aws.get_caller_identity().account_id
        partition = aws.get_partition().partition

        backup_vault = aws.backup.Vault(
            f"{name}-vault",
            tags=base_tags({"Purpose": "s3-backup"}, settings=configured_settings),
            opts=base_opts,
        )

        self.vault_lock = aws.backup.VaultLockConfiguration(
            f"{name}-vault-lock",
            backup_vault_name=backup_vault.name,
            min_retention_days=90,
            # Omitting changeable_for_days keeps governance mode reversible.
            opts=pulumi.ResourceOptions(parent=self, protect=True),
        )

        backup_role = aws.iam.Role(
            f"{name}-role",
            name=platform_role_name(configured_settings, "backup"),
            permissions_boundary=platform_boundary_arn(
                account_id, configured_settings, "backup", partition=partition
            ),
            assume_role_policy=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "backup.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }
                    ],
                }
            ),
            tags=base_tags({"Purpose": "s3-backup"}, settings=configured_settings),
            opts=base_opts,
        )

        aws.iam.RolePolicyAttachment(
            f"{name}-role-attachment",
            role=backup_role.name,
            policy_arn="arn:aws:iam::aws:policy/AWSBackupServiceRolePolicyForS3Backup",
            opts=base_opts,
        )
        restore_policy = aws.iam.RolePolicy(
            f"{name}-restore-drill-policy",
            role=backup_role.name,
            policy=_restore_drill_policy(account_id, partition, configured_settings),
            opts=base_opts,
        )

        backup_plan = aws.backup.Plan(
            f"{name}-plan",
            rules=[
                aws.backup.PlanRuleArgs(
                    rule_name="daily",
                    target_vault_name=backup_vault.name,
                    schedule="cron(0 5 * * ? *)",
                    start_window=60,
                    completion_window=120,
                    lifecycle=aws.backup.PlanRuleLifecycleArgs(delete_after=90),
                    recovery_point_tags=base_tags(
                        {"Purpose": "s3-backup"},
                        settings=configured_settings,
                    ),
                )
            ],
            tags=base_tags({"Purpose": "s3-backup"}, settings=configured_settings),
            opts=base_opts,
        )

        backup_resources = list(backup_target_arns)

        aws.backup.Selection(
            f"{name}-selection",
            iam_role_arn=backup_role.arn,
            plan_id=backup_plan.id,
            resources=backup_resources,
            opts=base_opts,
        )

        self.vault = backup_vault
        self.plan = backup_plan
        self.role = backup_role
        self.restore_policy = restore_policy

        self.register_outputs(
            {
                "backup_plan_id": backup_plan.id,
                "backup_vault_name": backup_vault.name,
                "backup_vault_arn": backup_vault.arn,
            }
        )
