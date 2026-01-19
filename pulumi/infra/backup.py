"""AWS Backup plan for centralized logging and Pulumi state buckets."""

import json
from typing import Sequence

import pulumi
import pulumi_aws as aws

from .utils.tags import base_tags


class S3BackupPlan(pulumi.ComponentResource):
  """Provision AWS Backup vault, plan, and selection for S3 buckets."""

  def __init__(
    self,
    name: str,
    *,
    backup_target_arns: Sequence[pulumi.Input[str]],
    opts: pulumi.ResourceOptions | None = None,
  ) -> None:
    """Initialize the AWS Backup plan for S3 resources."""
    super().__init__("bootstrap:backup:S3BackupPlan", name, None, opts)

    base_opts = pulumi.ResourceOptions(parent=self)

    backup_vault = aws.backup.Vault(
      f"{name}-vault",
      tags=base_tags({"Purpose": "s3-backup"}),
      opts=base_opts,
    )

    backup_role = aws.iam.Role(
      f"{name}-role",
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
      tags=base_tags({"Purpose": "s3-backup"}),
      opts=base_opts,
    )

    aws.iam.RolePolicyAttachment(
      f"{name}-role-attachment",
      role=backup_role.name,
      policy_arn="arn:aws:iam::aws:policy/AWSBackupServiceRolePolicyForS3Backup",
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
          recovery_point_tags=base_tags({"Purpose": "s3-backup"}),
        )
      ],
      tags=base_tags({"Purpose": "s3-backup"}),
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

    self.register_outputs({"backup_plan_id": backup_plan.id})
