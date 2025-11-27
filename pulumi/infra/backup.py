import json

import pulumi
import pulumi_aws as aws

from .logging_bucket import bucket as central_logs_bucket
from .pulumi_state import state_bucket_resources
from .utils.tags import base_tags


backup_vault = aws.backup.Vault(
  "s3BackupVault",
  tags=base_tags({"Purpose": "s3-backup"}),
)

backup_role = aws.iam.Role(
  "s3BackupServiceRole",
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
)

aws.iam.RolePolicyAttachment(
  "s3BackupServiceRoleAttachment",
  role=backup_role.name,
  policy_arn="arn:aws:iam::aws:policy/AWSBackupServiceRolePolicyForS3Backup",
)

backup_plan = aws.backup.Plan(
  "s3BackupPlan",
  rules=[
    aws.backup.PlanRuleArgs(
      rule_name="daily",
      target_vault_name=backup_vault.name,
      schedule="cron(0 5 * * ? *)",
      lifecycle=aws.backup.PlanRuleLifecycleArgs(cold_storage_after=0, delete_after=90),
      recovery_point_tags=base_tags({"Purpose": "s3-backup"}),
    )
  ],
  tags=base_tags({"Purpose": "s3-backup"}),
)

backup_resources = [central_logs_bucket.arn] + [bucket.arn for bucket in state_bucket_resources.values()]

aws.backup.Selection(
  "s3BackupSelection",
  iam_role_arn=backup_role.arn,
  plan_id=backup_plan.id,
  resources=backup_resources,
)
