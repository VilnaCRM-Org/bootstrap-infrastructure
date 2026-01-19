"""
Pulumi entrypoint that wires together shared infrastructure components.

This stack provisions the central logging bucket, Pulumi state storage,
GitHub OIDC roles, and backups. Components are created explicitly here to
avoid import-time side effects.
"""

import pulumi

from infra import CentralLoggingBuckets, PulumiStateBuckets, S3BackupPlan
from infra.iam import GitHubOidcRoles

logging = CentralLoggingBuckets("central-logging")
state = PulumiStateBuckets("pulumi-state")
oidc = GitHubOidcRoles("github-oidc")

backup_targets = [logging.bucket.arn] + list(state.bucket_arns.values())
S3BackupPlan("s3-backup", backup_target_arns=backup_targets)

pulumi.export("centralLogBucket", logging.bucket.bucket)
pulumi.export("centralLogBucketArn", logging.bucket.arn)
pulumi.export("pulumiStateBuckets", state.state_buckets)
pulumi.export("pulumiBackendUrls", state.backend_urls)
pulumi.export("deployRoleArns", oidc.deploy_role_arns)
