"""
Pulumi entrypoint that wires together shared infrastructure components.

This stack provisions the central logging bucket, Pulumi state storage,
GitHub OIDC roles, and backups. Components are created explicitly here to
avoid import-time side effects.
"""

import pulumi

from infra import CentralLoggingBuckets, PulumiStateBuckets, S3BackupPlan
from infra import PulumiSecretsKeys
from infra.iam import GitHubOidcRoles

logging = CentralLoggingBuckets("central-logging")
state = PulumiStateBuckets("pulumi-state")
secrets = PulumiSecretsKeys("pulumi-secrets")
oidc = GitHubOidcRoles("github-oidc", secrets_key_arns=secrets.key_arns)

backup_targets = [logging.bucket.arn, *state.bucket_arns.values()]
S3BackupPlan("s3-backup", backup_target_arns=backup_targets)

pulumi.export("centralLogBucket", logging.bucket.bucket)
pulumi.export("centralLogBucketArn", logging.bucket.arn)
pulumi.export("pulumiStateBuckets", state.state_buckets)
pulumi.export("pulumiBackendUrls", state.backend_urls)
pulumi.export("pulumiSecretsKeyArns", secrets.key_arns)
pulumi.export("pulumiSecretsAliases", secrets.alias_names)
pulumi.export("pulumiSecretsProviderUrls", secrets.provider_urls)
pulumi.export("deployRoleArns", oidc.deploy_role_arns)
