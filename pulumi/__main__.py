"""
Pulumi entrypoint that wires together shared infrastructure components.

This stack provisions the central logging bucket, Pulumi state storage,
GitHub OIDC roles, and backups. Components are created explicitly here to
avoid import-time side effects.
"""

import pulumi
from infra import (
    CentralLoggingBuckets,
    GitHubAutomation,
    PulumiSecretsKeys,
    PulumiStateBuckets,
    S3BackupPlan,
)
from infra.config import claude_readonly_principal_arns
from infra.iam import ClaudeReadOnlyRole, GitHubOidcRoles

logging = CentralLoggingBuckets("central-logging")
state = PulumiStateBuckets("pulumi-state")
secrets = PulumiSecretsKeys("pulumi-secrets")
oidc = GitHubOidcRoles("github-oidc", secrets_key_arns=secrets.key_arns)
automation = GitHubAutomation("github-automation")

readonly_principal_arns = claude_readonly_principal_arns()
if readonly_principal_arns:
    claude_readonly = ClaudeReadOnlyRole(
        "claude-readonly", principal_arns=readonly_principal_arns
    )
    pulumi.export("claudeReadonlyRoleArn", claude_readonly.role.arn)

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
pulumi.export("automationRoleArn", automation.role.arn)
pulumi.export("runnerRepositoryName", automation.repository.name)
pulumi.export("runnerRepositoryUrl", automation.repository.repository_url)
