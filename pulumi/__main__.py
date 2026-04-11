"""Pulumi entrypoint that exports baseline metadata and optional bootstrap infra."""

from __future__ import annotations

from app import EnvironmentSettings

import pulumi

settings = EnvironmentSettings("environment-settings")

pulumi.export("environment", settings.environment)
pulumi.export("serviceName", settings.service_name)
pulumi.export("stackTag", settings.stack_tag)
pulumi.export("defaultTags", settings.default_tags)

config = pulumi.Config()
bootstrap_requested = bool(
    config.get("repoSlug") or config.get_object("managedRepositories")
)

if bootstrap_requested:
    from infra import (
        CentralLoggingBuckets,
        GitHubAutomation,
        PulumiSecretsKeys,
        PulumiStateBuckets,
        S3BackupPlan,
    )
    from infra.iam import GitHubOidcRoles

    logging = CentralLoggingBuckets("central-logging")
    state = PulumiStateBuckets("pulumi-state")
    secrets = PulumiSecretsKeys("pulumi-secrets")
    oidc = GitHubOidcRoles("github-oidc", secrets_key_arns=secrets.key_arns)

    pulumi.export("centralLogBucket", logging.bucket.bucket)
    pulumi.export("centralLogBucketArn", logging.bucket.arn)
    pulumi.export("pulumiStateBuckets", state.state_buckets)
    pulumi.export("pulumiBackendUrls", state.backend_urls)
    pulumi.export("pulumiSecretsKeyArns", secrets.key_arns)
    pulumi.export("pulumiSecretsAliases", secrets.alias_names)
    pulumi.export("pulumiSecretsProviderUrls", secrets.provider_urls)
    pulumi.export("deployRoleArns", oidc.deploy_role_arns)

    if config.get("repoSlug"):
        automation = GitHubAutomation(
            "github-automation",
            oidc_provider_arn=oidc.provider.arn,
        )
        pulumi.export("automationRoleArn", automation.role.arn)
        pulumi.export("runnerRepositoryName", automation.repository.name)
        pulumi.export("runnerRepositoryUrl", automation.repository.repository_url)

    backup_targets = [logging.bucket.arn, *state.bucket_arns.values()]
    S3BackupPlan("s3-backup", backup_target_arns=backup_targets)
