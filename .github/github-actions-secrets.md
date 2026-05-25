# GitHub Actions Secrets

Privileged Pulumi workflows load account-local CI configuration directly from
AWS Secrets Manager through GitHub OIDC. Pulumi Cloud and Pulumi ESC are not
used.

Repository variables:

- `AWS_TEST_REGION`
- `AWS_TEST_PR_CI_CONFIG_ROLE_ARN`
- `AWS_TEST_CI_CONFIG_ROLE_ARN`
- `AWS_PROD_REGION`
- `AWS_PROD_PREVIEW_CI_CONFIG_ROLE_ARN`
- `AWS_PROD_CI_CONFIG_ROLE_ARN`

AWS Secrets Manager secret IDs:

- `/bootstrap-infrastructure/ci/test-pr`
- `/bootstrap-infrastructure/ci/test`
- `/bootstrap-infrastructure/ci/prod-preview`
- `/bootstrap-infrastructure/ci/prod`

Use the [AWS Secrets Manager CI cutover manual](../docs/aws-secrets-manager-ci-cutover.md)
for setup and cleanup. Do not store account IDs, role ARNs, Pulumi backend URLs,
stack lists, or KMS secrets-provider URIs in GitHub Environment variables after
AWS-only CI is green.
