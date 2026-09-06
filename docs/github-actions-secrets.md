# GitHub Actions Secrets and Variables

Privileged Pulumi workflows use GitHub OIDC and AWS Secrets Manager. Pulumi
Cloud and Pulumi ESC are not used for CI configuration.

Release workflows may use `REPO_GITHUB_TOKEN` when present and fall back to `GITHUB_TOKEN`
for repository-scoped release automation.

## Source Of Truth

AWS Secrets Manager is the account-configuration boundary and stores
account-local CI values. GitHub stores only non-secret metadata needed to find
and read those values:

- `AWS_TEST_REGION`
- `AWS_TEST_ACCOUNT_ID`
- `AWS_TEST_PR_CI_CONFIG_ROLE_ARN`
- `AWS_TEST_CI_CONFIG_ROLE_ARN`
- `AWS_PROD_REGION`
- `AWS_PROD_ACCOUNT_ID`
- `AWS_PROD_PREVIEW_CI_CONFIG_ROLE_ARN`
- `AWS_PROD_CI_CONFIG_ROLE_ARN`

The role ARNs and account IDs are not secret. Each role is trusted by GitHub OIDC
and scoped to one fixed CI secret suffix. The loader checks the independently
configured account ID before assuming the role, then verifies the returned CI
configuration belongs to that same account.

The config-reader policy permits the AWS-managed Secrets Manager key's existing
decrypt grant only when the request comes through Secrets Manager in the expected
region and carries the exact owned secret ARN in its encryption context. Separate
explicit denials reject a missing or different service and a missing or different
secret ARN. Direct KMS decryption, Pulumi secrets decryption and other secrets
remain denied; no general KMS allow is added.

The installed trusted controller retains separate governance routing. The operator
and governance programs are separate successor work. The config-reader repair
changes existing inline policies without provisioning roles or broadening
platform deployment permissions.

Every command environment allows exactly the `main` branch through a custom
deployment branch rule. Administrator bypass is disabled; the sole reviewer is
`Kravalg`, with self-review prevented. The evidence signing-key environment also
allows only `main`, with no reviewer gate because it publishes verified results
after the protected apply jobs. Verify the actual deployment branch rules through
the separate GitHub API endpoint; the environment mode alone is insufficient.

## Fixed Secret IDs

| CI suffix | AWS Secrets Manager secret ID |
| --- | --- |
| `test-pr` | `/bootstrap-infrastructure/ci/test-pr` |
| `test` | `/bootstrap-infrastructure/ci/test` |
| `prod-preview` | `/bootstrap-infrastructure/ci/prod-preview` |
| `prod` | `/bootstrap-infrastructure/ci/prod` |

The separately reviewed operator stack owns `test-pr` and `test` in the test
account, and `prod-preview` and `prod` in production. The platform consumes
references and must not take duplicate ownership. Operator stack outputs include
`ciConfigurationSecretIds`, `ciConfigurationSecretArns`, and
`githubCiConfigReadRoleArns`.

## Runtime Contract

`.github/actions/load-aws-ci-env`:

1. derives the fixed Secrets Manager secret ID from the workflow input suffix;
2. assumes the matching `GitHubCiConfigRead-*` role through GitHub OIDC;
3. reads the JSON payload with AWS CLI;
4. validates required keys and account ID without printing values;
5. exports the validated environment variables for later workflow steps.

Workflows must not accept account, role, backend, stack, or secret-provider
values from pull request text, issue comments, repository dispatch payloads, or
GitHub Environment variables.

## Required JSON Keys

Common keys:

- `AWS_ACCOUNT_ID`
- `AWS_REGION`
- `PULUMI_BACKEND_URL`
- `PULUMI_SECRETS_PROVIDER`

Purpose-specific keys:

- `AWS_PREVIEW_ROLE_ARN`
- `AWS_APPLY_ROLE_ARN`
- `AWS_DRIFT_ROLE_ARN`
- `AWS_OPERATIONS_ALERT_TRIAGE_ROLE_ARN`
- `PULUMI_PREVIEW_STACKS`
- `PULUMI_DRIFT_STACKS`
- `OPERATIONS_ALERT_QUEUE_NAME`
- `OPERATIONS_TOPIC_ARN`
- `OPERATIONS_CLOUDTRAIL_NAME`

## Operator Runbook

Follow [AWS Secrets Manager CI cutover manual](aws-secrets-manager-ci-cutover.md)
to refresh AWS CLI credentials, apply Pulumi stacks, populate Secrets Manager
payloads, set GitHub variables, verify privileged CI, and remove legacy GitHub
Environment variables.
The operator program at `pulumi/github-ci-bootstrap` is a separate #60
successor dependency, not included in this change. Use only its independently
reviewed checkout and ownership/migration procedure; do not recreate live roles.

Never paste secret payloads into chat, GitHub issues, workflow logs, docs, or
Pulumi config. Use `put-secret-value` with a private local JSON file, and use
`describe-secret` for metadata-only verification.

## Legacy GitHub Environment Cleanup

After AWS-only privileged CI is green, run **GitHub Environment Legacy Variable Cleanup**
with `dry_run=true`. The workflow needs a
`GH_ENVIRONMENT_ADMIN_TOKEN` with repository **Environments** write permission.
Store it only in the protected `governance` environment, never as a repository
secret. The cleanup job is restricted to `main` and waits for the environment
reviewer before receiving this token. Remove the temporary token after cutover.
Review the planned deletion of legacy keys, including old `PULUMI_PR_*`
variables, then rerun with `dry_run=false` and the documented confirmation
sentence from the cutover manual.

If legacy operations-alert issues need reconciliation and no new queued alert
exists to create a canonical issue, use **Operations Alert Canonical Backfill**
with an SRE-confirmed `stable_event_json` object first. Then use
**Operations Alert Legacy Reconcile** and provide the required
`sre_confirmation_reference`.
