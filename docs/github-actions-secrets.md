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
- `AWS_TEST_PR_CI_CONFIG_ROLE_ARN`
- `AWS_TEST_CI_CONFIG_ROLE_ARN`
- `AWS_PROD_REGION`
- `AWS_PROD_PREVIEW_CI_CONFIG_ROLE_ARN`
- `AWS_PROD_CI_CONFIG_ROLE_ARN`

The role ARNs are not secret. Each role is trusted by GitHub OIDC and scoped to
one fixed CI secret suffix.

The dedicated governance apply runner (`.github/workflows/pulumi-governance.yml`)
reads its own non-secret repo variables, because its apply jobs run under
`environment: governance` and cannot assume the `environment:test`/`prod`-trusted
CI-config roles above (see `docs/governance-stack.md`, Step 1b/Step 5):

- `AWS_GOVERNANCE_TEST_APPLY_ROLE_ARN` / `AWS_GOVERNANCE_PROD_APPLY_ROLE_ARN`
  (per-account governance automation role ARNs, trust = `environment:governance`)
- `AWS_GOVERNANCE_TEST_ACCOUNT_ID` / `AWS_GOVERNANCE_PROD_ACCOUNT_ID`
- `AWS_GOVERNANCE_TEST_BACKEND_URL` / `AWS_GOVERNANCE_PROD_BACKEND_URL`
- `AWS_GOVERNANCE_TEST_SECRETS_PROVIDER` / `AWS_GOVERNANCE_PROD_SECRETS_PROVIDER`

## Fixed Secret IDs

| CI suffix | AWS Secrets Manager secret ID |
| --- | --- |
| `test-pr` | `/bootstrap-infrastructure/ci/test-pr` |
| `test` | `/bootstrap-infrastructure/ci/test` |
| `prod-preview` | `/bootstrap-infrastructure/ci/prod-preview` |
| `prod` | `/bootstrap-infrastructure/ci/prod` |

The Pulumi `test` stack manages `test-pr` and `test`. The Pulumi `prod` stack
manages `prod-preview` and `prod`. Stack outputs include
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
Use [GitHub CI AWS bootstrap stack](github-ci-bootstrap-stack.md) for the
one-time local administrator apply that creates the OIDC roles and CI secret
payloads without Pulumi Cloud.

Never paste secret payloads into chat, GitHub issues, workflow logs, docs, or
Pulumi config. Use `put-secret-value` with a private local JSON file, and use
`describe-secret` for metadata-only verification.

## Legacy GitHub Environment Cleanup

After AWS-only privileged CI is green, run **GitHub Environment Legacy Variable Cleanup**
with `dry_run=true`. The workflow needs a
`GH_ENVIRONMENT_ADMIN_TOKEN` with repository **Environments** write permission.
Review the planned deletion of legacy keys, including old `PULUMI_PR_*`
variables, then rerun with `dry_run=false` and the documented confirmation
sentence from the cutover manual.

If legacy operations-alert issues need reconciliation and no new queued alert
exists to create a canonical issue, use **Operations Alert Canonical Backfill**
with an SRE-confirmed `stable_event_json` object first. Then use
**Operations Alert Legacy Reconcile** and provide the required
`sre_confirmation_reference`.
