# AWS Secrets Manager CI Cutover Manual

This project does not require Pulumi Cloud or Pulumi ESC for privileged CI.
GitHub Actions uses GitHub OIDC to assume AWS roles, reads account-local CI
configuration from AWS Secrets Manager, and then runs Pulumi CLI with the S3
backend and AWS KMS secrets provider.

## Architecture

Runtime flow:

1. GitHub Actions requests an OIDC token for the fixed workflow job.
2. `.github/actions/load-aws-ci-env` assumes the matching
   `GitHubCiConfigRead-*` role in AWS.
3. The action reads one AWS Secrets Manager JSON secret.
4. The action validates required keys without printing values.
5. The workflow assumes the preview, apply, drift, or operations role from the
   loaded JSON.
6. Pulumi uses `PULUMI_BACKEND_URL=s3://...` and
   `PULUMI_SECRETS_PROVIDER=awskms://...`.

Pulumi Cloud, Pulumi ESC, and `PULUMI_ACCESS_TOKEN` are not part of this setup.

## Required GitHub Variables

Set these repository variables. They are metadata, not secrets:

| Variable | Purpose |
| --- | --- |
| `AWS_TEST_REGION` | Region containing the test account CI config secrets |
| `AWS_TEST_PR_CI_CONFIG_ROLE_ARN` | Reads `/bootstrap-infrastructure/ci/test-pr` |
| `AWS_TEST_CI_CONFIG_ROLE_ARN` | Reads `/bootstrap-infrastructure/ci/test` |
| `AWS_PROD_REGION` | Region containing the prod account CI config secrets |
| `AWS_PROD_PREVIEW_CI_CONFIG_ROLE_ARN` | Reads `/bootstrap-infrastructure/ci/prod-preview` |
| `AWS_PROD_CI_CONFIG_ROLE_ARN` | Reads `/bootstrap-infrastructure/ci/prod` |

The Pulumi stack output `githubCiConfigReadRoleArns` contains the role ARNs.
The one-time bootstrap stack also exports `githubVariables` with these values.

## Required Secrets Manager Payloads

Create one JSON secret value per fixed CI suffix. The one-time bootstrap stack
writes these payloads automatically by default; use manual `put-secret-value`
only when `github-ci-bootstrap:writeSecretValues` is disabled or a repair is
needed.

| Suffix | Secret ID |
| --- | --- |
| `test-pr` | `/bootstrap-infrastructure/ci/test-pr` |
| `test` | `/bootstrap-infrastructure/ci/test` |
| `prod-preview` | `/bootstrap-infrastructure/ci/prod-preview` |
| `prod` | `/bootstrap-infrastructure/ci/prod` |

Common keys:

- `AWS_ACCOUNT_ID`
- `AWS_REGION`
- `PULUMI_BACKEND_URL`
- `PULUMI_SECRETS_PROVIDER`

Role keys by workflow need:

- `AWS_PREVIEW_ROLE_ARN`
- `AWS_APPLY_ROLE_ARN`
- `AWS_DRIFT_ROLE_ARN`
- `AWS_OPERATIONS_ALERT_TRIAGE_ROLE_ARN`

Other supported keys:

- `PULUMI_PREVIEW_STACKS`
- `PULUMI_DRIFT_STACKS`
- `OPERATIONS_ALERT_QUEUE_NAME`
- `OPERATIONS_TOPIC_ARN`
- `OPERATIONS_CLOUDTRAIL_NAME`

Use `put-secret-value` from a local private JSON file. Do not paste secret
payloads into chat, GitHub issues, workflow logs, Pulumi config, or docs. Do not
use `get-secret-value` for verification because it prints secret material.

## Fix Local AWS CLI For Test

First remove stale environment credentials from the shell that will run the
cutover:

```bash
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_PROFILE
```

If the test account uses AWS SSO:

```bash
aws sso login --profile <test-profile>
AWS_PROFILE=<test-profile> aws sts get-caller-identity --output json
```

If the test account uses another credential broker, run the approved login
command for that broker, then verify:

```bash
AWS_PROFILE=<test-profile> aws sts get-caller-identity --output json
```

The command must return the expected 12-digit test account ID. Share only the
profile name and account ID if help is needed; never share access keys or
session tokens.

## Bootstrap Or Update AWS Resources

Apply the isolated Pulumi project at `pulumi/github-ci-bootstrap` with
administrator credentials for the owning AWS account. The stack creates:

- Secrets Manager secret containers
- one `GitHubCiConfigRead-*` role per CI suffix
- `GitHubCiPreview-*`, `GitHubCiApply-*`, and `GitHubCiDrift-*` roles
- the test-account `OperationsAlertTriage-*` role
- least-privilege policies scoped to CI job purpose
- GitHub OIDC trust limited by repo subject and workflow ref
- encrypted AWS Secrets Manager CI JSON payloads by default

Use the detailed [GitHub CI AWS bootstrap stack manual](github-ci-bootstrap-stack.md)
for AWS CLI profile repair, one-time local admin apply commands, role and
permission mapping, and post-apply verification.

After each apply, capture:

```bash
pulumi -C pulumi/github-ci-bootstrap stack output githubVariables --stack test
pulumi -C pulumi/github-ci-bootstrap stack output ciConfigurationSecretIds --stack test
pulumi -C pulumi/github-ci-bootstrap stack output githubCiConfigReadRoleArns --stack test
pulumi -C pulumi/github-ci-bootstrap stack output githubCiDeploymentRoleArns --stack test
pulumi -C pulumi/github-ci-bootstrap stack output operationsAlertTriageRoleArn --stack test

pulumi -C pulumi/github-ci-bootstrap stack output githubVariables --stack prod
pulumi -C pulumi/github-ci-bootstrap stack output ciConfigurationSecretIds --stack prod
pulumi -C pulumi/github-ci-bootstrap stack output githubCiConfigReadRoleArns --stack prod
pulumi -C pulumi/github-ci-bootstrap stack output githubCiDeploymentRoleArns --stack prod
```

## Populate Secret Values Manually If Needed

The one-time bootstrap stack writes the CI secret values by default. If
`github-ci-bootstrap:writeSecretValues` is disabled or a payload needs repair,
prepare a private JSON file for each suffix and write it with:

```bash
AWS_PROFILE=<profile> aws secretsmanager put-secret-value \
  --secret-id /bootstrap-infrastructure/ci/<suffix> \
  --secret-string file://<private-payload>.json
```

Verify metadata only:

```bash
AWS_PROFILE=<profile> aws secretsmanager describe-secret \
  --secret-id /bootstrap-infrastructure/ci/<suffix>
```

Do not run `aws secretsmanager get-secret-value` during verification.
Do not use `get-secret-value` for verification.

## Configure GitHub

Set repository variables from the stack outputs:

```bash
gh variable set AWS_TEST_REGION --body '<region>'
gh variable set AWS_TEST_PR_CI_CONFIG_ROLE_ARN --body '<test-pr-role-arn>'
gh variable set AWS_TEST_CI_CONFIG_ROLE_ARN --body '<test-role-arn>'
gh variable set AWS_PROD_REGION --body '<region>'
gh variable set AWS_PROD_PREVIEW_CI_CONFIG_ROLE_ARN --body '<prod-preview-role-arn>'
gh variable set AWS_PROD_CI_CONFIG_ROLE_ARN --body '<prod-role-arn>'
```

The privileged workflows must keep `id-token: write`. They must not use
`PULUMI_ACCESS_TOKEN`, Pulumi Cloud, Pulumi ESC, or GitHub Environment variables
for account-local CI configuration.

## Validate

Re-run these checks after the variables and AWS secrets are present:

- `Pulumi PR Guardrails`
- `Pulumi Test Deploy`
- `Pulumi Production` preview and protected apply
- `Nightly Guardrails`
- `Operations Alert Triage`
- `Well-Architected Evidence`

Expected loader summary:

- source of truth is AWS Secrets Manager
- Pulumi Cloud/ESC is not used
- secret values are not printed

## Legacy GitHub Environment Cleanup

After AWS-only privileged CI is green, run
`GitHub Environment Legacy Variable Cleanup` with `dry_run=true`. Review the
planned deletions. The workflow requires `GH_ENVIRONMENT_ADMIN_TOKEN` because
GitHub's default token cannot delete repository environment variables. Then
rerun with `dry_run=false` and this confirmation:

```text
I confirm AWS Secrets Manager-backed privileged CI is green and legacy GitHub Environment variables can be removed
```

Run `Operations Alert Legacy Reconcile` separately if legacy alert issues need
manual reconciliation, and provide the required `sre_confirmation_reference`.
If no new queued alert exists to create a canonical fingerprinted issue, run
`Operations Alert Canonical Backfill` first with one SRE-confirmed
`stable_event_json` object and this confirmation:

```text
I confirm these stable fields represent the canonical operations alert stream
```

Use this reconciliation confirmation when closing duplicates:

```text
I confirm these legacy issues match the canonical operations alert stream
```
