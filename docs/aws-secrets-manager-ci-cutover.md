# AWS Secrets Manager CI Cutover Manual

> **Staged activation:** The installed scheduled v1 workflow remains byte-for-byte
> unchanged. The v2 consumer is staged at
> [`docs/examples/operations-alert-triage-v2.yml`](examples/operations-alert-triage-v2.yml). GitHub does not execute workflows
> from this documentation path. Local acknowledgment tests exercise that exact
> template and do not attest to live v2 consumption. Backfill/reconcile are
> protected manual preparation only; existing scheduling is not disabled.

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
| `AWS_TEST_ACCOUNT_ID` | Independently pinned test account ID |
| `AWS_TEST_REGION` | Region containing the test account CI config secrets |
| `AWS_TEST_PR_CI_CONFIG_ROLE_ARN` | Reads `/bootstrap-infrastructure/ci/test-pr` |
| `AWS_TEST_CI_CONFIG_ROLE_ARN` | Reads `/bootstrap-infrastructure/ci/test` |
| `AWS_PROD_ACCOUNT_ID` | Independently pinned production account ID |
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

**Operator prerequisite:** `pulumi/github-ci-bootstrap` is included in this source.
Follow the [operator guide](github-ci-bootstrap-stack.md). The commands below
apply only in an approved operator checkout after exact state ownership and
migration review. The platform
consumes existing control resources; do not create duplicate owners or attach
`AdministratorAccess` to CI roles. Never use this section to rerun an old import
or saved plan against an already migrated stack.


Apply the isolated Pulumi project at `pulumi/github-ci-bootstrap` with
approved short-lived operator credentials for the owning AWS account. The stack creates:

- Secrets Manager secret containers
- one `GitHubCiConfigRead-*` role per CI suffix
- `GitHubCiPreview-*`, `GitHubCiApply-*`, and `GitHubCiDrift-*` roles
- the test-account `OperationsAlertTriage-*` role
- least-privilege policies scoped to CI job purpose
- GitHub OIDC trust limited by exact repository/owner IDs, subject, workflow and ref
- encrypted AWS Secrets Manager CI JSON payloads by default

Review that operator project's provisioning, permissions, saved-plan and rollback
procedure before running it. This source assembly grants no new operator scope.

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
gh variable set AWS_TEST_ACCOUNT_ID --body '<test-account-id>'
gh variable set AWS_TEST_REGION --body '<region>'
gh variable set AWS_TEST_PR_CI_CONFIG_ROLE_ARN --body '<test-pr-role-arn>'
gh variable set AWS_TEST_CI_CONFIG_ROLE_ARN --body '<test-role-arn>'
gh variable set AWS_PROD_ACCOUNT_ID --body '<prod-account-id>'
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
GitHub's default token cannot delete repository environment variables. Store
this temporary token only in the protected `governance` environment. The job
requires main and reviewer approval. Remove the token after cleanup. Then
rerun with `dry_run=false`. Supply this confirmation for both runs; the explicit
`dry_run` input still controls whether any deletion is attempted:

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

## Preserved Execution And Saved-Plan Controls

Retain protected `test`, `test-preview`, `prod-preview`, `prod`, `governance`,
`governance-preview`, and `operations-alert-reconcile` environments and the
main-only evidence environment. Fixed secret suffixes are configuration selectors,
not permission to remove these approval and branch boundaries. Cleanup deletes
only the listed legacy environment variables, never independent repository
account pins or environment protections. Verify no stale AWS trust subjects
remain using current immutable-ID, exact workflow and ref contracts.

Run `make pulumi-plan`, review exact account/backend/project/stack/source and
policy evidence, then `make pulumi-up-plan`. Shared state uses the existing
checkpoint's KMS encrypted data key: the saved-plan helper reconstructs private
stack configuration and verifies key owner/account before replay. A provider URL
alone cannot supply cross-job encryption continuity. Never print encrypted or
plaintext provider material, use a direct apply fallback, or cancel an unknown lock.

Fingerprint-v2 issue cutover needs the SRE procedure in
[Alert routing evidence](alert-routing-evidence.md#fingerprint-version-2-cutover-2026-09-06-source-correction).
Record fresh hosted checks, actual routing and redelivery evidence separately;
local tests and this manual do not constitute current live acceptance.

## Promote The Staged v2 Consumer

No valid v1-to-v2 mapping receipt was present during source assembly. Keep
`.github/workflows/operations-alert-triage.yml` unchanged until the SRE has
recorded the full stable stream identities, v1-to-v2 mappings, uncertainty and
protected backfill/reconciliation receipts. New v2 canonical issues may be
prepared manually while the old consumer remains scheduled; they must not be
represented as successful v2 queue delivery.

Then open a reviewed source change that copies the exact staged template from
`docs/examples/operations-alert-triage-v2.yml` to the live workflow, switches the
v2 structural/integration tests to that live path, and replaces the legacy-byte
preservation assertion with the actual cutover receipt contract. Re-run lint,
classification, acknowledgment and controller/security checks. Validate the
expected SNS topic metadata, the applied exact `Operations Alert Issue Triage`
workflow-name OIDC condition, current main-only trust and role scope. Both alert
role constructors require this condition; source parity alone does not prove
that the consumed AWS role has been updated. Do not enable through an arbitrary repository
variable, dispatch bypass or fabricated status.

The conservative Backup event pattern may be deployed before v2. The retained
v1 consumer can create issues for benign overmatches in that interval; only v2
provides the typed benign/quarantine acknowledgment contract. Do not claim that
pattern deployment alone completes this rollout. After activation, observe a
real allowed event and redelivery against the mapped canonical v2 issue, and
record results without raw payloads or receipt handles.
