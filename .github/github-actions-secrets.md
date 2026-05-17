# GitHub Actions Secrets for Pulumi Workflows

This repository uses GitHub OIDC and GitHub environment-scoped configuration
for AWS-backed Pulumi workflows. Do not add long-lived AWS access keys for
preview, apply, drift, or IAM validation jobs.

## Environment Configuration

Configure account-specific values under **Settings -> Environments**:

- `test` for trusted PR previews, test apply, and test drift.
- `prod-preview` for production preview and production drift.
- `prod` for production apply only.

Each privileged environment should define these variables as applicable:

| Variable | Purpose |
| --- | --- |
| `AWS_ACCOUNT_ID` | Expected AWS account for `allowed-account-ids` |
| `AWS_REGION` | AWS region for OIDC and Pulumi |
| `AWS_PREVIEW_ROLE_ARN` | Preview and IAM validation role |
| `AWS_APPLY_ROLE_ARN` | Apply role for `test` and `prod` |
| `AWS_DRIFT_ROLE_ARN` | Drift role |
| `AWS_OPERATIONS_ALERT_TRIAGE_ROLE_ARN` | Dedicated role for operations alert issue triage |
| `PULUMI_BACKEND_URL` | Account-local Pulumi backend |
| `PULUMI_SECRETS_PROVIDER` | AWS KMS Pulumi secrets provider URI |
| `PULUMI_PREVIEW_STACKS` | Explicit preview stack list |
| `PULUMI_DRIFT_STACKS` | Explicit drift stack list |
| `PULUMI_PR_BACKEND_URL` | Optional backend used only by trusted PR previews |
| `PULUMI_PR_PREVIEW_STACKS` | Optional stack list used only by trusted PR previews |

Use `PULUMI_ACCESS_TOKEN` only as an environment secret when the selected
backend is Pulumi Cloud. Self-managed S3 backends do not need it.

## OIDC Trust

OIDC roles should trust the repository and the target GitHub environment:

```text
repo:VilnaCRM-Org/bootstrap-infrastructure:environment:<environment>
```

Use `allowed-account-ids: ${{ env.AWS_ACCOUNT_ID }}` in
`aws-actions/configure-aws-credentials` with `AWS_ACCOUNT_ID` populated from the
GitHub environment through job-level `env:`. That keeps the assumed account
preflight-validated and prevents a workflow from assuming a role in the wrong
account. Store role ARNs as job or workflow environment variables, not
repository-wide variables, when they differ by account or purpose.
The operations alert triage role should also trust only
`.github/workflows/operations-alert-triage.yml` on the protected main branch.

## Production Protection

The `prod` environment must require reviewers and deployment branch
restrictions before production apply is enabled. Production preview runs through
`prod-preview`; production apply verifies the same commit SHA before using the
saved Pulumi plan.

Release and template-sync credentials that are not AWS account-specific can
remain repository or organization secrets.
