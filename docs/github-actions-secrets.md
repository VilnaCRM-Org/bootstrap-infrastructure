# GitHub Actions Secrets and Variables

The hardened CI/CD layer in this repository is OIDC-first. Preview, IAM
validation, and nightly drift detection are designed to use short-lived AWS
credentials issued through GitHub Actions OIDC. Do not add long-lived static AWS
access keys for these workflows.

## Repository variables for guardrail workflows

Add these under **Settings → Secrets and variables → Actions → Variables → Repository variables**.

| Variable | Purpose | Notes |
| --- | --- | --- |
| `AWS_OIDC_ROLE_ARN` | IAM role assumed by preview, IAM validation, and drift jobs | Repository variable, not a secret |
| `AWS_REGION` | Region used by `configure-aws-credentials` | Optional; defaults to `eu-central-1` |
| `PULUMI_BACKEND_URL` | Shared backend used by real previews and drift checks | Required |
| `PULUMI_PREVIEW_STACKS` | Optional comma-separated stack list for PR previews | Optional; defaults to committed `Pulumi.<stack>.yaml` files |
| `PULUMI_DRIFT_STACKS` | Optional comma-separated stack list for nightly drift checks | Optional; defaults to committed `Pulumi.<stack>.yaml` files |

## Optional secrets for guardrail workflows

Add these under **Settings → Secrets and variables → Actions → Secrets → Repository secrets**.

| Secret | Purpose | Notes |
| --- | --- | --- |
| `PULUMI_ACCESS_TOKEN` | Authenticate against the Pulumi Service backend | Only required when the backend is Pulumi Cloud |

Shared Pulumi backends should use an AWS KMS-backed secrets provider rather
than a passphrase-managed stack secret flow.

## OIDC role setup

1. Create an IAM OIDC identity provider for `https://token.actions.githubusercontent.com` if your AWS account does not already have one.
2. Create an IAM role with a trust policy scoped to this repository and the `sts.amazonaws.com` audience.
3. Grant the role only the permissions required for preview, IAM validation, and drift detection.
4. Store the role ARN as the `AWS_OIDC_ROLE_ARN` repository variable.

See the dedicated [CI guardrails guide](ci-guardrails.md) for an example trust policy and the documented `sub` claim formats.

## Release Automation Secrets

| Secret | Purpose | Notes |
| --- | --- | --- |
| `REPO_GITHUB_TOKEN` | Publish changelog-based releases | Optional; if unset, workflows fall back to `GITHUB_TOKEN` with `contents:write`. |

## Template Sync Secrets

Choose one authentication strategy for the template sync workflows:

| Secret | Purpose | Notes |
| --- | --- | --- |
| `PERSONAL_ACCESS_TOKEN` | Authenticate template sync (PAT workflow) | Required by `.github/workflows/template-sync-pat.yml`. Needs repo write access. |
| `VILNACRM_APP_ID` | GitHub App ID for template sync | Required by `.github/workflows/template-sync-app.yml`. |
| `VILNACRM_APP_PRIVATE_KEY` | GitHub App private key for template sync | Required by `.github/workflows/template-sync-app.yml`. Store the PEM contents. |

## Setting Secrets and Variables

1. Navigate to **Settings → Secrets and variables → Actions** in your GitHub repository.
2. Add `AWS_OIDC_ROLE_ARN`, `PULUMI_BACKEND_URL`, `PULUMI_PREVIEW_STACKS`, and `PULUMI_DRIFT_STACKS` under **Variables → Repository variables**. Add `AWS_REGION` there only if you need a region other than the default `eu-central-1`.
3. Add `PULUMI_ACCESS_TOKEN` and any release or template-sync credentials under **Secrets → Repository secrets**.
4. If several repositories share the same guardrail configuration, use organization variables for `AWS_OIDC_ROLE_ARN`, `PULUMI_BACKEND_URL`, `PULUMI_PREVIEW_STACKS`, and `PULUMI_DRIFT_STACKS`. Add `AWS_REGION` at the organization level only if you want to override the default `eu-central-1`. Use organization secrets for `PULUMI_ACCESS_TOKEN` and any release or template-sync credentials.

Rotate credentials regularly and audit workflow runs for unexpected usage.
