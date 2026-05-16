# GitHub Actions Secrets and Variables

The hardened CI/CD layer in this repository is OIDC-first. Preview, IAM
validation, and nightly drift detection are designed to use short-lived AWS
credentials issued through GitHub Actions OIDC. Do not add long-lived static AWS
access keys for these workflows.

## GitHub environments

Privileged infrastructure workflows use GitHub environments as the account
boundary. This environment-scoped configuration keeps test and production
account values out of repository-wide variables. Configure these environments
under **Settings -> Environments**:

| Environment | Purpose | Protection |
| --- | --- | --- |
| `test` | Trusted PR previews, merge-to-main test applies, and test drift checks | No production approval; keep branch scope limited to protected branches for apply jobs |
| `prod-preview` | Production previews and production drift checks with read-only or preview-only AWS access | No apply permissions |
| `prod` | Production apply only | Require reviewers and restrict deployment branches |

Fork pull requests must stay unprivileged. Same-repo privileged jobs should fail
fast when required environment variables are missing.

## Environment variables

Add account-specific values under each GitHub environment's **Variables** tab.
Do not store AWS account configuration as repository-wide variables when it
differs between test and production.

| Variable | Purpose | Notes |
| --- | --- | --- |
| `AWS_ACCOUNT_ID` | Expected 12-digit AWS account ID for the environment | Used with OIDC account allow-listing and evidence |
| `AWS_REGION` | Region used by `configure-aws-credentials` and Pulumi | Optional only when the workflow has a safe default |
| `AWS_PREVIEW_ROLE_ARN` | OIDC role used by preview, IAM validation, and drift jobs | Required for `test` and `prod-preview` |
| `AWS_APPLY_ROLE_ARN` | OIDC role used by apply jobs | Required only for `test` and `prod` |
| `PULUMI_BACKEND_URL` | Account-specific shared Pulumi backend | Required for privileged jobs |
| `PULUMI_SECRETS_PROVIDER` | AWS KMS Pulumi secrets provider URI | Required; use an `awskms://...` URI |
| `PULUMI_PREVIEW_STACKS` | Comma-separated stack list for preview jobs | Use `test` in `test`; use `prod` in `prod-preview` |
| `PULUMI_DRIFT_STACKS` | Comma-separated stack list for drift jobs | Use explicit account-local stacks |

Optional PR-only overrides for the `test` environment:

| Variable | Purpose |
| --- | --- |
| `PULUMI_PR_BACKEND_URL` | Backend used by trusted PR previews and test deploys when `PULUMI_BACKEND_URL` is not populated |
| `PULUMI_PR_PREVIEW_STACKS` | Stack list used by trusted PR previews and test deploys when shared preview/drift stack lists are not populated |

`Pulumi Test Deploy` can also fall back from `AWS_APPLY_ROLE_ARN` and
`AWS_DRIFT_ROLE_ARN` to `AWS_PREVIEW_ROLE_ARN` in `test` while a single
environment-scoped bootstrap role is being expanded by the stack itself.

Use separate AWS roles per account and purpose. Preview roles should be unable
to mutate production resources. Apply roles should be scoped to the exact
resources Pulumi manages in that account.

## Optional environment secrets

Add these under the GitHub environment's **Secrets** tab only when needed.

| Secret | Purpose | Notes |
| --- | --- | --- |
| `PULUMI_ACCESS_TOKEN` | Authenticate against the Pulumi Service backend | Only required when the backend is Pulumi Cloud |

Shared Pulumi backends should use an AWS KMS-backed secrets provider rather
than a passphrase-managed stack secret flow.

## OIDC role setup

1. Create an IAM OIDC identity provider for `https://token.actions.githubusercontent.com` in each AWS account if it does not already exist.
2. Create separate preview and apply roles where the environment needs both.
3. Scope trust policies to this repository, the `sts.amazonaws.com` audience, and the relevant GitHub environment subject.
4. Store the role ARNs as `AWS_PREVIEW_ROLE_ARN` or `AWS_APPLY_ROLE_ARN` in the matching GitHub environment.
5. Configure workflows to use `allowed-account-ids` with `AWS_ACCOUNT_ID`.

See the dedicated [CI guardrails guide](ci-guardrails.md) for an example trust policy and the documented `sub` claim formats.

For environment-bound jobs, the trusted subject has this shape:

```text
repo:VilnaCRM-Org/bootstrap-infrastructure:environment:<environment>
```

Use `environment:test`, `environment:prod-preview`, or `environment:prod` as
appropriate. Avoid broad branch-only trust for production apply roles.

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
2. Create `test`, `prod-preview`, and `prod` under **Environments**.
3. Add the environment variables listed above to each environment with account-local values.
4. Add `PULUMI_ACCESS_TOKEN` as an environment secret only when the selected backend requires it.
5. Keep release and template-sync credentials as repository or organization secrets because they are not account-specific deploy credentials.
6. Require reviewers and deployment branch restrictions on `prod` before enabling production apply.

Rotate credentials regularly and audit workflow runs for unexpected usage.
