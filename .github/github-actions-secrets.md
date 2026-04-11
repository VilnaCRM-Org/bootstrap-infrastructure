# GitHub Actions Secrets for Pulumi Workflows

This repository uses GitHub Actions workflows in `.github/workflows/pulumi-preview.yml` and `.github/workflows/pulumi-deploy.yml` to run Pulumi previews and deployments. Both workflows rely on AWS and Pulumi credentials that must be stored as encrypted repository secrets before the jobs can succeed.

## Required Secrets

- `AWS_ACCESS_KEY_ID` – Access key for the AWS IAM user or role that Pulumi should use.
- `AWS_SECRET_ACCESS_KEY` – Secret key paired with the access key above.
- `PULUMI_ACCESS_TOKEN` – Access token for the Pulumi Service account that owns the target stack.

> These secrets are consumed by the `aws-actions/configure-aws-credentials@v4` and `pulumi/actions@v4` steps. Without them, the AWS step fails with “Could not load credentials from any providers,” preventing Pulumi from running.

## How to Configure the Secrets

1. Open the repository in GitHub.
2. Navigate to **Settings → Secrets and variables → Actions**.
3. Use **New repository secret** to add each value listed above.
4. Re-run the workflow to verify that credentials are loaded successfully.

## Why the Secrets Are Needed

`aws-actions/configure-aws-credentials@v4` expects either static access keys or an assumable role with GitHub OpenID Connect. The current workflows specify only the region, so GitHub Actions must load the AWS credentials from repository secrets. If the secrets are missing, the action cannot obtain temporary AWS credentials, and the workflow stops before Pulumi executes.

Similarly, `pulumi/actions@v4` uses `PULUMI_ACCESS_TOKEN` to authenticate against the Pulumi Service. Without the token, the action cannot access the stack state, so every deployment fails.

## Considering OIDC Instead of Static Keys

If you prefer not to store long-lived AWS keys, you can switch to GitHub’s OpenID Connect flow:

1. Create an IAM role in AWS that trusts `token.actions.githubusercontent.com`.
2. Grant the role the permissions required for your Pulumi stack.
3. Replace the static key inputs in the workflow with `role-to-assume` (and optionally `role-session-name`).

With OIDC configured, GitHub Actions exchanges a short-lived token for AWS credentials at runtime, removing the need to keep secret keys in the repository.
