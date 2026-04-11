# GitHub Actions Secrets for Pulumi Workflows

This repository prefers GitHub OpenID Connect (OIDC) for AWS authentication in
workflows that need cloud access. Use static AWS keys only as a legacy fallback
when OIDC is not available.

## Required Authentication Configuration

### Preferred: GitHub OIDC for AWS

1. Create an IAM role in AWS that trusts `token.actions.githubusercontent.com`.
2. Grant that role the permissions required for the Pulumi preview, apply, or
   drift workflow you are running.
3. Configure the workflow to assume the role with
   `aws-actions/configure-aws-credentials`, for example:

   ```yaml
   - uses: aws-actions/configure-aws-credentials@v4
     with:
       role-to-assume: ${{ vars.AWS_OIDC_ROLE_ARN }}
       role-session-name: gha-pulumi-${{ github.run_id }}
       aws-region: ${{ vars.AWS_REGION || 'eu-central-1' }}
   ```

4. Store the role ARN as a repository or organization variable such as
   `AWS_OIDC_ROLE_ARN`.

### Fallback: Static Credentials

Use these secrets only when OIDC cannot be used:

- `AWS_ACCESS_KEY_ID` – Access key for the IAM user or role that Pulumi should use.
- `AWS_SECRET_ACCESS_KEY` – Secret key paired with the access key above.
- `PULUMI_ACCESS_TOKEN` – Required only when the workflow uses Pulumi Cloud for
  state or authentication.

## How to Configure the Secrets

1. Open the repository in GitHub.
2. Navigate to **Settings → Secrets and variables → Actions**.
3. Prefer configuring `AWS_OIDC_ROLE_ARN` under **Variables** and wiring that
   value into `aws-actions/configure-aws-credentials`.
4. Add `PULUMI_ACCESS_TOKEN` only if your workflow uses Pulumi Cloud-backed
   state or Pulumi Cloud authentication.
5. Add `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` only as a legacy fallback
   when OIDC cannot be used.
6. Re-run the workflow to verify that credentials are loaded successfully.

## Why the Secrets Are Needed

With OIDC configured, GitHub Actions exchanges a short-lived GitHub identity
token for AWS credentials at runtime, removing the need to keep long-lived AWS
keys in repository secrets.

If OIDC is unavailable, `aws-actions/configure-aws-credentials@v4` can still
load static access keys from repository secrets. That path should be treated as
legacy compatibility, not the default.

`PULUMI_ACCESS_TOKEN` is only needed when the workflow authenticates against the
Pulumi Service. Self-managed backends do not need it.
