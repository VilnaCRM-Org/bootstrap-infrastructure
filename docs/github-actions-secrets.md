# GitHub Actions Secrets

The Pulumi CI workflows rely on repository- or organization-level secrets. Configure them before enabling the pipelines to avoid credential failures.

## Required Secrets

| Secret | Purpose | Notes |
| --- | --- | --- |
| `AWS_ACCESS_KEY_ID` | Authenticate AWS API calls | Optional if you use GitHub OIDC; pair with `AWS_SECRET_ACCESS_KEY`. |
| `AWS_SECRET_ACCESS_KEY` | Authenticate AWS API calls | Store the matching secret key when using static IAM users. |
| `PULUMI_ACCESS_TOKEN` | Authenticate against the Pulumi Service | Generate in the Pulumi UI under **Settings → Access Tokens**. |

### Using GitHub OIDC Instead of Static Keys

If you prefer short-lived credentials:

1. Create an IAM role that trusts your GitHub organization/repository via OpenID Connect.
2. Grant the role permissions to manage the stack resources.
3. Store the role ARN as `AWS_OIDC_ROLE_ARN` (or another name) and update the workflow to assume it.

See [Configuring OpenID Connect in GitHub](https://docs.github.com/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-github-actions) for detailed steps.

## Setting Secrets

1. Navigate to **Settings → Secrets and variables → Actions** in your GitHub repository.
2. Click **New repository secret** for each value listed above.
3. If several repositories share the same infrastructure credentials, consider using organization secrets instead.

Rotate credentials regularly and audit workflow runs for unexpected usage.
