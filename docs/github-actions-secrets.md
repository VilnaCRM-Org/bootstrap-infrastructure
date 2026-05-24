# GitHub Actions Secrets and Variables

The hardened CI/CD layer in this repository is OIDC-first. Preview, IAM
validation, PR-comment plan/apply commands, drift detection, operations alert
triage, and Well-Architected evidence jobs use short-lived credentials. Do not
add long-lived AWS access keys to GitHub.

Privileged account configuration is loaded from AWS Secrets Manager through
fixed Pulumi ESC environments. AWS Secrets Manager remains the source of truth
for the account-local values. ESC, including the Pulumi Cloud control plane
that opens those environments, is not the vault; it authenticates with AWS
through OIDC, imports the per-environment JSON secret through the `aws-secrets`
provider, and exports selected keys as workflow `environmentVariables`. GitHub
Environments are not used as an account-configuration store. The only
privileged deployment GitHub Environment that remains required is `prod`, which
gates production apply with reviewers and deployment branch restrictions. The
required `operations-alert-reconcile` Environment gates the manual non-AWS issue
closure workflow and must not contain account configuration.

## Pulumi ESC Environments

Create these ESC environments in the ESC organization configured by
`.github/ci/pulumi-esc.json`:

| ESC environment | Purpose |
| --- | --- |
| `vilnacrm-org/bootstrap-infrastructure/test-pr` | Trusted same-repo PR previews and IAM validation against the test account |
| `vilnacrm-org/bootstrap-infrastructure/test` | Main-branch test apply, test drift, operations alert triage, and Well-Architected evidence |
| `vilnacrm-org/bootstrap-infrastructure/prod-preview` | Production preview, production drift, and production IAM validation without apply permissions |
| `vilnacrm-org/bootstrap-infrastructure/prod` | Production apply only, after GitHub `prod` approval |

The ESC organization slug is a GitOps setting because the loader needs an
environment path before it can open ESC. Update
`.github/ci/pulumi-esc.json` if the real Pulumi organization or project slug
differs from the committed value. Do not store AWS account IDs, role ARNs,
Pulumi backend URLs, stack lists, or secrets-provider URIs in that file.

In this repository, ESC stores only environment definitions, provider bindings,
and projections. Account-local CI values stay in AWS Secrets Manager and are
read at runtime with the `aws-secrets` provider; do not copy those values into
ESC encrypted literals, Pulumi Cloud secrets, or any other ESC-managed secret
value.

Use the [Pulumi ESC and AWS Secrets Manager cutover manual](esc-aws-secrets-manager-cutover.md)
for the secure human steps that create AWS secret values, configure ESC, rerun
privileged CI, clean up legacy GitHub Environment variables, and reconcile
legacy alert issues.

Each privileged workflow authenticates to ESC through GitHub OIDC, opens one
fixed ESC environment with `pulumi/auth-actions` and `pulumi/esc-action`,
validates the loaded values, and then assumes the purpose-specific AWS role.
Workflows must not choose an ESC environment from PR input, issue-comment text,
or repository-dispatch payload data.

## AWS Secrets Manager Source

Store one JSON secret per ESC environment in the owning AWS account. Use a
stable name such as:

| ESC environment | AWS Secrets Manager secret ID |
| --- | --- |
| `test-pr` | `/bootstrap-infrastructure/ci/test-pr` |
| `test` | `/bootstrap-infrastructure/ci/test` |
| `prod-preview` | `/bootstrap-infrastructure/ci/prod-preview` |
| `prod` | `/bootstrap-infrastructure/ci/prod` |

The Pulumi `test` stack manages the `test-pr` and `test` secret containers and
their ESC read role. The Pulumi `prod` stack manages the `prod-preview` and
`prod` containers and read role. Pulumi intentionally creates only the
containers, tags, OIDC provider, and least-privilege read role; maintainers
populate or rotate the JSON secret values directly in AWS Secrets Manager.
The Pulumi stack exports `ciConfigurationSecretIds`,
`ciConfigurationSecretArns`, and `pulumiEscSecretsReadRoleArn` so the ESC
environment definition can reference the GitOps-created AWS resources.

Each secret should contain only the keys needed by that environment, for
example:

```json
{
  "AWS_ACCOUNT_ID": "123456789012",
  "AWS_REGION": "eu-central-1",
  "AWS_PREVIEW_ROLE_ARN": "arn:aws:iam::123456789012:role/bootstrap-preview",
  "PULUMI_BACKEND_URL": "s3://example-pulumi-state",
  "PULUMI_SECRETS_PROVIDER": "awskms://alias/pulumi-bootstrap-secrets?region=eu-central-1",
  "PULUMI_PREVIEW_STACKS": "test"
}
```

The ESC environment definition should use AWS OIDC plus the `aws-secrets`
provider to read that JSON secret and project keys into `environmentVariables`.
Use placeholder ARNs in documentation and review; do not commit real secret
payloads.

```yaml
values:
  aws:
    login:
      fn::open::aws-login:
        oidc:
          roleArn: arn:aws:iam::<account-id>:role/PulumiEscCiSecretsRead-bootstrap-infrastructure-test
          sessionName: pulumi-esc-bootstrap-infrastructure
          subjectAttributes:
            - currentEnvironment.name
    secrets:
      fn::open::aws-secrets:
        region: eu-central-1
        login: ${aws.login}
        get:
          ci:
            secretId: /bootstrap-infrastructure/ci/test
    ci:
      fn::fromJSON: ${aws.secrets.ci}
  environmentVariables:
    AWS_ACCOUNT_ID: ${aws.ci.AWS_ACCOUNT_ID}
    AWS_REGION: ${aws.ci.AWS_REGION}
    AWS_PREVIEW_ROLE_ARN: ${aws.ci.AWS_PREVIEW_ROLE_ARN}
    PULUMI_BACKEND_URL: ${aws.ci.PULUMI_BACKEND_URL}
    PULUMI_SECRETS_PROVIDER: ${aws.ci.PULUMI_SECRETS_PROVIDER}
    PULUMI_PREVIEW_STACKS: ${aws.ci.PULUMI_PREVIEW_STACKS}
```

## ESC Environment Variables

Define these `environmentVariables` values in ESC only as projections from the
AWS Secrets Manager JSON secret. They are exported into the GitHub job
environment by `.github/actions/load-esc-ci-env`.

| Variable | Required in | Purpose |
| --- | --- | --- |
| `AWS_ACCOUNT_ID` | all ESC environments | Expected 12-digit AWS account ID for `allowed-account-ids` and evidence |
| `AWS_REGION` | all ESC environments | Region used by AWS OIDC and Pulumi |
| `PULUMI_BACKEND_URL` | all ESC environments | Account-local shared Pulumi backend; use `s3://...` for privileged jobs |
| `PULUMI_SECRETS_PROVIDER` | all ESC environments | AWS KMS Pulumi secrets provider URI; use `awskms://...` |
| `AWS_PREVIEW_ROLE_ARN` | `test-pr`, `test`, `prod-preview` | OIDC role for preview and IAM validation |
| `AWS_APPLY_ROLE_ARN` | `test`, `prod` | OIDC role for test or production apply |
| `AWS_DRIFT_ROLE_ARN` | `test`, `prod-preview` | OIDC role for drift checks |
| `PULUMI_PREVIEW_STACKS` | preview/apply environments | Comma-separated stacks for preview/apply jobs, for example `test` or `prod` |
| `PULUMI_DRIFT_STACKS` | drift environments | Comma-separated stacks for drift jobs |
| `AWS_OPERATIONS_ALERT_TRIAGE_ROLE_ARN` | `test` | Dedicated OIDC role for operations alert issue triage |
| `OPERATIONS_ALERT_QUEUE_NAME` | `test` | SQS queue drained by operations alert triage |
| `OPERATIONS_TOPIC_ARN` | `test` | Operations SNS topic used by Well-Architected evidence |
| `OPERATIONS_CLOUDTRAIL_NAME` | `test` | Operations CloudTrail name used by evidence collection |

Optional non-secret evidence pointers such as restore-drill, alert-route,
security-attestation, and external-control evidence may remain repository
variables when they are not account credentials. Keep AWS account IDs, role
ARNs, Pulumi backend URLs, stack lists, and Pulumi secrets-provider URIs in AWS
Secrets Manager; ESC may expose them only by projecting the `aws-secrets`
result.

## ESC Pulumi Config

ESC `pulumiConfig` may contain non-account-local static stack configuration or
values projected from AWS Secrets Manager. Do not use ESC `pulumiConfig` to
store AWS account IDs, role ARNs, backend URLs, stack lists, or
secrets-provider URIs directly. Stack initialization and migration still must
use the AWS KMS secrets provider projected from AWS Secrets Manager:

```bash
pulumi -C pulumi stack init <stack> --secrets-provider "$PULUMI_SECRETS_PROVIDER"
```

Do not document or use passphrase-managed Pulumi secrets for shared CI stacks.

<a id="template-sync-secrets"></a>

## GitHub Setup

Configure **Settings -> Environments -> prod** with required reviewers and
deployment branch restrictions before production apply is enabled. Do not add
`test` or `prod-preview` GitHub Environments for privileged account
configuration; those boundaries are now ESC environments plus AWS IAM trust.

Repository or organization secrets are still appropriate for release and
template-sync credentials that are not AWS deployment credentials:

| Secret | Purpose | Notes |
| --- | --- | --- |
| `REPO_GITHUB_TOKEN` | Publish changelog-based releases | Optional; workflows fall back to `GITHUB_TOKEN` when possible |
| `PERSONAL_ACCESS_TOKEN` | Template sync with a PAT | Required only by `.github/workflows/template-sync-pat.yml` |
| `VILNACRM_APP_ID` | GitHub App ID for template sync | Required only by `.github/workflows/template-sync-app.yml` |
| `VILNACRM_APP_PRIVATE_KEY` | GitHub App private key for template sync | Store the PEM contents |
| `GH_ENVIRONMENT_ADMIN_TOKEN` | One-time GitHub Environment variable cleanup | Temporary fine-grained PAT or GitHub App installation token with repository **Environments** write permission; remove after cleanup succeeds |

## OIDC Role Setup

1. Create an IAM OIDC identity provider for `https://token.actions.githubusercontent.com` in each AWS account if one does not already exist.
2. Create purpose-specific preview, apply, drift, and operations alert triage roles where the environment needs them.
3. Scope AWS role trust to the repository, the `sts.amazonaws.com` audience, fixed workflow files, and the intended ref or GitHub production environment subject.
4. Store role ARNs in the owning AWS Secrets Manager JSON secret, then project them through ESC as `AWS_PREVIEW_ROLE_ARN`, `AWS_APPLY_ROLE_ARN`, `AWS_DRIFT_ROLE_ARN`, or `AWS_OPERATIONS_ALERT_TRIAGE_ROLE_ARN`.
5. Keep `allowed-account-ids` wired to the AWS Secrets Manager value projected by ESC as `AWS_ACCOUNT_ID`.

Non-approval jobs use branch or pull-request subjects:

```text
repo:VilnaCRM-Org/bootstrap-infrastructure:ref:refs/heads/main
repo:VilnaCRM-Org/bootstrap-infrastructure:pull_request
```

Production apply is the only account workflow that should use an AWS role
trusting only the protected GitHub Environment subject:

```text
repo:VilnaCRM-Org/bootstrap-infrastructure:environment:prod
```

Bind `token.actions.githubusercontent.com:job_workflow_ref` to the exact
workflow files that need the role. The operations alert triage role should only
trust:

```text
VilnaCRM-Org/bootstrap-infrastructure/.github/workflows/operations-alert-triage.yml@refs/heads/main
```

See the dedicated [CI guardrails guide](ci-guardrails.md) for the full trust
policy shape.

## PR Comment Commands

Repository owners, members, and collaborators can request Pulumi operations from
same-repository pull requests:

```text
/pulumi test plan
/pulumi test up
/pulumi prod plan
/pulumi prod up
```

Fork pull requests are rejected before any AWS or ESC-backed credentials are
requested. Production commands always run the test account sequence first for
the exact PR head SHA before entering `prod-preview` or protected `prod`.

## Migration Checklist

Follow the dedicated [Pulumi ESC and AWS Secrets Manager cutover manual](esc-aws-secrets-manager-cutover.md)
for command templates, verification gates, and secret-safe evidence capture.

1. Apply the Pulumi `test` and `prod` stacks so AWS contains the four Secrets Manager containers and the `PulumiEscCiSecretsRead-*` roles.
2. Populate the four AWS Secrets Manager JSON secret values listed above in the owning AWS accounts.
3. Create the four ESC environments listed above and configure them to import those JSON secrets through `fn::open::aws-secrets`; do not store the JSON payloads directly in ESC.
4. Configure ESC AWS OIDC so each environment can assume the AWS Secrets Manager read role exported as `pulumiEscSecretsReadRoleArn`.
5. Configure GitHub OIDC for the repository and ESC organization so workflows can open the fixed ESC environments without `PULUMI_ACCESS_TOKEN`.
6. Move AWS account IDs, role ARNs, regions, Pulumi backend URLs, KMS secrets-provider URIs, and stack lists out of GitHub Environment variables and into AWS Secrets Manager; ESC should only project those AWS Secrets Manager values.
7. Keep the protected `prod` GitHub Environment for production approval.
8. Create or verify the protected `operations-alert-reconcile` GitHub
   Environment with required SRE or reviewer approval before running the legacy
   operations-alert closure workflow; keep it free of account configuration.
   The workflow requires an HTTPS `sre_confirmation_reference` to the sanitized
   SRE confirmation record.
   Repository administrators can apply and verify both protected GitHub
   Environments with `make configure-github-repository-controls`.
9. Re-run privileged previews, test deploy, drift, operations alert triage, and Well-Architected evidence before removing any legacy GitHub variables.
10. Create the temporary `GH_ENVIRONMENT_ADMIN_TOKEN` repository secret for the cleanup operator. It must grant repository **Environments** write permission only for this repository; do not use an AWS credential.
11. Run **GitHub Environment Legacy Variable Cleanup** in dry-run mode and verify it reports only legacy account-configuration variables, including any older `PULUMI_PR_*` backend or stack-list aliases.
12. Re-run **GitHub Environment Legacy Variable Cleanup** with `dry_run=false` and this exact confirmation sentence: `I confirm ESC-backed privileged CI is green and legacy GitHub Environment variables can be removed`.
13. Confirm GitHub `prod` still keeps reviewer and branch protections; this cleanup removes only variable names and does not manage Environment protection rules.
14. Delete the temporary `GH_ENVIRONMENT_ADMIN_TOKEN` repository secret.

Rotate credentials regularly and audit workflow runs for unexpected privileged
access.
