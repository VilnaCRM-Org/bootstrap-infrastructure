# Pulumi ESC and AWS Secrets Manager Cutover Manual

This runbook is for the human maintainer who completes the privileged setup
after the GitOps changes are reviewed. It deliberately keeps secret values out
of Git, GitHub Environment variables, Pulumi Cloud encrypted literals, PR
comments, and retained evidence.

AWS Secrets Manager is the source of truth for account-local CI values. Pulumi
Cloud and Pulumi ESC are only the OIDC and projection layer that opens a fixed
environment, reads one AWS Secrets Manager JSON secret with `aws-secrets`, and
exports selected keys as workflow `environmentVariables`.

## Safety Rules

Stop and rotate any touched credential if one of these rules is broken:

1. Do not paste secret JSON values into GitHub issues, PRs, Slack, retained
   artifacts, or ESC encrypted literals.
2. Do not run `aws secretsmanager get-secret-value`, `esc env open`,
   `pulumi env open`, `pulumi config --show-secrets`, or
   `pulumi stack output --show-secrets` in a shared terminal or transcript.
3. Do not add long-lived AWS keys to GitHub repository, organization, or
   Environment secrets.
4. Do not remove legacy GitHub Environment variables until ESC-backed
   privileged CI is green.
5. Do not close legacy operations-alert issues until SRE has confirmed the
   duplicate mapping and provided a sanitized HTTPS evidence URL.

Record only metadata in tickets and PR comments: account aliases, secret IDs,
role names, ARN shapes when already documented, workflow URLs, check names, and
timestamps. Never record secret payloads or decrypted Pulumi outputs.

## Inputs

Confirm these values before starting:

| Input | Source |
| --- | --- |
| Repository | `VilnaCRM-Org/bootstrap-infrastructure` |
| ESC org/project | `.github/ci/pulumi-esc.json` |
| AWS region | Owner-approved region, currently `eu-central-1` |
| Pulumi stacks | `test` and `prod` |
| Test account access | MFA-backed AWS CLI profile or equivalent owner-approved session |
| Production account access | Approved production access path; assisted reviews may use AWS MCP for metadata-only checks, but mutation requires human approval |
| GitHub admin access | Repository admin token for rulesets, protected environments, and temporary cleanup secret |
| SRE reference | Sanitized HTTPS URL for legacy operations-alert duplicate confirmation |

If the real Pulumi ESC organization slug differs from
`.github/ci/pulumi-esc.json`, update that file in a PR before continuing. An
`invalid organization <slug>` failure from `pulumi/auth-actions` means either
the slug is wrong or GitHub-to-ESC OIDC has not been configured for that
organization.

## Required Secrets Manager Payloads

Create one JSON secret value per ESC environment. The Pulumi stacks create the
secret containers and read roles; humans populate only the secret versions.

| ESC suffix | AWS Secrets Manager secret ID | Required keys |
| --- | --- | --- |
| `test-pr` | `/bootstrap-infrastructure/ci/test-pr` | `AWS_ACCOUNT_ID`, `AWS_REGION`, `AWS_PREVIEW_ROLE_ARN`, `PULUMI_BACKEND_URL`, `PULUMI_SECRETS_PROVIDER`, `PULUMI_PREVIEW_STACKS` |
| `test` | `/bootstrap-infrastructure/ci/test` | `AWS_ACCOUNT_ID`, `AWS_REGION`, `AWS_PREVIEW_ROLE_ARN`, `AWS_APPLY_ROLE_ARN`, `AWS_DRIFT_ROLE_ARN`, `AWS_OPERATIONS_ALERT_TRIAGE_ROLE_ARN`, `OPERATIONS_ALERT_QUEUE_NAME`, `OPERATIONS_TOPIC_ARN`, `OPERATIONS_CLOUDTRAIL_NAME`, `PULUMI_BACKEND_URL`, `PULUMI_SECRETS_PROVIDER`, `PULUMI_PREVIEW_STACKS`, `PULUMI_DRIFT_STACKS` |
| `prod-preview` | `/bootstrap-infrastructure/ci/prod-preview` | `AWS_ACCOUNT_ID`, `AWS_REGION`, `AWS_PREVIEW_ROLE_ARN`, `AWS_DRIFT_ROLE_ARN`, `PULUMI_BACKEND_URL`, `PULUMI_SECRETS_PROVIDER`, `PULUMI_PREVIEW_STACKS`, `PULUMI_DRIFT_STACKS` |
| `prod` | `/bootstrap-infrastructure/ci/prod` | `AWS_ACCOUNT_ID`, `AWS_REGION`, `AWS_APPLY_ROLE_ARN`, `PULUMI_BACKEND_URL`, `PULUMI_SECRETS_PROVIDER`, `PULUMI_PREVIEW_STACKS` |

Use this shape, replacing placeholders in a private editor:

```json
{
  "AWS_ACCOUNT_ID": "<12-digit-account-id>",
  "AWS_REGION": "eu-central-1",
  "AWS_PREVIEW_ROLE_ARN": "arn:aws:iam::<account-id>:role/<preview-role>",
  "PULUMI_BACKEND_URL": "s3://<pulumi-state-bucket>",
  "PULUMI_SECRETS_PROVIDER": "awskms://alias/<pulumi-kms-alias>?region=eu-central-1",
  "PULUMI_PREVIEW_STACKS": "test"
}
```

Keep the JSON minimal for each environment. Do not add production apply roles
to `prod-preview` or operations triage roles to production environments.

## Phase 1: Preflight

Work from the reviewed branch or merged commit that contains the ESC changes.

```bash
git status --short --branch
gh auth status
gh pr checks 57 --repo VilnaCRM-Org/bootstrap-infrastructure
```

Verify repository admin capability before applying GitHub controls:

```bash
gh api graphql \
  -f query='query { repository(owner:"VilnaCRM-Org", name:"bootstrap-infrastructure") { viewerPermission viewerCanAdminister } }' \
  --jq '.data.repository'
```

Verify AWS identity with metadata-only commands. Use the test profile for test
account work and the approved production access path for production work:

```bash
AWS_PROFILE=<test-admin-profile> \
AWS_REGION=eu-central-1 \
aws sts get-caller-identity --output json
```

The output account must match the account you are about to mutate. Do not
continue if the profile points at the wrong account.

## Phase 2: Apply Pulumi AWS Containers and Read Roles

The first apply cannot depend on ESC because the ESC environments and backing
secret values are not ready yet. Use the current owner-approved backend,
secrets-provider, and stack list values from a secure source, then move those
values into AWS Secrets Manager in Phase 3.

Preview first:

```bash
AWS_PROFILE=<test-admin-profile> \
AWS_REGION=eu-central-1 \
PULUMI_STACK=test \
PULUMI_BACKEND_URL=s3://<test-pulumi-state-bucket> \
PULUMI_SECRETS_PROVIDER='awskms://alias/<test-pulumi-kms-alias>?region=eu-central-1' \
PULUMI_PREVIEW_STACKS=test \
PULUMI_DRIFT_STACKS=test \
make pulumi-preview
```

Apply only after reviewing the preview:

```bash
AWS_PROFILE=<test-admin-profile> \
AWS_REGION=eu-central-1 \
PULUMI_STACK=test \
PULUMI_BACKEND_URL=s3://<test-pulumi-state-bucket> \
PULUMI_SECRETS_PROVIDER='awskms://alias/<test-pulumi-kms-alias>?region=eu-central-1' \
PULUMI_PREVIEW_STACKS=test \
PULUMI_DRIFT_STACKS=test \
make pulumi-up
```

Repeat for production with the production account, production backend, and
`PULUMI_STACK=prod`. Production mutation requires the normal production human
approval path.

After each apply, capture only these non-secret outputs:

```bash
pulumi -C pulumi stack output ciConfigurationSecretIds --stack test
pulumi -C pulumi stack output ciConfigurationSecretArns --stack test
pulumi -C pulumi stack output pulumiEscSecretsReadRoleArn --stack test
```

Repeat with `--stack prod`. Do not use `--show-secrets`.

## Phase 3: Populate AWS Secrets Manager

Create the secret JSON file in a private temporary file, write it directly to
AWS Secrets Manager, then remove the local file.

```bash
umask 077
secret_file="$(mktemp)"
"${EDITOR:-vi}" "${secret_file}"

AWS_PROFILE=<test-admin-profile> \
AWS_REGION=eu-central-1 \
aws secretsmanager put-secret-value \
  --secret-id /bootstrap-infrastructure/ci/test-pr \
  --secret-string "file://${secret_file}"

if command -v shred >/dev/null 2>&1; then
  shred -u "${secret_file}"
else
  rm -f "${secret_file}"
fi
```

Repeat for `/bootstrap-infrastructure/ci/test`,
`/bootstrap-infrastructure/ci/prod-preview`, and
`/bootstrap-infrastructure/ci/prod` in the owning accounts.

Verify metadata without reading the secret value:

```bash
AWS_PROFILE=<test-admin-profile> \
AWS_REGION=eu-central-1 \
aws secretsmanager describe-secret \
  --secret-id /bootstrap-infrastructure/ci/test \
  --query '{Name:Name,ARN:ARN,LastChangedDate:LastChangedDate,VersionIdsToStages:VersionIdsToStages}' \
  --output json
```

Do not use `get-secret-value` for verification.

## Phase 4: Configure ESC Environments

Create these ESC environments in the configured Pulumi organization and
project:

```text
vilnacrm-org/bootstrap-infrastructure/test-pr
vilnacrm-org/bootstrap-infrastructure/test
vilnacrm-org/bootstrap-infrastructure/prod-preview
vilnacrm-org/bootstrap-infrastructure/prod
```

Pulumi documents `esc env init <org>/<project>/<environment>` for creation and
`esc env edit <org>/<project>/<environment>` for editor-based updates. Use the
Pulumi Cloud environment definition editor if that is the approved internal
path. Do not use commands that open and print evaluated environments during
this setup.

Each ESC definition should follow this pattern. Use the `test` stack read role
for `test-pr` and `test`; use the `prod` stack read role for `prod-preview`
and `prod`.

```yaml
values:
  aws:
    login:
      fn::open::aws-login:
        oidc:
          roleArn: arn:aws:iam::<account-id>:role/PulumiEscCiSecretsRead-bootstrap-infrastructure-<test-or-prod>
          sessionName: pulumi-esc-bootstrap-infrastructure
          subjectAttributes:
            - currentEnvironment.name
    secrets:
      fn::open::aws-secrets:
        region: eu-central-1
        login: ${aws.login}
        get:
          ci:
            secretId: /bootstrap-infrastructure/ci/<environment-suffix>
    ci:
      fn::fromJSON: ${aws.secrets.ci}
  environmentVariables:
    AWS_ACCOUNT_ID: ${aws.ci.AWS_ACCOUNT_ID}
    AWS_REGION: ${aws.ci.AWS_REGION}
    AWS_PREVIEW_ROLE_ARN: ${aws.ci.AWS_PREVIEW_ROLE_ARN}
    AWS_APPLY_ROLE_ARN: ${aws.ci.AWS_APPLY_ROLE_ARN}
    AWS_DRIFT_ROLE_ARN: ${aws.ci.AWS_DRIFT_ROLE_ARN}
    AWS_OPERATIONS_ALERT_TRIAGE_ROLE_ARN: ${aws.ci.AWS_OPERATIONS_ALERT_TRIAGE_ROLE_ARN}
    OPERATIONS_ALERT_QUEUE_NAME: ${aws.ci.OPERATIONS_ALERT_QUEUE_NAME}
    OPERATIONS_TOPIC_ARN: ${aws.ci.OPERATIONS_TOPIC_ARN}
    OPERATIONS_CLOUDTRAIL_NAME: ${aws.ci.OPERATIONS_CLOUDTRAIL_NAME}
    PULUMI_BACKEND_URL: ${aws.ci.PULUMI_BACKEND_URL}
    PULUMI_SECRETS_PROVIDER: ${aws.ci.PULUMI_SECRETS_PROVIDER}
    PULUMI_PREVIEW_STACKS: ${aws.ci.PULUMI_PREVIEW_STACKS}
    PULUMI_DRIFT_STACKS: ${aws.ci.PULUMI_DRIFT_STACKS}
```

For each environment, remove projection lines for keys that are not required by
that environment's JSON payload. For example, `prod` should not project
`AWS_PREVIEW_ROLE_ARN`, `AWS_DRIFT_ROLE_ARN`, or operations alert keys unless a
future reviewed workflow requires them.

## Phase 5: Configure OIDC Trust

Configure GitHub-to-ESC OIDC in Pulumi Cloud for the real organization. The
Pulumi action requests an organization token, so the authorization policy must
allow this repository:

```text
aud: urn:pulumi:org:<pulumi-org>
sub: repo:VilnaCRM-Org/bootstrap-infrastructure:*
token type: organization
```

The workflows already use `id-token: write`, call `pulumi/auth-actions`, and
request `urn:pulumi:token-type:access_token:organization`. If token exchange
still reports `invalid organization`, fix the organization slug in GitOps or
repair the Pulumi Cloud OIDC issuer/policy before changing AWS.

The Pulumi stacks create the AWS-side ESC OIDC provider and
`PulumiEscCiSecretsRead-*` roles. Verify role trust metadata only:

```bash
AWS_PROFILE=<test-admin-profile> \
AWS_REGION=eu-central-1 \
aws iam get-role \
  --role-name PulumiEscCiSecretsRead-bootstrap-infrastructure-test \
  --query '{RoleName:Role.RoleName,Arn:Role.Arn,AssumeRolePolicyDocument:Role.AssumeRolePolicyDocument}' \
  --output json
```

The trust policy should use `https://api.pulumi.com/oidc`, audience
`aws:<pulumi-org>`, and subjects that include only the expected ESC environment
names for that account.

## Phase 6: Configure GitHub Protected Environments

Use the repository helper so `prod` and `operations-alert-reconcile` stay
reproducible.

Dry run:

```bash
GITHUB_REPOSITORY_CONTROLS_REPO=VilnaCRM-Org/bootstrap-infrastructure \
GITHUB_REPOSITORY_CONTROLS_PROD_REVIEWER=Kravalg \
GITHUB_REPOSITORY_CONTROLS_MODE=--dry-run \
make configure-github-repository-controls
```

Apply with an admin-capable GitHub token:

```bash
GITHUB_REPOSITORY_CONTROLS_REPO=VilnaCRM-Org/bootstrap-infrastructure \
GITHUB_REPOSITORY_CONTROLS_PROD_REVIEWER=Kravalg \
GITHUB_REPOSITORY_CONTROLS_MODE=--apply \
make configure-github-repository-controls
```

Verify:

```bash
GITHUB_REPOSITORY_CONTROLS_REPO=VilnaCRM-Org/bootstrap-infrastructure \
GITHUB_REPOSITORY_CONTROLS_PROD_REVIEWER=Kravalg \
GITHUB_REPOSITORY_CONTROLS_MODE=--verify-only \
make configure-github-repository-controls
```

The `operations-alert-reconcile` GitHub Environment is for manual issue
closure approval only. Keep it free of AWS account IDs, role ARNs, backend
URLs, and secret values.

## Phase 7: Rerun Privileged CI

Rerun the blocked privileged jobs or push a no-op reviewed commit if a fresh
run is required by repository policy. The expected green checks include:

- `Preview`
- `Destructive Diff Gate`
- `IAM Validation`
- `Test Account Evidence`
- `Pulumi Test Deploy` after merge to `main`
- production preview and drift checks before protected production apply

The first lines of the ESC loader summary should still state that AWS Secrets
Manager is the source of truth and that ESC projects values through
`aws-secrets`.

## Phase 8: Remove Legacy GitHub Environment Variables

Only after privileged ESC-backed CI is green, create a temporary
`GH_ENVIRONMENT_ADMIN_TOKEN` repository secret with repository Environment
write permission. Do not use an AWS credential.

Run **GitHub Environment Legacy Variable Cleanup** with:

```text
dry_run: true
confirmation: I confirm ESC-backed privileged CI is green and legacy GitHub Environment variables can be removed
```

Review the dry-run output. It must list only allowlisted legacy account
configuration variables in `test`, `prod-preview`, or `prod`.

Run it again with:

```text
dry_run: false
confirmation: I confirm ESC-backed privileged CI is green and legacy GitHub Environment variables can be removed
```

Verify that protected `prod` reviewers and deployment branch restrictions still
exist. Delete the temporary `GH_ENVIRONMENT_ADMIN_TOKEN` repository secret
after cleanup succeeds.

## Phase 9: Reconcile Legacy Operations Alert Issues

Do this only after the merged triage workflow has created or updated a
canonical issue containing `operations-alert:fingerprint=`.

1. SRE compares the legacy issues with the canonical fingerprinted issue.
2. SRE writes a sanitized confirmation record that does not include raw alert
   payloads, private incident notes, or secret values.
3. The record is reachable by HTTPS and becomes `sre_confirmation_reference`.
4. Run **Operations Alert Legacy Reconcile** through the protected
   `operations-alert-reconcile` Environment.

Workflow inputs:

```text
canonical_issue: <canonical fingerprinted issue number>
legacy_issues: <space or comma separated legacy issue numbers>
confirmation: I confirm these legacy issues match the canonical operations alert stream
sre_confirmation_reference: https://<sanitized-sre-confirmation-url>
```

The workflow refuses to close issues unless the canonical issue is open, has an
operations-alert title, contains the fingerprint marker, every legacy issue is
open and unfingerprinted, and the SRE reference is an HTTPS URL.

## Phase 10: Final Evidence

Record these non-secret evidence items:

- PR or commit SHA used for the cutover.
- Pulumi stack preview/apply workflow URLs or local operator attestation.
- Secrets Manager secret IDs populated, without values.
- ESC environment names created or updated.
- GitHub-to-ESC OIDC policy summary.
- GitHub protected environment verification output.
- Green privileged CI workflow URLs.
- Legacy GitHub Environment cleanup workflow URL.
- Operations alert reconcile workflow URL, if run.

Do not close issue #20 until the ESC-backed privileged checks are green. Do
not close legacy alert issues #49, #50, or #52 through #56 without the SRE
confirmation workflow.

## References

- [Pulumi ESC environments](https://www.pulumi.com/docs/esc/environments/working-with-environments/):
  `esc env init` creates environments and `esc env edit` updates environment
  definitions.
- [Pulumi ESC GitHub integration](https://www.pulumi.com/docs/esc/integrations/dev-tools/github/):
  `pulumi/auth-actions` exchanges GitHub OIDC for a short-lived Pulumi token
  when `id-token: write` is granted.
- [Pulumi ESC `aws-login` provider](https://www.pulumi.com/docs/esc/integrations/dynamic-login-credentials/aws-login/):
  `subjectAttributes` can include `currentEnvironment.name` for AWS trust
  binding.
- [Pulumi ESC `aws-secrets` provider](https://www.pulumi.com/docs/esc/integrations/dynamic-secrets/aws-secrets/):
  `secretId` identifies the AWS Secrets Manager secret imported at environment
  evaluation time.
