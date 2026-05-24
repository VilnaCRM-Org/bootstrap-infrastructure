# GitHub Actions Secrets for Pulumi Workflows

Privileged Pulumi workflows use GitHub OIDC and fixed Pulumi ESC environments.
AWS Secrets Manager is the source of truth for account-local CI values; ESC and
the Pulumi Cloud control plane are not the vault. ESC imports those values with
the `aws-secrets` provider and projects them into workflow environment
variables. Do not add long-lived AWS access keys to GitHub.

## ESC Configuration

Account-specific deployment values belong in AWS Secrets Manager and are
projected by Pulumi ESC, not stored in Pulumi Cloud or GitHub Environment
variables:

- `vilnacrm-org/bootstrap-infrastructure/test-pr`
- `vilnacrm-org/bootstrap-infrastructure/test`
- `vilnacrm-org/bootstrap-infrastructure/prod-preview`
- `vilnacrm-org/bootstrap-infrastructure/prod`

The ESC organization and project slugs are committed in
`.github/ci/pulumi-esc.json` because the ESC control plane needs them before an
environment opens. Account-specific deployment values belong in AWS Secrets
Manager JSON secrets, not in that file.

Use one AWS Secrets Manager JSON secret per ESC environment, for example:

| ESC environment | AWS Secrets Manager secret ID |
| --- | --- |
| `test-pr` | `/bootstrap-infrastructure/ci/test-pr` |
| `test` | `/bootstrap-infrastructure/ci/test` |
| `prod-preview` | `/bootstrap-infrastructure/ci/prod-preview` |
| `prod` | `/bootstrap-infrastructure/ci/prod` |

The Pulumi `test` and `prod` stacks create the AWS Secrets Manager secret
containers and `PulumiEscCiSecretsRead-*` roles. Maintainers still populate the
JSON values directly in AWS Secrets Manager; Pulumi does not manage secret
versions, and the values must not be copied into ESC encrypted literals.

Each ESC environment should authenticate to AWS with `fn::open::aws-login`,
read the corresponding JSON secret with `fn::open::aws-secrets`, parse it with
`fn::fromJSON`, and expose only the required keys as `environmentVariables`.
Set `subjectAttributes: [currentEnvironment.name]` in the `aws-login` OIDC
block and use the stack's `pulumiEscSecretsReadRoleArn` output as the role ARN.

Define these `environmentVariables` in ESC as projections from the AWS Secrets
Manager JSON secret:

| Variable | Purpose |
| --- | --- |
| `AWS_ACCOUNT_ID` | Expected AWS account for `allowed-account-ids` |
| `AWS_REGION` | AWS region for OIDC and Pulumi |
| `AWS_PREVIEW_ROLE_ARN` | Preview and IAM validation role |
| `AWS_APPLY_ROLE_ARN` | Apply role for `test` and `prod` |
| `AWS_DRIFT_ROLE_ARN` | Drift role |
| `AWS_OPERATIONS_ALERT_TRIAGE_ROLE_ARN` | Dedicated role for operations alert triage |
| `OPERATIONS_ALERT_QUEUE_NAME` | Alert queue drained by triage |
| `OPERATIONS_TOPIC_ARN` | Operations SNS topic for evidence |
| `OPERATIONS_CLOUDTRAIL_NAME` | Operations CloudTrail for evidence |
| `PULUMI_BACKEND_URL` | Account-local Pulumi backend |
| `PULUMI_SECRETS_PROVIDER` | AWS KMS Pulumi secrets provider URI |
| `PULUMI_PREVIEW_STACKS` | Explicit preview/apply stack list |
| `PULUMI_DRIFT_STACKS` | Explicit drift stack list |

Shared CI stacks must use an `awskms://` Pulumi secrets provider. Do not use
passphrase-managed stack secrets for shared CI state.

## OIDC Trust

Non-approval jobs trust fixed repository subjects plus workflow refs:

```text
repo:VilnaCRM-Org/bootstrap-infrastructure:ref:refs/heads/main
repo:VilnaCRM-Org/bootstrap-infrastructure:pull_request
```

Production apply trusts only the protected GitHub Environment subject:

```text
repo:VilnaCRM-Org/bootstrap-infrastructure:environment:prod
```

The `prod` GitHub Environment must require reviewers and deployment branch
restrictions. `test` and `prod-preview` account separation is handled by fixed
ESC environments and AWS IAM roles.

Release and template-sync credentials that are not AWS account-specific can
remain repository or organization secrets.
