# GitHub CI AWS Bootstrap Stack

Issue #59 adds a separate one-time Pulumi project at
`pulumi/github-ci-bootstrap`. Run it locally with an administrator AWS identity
in each account to create the GitHub OIDC CI roles and the AWS Secrets Manager
CI configuration used by GitHub Actions. Pulumi Cloud and Pulumi ESC are not
used.

Normal GitHub CI roles must not receive `AdministratorAccess`. The local admin
profile is only for the one-time bootstrap apply.

## What It Creates

Per account, the stack creates or adopts:

- GitHub Actions OIDC provider for `token.actions.githubusercontent.com`
- AWS Secrets Manager CI config containers under `/bootstrap-infrastructure/ci/`
- one `GitHubCiConfigRead-*` role per fixed CI suffix
- dedicated `GitHubCiPreview-*`, `GitHubCiApply-*`, and `GitHubCiDrift-*` roles
- `OperationsAlertTriage-*` in the test account only
- encrypted `SecretVersion` payloads by default, containing role ARNs, backend
  URL, stack names, and operations metadata

## CI Role Mapping

| Workflow job | CI suffix | Runtime role | Permission set |
| --- | --- | --- | --- |
| PR guardrails preview | `test-pr` | `AWS_PREVIEW_ROLE_ARN` | preview |
| PR guardrails IAM validation | `test-pr` | `AWS_PREVIEW_ROLE_ARN` | preview plus IAM validation |
| Test deploy preview | `test` | `AWS_PREVIEW_ROLE_ARN` | preview |
| Test deploy apply | `test` | `AWS_APPLY_ROLE_ARN` | apply |
| Test deploy drift | `test` | `AWS_DRIFT_ROLE_ARN` | drift |
| Prod preview | `prod-preview` | `AWS_PREVIEW_ROLE_ARN` | preview |
| Prod apply | `prod` | `AWS_APPLY_ROLE_ARN` | apply through GitHub `prod` environment |
| Prod drift | `prod-preview` | `AWS_DRIFT_ROLE_ARN` | drift |
| Nightly drift | `test`, `prod-preview` | `AWS_DRIFT_ROLE_ARN` | drift |
| PR command runner | `test`, `prod-preview`, `prod` | preview/apply/drift role by command | matching command role |
| Well-Architected evidence | `test-pr` or `test` | `AWS_PREVIEW_ROLE_ARN` | preview plus account evidence reads |
| Operations alert triage | `test` | `AWS_OPERATIONS_ALERT_TRIAGE_ROLE_ARN` | SQS triage |

## Permission Shape

| Role | Scope |
| --- | --- |
| `GitHubCiConfigRead-*` | `secretsmanager:DescribeSecret` and `secretsmanager:GetSecretValue` on exactly one fixed CI secret ARN pattern. Trust is constrained by repository subject and workflow name. |
| `GitHubCiPreview-*` | S3 Pulumi backend access, AWS KMS secrets-provider use, `access-analyzer:ValidatePolicy`, `sts:GetCallerIdentity`, and read/list/describe/get for the stack-managed AWS services. It explicitly denies Secrets Manager value reads. |
| `GitHubCiDrift-*` | Same read surface as preview, because refresh-based drift detection reads live AWS state and uses Pulumi backend locks. |
| `GitHubCiApply-*` | S3/KMS backend access plus the existing bootstrap mutation surface for S3, KMS, IAM/OIDC, CI secret containers, Backup, ECR, EventBridge, CloudTrail, SNS, SQS configuration, Budgets, Cost Explorer, GuardDuty, Security Hub, and AWS Config. |
| `OperationsAlertTriage-*` | `sqs:GetQueueUrl`, `sqs:ReceiveMessage`, and `sqs:DeleteMessage` on the deterministic test operations queue only. |

The apply role includes wildcard resources only for AWS APIs that do not support
useful resource-level scoping, such as identity reads, some list calls, OIDC
provider creation, Cost Explorer create/list APIs, and AWS Config delivery
channel APIs. The policies do not include `Action: "*"` or
`AdministratorAccess`.

## Fix Local AWS CLI Profiles

Remove inherited shell credentials first. Do not set empty AWS variables.

```bash
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_PROFILE
```

Log in and verify the exact account before each apply:

```bash
aws sso login --profile <test-admin-profile>
AWS_PROFILE=<test-admin-profile> aws sts get-caller-identity --output json

aws sso login --profile <prod-admin-profile>
AWS_PROFILE=<prod-admin-profile> aws sts get-caller-identity --output json
```

The test command must return account `891377212104`; the prod command must
return account `933245420672`.

## One-Time Local Apply

Use the shared S3 backend and AWS KMS secrets provider. Direct `pulumi up` is
allowed only for this local bootstrap step.

```bash
export AWS_REGION=eu-central-1
export PULUMI_DIR=pulumi/github-ci-bootstrap

AWS_PROFILE=<test-admin-profile> \
PULUMI_SECRETS_PROVIDER='awskms://alias/pulumi-platform-bootstrap-test?region=eu-central-1' \
pulumi -C "${PULUMI_DIR}" login s3://pulumi-bootstrap-infrastructure-test-state

AWS_PROFILE=<test-admin-profile> \
PULUMI_SECRETS_PROVIDER='awskms://alias/pulumi-platform-bootstrap-test?region=eu-central-1' \
pulumi -C "${PULUMI_DIR}" stack select test

AWS_PROFILE=<test-admin-profile> \
PULUMI_SECRETS_PROVIDER='awskms://alias/pulumi-platform-bootstrap-test?region=eu-central-1' \
pulumi -C "${PULUMI_DIR}" preview --stack test

AWS_PROFILE=<test-admin-profile> \
PULUMI_SECRETS_PROVIDER='awskms://alias/pulumi-platform-bootstrap-test?region=eu-central-1' \
pulumi -C "${PULUMI_DIR}" up --stack test --yes
```

Repeat for prod:

```bash
AWS_PROFILE=<prod-admin-profile> \
PULUMI_SECRETS_PROVIDER='awskms://alias/pulumi-platform-bootstrap-prod?region=eu-central-1' \
pulumi -C "${PULUMI_DIR}" login s3://pulumi-bootstrap-infrastructure-prod-state

AWS_PROFILE=<prod-admin-profile> \
PULUMI_SECRETS_PROVIDER='awskms://alias/pulumi-platform-bootstrap-prod?region=eu-central-1' \
pulumi -C "${PULUMI_DIR}" stack select prod

AWS_PROFILE=<prod-admin-profile> \
PULUMI_SECRETS_PROVIDER='awskms://alias/pulumi-platform-bootstrap-prod?region=eu-central-1' \
pulumi -C "${PULUMI_DIR}" preview --stack prod

AWS_PROFILE=<prod-admin-profile> \
PULUMI_SECRETS_PROVIDER='awskms://alias/pulumi-platform-bootstrap-prod?region=eu-central-1' \
pulumi -C "${PULUMI_DIR}" up --stack prod --yes
```

If a stack has not been initialized yet, run `pulumi -C "${PULUMI_DIR}" stack
init <stack> --secrets-provider "$PULUMI_SECRETS_PROVIDER"` once with the same
admin profile before `stack select`.

## Outputs To Capture

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

Set the GitHub repository variables from `githubVariables`:

```bash
gh variable set AWS_TEST_REGION --body '<region>'
gh variable set AWS_TEST_PR_CI_CONFIG_ROLE_ARN --body '<test-pr-config-read-role-arn>'
gh variable set AWS_TEST_CI_CONFIG_ROLE_ARN --body '<test-config-read-role-arn>'
gh variable set AWS_PROD_REGION --body '<region>'
gh variable set AWS_PROD_PREVIEW_CI_CONFIG_ROLE_ARN --body '<prod-preview-config-read-role-arn>'
gh variable set AWS_PROD_CI_CONFIG_ROLE_ARN --body '<prod-config-read-role-arn>'
```

## Secret Payloads

By default, the stack writes the required AWS Secrets Manager JSON values with
Pulumi secret encryption. The payloads contain no static credentials.

If you set `github-ci-bootstrap:writeSecretValues` to `"false"` or need to
repair a payload manually, use `put-secret-value` from a private local JSON file:

```bash
AWS_PROFILE=<test-admin-profile> aws secretsmanager put-secret-value \
  --secret-id /bootstrap-infrastructure/ci/test-pr \
  --secret-string file://<test-pr-payload>.json

AWS_PROFILE=<test-admin-profile> aws secretsmanager put-secret-value \
  --secret-id /bootstrap-infrastructure/ci/test \
  --secret-string file://<test-payload>.json

AWS_PROFILE=<prod-admin-profile> aws secretsmanager put-secret-value \
  --secret-id /bootstrap-infrastructure/ci/prod-preview \
  --secret-string file://<prod-preview-payload>.json

AWS_PROFILE=<prod-admin-profile> aws secretsmanager put-secret-value \
  --secret-id /bootstrap-infrastructure/ci/prod \
  --secret-string file://<prod-payload>.json
```

Verify with `describe-secret`. Do not use `get-secret-value` for verification.
