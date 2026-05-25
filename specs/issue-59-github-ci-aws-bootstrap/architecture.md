# Architecture: Issue 59 GitHub CI AWS Bootstrap

## Control Boundaries

AWS is the only control plane for CI configuration and Pulumi secret encryption.
The one-time bootstrap stack is run locally by a human with administrator access
in each AWS account. After that setup, GitHub Actions receives short-lived AWS
credentials only through GitHub OIDC and scoped IAM roles.

```text
Human operator
  -> AWS admin profile for test or prod
  -> Pulumi CLI with S3 backend and AWS KMS secrets provider
  -> pulumi/github-ci-bootstrap stack
  -> AWS IAM OIDC provider, roles, policies, and Secrets Manager payloads

GitHub Actions
  -> repository variables select config-read role and AWS region
  -> GitHub OIDC assumes one config-read role
  -> AWS Secrets Manager returns the fixed CI JSON payload
  -> workflow assumes preview, apply, drift, or operations role
```

Pulumi Cloud and Pulumi ESC are not in the control path.

## Tech Stack

- Pulumi Python for infrastructure definitions.
- AWS IAM for OIDC trust, role boundaries, and inline role policies.
- AWS Secrets Manager for CI configuration JSON payload storage.
- AWS S3 for Pulumi backend state.
- AWS KMS for Pulumi secrets-provider encryption.
- GitHub Actions OIDC for short-lived CI credentials.
- GitHub repository variables for non-secret role discovery values.

## Bootstrap Stack Contract

The isolated Pulumi project lives at `pulumi/github-ci-bootstrap`. It imports the
shared infrastructure component library and creates only CI bootstrap resources.
It is not part of normal stack discovery and is applied manually before
privileged CI can pass.

| Stack | AWS account | CI suffixes | Special role |
| --- | --- | --- | --- |
| `test` | `891377212104` | `test-pr`, `test` | Operations alert triage |
| `prod` | `933245420672` | `prod-preview`, `prod` | None |

The stack writes protected IAM and Secrets Manager resources, emits role and
secret identifiers as stack outputs, and defaults to writing the generated CI
payload versions. Operators can disable payload writes with
`github-ci-bootstrap:writeSecretValues=false` when they need a container-only
repair.

## AWS Trust Model

Every GitHub-assumable role requires `aud=sts.amazonaws.com`, a repository
subject, and an allowed `job_workflow_ref`.

| Role type | Trusted subject |
| --- | --- |
| Test PR preview/config | `repo:VilnaCRM-Org/bootstrap-infrastructure:pull_request` |
| Test branch apply/drift/config | `repo:VilnaCRM-Org/bootstrap-infrastructure:ref:refs/heads/main` |
| Prod preview/drift/config | `repo:VilnaCRM-Org/bootstrap-infrastructure:ref:refs/heads/main` |
| Prod apply | `repo:VilnaCRM-Org/bootstrap-infrastructure:environment:prod` |

Preview and drift roles can read stack metadata and Pulumi backend state, but
they explicitly cannot read arbitrary Secrets Manager secret values. Apply roles
receive only the account-local mutation permissions needed by the Pulumi stack.

## AWS-Using CI Permission Inventory

Each AWS-using workflow first assumes a config-read role that can read exactly
one Secrets Manager CI payload. The workflow then assumes the second-stage role
from that payload for the actual AWS operation.

| Workflow job | Config suffix | Second-stage role | AWS purpose |
| --- | --- | --- | --- |
| `pulumi-pr-guardrails.yml` `Preview` on pull requests | `test-pr` | Test preview | PR Pulumi preview against shared test backend |
| `pulumi-pr-guardrails.yml` `IAM Validation` on pull requests | `test-pr` | Test preview | Access Analyzer validation for IAM policies from the preview artifact |
| `well-architected-evidence.yml` `Test Account Evidence` on pull requests | `test-pr` | Test preview | Read-only evidence collection for Well-Architected checks |
| `pulumi-test-deploy.yml` `Test Preview` | `test` | Test preview | Main-branch test plan creation |
| `pulumi-test-deploy.yml` `Test IAM Validation` | `test` | Test preview | Access Analyzer validation for test plan IAM policies |
| `pulumi-test-deploy.yml` `Test Apply` | `test` | Test apply | Apply the saved test plan |
| `pulumi-test-deploy.yml` `Test Post-Apply Drift` | `test` | Test drift | Verify no test drift after apply |
| `nightly-guardrails.yml` `Test Drift Detection` | `test` | Test drift | Scheduled test drift detection |
| `operations-alert-triage.yml` `Triage Operations Alerts` | `test` | Operations alert triage | Read/delete test operations SQS messages and create GitHub issues |
| `well-architected-evidence.yml` `Test Account Evidence` on `main` or schedule | `test` | Test preview | Read-only evidence collection from the protected branch |
| `pulumi-pr-command-runner.yml` test preview/IAM/apply/drift jobs | `test` | Test preview, apply, or drift | Maintainer-triggered test operations from trusted branch workflow refs |
| `pulumi-prod.yml` `Prod Preview` | `prod-preview` | Prod preview | Production plan creation |
| `pulumi-prod.yml` `Prod IAM Validation` | `prod-preview` | Prod preview | Access Analyzer validation for prod plan IAM policies |
| `pulumi-prod.yml` `Prod Apply` | `prod` | Prod apply | Apply saved production plan after GitHub `prod` environment approval |
| `pulumi-prod.yml` `Prod Post-Apply Drift` | `prod-preview` | Prod drift | Verify no production drift after apply |
| `nightly-guardrails.yml` `Prod Drift Detection` | `prod-preview` | Prod drift | Scheduled production drift detection |
| `pulumi-pr-command-runner.yml` prod preview/IAM/apply/drift jobs | `prod-preview` or `prod` | Prod preview, apply, or drift | Maintainer-triggered production operations with protected apply trust |

IAM validation intentionally uses the preview role because the helper can call
AWS Access Analyzer and, when artifacts are absent, may need the same read-only
Pulumi preview surface. It does not receive a separate apply-capable role.

## Secrets Manager Payload Contract

The bootstrap stack creates these fixed secrets:

| Suffix | Secret ID |
| --- | --- |
| `test-pr` | `/bootstrap-infrastructure/ci/test-pr` |
| `test` | `/bootstrap-infrastructure/ci/test` |
| `prod-preview` | `/bootstrap-infrastructure/ci/prod-preview` |
| `prod` | `/bootstrap-infrastructure/ci/prod` |

Payloads include account ID, region, Pulumi backend URL, AWS KMS
secrets-provider URL, stack lists, and purpose-specific role ARNs. The workflows
load one fixed suffix per job and validate the payload before assuming the
deployment role.

By default the bootstrap stack writes the generated Secrets Manager secret
versions. This replaces the earlier manual payload-entry step and reduces human
copy/paste of secret JSON. Operators can set
`github-ci-bootstrap:writeSecretValues=false` for a container-only repair; in
that mode they must write payloads later with `aws secretsmanager
put-secret-value --secret-string file://payload.json` from local files and must
not print the payloads in terminal output, PR comments, or documentation.

## GitHub Repository Variables

The stack output `githubVariables` provides the values operators set in the
repository:

- `AWS_TEST_REGION`
- `AWS_TEST_PR_CI_CONFIG_ROLE_ARN`
- `AWS_TEST_CI_CONFIG_ROLE_ARN`
- `AWS_PROD_REGION`
- `AWS_PROD_PREVIEW_CI_CONFIG_ROLE_ARN`
- `AWS_PROD_CI_CONFIG_ROLE_ARN`

These variables are not secret material; they only let GitHub locate the
account-local config-read roles.

## Manual Secure Steps

1. Refresh the local administrator AWS profile for the test account and verify
   the account ID with `aws sts get-caller-identity`.
2. Log in Pulumi to the test S3 backend and select or initialize the `test`
   stack with the AWS KMS secrets provider.
3. Run `pulumi preview --stack test`, inspect the IAM and Secrets Manager diff,
   then run `pulumi up --stack test --yes`.
4. Repeat the same flow with the production administrator AWS profile and the
   `prod` stack.
5. Set the GitHub repository variables from the stack `githubVariables` outputs.
6. If `writeSecretValues=false` was used, write the four CI payload versions
   locally with `aws secretsmanager put-secret-value --secret-string
   file://payload.json` without printing the JSON values.
7. Rerun the privileged PR checks that previously failed because the test
   config-read role did not exist.
