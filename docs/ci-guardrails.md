# CI Guardrails

This repository treats infrastructure pull requests as high-risk changes. The
guardrail layer below is designed to catch the common failure modes of
AI-generated Pulumi and AWS code before anyone merges or applies it.

For the broader Python, dependency, workflow, Dockerfile, and scheduled
maintainability checks, use [CI quality gates](ci-quality-gates.md).

## Required PR checks

These checks are intended to be marked as required in branch protection:

| Check | Local command | Purpose |
| --- | --- | --- |
| `Preview` | `make test-preview` | Produces a non-destructive Pulumi preview artifact for every configured stack |
| `Destructive Diff Gate` | `make test-destructive-diff` | Blocks deletes and replacements of critical infrastructure unless explicitly approved |
| `IAM Validation` | `make test-iam-validation` | Validates previewed IAM policies with AWS IAM Access Analyzer |
| `Secrets Scan` | `make test-secrets` | Runs Gitleaks against tracked Git content |
| `Dependency Audit` | `make test-deps-security` | Audits Python dependencies with `pip-audit --strict` |
| `Bandit` | `make test-bandit` | Lints repository Python code for common security hazards |
| `Actionlint` | `make test-actionlint` | Lints GitHub Actions workflow syntax and common security issues |
| `CodeQL (python)` | GitHub-native | Scans Python code for security issues |
| `CodeQL (actions)` | GitHub-native | Scans workflow code for insecure patterns |

`make test-security` aggregates Gitleaks, dependency audit, and Bandit.
`make test-repo-hygiene` aggregates Actionlint, Yamllint, and Hadolint.
`make test-guardrails` aggregates real preview generation, destructive diff
gating, and static cost proxy checks. `make test-guardrails-unprivileged` uses
an empty preview artifact to exercise the destructive-diff parser, cost proxy,
and IAM-input extraction for fork pull requests. `make ci-pr` and `make ci`
keep the real preview path.

### Same-repo privileged check contract

For same-repo infrastructure pull requests, branch protection should require
the AWS-backed guardrail checks from `.github/workflows/pulumi-pr-guardrails.yml`
by exact workflow and job name:

| Required evidence | Workflow / check name | Job ID | Required result |
| --- | --- | --- | --- |
| AWS-backed Pulumi preview artifact | `Pulumi PR Guardrails / Preview` | `preview` | Success |
| Destructive diff review and static cost/quota proxy over the preview artifact | `Pulumi PR Guardrails / Destructive Diff Gate` | `destructive_diff` | Success |
| AWS IAM Access Analyzer validation | `Pulumi PR Guardrails / IAM Validation` | `iam_validation` | Success |

The fork-only checks `Pulumi PR Guardrails / Preview (Unprivileged)` and
`Pulumi PR Guardrails / IAM Validation (Unprivileged)` are credential-free
fallback evidence. They must not be treated as equivalent to same-repo AWS
validation for infrastructure changes that need privileged proof.

A skipped privileged `Preview` or `IAM Validation` check is not an acceptable
skip for a same-repo infrastructure PR. If a maintainer cannot rerun the change
from a trusted same-repo branch, a repository branch-protection owner must
explicitly approve the temporary exception and record the missing check, reason,
compensating validation, and follow-up before the PR can be treated as merge
ready. The destructive-diff gate remains governed only by the
`allow-destructive-infra-change` label described below.

## Preview model

The preview workflow uses the same Docker workspace and policy pack that local
developers use:

1. a credential-free mode-selection job checks whether the pull request came
   from a fork
2. trusted same-repo runs use `make start` and
   `make publish-pulumi-preview-summary` in the `test` GitHub environment
3. fork pull requests use `make start` and `make test-preview-unprivileged`
   without a GitHub environment, OIDC permission, AWS credentials, or
   environment variables
4. `make test-destructive-diff`
5. `make test-iam-validation` for trusted previews, or
   `make test-iam-validation-unprivileged` for fork previews

Preview artifacts are written under `.artifacts/pulumi-preview/` and uploaded to
GitHub Actions. The preview summary is appended to `GITHUB_STEP_SUMMARY` so
reviewers can inspect the plan without digging through raw logs first.

For issue 18, privileged previews are environment-scoped:

- trusted same-repo PRs use the `test` GitHub environment and preview the
  configured test stack
- production release previews use the `prod-preview` GitHub environment and
  preview the production stack without apply permissions
- fork PRs stay on the unprivileged artifact path and never receive AWS
  credentials or `id-token: write` permission

Test and production deployment workflows use `make pulumi-plan` to save the
Pulumi update plan and write the corresponding preview JSON artifact in the same
operation. Destructive-diff and IAM validation gates consume that uploaded
artifact, so apply jobs use a plan whose preview has already passed guardrails.

Stack selection follows this order:

1. `PULUMI_PREVIEW_STACKS` environment variable if set
2. committed `pulumi/Pulumi.<stack>.yaml` files

Committed example files are not deployment targets. Keep privileged jobs
explicit by setting `PULUMI_PREVIEW_STACKS` to account-local stacks such as
`test` or `prod`.

If local Pulumi plugin downloads hit anonymous GitHub rate limits, pass a token
explicitly only to the preview-oriented command you are running, for example:

```bash
GITHUB_TOKEN="$(gh auth token)" make test-preview
```

The Docker workspace does not inject `GITHUB_TOKEN` by default.

## Destructive change gate

The destructive-diff gate fails when the preview proposes deletes or
replacements against critical resource families such as:

- VPC and networking primitives
- IAM roles and policies
- KMS keys
- S3 buckets
- RDS and other database resources
- Secrets Manager resources
- Route53 records
- EKS resources

Intentional destructive changes must be reviewed manually and then approved with
the pull-request label `allow-destructive-infra-change`. The label is the only
supported override because it leaves an auditable trail in GitHub.

## Cost and Quota Proxy

`make test-cost-proxy` reads the same Pulumi preview JSON artifact as the
destructive-diff gate. It counts create and replace operations for resource
families that usually affect cost, quotas, or operational fanout, including S3
buckets, KMS keys, IAM roles, AWS Backup resources, ECR repositories, SNS
topics, EventBridge rules, CloudTrail trails, and S3 replication configuration.

The proxy is intentionally static. It does not estimate monthly spend and it
does not replace the repo-managed AWS Budget, Cost Anomaly Detection resources,
Service Quotas, or a FinOps review. It gives reviewers an early signal that a
pull request is adding or replacing unusually many durable resources before the
change reaches the test account.

The default weighted threshold is `64`, which matches the expected full
first-time bootstrap footprint after automation, management CloudTrail, backup,
cost, and operations controls are included. Pull requests that exceed that
threshold need an explicit guardrail change or a reduction in durable-resource
fanout.

## IAM validation

`scripts/pulumi_ci_guardrails.py validate-iam` extracts IAM policy documents
from a real preview artifact and validates them with AWS IAM Access Analyzer.

Current behavior:

- No IAM policies in the preview: the check exits successfully and prints a
  short note
- IAM policies in the preview with valid AWS credentials: findings of type
  `ERROR` and `SECURITY_WARNING` fail the check
- Fork pull request previews: the workflow uses
  `make test-iam-validation-unprivileged` to extract IAM validation inputs from
  the uploaded artifact without calling AWS Access Analyzer

This complements the custom Pulumi CrossGuard pack. The policy pack blocks
wildcard IAM permissions in repository code; Access Analyzer adds AWS-native
semantic validation for the rendered policy documents.

## OIDC-based AWS access

The guardrail workflows are OIDC-first. They do not use long-lived
`AWS_ACCESS_KEY_ID` or `AWS_SECRET_ACCESS_KEY` repository secrets.

Privileged jobs read account-specific values from the active GitHub
environment, not repository-wide variables. The required environment variables
are:

| Variable | Purpose |
| --- | --- |
| `AWS_ACCOUNT_ID` | Expected AWS account for `allowed-account-ids` and audit evidence |
| `AWS_PREVIEW_ROLE_ARN` | OIDC role assumed by preview and IAM validation jobs |
| `AWS_DRIFT_ROLE_ARN` | OIDC role assumed by drift jobs |
| `PULUMI_BACKEND_URL` | Account-specific shared Pulumi backend |
| `PULUMI_SECRETS_PROVIDER` | AWS KMS Pulumi secrets provider URI used by stacks |

Optional or job-specific environment variables:

| Variable | Purpose |
| --- | --- |
| `AWS_REGION` | AWS region used by `configure-aws-credentials`; defaults to `eu-central-1` |
| `PULUMI_PR_BACKEND_URL` | Optional PR-only backend, useful while a legacy shared test stack is being migrated |
| `PULUMI_PR_PREVIEW_STACKS` | Optional PR-only stack list; used by trusted PR and test deploy fallbacks |
| `PULUMI_PREVIEW_STACKS` | Optional comma-separated stack list for preview |
| `PULUMI_DRIFT_STACKS` | Optional comma-separated stack list for nightly drift checks |
| `AWS_APPLY_ROLE_ARN` | OIDC role used by test or production apply jobs |
| `OPERATIONS_CLOUDTRAIL_NAME` | Standard metadata input for evidence collection when the environment reuses an existing operations CloudTrail |
| `RESTORE_DRILL_EVIDENCE` | Standard metadata input pointing to the latest workload-scoped restore drill evidence record |
| `QUESTION_MATRIX_EVIDENCE` | Standard metadata input pointing to the structured 57-question review evidence record |
| `EXTERNAL_CONTROL_EVIDENCE` | Standard metadata input pointing to the structured external-control owner and freshness evidence record |

Optional environment secrets:

| Secret | Purpose |
| --- | --- |
| `PULUMI_ACCESS_TOKEN` | Required only when the backend is the Pulumi Service |

Shared backends should use an AWS KMS-backed Pulumi secrets provider rather
than a passphrase-managed stack secret flow.

`Pulumi Test Deploy` uses the generic backend, stack, apply-role, and drift-role
variables when they exist. In the `test` environment it can fall back to
`PULUMI_PR_BACKEND_URL`, `PULUMI_PR_PREVIEW_STACKS`, and `AWS_PREVIEW_ROLE_ARN`
so an existing single bootstrap automation role can apply its own narrowed
policy before creating new operations and cost-control resources.

Fork pull requests always run the unprivileged artifact path and the
destructive diff gate. Same-repo pull requests fail fast when required
AWS-backed environment variables are missing instead of silently bypassing
privileged guardrails. The AWS-backed preview and Access Analyzer validation
paths remain same-repo only because they require OIDC-issued AWS credentials.

Privileged jobs should emit sanitized evidence in the job summary or logs:

- GitHub environment name
- expected AWS account ID and selected AWS region
- role purpose, such as preview, drift, or apply
- Pulumi backend type, stack names, and guardrail mode
- commit SHA and whether the run used a saved plan

Do not print raw secrets, stack exports, decrypted values, or secret-bearing
Pulumi output.

Use `make report-well-architected-evidence` to collect a metadata-only evidence
bundle for PR readiness, branch protection, AWS identity, account cost controls,
optional operations topic routing, restore-job freshness, and repository fanout.
The report is written to `.artifacts/well-architected/evidence.json`; missing
external evidence is reported as a blocker rather than treated as success.
When set, `OPERATIONS_CLOUDTRAIL_NAME`, `RESTORE_DRILL_EVIDENCE`,
`QUESTION_MATRIX_EVIDENCE`, and `EXTERNAL_CONTROL_EVIDENCE` are standard
evidence inputs, not secrets. Restore evidence must be scoped to this bootstrap
workload and include cleanup confirmation for any isolated restore location.
Question-matrix and external-control records must include owner, freshness,
coverage, unresolved-count, evidence-location, and fallback fields; boolean
confirmation flags do not unlock final 5/5 scores.

### Example IAM trust policy

Replace the account ID, organization, repository name, and GitHub environment
with your own values. `<ACCOUNT_ID>` must be the target 12-digit AWS account ID
using digits only:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::<ACCOUNT_ID>:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
          "token.actions.githubusercontent.com:sub": "repo:VilnaCRM-Org/bootstrap-infrastructure:environment:<ENVIRONMENT>"
        }
      }
    }
  ]
}
```

Use `environment:test` for test preview/apply roles, `environment:prod-preview`
for production preview and drift roles, and `environment:prod` only for the
production apply role.

## Production protection

Production release automation has two boundaries:

- `prod-preview` can create review evidence but cannot apply changes
- `prod` can apply only after GitHub environment approval, branch protection,
  and commit SHA verification

The production workflow also checks that the requested commit SHA already has a
successful `Pulumi Test Deploy` workflow run on `main`. That keeps production
from bypassing the test-account deployment path.

Approvers should review the production preview summary, destructive diff result,
IAM validation result, target account evidence, and commit SHA before approving
`prod`. Keep preview artifacts on short retention and do not upload Pulumi stack
exports.

## Nightly-only checks

Nightly workflows are visible but do not block pull requests:

| Check | Purpose |
| --- | --- |
| `Drift Detection` | Runs `pulumi preview --refresh --expect-no-changes` against configured `test` and production preview stacks |
| `Scorecard` | Runs OpenSSF Scorecard and uploads SARIF results for repository health visibility |

Drift detection intentionally skips when `PULUMI_BACKEND_URL` is not configured
for a shared backend. Running a drift job against an ephemeral file backend on a
fresh GitHub runner would be misleading.

## Manual maintainer follow-up

The workflows are committed in this repository, but maintainers still need to:

1. create the GitHub OIDC IAM role in AWS
2. create `test`, `prod-preview`, and `prod` GitHub environments
3. set the environment variables and optional secrets listed above
4. enable required reviewers and branch restrictions on `prod`
5. mark the required PR checks in GitHub branch protection
6. decide whether production repositories want stricter stack lists or narrower
   IAM role scopes than the template defaults

## Current limitations

- CodeQL is GitHub-native; the repository keeps the workflow under structural
  test coverage, but there is no local `make` equivalent
- The custom VilnaCRM CrossGuard pack is the enforced policy-pack layer in this
  template; the workflow does not vendor the Node-based AWSGuard package into
  the Python/uv Docker image
- IAM validation is only as complete as the preview artifact; policies that are
  created entirely outside Pulumi still need separate review
