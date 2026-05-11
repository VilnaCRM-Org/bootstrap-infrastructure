# CI Guardrails

This repository treats infrastructure pull requests as high-risk changes. The
guardrail layer below is designed to catch the common failure modes of
AI-generated Pulumi and AWS code before anyone merges or applies it.

For the broader Python, dependency, workflow, Dockerfile, and scheduled
maintainability details behind these checks, use
[CI quality gates](ci-quality-gates.md).

## Required PR checks

These checks are intended to be marked as required in branch protection:

| Check | Local command | Purpose |
| --- | --- | --- |
| `Ruff` | `make test-ruff` | Lint, import-order, formatting drift, and McCabe complexity |
| `Ty` | `make test-ty` | Fast static typing diagnostics |
| `Maintainability` | `make test-maintainability` | Radon/Xenon complexity and maintainability gates |
| `Architecture` | `make test-architecture` | Import Linter contracts for package isolation and dependency direction |
| `Structural` | `make test-pulumi && make test-repository-catalogs && make test-repository-fanout` | Pulumi project, workflow, catalog, and static fanout checks |
| `Dependency Hygiene` | `make test-dependency-hygiene` | `uv lock --check` plus Deptry for missing, misplaced, and unused dependencies |
| `Coverage` | `make test-coverage` | Combined branch-coverage gate after unit, policy, and integration suites |
| `Local Battery` | `make ci-pr` or `make ci-pr-unprivileged` | Dockerized PR battery including image build and local gate composition |
| `Mutation` | `make test-mutation` | Mutation analysis of the Pulumi component layer |
| `Run Bats Tests` | `make test-cli` | Makefile and CLI front-end regression suite |
| `Secrets Scan` | `make test-secrets` | Runs Gitleaks against tracked Git content |
| `Dependency Audit` | `make test-deps-security` | Audits Python dependencies with `pip-audit --strict` |
| `Bandit` | `make test-bandit` | Lints repository Python code for common security hazards |
| `Dependency Review` | GitHub-native | Reviews pull-request dependency risk against GitHub advisories |
| `Actionlint` | `make test-actionlint` | Lints GitHub Actions workflow syntax and common security issues |
| `Yamllint` | `make test-yaml` | Lints GitHub workflow, Pulumi stack, and operational YAML |
| `Hadolint` | `make test-dockerfile` | Lints Dockerfile quality and safety rules |
| `Preview` | `make test-preview` | Produces a non-destructive Pulumi preview artifact for every configured stack |
| `Destructive Diff Gate` | `make test-destructive-diff` | Blocks deletes and replacements of critical infrastructure unless explicitly approved |
| `IAM Validation` | `make test-iam-validation` | Validates previewed IAM policies with AWS IAM Access Analyzer |
| `Policy` | `make test-policy` | Enforces the custom Pulumi CrossGuard policy pack |
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
`make pulumi-plan` also writes `.artifacts/pulumi-plan/manifest.json` with the
selected stack, backend URL, commit SHA, plan hash, and preview hash. `make
pulumi-up-plan` refuses to apply when the manifest is missing, stale, from a
different commit or backend, or when the saved plan hash no longer matches.
Production applies remain saved-plan-only. The test deployment workflow may
fall back to a direct `make pulumi-up` only when `pulumi up --plan` fails with
Pulumi's known KMS-backed saved-plan decryption error after the same-run
preview, destructive-diff, and IAM validation gates have passed under the
test-state concurrency lock.

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
topics, EventBridge rules, CloudTrail trails, S3 replication configuration,
GuardDuty, Security Hub, and AWS Config recorder resources.

The proxy is intentionally static. It does not estimate monthly spend and it
does not replace the repo-managed AWS Budget, Cost Anomaly Detection resources,
Service Quotas, or a FinOps review. It gives reviewers an early signal that a
pull request is adding or replacing unusually many durable resources before the
change reaches the test account.

The default weighted threshold is `66`, which matches the expected full
first-time bootstrap footprint after automation, management CloudTrail, backup,
cost, security detection, configuration inventory, and operations controls are
included. Pull requests that exceed that threshold need an explicit guardrail
change or a reduction in durable-resource fanout.

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
| `PRODUCTION_DR_OWNER_EVIDENCE` | Optional non-secret production-owner DR evidence that binds RTO/RPO, recovery ownership, escalation, communications, latest accepted drill, next review, and retention location to current restore-drill metadata |
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
bundle for PR readiness, branch protection, protected production-environment
approval, AWS identity, aggregate IAM account-access posture, account cost
controls, optional operations topic routing, restore-job freshness, and
repository fanout. The report is written to
`.artifacts/well-architected/evidence.json` with a sanitized Markdown summary at
`.artifacts/well-architected/evidence.md`; missing external evidence is reported
as a blocker rather than treated as success. IAM account-access evidence is
aggregate only: do not emit user names or access key IDs.
The `Well-Architected Evidence` workflow runs the same collector against the
real test-account OIDC role for trusted PRs and pushes, uploads the JSON and
Markdown artifacts, and appends the Markdown summary to the GitHub job summary.
It is advisory while the external controls tracked in #26-#30 remain open; set
`WELL_ARCHITECTED_EVIDENCE_ENFORCE=true` only after those blockers are closed
and the collector exits cleanly. Fork PRs do not receive AWS credentials and
record an unprivileged skip summary instead.
When set, `OPERATIONS_CLOUDTRAIL_NAME`, `RESTORE_DRILL_EVIDENCE`,
`QUESTION_MATRIX_EVIDENCE`, `EXTERNAL_CONTROL_EVIDENCE`, and
`PRODUCTION_DR_OWNER_EVIDENCE` are standard evidence inputs, not secrets.
Restore evidence must be scoped to this bootstrap workload and include cleanup
confirmation for any isolated restore location.
The collector also reads non-secret Dependabot alert metadata for the configured
dependency and manifest path; unresolved high or critical default-branch alerts
remain SEC11 blockers until closed or covered by an owner-approved exception.
If `DEPENDABOT_EXCEPTION_EVIDENCE` is set, the collector reads a non-secret
JSON exception record and only treats it as coverage when it is current,
matches the dependency and manifest, covers the exact open alert numbers, and
records owner approval plus a remediation plan. Invalid or expired exception
records do not suppress live alert blockers.
When `report-dependabot-exception` writes JSON, it reads the latest collector
`github_dependabot_alerts` evidence, copies the exact open alert numbers, and
rejects missing evidence notes, invalid approvals, missing or expired
`DEPENDABOT_EXCEPTION_EXPIRY_DATE`, stale or future
`DEPENDABOT_EXCEPTION_REVIEW_DATE`, and missing dependency or manifest metadata
before producing a record for `DEPENDABOT_EXCEPTION_EVIDENCE`.
Set `DEPENDABOT_EXCEPTION_FORCE=1` only when intentionally replacing an
existing Markdown or JSON exception artifact.
If `ALERT_ROUTE_OBSERVATION_EVIDENCE` is set, the collector reads a non-secret
SRE-approved alert-route observation record. The record must be current,
unexpired, include an approved downstream route or queue-owner process,
evidence/remediation notes, and match the live stable SNS/SQS route metadata
exactly. Volatile queue-depth counts are retained as observation-only metadata
and are not used for exact matching.
When `report-alert-route-observation` writes JSON, it rejects missing or
expired `ALERT_ROUTE_EXPIRY_DATE`, stale or future `ALERT_ROUTE_REVIEW_DATE`,
and decision values the collector would reject.
Set `ALERT_ROUTE_OBSERVATION_FORCE=1` only when intentionally replacing an
existing Markdown or JSON observation artifact.
If `SECURITY_ACCOUNT_ATTESTATION_EVIDENCE` is set, the collector reads a
non-secret JSON security-owner attestation for aggregate IAM account-access
posture. The attestation must be current, unexpired, owner-approved, include
human MFA/SSO, active-key, permissions-boundary or exemption decisions, and
match the live aggregate IAM counts exactly. It can only cover the human-access
and active-key exception blockers; root MFA, root access keys, or unreadable IAM
metadata remain hard failures.
When `report-security-account-attestation` writes JSON, it rejects missing or
expired `SECURITY_ACCOUNT_EXPIRY_DATE`, stale or future
`SECURITY_ACCOUNT_REVIEW_DATE`, and owner decision values the collector would
reject.
Set `SECURITY_ACCOUNT_ATTESTATION_FORCE=1` only when intentionally replacing an
existing Markdown or JSON attestation artifact.
If `PRODUCTION_DR_OWNER_EVIDENCE` is set, the collector reads a non-secret JSON
production DR owner record. The record must be current, unexpired,
owner-approved, include production recovery ownership, escalation,
communications, RTO/RPO, latest accepted drill, next review, evidence retention,
and match the latest restore-drill metadata exactly.
When `report-production-dr-owner-evidence` writes JSON, it rejects missing or
expired `PRODUCTION_DR_EXPIRY_DATE`, stale or future
`PRODUCTION_DR_REVIEW_DATE`, missing owner actions, invalid approvals, and
restore-drill mismatches the collector would reject.
Set `PRODUCTION_DR_OWNER_FORCE=1` only when intentionally replacing an existing
Markdown or JSON production DR owner artifact.
Question-matrix and external-control records must include owner, freshness,
coverage, unresolved-count, evidence-location, and fallback fields; boolean
confirmation flags do not unlock final 5/5 scores.
Question-matrix records must also include `frameworkSourceVerification` with a
fresh `checkedAt`, source label, the official AWS Well-Architected TOC URL
(`https://docs.aws.amazon.com/wellarchitected/latest/framework/toc-contents.json`),
and pillar question counts matching the current AWS Well-Architected Framework
question set: Operational Excellence `11`, Security `11`, Reliability `13`,
Performance Efficiency `5`, Cost Optimization `11`, and Sustainability `6`.
Run `make verify-well-architected-questions` when refreshing the matrix to
compare the local Markdown matrix rows, `questionScores` IDs, `questionCount`,
pillar counts, 1-5 score values, and score/status consistency against the AWS
public Framework TOC; the verification artifact records its own `checkedAt`
timestamp for audit freshness.
Non-passed `questionScores` entries must also retain non-empty `evidenceRefs`
so each remaining blocker maps to a concrete issue, collector check, script, workflow,
or evidence artifact.
External-control records are checked per control as well as at the file level:

- `controlCount` must match the number of objects in `controls`
- `unresolvedControlCount` must match controls whose `status` is not `passed`
- every required control ID must be present
- every control, passed or unresolved, must include a non-empty `evidence` string list
- every non-passed control must also include a non-empty `unresolvedReason`

The accepted shape is intentionally non-secret:

```json
{
  "id": "branch_protection",
  "status": "passed",
  "evidence": [
    "GitHub ruleset 13906584 requires Ruff, Ty, Maintainability, Architecture, Structural, Dependency Hygiene, Coverage, Local Battery, Mutation, Run Bats Tests, Secrets Scan, Dependency Audit, Bandit, Dependency Review, Actionlint, Yamllint, Hadolint, Preview, Destructive Diff Gate, IAM Validation, Policy, CodeQL (python), and CodeQL (actions)."
  ]
}
```

For unresolved controls, keep the evidence non-secret and explain the blocker:

```json
{
  "id": "security_account_controls",
  "status": "unresolved",
  "evidence": [
    "Aggregate IAM collector reports root/account MFA enabled and no root access keys."
  ],
  "unresolvedReason": "Security-owner attestation for human MFA/SSO and the active IAM user access-key exception is still pending."
}
```

The accepted Dependabot exception shape is also non-secret:

```json
{
  "workload": "bootstrap-infrastructure",
  "owner": "security-reviewer",
  "approvedBy": "Kravalg",
  "reviewedAt": "2026-06-10T09:00:00Z",
  "expiresAt": "2026-06-17T09:00:00Z",
  "dependencyName": "GitPython",
  "manifestPath": "uv.lock",
  "alertNumbers": [4, 5, 6, 7, 8],
  "approval": "approved",
  "reason": "Patched lockfile is staged and default-branch alert closure is pending merge.",
  "remediationPlan": "Merge the patched lockfile or revisit the exception before expiry.",
  "evidence": [
    "Security owner approved this short exception window."
  ]
}
```

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

Repository administrators can make steps 4 and 5 reproducible with:

```bash
gh api graphql \
  -f query='query { repository(owner:"VilnaCRM-Org", name:"bootstrap-infrastructure") { viewerPermission viewerCanAdminister } }' \
  --jq '.data.repository'

uv run python scripts/configure_github_repository_controls.py \
  --repo VilnaCRM-Org/bootstrap-infrastructure \
  --prod-reviewer Kravalg \
  --apply
```

The GraphQL preflight must report an admin-capable identity before `--apply`
can update repository-owned rulesets or protected environments. The current
non-admin evidence for PR #22 is `viewerPermission=WRITE` and
`viewerCanAdminister=false`, so this command is intentionally expected to stop
at the admin-rights preflight until a repository administrator runs it.

Run the same command with `--dry-run`, or with neither `--dry-run` nor
`--apply`, to inspect the ruleset and protected environment payloads. Dry runs
resolve the reviewer login to the numeric GitHub user ID used by the environment
API. Use `--verify-only` after applying settings manually or through another
tool to re-read the active `main` ruleset and `prod` environment without
writing. With `--apply`, the helper writes the desired controls and then runs
the same verification. Verification exits non-zero unless the required checks,
pull-request review/thread-resolution rules, protected-branch deployment
policy, self-review prevention, and configured production reviewer are visible
in GitHub metadata.

## Current limitations

- CodeQL is GitHub-native; the repository keeps the workflow under structural
  test coverage, but there is no local `make` equivalent
- The custom VilnaCRM CrossGuard pack is the enforced policy-pack layer in this
  template; the workflow does not vendor the Node-based AWSGuard package into
  the Python/uv Docker image
- IAM validation is only as complete as the preview artifact; policies that are
  created entirely outside Pulumi still need separate review
