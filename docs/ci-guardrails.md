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
| `Governance Promotion` | Trusted GitHub evidence app | Governance changes require the same PR commit to pass test and prod apply plus drift; other changes pass scope verification |
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
| `Test Account Evidence` | Collector CLI with 24 explicit installation status-check arguments; ordinary target: `make report-well-architected-evidence` | Fails trusted PR and main evidence runs when final Well-Architected readiness is below 5/5 |

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
2. trusted same-repo runs load the fixed `test-pr` AWS Secrets Manager CI secret, then use
   `make start` and `make publish-pulumi-preview-summary`
3. fork pull requests use `make start` and `make test-preview-unprivileged`
   without a GitHub environment, OIDC permission, AWS credentials, or
   environment variables
4. `make test-destructive-diff`
5. `make test-iam-validation` for trusted previews, or
   `make test-iam-validation-unprivileged` for fork previews

Preview artifacts are written under `.artifacts/pulumi-preview/` and uploaded to
GitHub Actions. The preview summary is appended to `GITHUB_STEP_SUMMARY` so
reviewers can inspect the plan without digging through raw logs first.

For issue 20, privileged previews are AWS Secrets Manager-scoped:

- trusted same-repo PRs use the fixed `test-pr` AWS Secrets Manager CI secret and preview the
  configured test stack
- production release previews use the fixed `prod-preview` AWS Secrets Manager CI secret and
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
The commit identity must be nonempty, and the recorded Pulumi project and policy
pack directories must match the apply job. Local saved-plan commands must set
`PULUMI_COMMIT_SHA` to the reviewed commit, with `PULUMI_EXPECTED_SHA` set to that
same commit when applying. A failed saved-plan apply never cancels a stack lock
or retries as a direct apply. Investigate the owner of an existing lock and
resolve it through the documented recovery procedure before generating a fresh
plan; an error message alone does not prove that a lock is stale.
Test and production applies remain saved-plan-only. If a saved plan cannot be
applied, the workflow fails instead of switching to a direct apply path; rerun
preview and plan generation after fixing the underlying backend, KMS, or plan
artifact issue.

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

Platform deployment jobs read account-specific runtime values directly from fixed
AWS Secrets Manager JSON secrets, rather than GitHub Environment variables,
Pulumi Cloud, or Pulumi ESC. Their repository variables identify the narrowly
scoped configuration loader roles. The separate governance runner uses dedicated
nonsecret repository variables and protected `governance-preview`/`governance`
environments, as described in [the governance runbook](governance-stack.md). AWS Secrets Manager is the vault and
source of truth for account-local values. The fixed CI suffixes are:

| CI suffix | Use |
| --- | --- |
| `test-pr` | Trusted same-repo PR preview, IAM validation, and PR evidence collection |
| `test` | Test apply, test drift, operations alert triage, and Well-Architected evidence |
| `prod-preview` | Production preview, IAM validation, and drift |
| `prod` | Production apply after protected GitHub `prod` approval |

Workflow call sites pass fixed suffixes like `test`, `test-pr`, `prod-preview`,
and `prod`; PR input, issue comments, and repository-dispatch payloads cannot
supply arbitrary secret names. Each suffix maps to one AWS Secrets Manager JSON
secret in the owning AWS account:

| AWS Secrets Manager CI secret suffix | AWS Secrets Manager secret ID |
| --- | --- |
| `test-pr` | `/bootstrap-infrastructure/ci/test-pr` |
| `test` | `/bootstrap-infrastructure/ci/test` |
| `prod-preview` | `/bootstrap-infrastructure/ci/prod-preview` |
| `prod` | `/bootstrap-infrastructure/ci/prod` |

The Pulumi `test` and `prod` stacks manage these AWS Secrets Manager secret
containers and the account-local `GitHubCiConfigRead-*` roles. The isolated
`github-ci-bootstrap` project creates encrypted `SecretVersion` payloads by
default; maintainers populate values manually only when `writeSecretValues` is
disabled or a repair is required.
The workflow loader assumes the matching `GitHubCiConfigRead-*` role through
GitHub OIDC, calls `aws secretsmanager get-secret-value`, parses JSON, validates
the required keys, and exports only validated environment variables. Do not store
secret payloads, credentials, or decrypted values in tracked Pulumi config,
workflow logs, or docs. Explicit nonsecret account IDs in bootstrap stack config
are required to reject the wrong AWS identity before resource allocation.
Nonsecret role/backend/provider metadata may be recorded in the documented
bootstrap outputs and governance variables; this does not permit secret values.

The required AWS CI config `environmentVariables` are:

| Variable | Purpose |
| --- | --- |
| `AWS_ACCOUNT_ID` | Expected AWS account for `allowed-account-ids` and audit evidence |
| `AWS_REGION` | AWS region used by `configure-aws-credentials` and Pulumi |
| `AWS_PREVIEW_ROLE_ARN` | OIDC role assumed by preview and IAM validation jobs |
| `AWS_APPLY_ROLE_ARN` | OIDC role used by test or production apply jobs |
| `AWS_DRIFT_ROLE_ARN` | OIDC role assumed by drift jobs |
| `PULUMI_BACKEND_URL` | Account-specific shared Pulumi backend |
| `PULUMI_SECRETS_PROVIDER` | AWS KMS Pulumi secrets provider URI used by stacks |
| `PULUMI_PREVIEW_STACKS` | Comma-separated stack list for preview and apply |
| `PULUMI_DRIFT_STACKS` | Comma-separated stack list for drift checks |

Job-specific AWS CI variables:

| Variable | Purpose |
| --- | --- |
| `AWS_OPERATIONS_ALERT_TRIAGE_ROLE_ARN` | Dedicated OIDC role for operations alert triage |
| `OPERATIONS_ALERT_QUEUE_NAME` | SQS queue drained by operations alert triage |
| `OPERATIONS_TOPIC_ARN` | Standard metadata input for evidence collection when the environment reuses an existing operations SNS topic |
| `OPERATIONS_CLOUDTRAIL_NAME` | Standard metadata input for evidence collection when the environment reuses an existing operations CloudTrail |

Optional non-secret repository variables:

| Variable | Purpose |
| --- | --- |
| `RESTORE_DRILL_EVIDENCE` | Standard metadata input pointing to the latest workload-scoped restore drill evidence record |
| `DEPENDABOT_EXCEPTION_EVIDENCE` | Optional non-secret exception evidence covering exact open default-branch Dependabot alert numbers when remediation cannot land immediately |
| `ALERT_ROUTE_OBSERVATION_EVIDENCE` | Optional non-secret SRE-approved downstream alert-route observation evidence matching the live operations route |
| `SECURITY_ACCOUNT_ATTESTATION_EVIDENCE` | Optional non-secret security-owner attestation for aggregate IAM account-access posture, human MFA/SSO posture, active-key decision, and permissions-boundary or exemption decision |
| `PRODUCTION_DR_OWNER_EVIDENCE` | Optional non-secret production-owner DR evidence that binds RTO/RPO, recovery ownership, escalation, communications, latest accepted drill, next review, and retention location to current restore-drill metadata |
| `QUESTION_MATRIX_EVIDENCE` | Standard metadata input pointing to the structured 57-question review evidence record |
| `EXTERNAL_CONTROL_EVIDENCE` | Standard metadata input pointing to the structured external-control owner and freshness evidence record |

Shared backends should use an AWS KMS-backed Pulumi secrets provider rather
than a passphrase-managed stack secret flow.

`Pulumi Test Deploy` uses the `test` AWS Secrets Manager CI backend, stack list, apply role, and
drift role. Missing AWS CI values fail fast before AWS credentials are requested.

Fork pull requests always run the unprivileged artifact path and the
destructive diff gate. Same-repo pull requests fail fast when required
AWS-backed environment variables are missing instead of silently bypassing
privileged guardrails. The AWS-backed preview and Access Analyzer validation
paths remain same-repo only because they require OIDC-issued AWS credentials.

Privileged jobs should emit sanitized evidence in the job summary or logs:

- AWS Secrets Manager CI secret name
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
The trusted PR and push path is enforced: non-scheduled runs fail when the
collector exits non-zero. Fork PRs do not receive AWS credentials and record an
unprivileged skip summary instead.
The Make target only creates the output artifact paths; the Python collector
reads the standard environment variables directly when the matching CLI flags
are omitted. When set, `PR_NUMBER`, `AWS_ACCOUNT_ID`, `OPERATIONS_TOPIC_ARN`,
`OPERATIONS_CLOUDTRAIL_NAME`, `RESTORE_DRILL_EVIDENCE`,
`QUESTION_MATRIX_EVIDENCE`, `EXTERNAL_CONTROL_EVIDENCE`, and
`PRODUCTION_DR_OWNER_EVIDENCE` are standard evidence inputs, not secrets.
Restore evidence must be scoped to this bootstrap workload and include cleanup
confirmation for any isolated restore location.
The collector also reads non-secret Dependabot alert metadata for the configured
manifest path, or for an explicit dependency when `--dependabot-dependency` is
set. Unresolved high or critical default-branch alerts remain SEC11 blockers
until closed or covered by an owner-approved exception.
If `DEPENDABOT_EXCEPTION_EVIDENCE` is set, the collector reads a non-secret
JSON exception record and only treats it as coverage when it is current,
matches the dependency scope and manifest, covers the exact open alert numbers,
and records owner approval plus a remediation plan. Invalid or expired exception
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
pillar counts, `unresolvedQuestionCount`, `unresolvedQuestionIds`,
per-pillar unresolved counts, score averages, 1-5 score values, status values,
score/status consistency, and `frameworkSourceVerification` source metadata
against the AWS public Framework TOC; the verification artifact records its own
`checkedAt` timestamp for audit freshness and includes a sanitized copy of the
validated framework-source metadata. By default the Make target writes this
artifact to `.artifacts/well-architected/question-verification.json`; set
`AWS_WA_QUESTION_VERIFY_OUTPUT` only when a different path is needed.
The hosted Well-Architected Evidence workflow runs the verifier after the
collector, renders `.artifacts/well-architected/owner-closeout-bundle.md` with
`make report-well-architected-closeout`, appends the closeout audit to the job
summary, and uploads the full `.artifacts/well-architected` directory.
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
    "GitHub ruleset 13906584 requires Ruff, Ty, Maintainability, Architecture, Structural, Dependency Hygiene, Coverage, Local Battery, Mutation, Run Bats Tests, Secrets Scan, Dependency Audit, Bandit, Dependency Review, Actionlint, Yamllint, Hadolint, Preview, Destructive Diff Gate, IAM Validation, Policy, CodeQL (python), CodeQL (actions), and Test Account Evidence."
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
  "dependencyName": "all",
  "dependencyNames": ["GitPython", "urllib3"],
  "manifestPath": "uv.lock",
  "alertNumbers": [4, 5, 6, 7, 8, 9, 10],
  "approval": "approved",
  "reason": "Patched lockfile is staged and default-branch alert closure is pending merge.",
  "remediationPlan": "Merge the patched lockfile or revisit the exception before expiry.",
  "evidence": [
    "Security owner approved this short exception window."
  ]
}
```

### Example IAM trust policy

Replace the account ID, organization, repository name, workflow names, and branch
with your own values. `<ACCOUNT_ID>` must be the target 12-digit AWS account ID
using digits only. Non-approval preview, drift, evidence, and test apply roles
trust fixed repository refs or pull requests plus fixed workflow names:

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
          "token.actions.githubusercontent.com:sub": [
            "repo:VilnaCRM-Org/bootstrap-infrastructure:ref:refs/heads/main",
            "repo:VilnaCRM-Org/bootstrap-infrastructure:pull_request"
          ]
        },
        "StringLike": {
          "token.actions.githubusercontent.com:workflow": [
            "Pulumi PR Guardrails",
            "Pulumi Test Deploy",
            "Nightly Guardrails",
            "Pulumi Production",
            "Pulumi PR Command Runner",
            "Well-Architected Evidence"
          ]
        }
      }
    }
  ]
}
```

For the platform deployment roles, production apply is the path that uses a
GitHub Environment subject. The separate governance roles use their own protected
`governance-preview` and `governance` subjects; do not reuse their trust policies
for the platform roles. The platform production subject is:

```text
repo:VilnaCRM-Org/bootstrap-infrastructure:environment:prod
```

Production apply does not trust branch or pull request subjects. Production
preview, IAM validation, and drift jobs run from the protected default branch
through fixed `prod-preview` AWS CI configuration, while production apply requires
only the protected GitHub `prod` Environment subject.

The operations alert triage role should trust only
`operations-alert-triage.yml@refs/heads/main`.

## Production protection

Production release automation has two boundaries:

- `prod-preview` AWS CI config can create review evidence but cannot apply changes
- protected GitHub `prod` approval can apply only after branch protection,
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

1. create or adopt the GitHub OIDC provider in AWS
2. apply the Pulumi `test` and `prod` stacks so AWS creates the four Secrets
   Manager containers and `GitHubCiConfigRead-*` roles
3. populate the four AWS Secrets Manager JSON values in the owning AWS accounts
4. set the repository variables from `githubCiConfigReadRoleArns` and the AWS
   regions
5. apply the Pulumi test and production stacks so the updated IAM trust policies
   converge in AWS
6. run **GitHub Environment Legacy Variable Cleanup** first as a dry run, then
   with the documented confirmation sentence after AWS Secrets Manager-backed privileged CI is
   green
7. delete the temporary `GH_ENVIRONMENT_ADMIN_TOKEN` repository secret after
   cleanup succeeds
10. create the protected `prod` GitHub Environment for production approval
11. enable required reviewers and branch restrictions on `prod`
12. create the protected `operations-alert-reconcile` GitHub Environment with
   required SRE or reviewer approval and no account configuration before legacy
   operations-alert backfill or issue closure; the manual backfill and closure
   workflows also require an HTTPS `sre_confirmation_reference` to the sanitized
   SRE confirmation record
13. mark the required PR checks in GitHub branch protection
14. confirm no stale AWS trust subjects or privileged GitHub Environment account
   variables remain outside the protected `prod` approval boundary
15. decide whether production repositories want stricter stack lists or narrower
   IAM role scopes than the template defaults

Repository administrators can make the GitHub protection steps reproducible with:

```bash
gh api graphql \
  -f query='query { repository(owner:"VilnaCRM-Org", name:"bootstrap-infrastructure") { viewerPermission viewerCanAdminister } }' \
  --jq '.data.repository'

GITHUB_REPOSITORY_CONTROLS_REPO=VilnaCRM-Org/bootstrap-infrastructure \
GITHUB_REPOSITORY_CONTROLS_PROD_REVIEWER=Kravalg \
GITHUB_REPOSITORY_CONTROLS_PROMOTION_APP_ID="${PROMOTION_APP_ID:?Set the dedicated App ID}" \
GITHUB_REPOSITORY_CONTROLS_MODE=--apply \
make configure-github-repository-controls
```

The GraphQL preflight must report an admin-capable identity before `--apply`
can update repository-owned rulesets or protected environments. The current
non-admin evidence for issue #17 is `viewerPermission=WRITE` and
`viewerCanAdminister=false`, so this command is intentionally expected to stop
at the admin-rights preflight until a repository administrator runs it.

Set `GITHUB_REPOSITORY_CONTROLS_MODE=--dry-run`, or omit the variable, to
inspect the ruleset and protected environment payloads. Dry runs resolve the
reviewer login to the numeric GitHub user ID used by the environment API and
print payloads for both `prod` and `operations-alert-reconcile`. Set
`GITHUB_REPOSITORY_CONTROLS_MODE=--verify-only` after applying settings
manually or through another tool to re-read the active `main` ruleset plus the
`prod` and `operations-alert-reconcile` environments without writing. With
`GITHUB_REPOSITORY_CONTROLS_MODE=--apply`, the helper writes the desired
controls and then runs the same verification. Verification exits non-zero unless
the required checks, pull-request review/thread-resolution rules,
exactly one custom deployment rule for the `main` branch, disabled administrator
bypass, self-review prevention, and the sole configured reviewer are visible in
GitHub metadata for every protected command environment. The verifier reads
deployment branch rules separately from the environment settings. Do not use
"Protected branches only": GitHub allows every branch under that setting when
the repository has no classic branch protection rules, even when a ruleset
protects `main`. Tags, wildcard rules, extra branches, and missing branch-rule
metadata fail verification.

## Current limitations

- CodeQL is GitHub-native; the repository keeps the workflow under structural
  test coverage, but there is no local `make` equivalent
- The custom VilnaCRM CrossGuard pack is the enforced policy-pack layer in this
  template; the workflow does not vendor the Node-based AWSGuard package into
  the Python/uv Docker image
- IAM validation is only as complete as the preview artifact; policies that are
  created entirely outside Pulumi still need separate review


### Controller installation evidence

The first controller installation preserves the existing 24 required checks,
three independent approving reviews, and successful `test`/`prod` deployment
requirements. The `Test Account Evidence` workflow explicitly supplies those
24 contexts to the collector during this installation phase. The CLI default,
`REQUIRED_STATUS_CHECKS`, and repository control configurator still require the
final 25 contexts, including the App-issued `Governance Promotion` check. There
is no dispatch input, environment flag, automatic fallback, or alternate signer
that can select a weaker contract. All other evidence checks, readiness scoring,
exit handling, question verification and closeout reporting remain enforced.

This narrow installation invocation avoids requiring a controller-generated
check before its trusted code exists on main. After the corrected controller is
installed, produce genuine promotion proof and enroll the 25th required check
with its dedicated App issuer. In that explicit activation change, remove the
workflow's 24 `--required-status-check` arguments and restore
`make report-well-architected-evidence`; update the installation contract test
at the same time. Keep all existing checks and stronger review/deployment rules
throughout this sequence.

Initial deployment records must describe actual completed operator executions,
with exact commit/account/plan bindings and apply plus drift receipts. Publish
success only after those executions succeed. Label their operator provenance;
they do not prove GitHub OIDC execution or protected-environment approval. Do not
fabricate check contexts or use an extra App key to satisfy installation gates.
