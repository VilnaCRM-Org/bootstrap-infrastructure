# SRE Operations Guide

This guide covers the day-2 operating model for the template: validating local
prerequisites, previewing changes safely, and handling common infrastructure
maintenance flows.

## Preflight

Run the basic workstation check before blaming Docker, Pulumi, or CI:

```bash
make doctor
```

The command verifies that Docker and Docker Compose are available, reports the
effective env file, and prints the service and Pulumi directory that the
Makefile will target. It does not print secrets.

## Daily Workflow

For the normal edit-test loop:

```bash
make test
```

Before pushing a branch that changes infrastructure logic, Docker wiring, or CI
contracts, use the same non-mutation battery that GitHub runs in
`pulumi-local.yml`:

```bash
make ci-pr
```

When you also want the dedicated mutation suite locally:

```bash
make ci
```

Use `make ci-pr` to catch the same structural, policy, quality, unit,
integration, CLI, security-scan, and preview guardrails that GitHub runs before
merge. Use `make ci` when you also want the mutation suite before the branch
reaches GitHub Actions.

## Preview and Apply

Use previews as the default gate for real infrastructure changes:

```bash
make pulumi-preview
```

The preview target syncs the shared `uv` environment if necessary and enables
the repository policy pack automatically, so guardrail drift is caught before
the Pulumi plan is shown.

When you want to reproduce the credential-free PR preview flow locally, use:

```bash
make test-guardrails
```

That target generates the preview artifact and blocks destructive changes to
critical resources without requiring live AWS credentials. Keep
`make test-iam-validation` for the separate Access Analyzer check when you
intentionally have AWS credentials configured.

Save and review the exact plan with `make pulumi-plan`, then apply that plan:

```bash
make pulumi-up-plan
pulumi -C pulumi stack output
```

`make pulumi-up-plan` uses the same policy-pack enforcement path as preview.

For drift reconciliation without applying a fresh plan:

```bash
make pulumi-refresh
```

For teardown:

```bash
make pulumi-destroy
```

Treat destroy as irreversible unless you have a tested restore path.

## Stack Strategy

Recommended stack patterns:

- `test` for the shared test AWS account
- `prod` for the protected production AWS account
- `dev` for local or shared baseline development when the repository still uses it
- `pr-<number>` for short-lived validation environments
- `smoke` for manual release verification

Avoid mixing unrelated validation work into one long-lived shared stack. It
makes previews noisy and rollback decisions ambiguous.

Shared `test` and `prod` stacks are not scratch space. Use ephemeral stacks for
experiments and destroy them after validation. Automation does not implicitly
create missing stacks in shared backends; initialize or migrate shared stacks
explicitly with the configured AWS KMS Pulumi secrets provider:

```bash
pulumi -C pulumi stack init <stack> --secrets-provider "$PULUMI_SECRETS_PROVIDER"
```

Use the stack-targeted migration command for legacy stacks that need to move to
AWS KMS-backed secrets:

```bash
pulumi -C pulumi stack change-secrets-provider \
  "awskms://alias/ALIAS_NAME?region=REGION" \
  --stack <stack>
```

Replace `ALIAS_NAME` and `REGION` with the target AWS KMS key alias or key ID
and AWS Region.

## Replica Region Migration

Committed `test` and `prod` stack files pin
`bootstrap-infrastructure:replicationRegion: eu-west-1` so future code defaults
cannot silently relocate replica buckets. That setting drives both the Pulumi
state replica buckets in `pulumi/infra/pulumi_state.py` and the central logging
replica bucket in `pulumi/infra/logging_bucket.py`.

Existing stacks that relied on the old implicit default need an explicit
migration choice before their next `pulumi up`:

1. Preserve the existing replica region by setting
   `bootstrap-infrastructure:replicationRegion: us-east-1` in that stack's
   `pulumi/Pulumi.<stack>.yaml`, then run a normal preview. If the policy
   allow-list blocks that legacy region, carry a reviewed migration exception
   with the same change instead of bypassing CrossGuard.
2. Move to `eu-west-1` by performing a manual replica drain first. Confirm S3
   replication is caught up, retain or copy any required objects from the old
   state and logging replicas, then update the stack config and review the
   preview during a maintenance window.

Do not run targeted or partial updates that include `pulumi-state` while
omitting `central-logging` during this migration. State bucket logging depends
on the concrete central logging bucket resources, so a full-stack preview/apply
keeps the logging and state replica changes ordered together.

## GitHub Environment Operations

The deployment boundary is the GitHub environment:

- `test-preview` handles protected command previews; eligible same-repo PR
  guardrails use their bounded PR role
- `test` handles main-branch test applies and test drift
- `prod-preview` handles production preview and drift without production apply
  permissions
- `prod` handles production apply and must require reviewers plus deployment
  branch restrictions

Before approving `prod`, compare the reviewed commit SHA with the apply SHA and
review the preview summary, destructive diff result, IAM validation result, AWS
account evidence, stack name, and role purpose. Do not approve a production
apply from a different SHA than the preview you reviewed.

Privileged runs should preserve evidence that is useful but not sensitive:
GitHub environment, account ID, region, OIDC role purpose, backend type, stack
names, guardrail mode, commit SHA, and artifact names. Evidence must not include
stack exports, decrypted secret values, access keys, tokens, or private keys.

## Safe AWS Validation

Use metadata-only checks when validating account setup:

```bash
aws sts get-caller-identity
aws s3api head-bucket --bucket <state-bucket>
aws kms describe-key --key-id alias/<pulumi-secrets-key-alias>
aws iam get-role --role-name <github-oidc-role-name>
```

These commands confirm identity and bootstrap dependencies without reading
secret payloads. Keep Pulumi validation non-secret as well:

```bash
pulumi -C pulumi stack ls
pulumi -C pulumi config
```

Do not use secret-revealing flags or raw stack export commands for routine
evidence collection.

## Operations Alerting

The bootstrap stack provisions an encrypted SNS topic named
`bootstrap-<environment>-operations`, a customer-managed KMS key aliased as
`alias/bootstrap-<environment>-operations-alerting`, and EventBridge rules for
high-severity control-plane signals:

| Signal | Source | Immediate owner action |
| --- | --- | --- |
| AWS Backup failed, aborted, expired, or completed-with-issues job | `aws.backup` job state events | Confirm the affected vault, plan, and protected bucket, then schedule a fresh backup or restore drill |
| KMS key deletion, disablement, rotation disablement, or policy change | `aws.kms` CloudTrail events | Verify the key and actor, cancel unintended deletion, and review deploy role access |
| IAM OIDC provider or role policy changes | `aws.iam` CloudTrail events | Confirm the GitHub OIDC trust still matches approved branches or environments |
| S3 bucket encryption, logging, policy, or replication changes | `aws.s3` CloudTrail events | Confirm state and log buckets still enforce encryption, TLS, logging, and replication |

The stack creates an account-local SQS subscription for durable alert capture.
Do not treat human escalation as complete until the target account also has a
confirmed owner and incident route for processing that queue or forwarding the
SNS topic into ChatOps, ticketing, or paging.

For monthly OPS8 evidence, run the Well-Architected collector first, then
render a reviewed alert-route observation from the collector output:

```bash
make report-well-architected-evidence

ALERT_ROUTE_OBSERVATION_OUTPUT=docs/alert-route-observation-YYYY-MM-DD.md \
ALERT_ROUTE_OBSERVATION_JSON_OUTPUT=docs/alert-route-observation-YYYY-MM-DD.json \
ALERT_ROUTE_REVIEWER='<reviewer or team>' \
ALERT_ROUTE_OWNER='SRE' \
ALERT_ROUTE_DOWNSTREAM='<ChatOps, ticketing, paging, or approved queue-owner process>' \
ALERT_ROUTE_SEVERITY='<severity and response expectation>' \
ALERT_ROUTE_FALLBACK='<fallback when the downstream route is unavailable>' \
ALERT_ROUTE_DECISION='accepted' \
ALERT_ROUTE_EXPIRY_DATE='YYYY-MM-DDTHH:MM:SSZ' \
ALERT_ROUTE_ACTION='<non-secret evidence and remediation note>' \
make report-alert-route-observation

ALERT_ROUTE_OBSERVATION_EVIDENCE=docs/alert-route-observation-YYYY-MM-DD.json \
make report-well-architected-evidence
```

Set `ALERT_ROUTE_OBSERVATION_FORCE=1` only when intentionally replacing an
existing Markdown or JSON observation artifact.

The generated observation is only acceptable evidence after the reviewer
records a real downstream route or explicitly approved queue-owner process. The
target file should be committed or otherwise retained as the monthly
observation history for the workload.

## Operations Evidence Contract

Well-Architected evidence should use metadata and durable review artifacts, not
secret-bearing dumps. Retain these non-secret handles when validating a stack:

- `operationsAlertTopicArn`
- `operationsAlertRuleNames`
- `operationsAlertTopicKeyAliasName`
- `operationsAlertQueueArn`
- `operationsAlertQueueName`
- `operationsAlertQueueSubscriptionArn`
- `monthlyBudgetName`
- `costAnomalyMonitorArn`
- `costAnomalySubscriptionArn`
- `backupVaultName` and `backupVaultArn`
- `OPERATIONS_TOPIC_ARN` when an existing operations SNS topic is reused
- `OPERATIONS_CLOUDTRAIL_NAME` when an existing operations trail is reused
- `RESTORE_DRILL_EVIDENCE` for the latest workload-scoped restore drill record
- `DEPENDABOT_EXCEPTION_EVIDENCE` for non-secret exact-alert exception
  evidence when default-branch remediation cannot land immediately
- `ALERT_ROUTE_OBSERVATION_EVIDENCE` for non-secret downstream alert-route
  observation evidence
- `SECURITY_ACCOUNT_ATTESTATION_EVIDENCE` for non-secret security-owner
  attestation of aggregate IAM account-access posture
- `PRODUCTION_DR_OWNER_EVIDENCE` for non-secret production DR owner approval,
  RTO/RPO, escalation, communications, drill, review, and retention evidence
- `QUESTION_MATRIX_EVIDENCE` for the structured 57-question review record
- `EXTERNAL_CONTROL_EVIDENCE` for structured external-control evidence

For each environment, the monthly evidence bundle should also record the
reviewer, review date, alert subscription status, incident route, last backup
review, last restore drill, last drift run, budget threshold, anomaly threshold,
and any missed KPI actions. Do not include stack exports, decrypted Pulumi
config, secret values, access keys, tokens, private keys, or contents of state
objects.

Run `make report-well-architected-evidence` after privileged guardrails or a
test-account smoke deploy to create the standard metadata-only evidence bundle.
The target writes `.artifacts/well-architected/evidence.json` and
`.artifacts/well-architected/evidence.md`; the collector reads
`PR_NUMBER`, `AWS_ACCOUNT_ID`, `OPERATIONS_TOPIC_ARN`,
`OPERATIONS_CLOUDTRAIL_NAME`, `RESTORE_DRILL_EVIDENCE`,
`QUESTION_MATRIX_EVIDENCE`, `EXTERNAL_CONTROL_EVIDENCE`, and optional
owner-evidence paths such as `DEPENDABOT_EXCEPTION_EVIDENCE`,
`ALERT_ROUTE_OBSERVATION_EVIDENCE`, `SECURITY_ACCOUNT_ATTESTATION_EVIDENCE`,
and `PRODUCTION_DR_OWNER_EVIDENCE` directly when the matching CLI flags are
omitted. Set those variables only when the non-secret identifiers or
evidence records are available; the collector records missing values as
blockers so operators can close them without fabricating 5/5 evidence.
After the collector and AWS question verifier run, use
`make report-well-architected-closeout` to render
`.artifacts/well-architected/owner-closeout-bundle.md`. The bundle keeps the
owner/admin handoff non-secret and includes an Objective Audit plus
Prompt-To-Artifact Checklist that maps the 5/5 goal to current evidence,
scores, failed gates, unresolved questions, and unresolved external controls.
External-control evidence must name the required control IDs for
branch protection, alert route, backup/restore, FinOps, quota headroom,
security account controls, sustainability governance, and production approval.
The collector also validates the per-control proof shape: passed controls need
a non-empty `evidence` list, unresolved controls need an `unresolvedReason`, and
the top-level control counts must match the `controls` array. Owner comments,
private screenshots, or admin-only views can be referenced by non-secret issue
URLs or metadata summaries, but do not include private user lists, access key
IDs, secret values, or stack exports.

## Ownership And RACI

Repository-owned controls still need accountable humans or teams before they
can support a 5/5 claim.

| Activity | Accountable | Responsible | Consulted | Informed |
| --- | --- | --- | --- | --- |
| CI guardrail and branch-protection evidence | Maintainer | Platform owner | SRE, security reviewer | Repository contributors |
| Backup health, restore drills, drift, and DR evidence | SRE | SRE | Maintainer, security reviewer | FinOps for cost impact |
| KMS, IAM/OIDC, state access, and logging incidents | Security reviewer | SRE | Maintainer | Repository contributors |
| Budget, anomaly, transfer-cost, and quota evidence | `platform-maintainers` for the test workload; FinOps owner for future shared or production workloads | Maintainer | SRE | Security reviewer |
| Repository catalog owner and stale cleanup review | Maintainer | Repository owner | SRE, FinOps owner | Platform owner |

Current external-control closeout for issue #17 is routed through issues #26-#30.
Those issues are assigned to `Kravalg`, `pixelTM`, and `vilnacrm` because the
remaining controls require repository admin, security-owner, or SRE evidence
outside the current automation token.

If any role or external-control owner is unnamed for an environment, the
related Well-Architected score must stay unchanged and the review should record
the missing owner as a blocker.

## Severity Model

Use these severities for bootstrap infrastructure events:

| Severity | Examples | Response expectation |
| --- | --- | --- |
| SEV1 | Production state bucket access failure, unintended KMS key deletion schedule, state/log bucket policy removal, confirmed secret exposure, or destructive prod apply drift. | Immediate incident owner, containment first, maintainer and security reviewer notified. |
| SEV2 | Failed AWS Backup job for protected resources, prod drift, GitHub OIDC trust change, budget forecast at or above 100%, or Cost Anomaly alert above threshold. | Same business day triage, owner assigned, mitigation or accepted-risk note recorded. |
| SEV3 | Test-environment drift, non-prod backup failure, catalog fanout warning, quota headroom warning, or stale repository metadata. | Triage within three business days and track follow-up to closure. |
| SEV4 | Documentation gaps, dashboard freshness gaps, non-urgent KPI misses, or scheduled review actions. | Review in the next monthly operations cycle. |

## KPI Register

The monthly operations review should track these minimum KPIs:

| KPI | Target | Evidence source | Owner |
| --- | --- | --- | --- |
| Backup job health | No unresolved failed, aborted, or expired protected-resource jobs. | AWS Backup metadata and EventBridge alert history. | SRE |
| Restore drill freshness | Last successful non-production drill is no older than 90 days. | Restore evidence record. | SRE |
| Drift freshness | Scheduled drift evidence is no older than 24 hours for shared stacks. | GitHub workflow run or safe Pulumi refresh evidence. | SRE |
| Guardrail health | Required same-repo safety checks are passing and not skipped outside policy. | GitHub checks and branch-protection evidence. | Maintainer |
| Alert route freshness | Operations SNS subscription and downstream route confirmed in the last 30 days or after route changes. | SNS metadata or incident-tool evidence. | SRE |
| Cost alert readiness | Budget and Cost Anomaly thresholds reviewed in the last 30 days. | Budget/anomaly metadata plus `docs/finops-review-2026-05-09.md`. | `platform-maintainers` |
| Catalog demand review | Active catalog entries have owner, lifecycle state, last-reviewed date, and expected environments. | Repository catalog and fanout output. | Maintainer |

Missing or stale KPI evidence is a no-go for an honest 5/5 even when the
underlying AWS resources exist.

## Runbook Expectations

Every bootstrap runbook or alert playbook should include:

- Signal source, severity, owner, and escalation route.
- First five minutes of metadata-only checks.
- Containment and rollback or fail-forward decision points.
- Recovery steps and validation commands that avoid secret-revealing output.
- Communication template for affected maintainers or account owners.
- Evidence to retain, including timestamps, workflow URLs, AWS resource names,
  and cleanup confirmation.
- Post-incident review trigger, action owner, target date, and fallback if the
  evidence cannot be collected safely.

## Backup and Restore Evidence

Monthly backup review should record the stack, account, vault name, plan name,
last successful backup job timestamp, and any failed job IDs. Quarterly restore
drills should restore into an isolated location and verify object metadata only;
do not inspect Pulumi state contents, decrypted stack values, or secret payloads
as part of routine evidence collection. Restore evidence must identify the
bootstrap workload, source recovery point, operator, validation result, and
cleanup confirmation for the isolated restore location; generic account-level
restore evidence is not enough for this workload.

Target recovery posture for bootstrap state is:

- RPO: one daily AWS Backup recovery point plus S3 versioning
- RTO: restore procedure reviewed and executable within one business day
- DR boundary: primary-region state and log buckets have cross-region replicas

## Incident and Drift Triage

When something looks wrong:

1. run `make doctor`
2. run `make test` to separate local code issues from cloud drift
3. run `make pulumi-refresh` if the concern is live-state drift
4. inspect `pulumi -C pulumi stack output` for the non-secret state you expect
5. use an ephemeral stack for risky experiments instead of debugging directly in
   a shared environment
6. if a change is intentionally destructive, document the reason and add the
   `allow-destructive-infra-change` label instead of bypassing the workflow

## CI Troubleshooting

Map failures back to their local commands:

- `Structural` -> `make test-pulumi && make test-repository-catalogs && make test-repository-fanout`
- `Policy` -> `make test-policy`
- `Ruff` -> `make test-ruff`
- `Ty` -> `make test-ty`
- `Maintainability` -> `make test-maintainability`
- `Architecture` -> `make test-architecture`
- `Dependency Hygiene` -> `make test-dependency-hygiene`
- `Coverage` -> `make test-unit && make test-integration-unprivileged && make test-policy && make test-coverage` when AWS-backed automation tests are disabled; use `make test-unit && make test-integration && make test-policy && make test-coverage` when they are enabled
- `Unit` -> `make test-unit`
- `Integration` -> `make test-integration-unprivileged` by default, or `make test-integration` when AWS-backed automation tests are enabled
- `Mutation` -> `make test-mutation`
- `Run Bats Tests` -> `make test-cli`
- `Local Battery` -> `make ci-pr-unprivileged` by default, or `make ci-pr` when AWS-backed automation tests are enabled
- `Preview` -> `make test-preview-unprivileged` by default, or `make test-preview` when AWS-backed preview variables are configured
- `Destructive Diff Gate` -> `make test-destructive-diff`
- `Cost Proxy` -> `make test-cost-proxy`
- `IAM Validation` -> `make test-iam-validation-unprivileged` by default, or `make test-iam-validation` when AWS credentials are configured
- `Secrets Scan` -> `make test-secrets`
- `Dependency Audit` -> `make test-deps-security`
- `Bandit` -> `make test-bandit`
- `Actionlint` -> `make test-actionlint`
- `Yamllint` -> `make test-yaml`
- `Hadolint` -> `make test-dockerfile`
- `CodeQL`, `Dependency Review`, `Infracost`, and `CodeRabbit` -> GitHub-native only

That mapping is intentional. If a failure cannot be reproduced locally with the
matching target, the problem is probably workflow-specific and should be treated
as a CI contract issue.

## Release Hygiene

Release automation should stay boring:

- keep changelog generation deterministic
- use the documented token fallback contract
- avoid mixing release logic with deployment logic
- prefer one-purpose workflows over single giant pipelines

## Cleanup

When local state gets messy:

```bash
make clean
```

This removes Compose state and Python build artifacts without touching cloud
resources.

## AWS Configuration And Alert Cutover

AWS Secrets Manager stores account-local CI configuration in the fixed suffixes
`test-pr`, `test`, `prod-preview`, and `prod`. Independently pinned repository
variables `AWS_TEST_ACCOUNT_ID` and `AWS_PROD_ACCOUNT_ID` are validated before
configuration-role assumption; all returned role/backend/KMS values must agree.
The protected `test`, `test-preview`, `prod-preview`, `prod`, `governance`,
`governance-preview`, and `operations-alert-reconcile` environments remain in use.
Configuration suffixes do not replace approval or main-only branch restrictions.
The installed trusted main controller validates original comments, current
permissions, scope, fresh PR head and verified same-head deployment evidence.
No apply/drift role fallback is permitted.

Follow the [AWS Secrets Manager CI cutover manual](aws-secrets-manager-ci-cutover.md)
before privileged CI. Run `make pulumi-plan` and review its exact saved-plan
manifest before `make pulumi-up-plan`; never bypass a failed plan or stale lock.
The alert transition uses fingerprint version 2 and requires sanitized SRE
confirmation before backfill or reconciliation. Main-only environment approval
remains required for `Operations Alert Canonical Backfill` and
`Operations Alert Legacy Reconcile`.
