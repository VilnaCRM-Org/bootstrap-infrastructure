# Implementation Readiness: Well-Architected 5/5 Remediation Roadmap

## Readiness Summary
Issue #17 planning is ready and the first implementation PR is now scoped to
safe, non-secret controls that do not require irreversible account-level cost or
retention decisions. This implementation covers the highest-priority in-repo
slice: automation IAM blast-radius reduction, operations/security event
monitoring, classification tags, repository metadata, static fanout checks,
preview cost proxy evidence, and AWS Budget/Cost Anomaly Detection controls.

This implementation does not claim final 5/5 Well-Architected scores. Several
target controls still require external evidence or account-owner decisions,
including branch protection proof, confirmed alert subscriptions, live AWS quota
headroom, activated cost allocation tags, monthly FinOps review artifacts,
restore drills, and production approval evidence.
Any proxy score or guardrail pass is therefore an interim readiness signal, not
a final 5/5 Well-Architected score, while question-matrix gaps and external
evidence remain open.

## Alignment Checks

| Area | Status | Notes |
| --- | --- | --- |
| Problem definition | Ready | Issue #17 provides pillar scores, question-level gaps, priority groups, and completion criteria. |
| Scope boundary | Ready | This implementation PR changes Pulumi code, scripts, docs, tests, and specs, but avoids secret access, stack exports, irreversible Vault Lock decisions, and organization-wide cost-policy changes. |
| Epic decomposition | Ready | Eight epics preserve the issue priority model and cover all listed roadmap items. |
| Evidence model | Ready | Future controls require repo, CI, AWS metadata, or external-control evidence. |
| Question coverage | Ready | `question-matrix.md` covers all 57 AWS Well-Architected questions with current evidence, gaps, target proof, owner role, and cadence. |
| FR/NFR coverage | Ready | PRD and architecture cover current repo functions, non-functional constraints, evidence freshness, and score-claim gates. |
| Secret safety | Ready | Future validation must avoid stack exports, decrypted config, cloud-secret payloads, and environment dumps. |
| Implementation readiness | Partially implemented | P0/P1 in-repo guardrails are implemented where ownership is clear; remaining items need owners and external evidence decisions. |

## Implemented In This PR

| Area | Evidence |
| --- | --- |
| Automation IAM | Repository Pulumi secrets KMS data-plane actions were removed from bootstrap automation; new SNS/EventBridge permissions are scoped to deterministic operations resources. |
| Operations monitoring | `OperationsMonitoring` creates the environment operations SNS topic, a dedicated customer-managed KMS key for encrypted EventBridge delivery, and EventBridge rules for Backup failure, KMS risk, IAM/OIDC risk, and S3 control-plane risk events. |
| CloudTrail evidence | Environments may pass `OPERATIONS_CLOUDTRAIL_NAME` as standard evidence input to reuse an existing operations CloudTrail and avoid creating or managing duplicate management trails. |
| Cost controls | `CostControls` creates the monthly AWS Budget, 80% actual and 100% forecast notifications, creates or reuses a service-dimensional Cost Anomaly Detection monitor, creates an immediate anomaly subscription, supports optional cost allocation tag activation, and exports non-secret review handles. |
| Classification | `DataClassification`, `Criticality`, and `RetentionClass` are default tags, committed stack config values, and policy-pack required tags. |
| Catalog demand metadata | Repository catalogs support `owner`, `lifecycleState`, `lastReviewed`, and `expectedEnvironments`; metadata is exported and tagged where repository resources are created. |
| Static fanout | `make test-repository-fanout` estimates resource growth before catalog expansion is merged. |
| Preview cost proxy | `make test-cost-proxy` reads Pulumi preview JSON and blocks unusually large durable-resource fanout. |
| Documentation | SRE, security, CI guardrail, testing, and cost/performance/sustainability docs describe the new evidence and remaining external-control requirements. |

## Recommended Implementation Order

1. Epic 1: make same-repo AWS-backed guardrails mandatory and evidence-backed.
2. Epic 2: fix replication-region defaulting, allowlist validation, and RTO/RPO assumptions.
3. Epic 3: reduce bootstrap automation IAM blast radius and document remaining wildcards.
4. Epic 4 and Epic 5: add monitoring, alerting, incident process, restore runbooks, and restore validation.
5. Epic 6 and Epic 7: operationalize cost controls, repo-fanout preflight, quota checks, and cleanup cadence.
6. Epic 8: add lifecycle, sustainability, and conditional future policy coverage.
7. Run a follow-up Well-Architected review and update scores only after implementation evidence exists.

## External Dependencies

| Dependency | Needed For | Evidence Required |
| --- | --- | --- |
| GitHub branch protection settings | Epic 1 | Required status checks, reviewer rules, and skip policy evidence. |
| FinOps operating model and payer-account evidence | Epic 6 | Cost Explorer enabled in the target account, approved budget/anomaly thresholds, confirmed alert route, activated tag evidence when enabled, monthly cost report location, transfer model, and spend approval policy. |
| Alert routing destination | Epic 4 | Confirmed SNS subscription, ChatOps, ticketing, or external incident tool ownership and routing evidence. |
| Backup Vault Lock decision | Epic 5 | In-repo implementation evidence or external-control exemption. |
| Quota ownership | Epic 7 | Service quota thresholds, approval owner, and escalation path. |
| Restore drill evidence | Epic 5 | `RESTORE_DRILL_EVIDENCE` record for this bootstrap workload with latest non-production restore date, operator, source backup, validation result, isolated restore location, and cleanup confirmation. |
| Production approval evidence | Epic 1 | Protected environment reviewer rules, approved apply evidence, reviewed SHA, and skipped-check policy. |
| Security account controls | SEC1-SEC11 | MFA/SSO posture, CloudTrail live-apply evidence, GuardDuty/Security Hub/Config evidence, vulnerability SLA, and exception register where applicable. |
| Sustainability goals | Epic 8 | Owner-approved goals for region selection, retention, backups, and cleanup. |
| Well-Architected review owner | Epic 0 | Owner for question-matrix updates, score changes, evidence expiry, and follow-up review. |

## Remaining Blockers For Honest 5/5

The current branch implements meaningful repo-owned controls, but a final 5/5
claim is blocked until all of the following are current and non-secret:

- Branch protection proof for exact required checks and reviewer rules.
- Confirmed operations SNS subscription and downstream incident route.
- FinOps owner approval for budget/anomaly thresholds, monthly cost report
  location, Cost Explorer enablement, activated cost allocation tags where
  enabled, spend policy, and transfer-cost model.
- Live AWS Service Quotas or account headroom evidence for catalog expansion.
- Backup Vault Lock decision or documented exemption plus quarterly restore
  drill evidence scoped to this workload and cleanup-confirmed.
- Named RACI owners, severity escalation path, KPI observations, and runbook
  drill records for each shared environment.
- Security account evidence for human access posture and external detection
  services.
- Production apply approval evidence tied to the reviewed commit SHA.
- Sustainability owner, KPI cadence, and exception process.

## Risk Controls For Future PRs

- Keep each implementation PR focused on one epic or one tightly related story group.
- Update docs and tests in the same PR as any infrastructure or workflow behavior change.
- Use `pulumi -C pulumi ...` for direct Pulumi commands.
- Use AWS KMS Pulumi secrets providers; do not add passphrase-backed shared backend guidance.
- Prefer metadata-only AWS validation such as identity, bucket, KMS, IAM, Backup, Budget, EventBridge, CloudWatch, or quota descriptions.
- Validate risky changes in ephemeral stacks such as `pr-<number>` or `smoke`, then destroy the stack after validation.
- Do not treat skipped privileged checks as success for same-repo infrastructure changes unless the skip policy explicitly allows it.
- Do not raise a question score unless the `question-matrix.md` row includes implemented evidence, owner, freshness SLA, fallback action, and comparison with `main`.
- Do not treat proxy scores, static fanout checks, or guardrail pass/fail status as final 5/5 Well-Architected scores while question-matrix gaps, restore-drill evidence, or external evidence blockers remain.
- Do not use boolean confirmation flags for score increases; final score evidence must be structured JSON with owner, freshness, coverage, unresolved-count, evidence-location, and fallback fields.
- Prefer existing OIDC-backed GitHub workflows for test-account Pulumi apply evidence when local Pulumi or KMS backend metadata is not safely configured.

## Test-Account Validation Strategy

The planning PR itself does not mutate Pulumi resources, but the user requested a real AWS test-account validation path before merge. The safe validation strategy is:

| Step | Method | Secret-safety rule | Expected evidence |
| --- | --- | --- | --- |
| Local AWS identity sanity check | `aws sts get-caller-identity` | Metadata-only output; do not inspect credentials. | Confirms AWS CLI can reach an account before any deploy attempt. |
| Local Pulumi readiness check | `pulumi -C pulumi ...` only when Pulumi is installed and KMS backend metadata is configured. | Do not run stack export, show secrets, decrypt, or print environment values. | If local prerequisites are absent, local apply is skipped and CI deploy is used. |
| Branch test deploy | Dispatch `Pulumi Test Deploy` on the PR branch. | Uses GitHub OIDC and configured environment metadata without printing secret values. | Workflow URL, head SHA, preview result, destructive diff result, IAM validation result, apply result, and post-apply drift result. |
| Post-run review | `gh run view` and `gh pr checks` | Inspect logs only for status and failure causes; do not print secrets. | PR comment or readiness update with run conclusion and remaining blockers. |

Current implementation-PR readiness observations:

- Local validation can prove static behavior, policy behavior, preview-artifact
  parsing, and unprivileged guardrail behavior without reading secrets.
- Real test-account evidence still must come from either a safe local
  `pulumi -C pulumi ...` run with AWS KMS backend metadata already configured or
  the existing OIDC-backed GitHub `Pulumi Test Deploy` workflow for this PR
  branch.
- If GitHub test deploy prerequisite metadata is absent, no Pulumi preview/apply
  will run and no AWS resources will be changed. The missing metadata must be
  supplied through the current GitHub environment model or replaced by a
  follow-up Pulumi ESC integration before final merge-readiness can be claimed.

## No-Go Conditions

Future implementation should pause if:
- A story requires reading or printing raw secrets, decrypted Pulumi config, stack exports, or cloud-secret payloads.
- Required branch-protection or external-control evidence cannot be obtained.
- A P0 safety control conflicts with current GitHub environment or AWS account setup.
- A proposed cost, quota, or monitoring control has no owner.
- A future PR widens infrastructure behavior without matching tests or docs.

## Validation For This Implementation PR

This PR should be validated by:

- Confirming the committed diff excludes BMAD/BMALPH/Ralph runtime files and
  keeps only repository-owned specs under `specs/`.
- Running Python lint, format, type, unit, policy, structural, coverage, and
  workflow hygiene checks.
- Running `make test-guardrails-unprivileged`, `make test-cost-proxy`, and
  `make test-repository-fanout` to prove the new guardrails work without AWS
  credentials.
- Confirming the question matrix still contains all 57 AWS Well-Architected
  questions and does not claim final 5/5 scores before structured
  `QUESTION_MATRIX_EVIDENCE` and `EXTERNAL_CONTROL_EVIDENCE` records exist.
- Dispatching or observing the existing `Pulumi Test Deploy` workflow, or a
  safe equivalent test-account Pulumi run, before merge readiness is claimed.

Direct local Pulumi apply is acceptable only when the active AWS identity,
backend URL, stack names, and AWS KMS secrets provider are configured without
printing secret values. Otherwise, use the OIDC-backed test deploy workflow and
record the run outcome.
