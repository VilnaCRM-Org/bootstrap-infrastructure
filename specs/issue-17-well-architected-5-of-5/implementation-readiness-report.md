# Implementation Readiness: Well-Architected 5/5 Remediation Roadmap

## Readiness Summary
Issue #17 planning is ready and the first implementation PR now covers the
repository-owned Well-Architected remediation slice: automation IAM blast-radius
reduction, operations/security event monitoring, classification tags,
repository metadata, static fanout checks, preview cost proxy evidence,
AWS Budget/Cost Anomaly Detection controls, security-account service
definitions, operating evidence, and structured score-claim gates.

This implementation does not claim final 5/5 Well-Architected scores. Several
target controls still require external evidence or account-owner decisions,
including branch protection proof, downstream human alert routing, security
account posture, and production approval evidence.
Any proxy score or guardrail pass is therefore an interim readiness signal, not
a final 5/5 Well-Architected score, while question-matrix gaps and external
evidence remain open.

## Alignment Checks

| Area | Status | Notes |
| --- | --- | --- |
| Problem definition | Ready | Issue #17 provides pillar scores, question-level gaps, priority groups, and completion criteria. |
| Scope boundary | Ready | This implementation PR changes Pulumi code, scripts, docs, tests, and specs, but avoids secret access, stack exports, and irreversible Vault Lock decisions; account-wide cost allocation tag activation is now recorded as metadata-only FinOps evidence. |
| Epic decomposition | Ready | Eight epics preserve the issue priority model and cover all listed roadmap items. |
| Evidence model | Ready | Future controls require repo, CI, AWS metadata, or external-control evidence. |
| Question coverage | Ready | `question-matrix.md` covers all 57 AWS Well-Architected questions with current evidence, gaps, target proof, owner role, and cadence; structured evidence also carries the official AWS Well-Architected TOC URL (`https://docs.aws.amazon.com/wellarchitected/latest/framework/toc-contents.json`) for source verification. |
| FR/NFR coverage | Ready | PRD and architecture cover current repo functions, non-functional constraints, evidence freshness, and score-claim gates. |
| Secret safety | Ready | Future validation must avoid stack exports, decrypted config, cloud-secret payloads, and environment dumps. |
| Implementation readiness | Repository-owned slice implemented | P0/P1 in-repo guardrails, operating evidence, and AWS metadata evidence are implemented where ownership is clear; remaining blockers are external GitHub admin, security-owner, downstream alert-route, and production-approval controls. |

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
| Security account controls | Pulumi defines GuardDuty, Security Hub, AWS Config recorder/delivery, and a dedicated encrypted Config delivery bucket; guarded local apply, live metadata checks, and no-drift validation prove the current test posture. |
| Operating evidence | Current docs record RACI roles, ORR, KPI review, restore and DR drills, FinOps evidence, alert-route evidence, secure-SDLC evidence, performance/resource ADRs, sustainability governance, and question-level score rationale. |
| GitHub admin handoff | `scripts/configure_github_repository_controls.py` emits the required branch ruleset and protected `prod` environment payloads, refuses `--apply` without repository admin rights, and verifies the applied `main` ruleset plus `prod` environment metadata before reporting admin success. |
| Documentation | SRE, security, CI guardrail, testing, and cost/performance/sustainability docs describe the new evidence and remaining external-control requirements. |

## Remaining Handoff Order

1. Repository admin applies the documented `main` ruleset and protected `prod`
   environment.
2. Security owner records human MFA/SSO, static-key exception, external
   security-owner approval, and permissions-boundary or exemption evidence.
3. SRE records the downstream human alert route or an accepted SQS-only
   escalation exemption.
4. Production owner records protected-environment approval evidence for the
   reviewed commit, saved plan, destructive diff, and IAM validation, and
   supplies `PRODUCTION_DR_OWNER_EVIDENCE` for `REL13` production DR ownership,
   RTO/RPO, escalation, recovery order, communications, latest accepted drill,
   next review, and evidence retention location.
5. Maintainer reruns the collector and updates structured evidence only when
   every question row and external control is resolved.

## External Dependencies

| Dependency | Needed For | Evidence Required |
| --- | --- | --- |
| GitHub branch protection settings | Epic 1 | Required status checks, reviewer rules, and skip policy evidence. |
| FinOps operating model and payer-account evidence | Epic 6 | Current for the test workload in `docs/finops-review-2026-05-09.md`; refresh before production approval, catalog growth, new replicated data classes, region changes, or service-family expansion. |
| Alert routing destination | Epic 4 | SNS-to-SQS routing is current in `docs/alert-routing-evidence.md`; downstream human route, ChatOps, ticketing, or incident-tool ownership evidence is still external. |
| Backup Vault Lock decision | Epic 5 | Current test-workload exemption is recorded in `docs/data-protection-recovery-evidence.md`; revisit before production approval or expiry. |
| Quota ownership | Epic 7 | Current headroom is recorded in `quota-headroom-evidence-2026-05-09.json`; refresh before catalog expansion or account-level service changes. |
| Restore drill evidence | Epic 5 | Current restore evidence is `restore-drill-evidence-2026-04-27.json`; next restore drill is due before the 90-day freshness window expires. |
| Production approval evidence | Epic 1 | Protected environment reviewer rules, approved apply evidence, reviewed SHA, and skipped-check policy. |
| Security account controls | SEC1-SEC11 | MFA/SSO posture, static-key exception or remediation evidence, permissions-boundary or exemption attestation, and external security-owner approval. Live GuardDuty/Security Hub/AWS Config posture is current for the test stack, and `make report-security-account-attestation` now provides the non-secret record path once the owner decision exists. |
| Dependabot alert closure or exception | SEC11 | Current Dependabot metadata reports zero open high or critical default-branch alerts for `uv.lock`, and the latest collector passes `github_dependabot_alerts`. If future alerts cannot close immediately, `make report-dependabot-exception` renders the non-secret Markdown/JSON record from the latest collector output and validates approval, evidence notes, freshness, expiry, dependency scope, manifest, and exact alert-number metadata before JSON can be supplied to the collector. |
| Sustainability goals | Epic 8 | Current governance is recorded in `docs/well-architected-operating-evidence.md` and `docs/operating-review-2026-05-09.md`; refresh before region, retention, compute, or catalog expansion changes. |
| Well-Architected review owner | Epic 0 | Owner for question-matrix updates, score changes, evidence expiry, and follow-up review. |

## Remaining Blockers For Honest 5/5

The current branch implements meaningful repo-owned controls, but a final 5/5
claim is blocked until all of the following are current and non-secret:

- Repository-admin proof that the active `main` ruleset requires Ruff, Ty,
  Maintainability, Architecture, Structural, Dependency Hygiene, Coverage,
  Local Battery, Mutation, Run Bats Tests, Secrets Scan, Dependency Audit,
  Bandit, Dependency Review, Actionlint, Yamllint, Hadolint, Preview,
  Destructive Diff Gate, IAM Validation, Policy, CodeQL (python), CodeQL
  (actions), and Test Account Evidence.
- Repository-admin proof that the protected `prod` environment exists, requires
  reviewer approval, prevents self-review, and limits deployments to protected
  branches.
- Downstream human alert-route evidence for the operations queue or an accepted
  SRE exemption explaining why durable SQS-only routing is sufficient.
- Security-owner evidence for human MFA/SSO, static-key exceptions, external
  approval, and administrator-owned permissions boundary or exemption.
- Production apply approval evidence tied to the reviewed commit SHA, saved-plan
  manifest, destructive-diff result, IAM validation result, and approver.

Repository admins can apply the GitHub-owned controls with:

```bash
gh api graphql \
  -f query='query { repository(owner:"VilnaCRM-Org", name:"bootstrap-infrastructure") { viewerPermission viewerCanAdminister } }' \
  --jq '.data.repository'

GITHUB_REPOSITORY_CONTROLS_REPO=VilnaCRM-Org/bootstrap-infrastructure \
GITHUB_REPOSITORY_CONTROLS_PROD_REVIEWER=Kravalg \
GITHUB_REPOSITORY_CONTROLS_MODE=--apply \
make configure-github-repository-controls
```

The permission preflight must show an admin-capable identity before the helper
can write repository rulesets or protected environments. Current issue #17
operator evidence is `viewerPermission=WRITE` and `viewerCanAdminister=false`,
so the helper correctly fails before any write until a repository administrator
reruns it.

The command exits non-zero if the post-apply metadata does not show the full
required-check set, pull-request review/thread-resolution rules, protected-branch
deployment policy, self-review prevention, and configured production reviewer.

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

This implementation PR changes Pulumi definitions but does not mutate AWS
resources unless an approved local apply or GitHub deploy workflow runs. The
safe validation strategy is:

| Step | Method | Secret-safety rule | Expected evidence |
| --- | --- | --- | --- |
| Local AWS identity sanity check | `aws sts get-caller-identity` | Metadata-only output; do not inspect credentials. | Confirms AWS CLI can reach an account before any deploy attempt. |
| Local Pulumi readiness check | `pulumi -C pulumi ...` only when Pulumi is installed and KMS backend metadata is configured. | Do not run stack export, show secrets, decrypt, or print environment values. | If local prerequisites are absent, local apply is skipped and CI deploy is used. |
| Branch test deploy | Dispatch `Pulumi Test Deploy` on the PR branch. | Uses GitHub OIDC and configured environment metadata without printing secret values. | Workflow URL, head SHA, preview result, destructive diff result, IAM validation result, apply result, and post-apply drift result. |
| Post-run review | `gh run view` and `gh pr checks` | Inspect logs only for status and failure causes; do not print secrets. | PR comment or readiness update with run conclusion and remaining blockers. |

Current implementation readiness observations:

- Local validation and hosted PR checks are current for the branch head,
  including Preview, Destructive Diff Gate, IAM Validation, Local Battery,
  security scans, quality gates, mutation, dependency checks, and CodeQL.
- `completion-audit-2026-05-10.md` maps the active goal to concrete artifacts,
  current test and collector evidence, and the external blockers that still
  prevent an honest final 5/5 claim.
- The collector confirms the current branch evidence context, and hosted checks
  are green for current `main`, but admin-controlled repository settings remain
  external blockers.
- Real test-account preview/apply evidence exists for the branch. A guarded
  local apply on 2026-05-09 UTC created the GuardDuty, Security Hub, and AWS
  Config resources, and the hosted Pulumi Test Deploy for PR head `86e3a05`
  passed preview, IAM validation, destructive diff, apply, and post-apply drift
  on 2026-05-11 UTC.
- The current GitHub token has write access but not repository admin rights, so
  branch-protection and protected-environment repair must be performed by a
  repository admin.

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
  questions, includes the official AWS Well-Architected TOC source URL in
  `frameworkSourceVerification`, exposes the validated source metadata in the
  verifier artifact, and does not claim final 5/5 scores before structured
  `QUESTION_MATRIX_EVIDENCE` and `EXTERNAL_CONTROL_EVIDENCE` records exist.
- Dispatching or observing the existing `Pulumi Test Deploy` workflow, or a
  safe equivalent test-account Pulumi run, before merge readiness is claimed.
- Re-running `scripts/collect_well_architected_evidence.py` after each external
  control change and only updating final 5/5 claims when both structured
  evidence files report zero unresolved items.

Direct local Pulumi apply is acceptable only when the active AWS identity,
backend URL, stack names, and AWS KMS secrets provider are configured without
printing secret values. Otherwise, use the OIDC-backed test deploy workflow and
record the run outcome.
