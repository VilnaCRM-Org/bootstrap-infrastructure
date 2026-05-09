# AWS Well-Architected Planning Scorecard

Scope: issue #17 planning package and current implementation evidence for
improving the bootstrap infrastructure repository to an evidence-backed 5/5 AWS
Well-Architected posture.

This document separates the issue #17 baseline, current branch evidence, the
target state, and the remaining blockers. Current repo-owned controls may reduce
specific gaps, but final 5/5 scores are not claimed until owner, freshness,
validation, and external-control evidence are complete.

The full question-level ledger is `question-matrix.md`. It covers all 57 current AWS Well-Architected questions and is the controlling artifact for future score changes.

## Source Baseline

Issue #17 records the following assessment:

| Pillar | Repo overall | PR #14 delta | Planning implication |
| --- | ---: | ---: | --- |
| Operational Excellence | 3.09/5 | 2.70/5 | Strong CI exists, but alerting, incident ownership, runbooks, and operational health evidence need work. |
| Security | 3.09/5 | 3.44/5 | Policy pack, OIDC, and scans are strong; bootstrap IAM blast radius and detection evidence need work. |
| Reliability | 2.77/5 | 3.00/5 | Replication, backups, and a latest restore-drill evidence record exist; alarms, live quota checks, recurring drill ownership, and DR targets need proof. |
| Performance Efficiency | 2.60/5 | 3.33/5 | Managed services are reasonable; multi-repo fanout and quota modeling need guardrails. |
| Cost Optimization | 1.55/5 | 1.33/5 | Weakest pillar; budgets, anomaly detection, cost estimation, transfer review, and cost caps are missing. |
| Sustainability | 2.67/5 | 2.67/5 | Lifecycle basics exist; region selection, retention rationale, and sustainability goals need evidence. |

Overall repository score from issue #17: `2.63/5`.

Target score after future implementation: `5/5` for every question, either through in-repository controls or documented external controls with current evidence.

## Current Branch Corrections To The Issue Baseline

The issue #17 baseline remains the source assessment for this planning PR, but current branch evidence has moved in a few areas. Future implementation work should preserve these improvements and target the remaining proof gaps:

| Area | Current branch evidence | Remaining 5/5 gap |
| --- | --- | --- |
| Replica region | State and logging replica defaults currently target the allowlisted `eu-west-1` paired region. | Add explicit region decision evidence, RTO/RPO, residency, transfer-cost, sustainability rationale, and tests that reject unallowlisted regions. |
| Automation IAM | Automation permissions are already partly scoped with resource patterns, deterministic names, and tag conditions. | Add action-level wildcard justification, IAM Access Analyzer evidence, permissions-boundary decision, and tests that prove blast-radius limits. |
| CI guardrails | Same-repo workflows already include account checks, preview, destructive diff, IAM validation, saved-plan apply, and post-apply drift. | Add branch protection evidence, skipped-check policy, check-name contract, and test-account deployment evidence tied to the PR head SHA. |
| Lifecycle controls | Primary logs, state versions, backups, and ECR images have lifecycle or retention rules. | Add replica lifecycle rationale, data classification, storage-class decisions, cost and sustainability review, and stale cleanup evidence. |
| Operations evidence | The bootstrap stack exports operations alert topic/rule/key handles, and docs now define RACI, severity, KPI, and runbook expectations. | Confirm SNS subscriptions, downstream route ownership, reviewed KPI observations, incident drill evidence, and named owners per environment. |
| Cost controls | The bootstrap stack provisions a monthly AWS Budget, 80% actual and 100% forecast notifications, a service-dimensional Cost Anomaly Detection monitor or configured existing monitor ARN, and an immediate anomaly subscription to the operations topic when Cost Explorer is enabled in the target account. | Confirm Cost Explorer enablement, FinOps owner approval, alert subscription, activated cost allocation tag evidence, monthly report location, spend policy, transfer model, and account quota headroom. |

## Current Branch Documentation Score

| Area | Score | Rationale |
| --- | ---: | --- |
| Scope clarity | 5/5 | The specs distinguish original baseline, implemented repo-owned controls, remaining evidence blockers, and final 5/5 claims. |
| Traceability | 5/5 | Every issue roadmap item maps to an epic and stories. |
| Implementation readiness | 4/5 | Several repo-owned P0/P1 controls are implemented; final readiness still depends on external owners, subscriptions, drills, and account evidence. |
| Evidence model | 4/5 | Evidence types and output handles are defined; concrete monthly evidence locations must still be filled by operators. |
| Operational safety | 5/5 | Specs preserve secret-safe validation, KMS-backed Pulumi guidance, and metadata-only evidence collection. |
| Question coverage | 5/5 | `question-matrix.md` maps all 57 AWS Well-Architected questions to current evidence, gaps, and target proof. |
| FR/NFR coverage | 5/5 | PRD and architecture now cover current repo functions, non-functional constraints, evidence freshness, and test-account validation path. |

Documentation and evidence-contract score: `4.8/5`.

## Current Question-Level Review Evidence

The 2026-05-09 evidence record at
`question-matrix-evidence-2026-05-09.json` now includes a 1-5 score for each of
the 57 AWS Well-Architected Framework questions. These scores are current
review observations for this PR and the repository, not final 5/5 claims. As of
the 2026-05-09 review, 27 questions remain unresolved because those rows still
have at least one missing owner, freshness, validation, fallback, drill,
account, or administrator-owned evidence item.

Repository-owned operating evidence for owners, KPI cadence, priority/risk
tradeoffs, runbooks, decision matrices, and sustainability governance is now
recorded in `docs/well-architected-operating-evidence.md`. It improves the
current question-level scores, but does not close external blockers such as
branch protection, production environment approvals, FinOps account evidence,
or security account services.

Final Well-Architected score change claimed by this PR: `0.0`. The current
branch adds remediation evidence for some questions, but the pillar scores stay
unchanged until the remaining external blockers are closed and the
question-level claim gate is satisfied.

## Score Claim Method

Future implementation PRs must use this method before changing any score:

1. Identify the exact AWS Well-Architected question from `question-matrix.md`.
2. Compare PR behavior with `main`.
3. Link repo evidence, CI evidence, metadata-only AWS evidence, or external-control evidence.
4. Record owner, freshness SLA, review cadence, fallback action, and secret-safety classification.
5. Keep the score unchanged if evidence is missing, stale, secret-bearing in normal output, or not reproducible.
6. Run `make report-well-architected-evidence` with structured
   `QUESTION_MATRIX_EVIDENCE` and `EXTERNAL_CONTROL_EVIDENCE`; do not use
   boolean confirmations to unlock final scores.

## Required Evidence By Pillar

### Operational Excellence

Current repo-owned evidence includes the operations SNS topic, encrypted alert
delivery key, EventBridge alert rules, and documented RACI/severity/KPI/runbook
expectations. Remaining evidence must include:
- Required same-repo AWS-backed guardrail checks and branch protection evidence.
- Alert routing, severity model, incident communication, and post-incident review process.
- Dashboard or scheduled health evidence for backup, replication, drift, and CI guardrails.
- RACI or equivalent ownership for bootstrap infrastructure.
- ORR checklist, operational KPI register, severity model, post-incident review process, and quarterly evolve loop.

### Security

Future evidence must include:
- Narrowed automation IAM or documented wildcard justifications.
- OIDC-only privileged CI path with explicit account checks.
- Security-event detection for KMS changes, suspicious state/log access where practical, and guardrail failures.
- Policy-pack or IAM analyzer tests for permissions changes.
- Authentication matrix, data classification taxonomy, at-rest and in-transit decision matrices, incident playbooks, and vulnerability response SLA.

### Reliability

Future evidence must include:
- Explicit replication-region validation and RTO/RPO assumptions.
- Restore drills for Pulumi state and central logs.
- Backup Vault Lock implementation or documented external control.
- Quota preflight for repository fanout and service limits.
- Fault-isolation proof, saved-plan integrity, component-failure scenarios, reliability tests, and DR exercise evidence.

### Performance Efficiency

Future evidence must include:
- Resource fanout model for each managed repository.
- Quota thresholds and approval behavior before resource expansion.
- Control-plane efficiency expectations for CI, preview, drift, and reporting workflows.
- Storage access and replication-latency assumptions, region/network performance ADR, and monthly performance KPI review.

### Cost Optimization

Current repo-owned evidence includes AWS Budget and Cost Anomaly Detection
resources routed to the operations topic, optional reuse of an existing
service-dimensional anomaly monitor, optional Cost Explorer cost allocation tag
activation, and preview/static cost proxy checks. Remaining evidence must include:
- Approved FinOps ownership and thresholds for Budget and Cost Anomaly controls.
- Cost Explorer enabled in the target account before anomaly resources are
  applied.
- Confirmed alert route and monthly cost review artifact.
- Activated cost allocation tag evidence by `CostCenter`, `App`, and
  `RepositoryProject` when payer-account ownership allows activation.
- PR cost estimation or resource-count cost proxy.
- Cross-region data-transfer review for replication choices.
- Cost thresholds for repository catalog expansion.
- Activated cost allocation tag evidence, cost ADRs, pricing model review, demand/idle cleanup signals, new-service review, and cost-of-effort notes.

### Sustainability

Future evidence must include:
- Region selection goals and lower-impact paired-region rationale where applicable.
- Retention and storage-class rationale for primary and replica data.
- Scheduled reporting for bucket growth, backup volume, ECR image age, and tag-based cost or carbon indicators where available.
- Ephemeral validation stack cleanup expectations.
- Region decision matrix, demand inventory, CI efficiency targets, no-idle-compute rule, and sustainability KPI cadence.

## Highest-Priority Future Work

1. Make same-repo privileged guardrails mandatory and evidence-backed.
2. Remove unsafe replica-region fallback behavior or replace it with an allowlisted default.
3. Narrow bootstrap automation IAM and document any unavoidable wildcards.
4. Add operational alerting and restore proof before claiming reliability maturity.
5. Operationalize cost controls before scaling the repository catalog.

## Completion Criteria For Issue #17

Issue #17 can be closed only when:
- Every Well-Architected question in `question-matrix.md` is implemented to 5/5 in this repository or documented as an externally enforced control with current evidence.
- Branch protection requires relevant non-skipped safety checks for same-repo PRs.
- AWS-backed preview and IAM validation run successfully for infrastructure PRs.
- Restore drills, alarms, cost controls, and quota controls are implemented,
  routed to named owners, reviewed on the documented cadence, and evidenced
  without secrets.
- Remaining external blockers are closed: alert subscription, FinOps threshold
  approval, activated tag evidence where enabled, live quota/headroom evidence,
  production approval rules, security account controls, and sustainability owner
  approval.
- A follow-up Well-Architected review scores every pillar 5/5.

## Planning Non-Goals

- This scorecard update does not itself create, update, or destroy AWS
  resources; the current branch's Pulumi implementation still needs safe
  preview/apply evidence before live-resource claims are accepted.
- No branch protection setting is changed by this scorecard update.
- No Pulumi stack is exported or decrypted by this scorecard update. Test-account proof may be gathered by dispatching the existing `Pulumi Test Deploy` workflow on the PR branch.
- No raw secret material is read or committed by this PR.
