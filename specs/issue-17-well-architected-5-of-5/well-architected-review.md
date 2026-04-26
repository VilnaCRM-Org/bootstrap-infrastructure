# AWS Well-Architected Planning Scorecard

Scope: issue #17 planning package for improving the bootstrap infrastructure repository to an evidence-backed 5/5 AWS Well-Architected posture.

This document does not update implemented repository scores. It preserves the issue #17 baseline, defines the target, and records how future implementation evidence should be evaluated.

The full question-level ledger is `question-matrix.md`. It covers all 57 current AWS Well-Architected questions and is the controlling artifact for future score changes.

## Source Baseline

Issue #17 records the following assessment:

| Pillar | Repo overall | PR #14 delta | Planning implication |
| --- | ---: | ---: | --- |
| Operational Excellence | 3.09/5 | 2.70/5 | Strong CI exists, but alerting, incident ownership, runbooks, and operational health evidence need work. |
| Security | 3.09/5 | 3.44/5 | Policy pack, OIDC, and scans are strong; bootstrap IAM blast radius and detection evidence need work. |
| Reliability | 2.77/5 | 3.00/5 | Replication and backups exist; restore drills, alarms, quota checks, and DR targets need proof. |
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

## Planning PR Score

| Area | Score | Rationale |
| --- | ---: | --- |
| Scope clarity | 5/5 | The PR is explicitly planning-only and does not claim remediation is implemented. |
| Traceability | 5/5 | Every issue roadmap item maps to an epic and stories. |
| Implementation readiness | 4/5 | P0 items are ready to start; several P1/P2 items require external owners and evidence decisions. |
| Evidence model | 4/5 | Evidence types are defined; concrete evidence locations must be filled by implementation PRs. |
| Operational safety | 5/5 | Planning preserves secret-safe validation, KMS-backed Pulumi guidance, and no live mutation. |
| Question coverage | 5/5 | `question-matrix.md` maps all 57 AWS Well-Architected questions to current evidence, gaps, and target proof. |
| FR/NFR coverage | 5/5 | PRD and architecture now cover current repo functions, non-functional constraints, evidence freshness, and test-account validation path. |

Planning-only score: `4.8/5`.

Implemented Well-Architected score change from this PR: `0.0`. This PR creates the roadmap; it does not remediate controls.

## Score Claim Method

Future implementation PRs must use this method before changing any score:

1. Identify the exact AWS Well-Architected question from `question-matrix.md`.
2. Compare PR behavior with `main`.
3. Link repo evidence, CI evidence, metadata-only AWS evidence, or external-control evidence.
4. Record owner, freshness SLA, review cadence, fallback action, and secret-safety classification.
5. Keep the score unchanged if evidence is missing, stale, secret-bearing in normal output, or not reproducible.

## Required Evidence By Pillar

### Operational Excellence

Future evidence must include:
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

Future evidence must include:
- AWS Budgets or external FinOps controls by `CostCenter`, `App`, and `RepositoryProject`.
- Cost anomaly detection or equivalent externally documented control.
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
5. Add cost controls before scaling the repository catalog.

## Completion Criteria For Issue #17

Issue #17 can be closed only when:
- Every Well-Architected question in `question-matrix.md` is implemented to 5/5 in this repository or documented as an externally enforced control with current evidence.
- Branch protection requires relevant non-skipped safety checks for same-repo PRs.
- AWS-backed preview and IAM validation run successfully for infrastructure PRs.
- Restore drills, alarms, cost controls, and quota controls are implemented or evidenced externally.
- A follow-up Well-Architected review scores every pillar 5/5.

## Planning Non-Goals

- No AWS resources are created, updated, or destroyed by this PR.
- No GitHub Actions behavior or branch protection is changed by this PR.
- No Pulumi stack is exported or decrypted by this PR, and no committed change mutates stacks. Test-account proof may be gathered by dispatching the existing `Pulumi Test Deploy` workflow on the PR branch.
- No raw secret material is read or committed by this PR.
