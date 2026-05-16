# PRD: Well-Architected 5/5 Remediation Roadmap

## Executive Summary
This package turns issue #17 into an implementation roadmap and evidence ledger for moving the bootstrap infrastructure repository from the documented AWS Well-Architected baseline to an evidence-backed 5/5 target across all pillars. The current branch includes the first bounded repo-owned controls, so the primary users are maintainers, SREs, security reviewers, and FinOps owners who need clear sequencing, acceptance criteria, validation evidence, and external-control documentation without overstating final readiness.

## Success Criteria

| ID | Criterion | Measurement |
| --- | --- | --- |
| SC-1 | Every issue #17 roadmap item is mapped to an epic and story. | `epics.md` contains a traceability table that covers all P0, P1, and P2 bullets from issue #17. |
| SC-2 | The specs preserve the assessment target of 5/5 without claiming final implementation is complete. | `well-architected-review.md` keeps baseline scores, current implementation evidence, target scores, and remaining blockers separate. |
| SC-3 | Future implementation PRs have clear acceptance criteria. | Each story includes concrete deliverables, validation expectations, and evidence requirements. |
| SC-4 | External controls are acceptable only with audit-ready evidence. | Specs require owner, evidence location, review cadence, and fallback action for every externally enforced control. |
| SC-5 | Planning follows repository BMAD/BMALPH placement rules. | All new planning artifacts live under `specs/issue-17-well-architected-5-of-5/`; no generated BMAD, BMALPH, or Ralph tooling is committed. |
| SC-6 | All AWS Well-Architected Framework questions are analyzed. | `question-matrix.md` covers OPS1-11, SEC1-11, REL1-13, PERF1-5, COST1-11, and SUS1-6 with current evidence, gaps, and target evidence. |
| SC-7 | Functional and non-functional requirements cover the current repo, not only issue text. | FR/NFR sections include repository control-plane duties, external evidence contracts, safety constraints, test-account validation, and score-claim gates. |

## Product Scope

Current branch scope:
- Preserve the P0, P1, and P2 priority structure from the issue.
- Define epics, stories, acceptance criteria, evidence expectations, and readiness risks.
- Identify repo-owned implementation evidence and externally enforced control blockers.
- Record implemented repo-owned operations monitoring, cost Budget/Cost Anomaly controls, classification tags, catalog metadata, fanout checks, and preview cost proxy evidence.

Growth scope for future implementation PRs:
- Implement mandatory AWS-backed guardrail checks and branch protection evidence.
- Add region, replication, IAM, monitoring, restore, cost, quota, sustainability, and policy controls.
- Add operational evidence reporting that can support a follow-up Well-Architected review.

Vision scope:
- Every Well-Architected question in issue #17 is either implemented in this repository or documented as an externally enforced control with current evidence.
- A follow-up review can score each pillar 5/5 using repository evidence, CI evidence, AWS metadata checks, and documented external controls.

Out of scope for this PR:
- Changing branch protection, GitHub environment settings, payer-account policy, or AWS organization controls.
- Adding committed changes that run Pulumi preview/apply, mutate shared stacks outside the reviewed Pulumi implementation, read stack exports, or inspect secret-bearing configuration.
- Direct local Pulumi apply unless Pulumi is installed, KMS backend metadata is safely configured, and account checks pass; when real test-account proof is requested, use the existing OIDC-backed GitHub `Pulumi Test Deploy` workflow.
- Claiming final 5/5 while external owners, evidence freshness, subscriptions, restore drills, or branch-protection proof remain missing.

## User Journeys

| Journey | User | Outcome | Requirements |
| --- | --- | --- | --- |
| Roadmap review | Maintainer reviews issue #17 scope. | The maintainer can see which epic owns each P0, P1, and P2 item. | FR-1, FR-2 |
| Implementation planning | SRE selects the next safe PR. | The SRE can choose a bounded story with validation and rollback expectations. | FR-3, FR-4 |
| Security review | Security reviewer evaluates future control changes. | The reviewer can distinguish repo-owned controls from externally enforced controls. | FR-5, FR-6 |
| Cost governance | FinOps owner evaluates cost gaps. | The owner can see required budget, anomaly, transfer-cost, and repo-fanout evidence. | FR-7 |
| Readiness gate | Release reviewer checks if implementation can start. | The reviewer can see dependencies, risks, and missing external inputs. | FR-8 |
| Well-Architected review | Architect evaluates 5/5 readiness. | The architect can trace every AWS question to evidence, owner, cadence, and a no-go condition. | FR-9, FR-10, FR-11 |
| Test-account validation | SRE validates future Pulumi changes. | The SRE can run same-branch test deployment through safe CI without printing secrets. | FR-12 |

## Domain Requirements

Infrastructure remediation planning must protect shared AWS resources, avoid secret exposure, and keep test/prod stack workflows KMS-backed. Future work must use short-lived AWS credentials, metadata-only validation where possible, explicit account and region checks, least-privilege IAM, auditable evidence, and clear separation between repository-owned controls and externally managed organization controls.

## Innovation Analysis

The plan treats Well-Architected improvement as an evidence system rather than a checklist. Each future control must define the risk it mitigates, the repository surface it changes, the validation signal it produces, and the evidence required to sustain a 5/5 score. This avoids one-off remediation work that cannot be defended in later reviews.

## Project-Type Requirements

This is developer infrastructure automation. Planning must remain useful for AI coding agents and human reviewers, so it uses stable file names, traceable story IDs, explicit non-goals, and command-safe validation notes. Future implementation work must keep local CI runnable without live AWS credentials unless a story explicitly requires metadata-only AWS validation.

## Functional Requirements

| ID | Requirement | Test Criteria |
| --- | --- | --- |
| FR-1 | The planning package maps all issue #17 priority bullets to epics. | A traceability table lists each P0, P1, and P2 item and its owning epic. |
| FR-2 | The package preserves current and target Well-Architected scores. | The scorecard states the issue baseline, current branch evidence, target score, and why final score claims remain blocked. |
| FR-3 | Each epic can be implemented independently where practical. | Each epic defines deliverables, dependencies, acceptance criteria, and validation evidence. |
| FR-4 | Future implementation stories avoid secret-revealing workflows. | Story validation examples use safe commands and exclude `--show-secrets`, stack exports, secret payload reads, and decrypt operations. |
| FR-5 | External-control candidates require ownership evidence. | Each external-control story requires owner, evidence source, review cadence, and fallback if evidence is unavailable. |
| FR-6 | Security-sensitive future controls require policy or CI coverage. | IAM, region, replication, backup, and public exposure stories require policy-pack, structural, workflow, or metadata validation. |
| FR-7 | Cost remediation is first-class. | Cost stories cover budgets, anomaly detection, PR cost signal, cross-region transfer review, and multi-repo expansion thresholds. |
| FR-8 | Implementation readiness is explicit. | `implementation-readiness-report.md` records readiness status, blockers, sequencing, and no-go conditions. |
| FR-9 | Every AWS Well-Architected question has a repo-specific current-state analysis. | The question matrix lists current repository evidence or explains why the question is not currently applicable. |
| FR-10 | Every future 5/5 claim has target evidence. | The question matrix lists target evidence, owner role, review cadence, and the epic or story that must produce it. |
| FR-11 | External controls are represented as controlled dependencies, not assumptions. | Each externally managed control requires owner, evidence path or system of record, evidence freshness SLA, fallback, and secret-safety classification. |
| FR-12 | Real AWS validation is defined through existing test-account automation. | The readiness report explains that local metadata checks are safe, direct local apply depends on installed Pulumi and configured KMS backend, and same-branch `Pulumi Test Deploy` is the preferred test-account apply path. |
| FR-13 | Operational excellence evidence is measurable. | OPS stories require RACI, severity model, runbooks, alert matrix, KPI register, ORR checklist, and improvement cadence before score increases. |
| FR-14 | Security evidence covers identity, permissions, detection, data protection, incident response, and appsec. | SEC stories require OIDC/static-key boundaries, permission matrices, Access Analyzer evidence, detection routes, data classification, encryption decisions, and vulnerability response SLAs. |
| FR-15 | Reliability evidence covers quotas, change safety, monitoring, backups, failure testing, and DR. | REL stories require quota headroom, saved-plan integrity, alarm matrix, restore drills, fault scenarios, RTO/RPO, and DR exercise evidence. |
| FR-16 | Performance evidence covers resource choice and control-plane efficiency. | PERF stories require resource fanout, CI/runtime SLOs, storage access assumptions, network/region rationale, and regular metric review. |
| FR-17 | Cost evidence covers FinOps governance end to end. | COST stories require repo-managed budget/anomaly evidence, activated allocation tags or blocker, cost ADRs, cost proxy or estimation, transfer model, stale cleanup, and effort-vs-savings review. |
| FR-18 | Sustainability evidence covers region, demand, architecture, data, services, and process. | SUS stories require region decision matrix, demand inventory, CI efficiency targets, data retention matrix, no idle compute without justification, and sustainability KPI cadence. |

## Non-Functional Requirements

- Specs shall keep canonical issue #17 planning and evidence artifacts under `specs/issue-17-well-architected-5-of-5/`.
- The package shall contain no generated BMAD, BMALPH, Ralph, stack export, or secret-bearing files as measured by `git status --ignored` and staged file review.
- Future AWS validation shall use metadata-only commands unless a human explicitly authorizes a secret-management task.
- Future Pulumi CLI examples shall use `pulumi -C pulumi ...` and AWS KMS secrets providers.
- Future implementation PRs shall include the narrowest useful validation for touched files and shall not depend on skipped privileged CI checks for same-repo infrastructure changes.
- Score increases shall be blocked unless target evidence is current, non-secret, reproducible, and tied to the specific AWS Well-Architected question being raised.
- Evidence freshness shall be explicit: CI and deploy evidence should be refreshed per PR, alert and backup evidence at least monthly, cost and quota evidence at least monthly, and full Well-Architected review evidence at least quarterly unless an epic sets a stricter cadence.
- Evidence retention shall preserve enough history to compare main versus PR behavior without exposing secrets, including workflow URLs, run IDs, metadata-only AWS command outputs, review artifacts, and restore drill summaries.
- Required check names shall be stable and documented before branch protection depends on them.
- External-control evidence shall have a named owner and fallback; an unavailable screenshot, dashboard, or organizational policy shall count as missing evidence.
- Pulumi test-account apply evidence shall come from existing OIDC-backed GitHub workflows or a local environment with Pulumi installed, KMS secrets provider configured, and safe account checks completed first.
- Future changes shall prefer deterministic, auditable automation over manual console state; any manual step must have owner, date, reason, and verification evidence.
- Future planning and implementation shall avoid one-off local assumptions by documenting current repo evidence and main-branch comparison points.
