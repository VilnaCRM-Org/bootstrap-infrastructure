# PRD: Well-Architected 5/5 Remediation Roadmap

## Executive Summary
This planning package turns issue #17 into an implementation-ready roadmap for moving the bootstrap infrastructure repository from the documented AWS Well-Architected baseline to an evidence-backed 5/5 target across all pillars. The primary users are maintainers, SREs, security reviewers, and FinOps owners who need clear sequencing, acceptance criteria, validation evidence, and external-control documentation before infrastructure changes begin.

## Success Criteria

| ID | Criterion | Measurement |
| --- | --- | --- |
| SC-1 | Every issue #17 roadmap item is mapped to an epic and story. | `epics.md` contains a traceability table that covers all P0, P1, and P2 bullets from issue #17. |
| SC-2 | The plan preserves the assessment target of 5/5 without claiming implementation is complete. | `well-architected-review.md` keeps current scores separate from target scores and labels this PR as planning-only. |
| SC-3 | Future implementation PRs have clear acceptance criteria. | Each story includes concrete deliverables, validation expectations, and evidence requirements. |
| SC-4 | External controls are acceptable only with audit-ready evidence. | Specs require owner, evidence location, review cadence, and fallback action for every externally enforced control. |
| SC-5 | Planning follows repository BMAD/BMALPH placement rules. | All new planning artifacts live under `specs/issue-17-well-architected-5-of-5/`; no generated BMAD, BMALPH, or Ralph tooling is committed. |

## Product Scope

MVP scope for this PR:
- Add BMAD-style planning artifacts for issue #17 under `specs/`.
- Preserve the P0, P1, and P2 priority structure from the issue.
- Define epics, stories, acceptance criteria, evidence expectations, and readiness risks.
- Identify repo-owned implementation candidates and externally enforced control candidates.

Growth scope for future implementation PRs:
- Implement mandatory AWS-backed guardrail checks and branch protection evidence.
- Add region, replication, IAM, monitoring, restore, cost, quota, sustainability, and policy controls.
- Add operational evidence reporting that can support a follow-up Well-Architected review.

Vision scope:
- Every Well-Architected question in issue #17 is either implemented in this repository or documented as an externally enforced control with current evidence.
- A follow-up review can score each pillar 5/5 using repository evidence, CI evidence, AWS metadata checks, and documented external controls.

Out of scope for this PR:
- Changing Pulumi resources, AWS IAM policies, GitHub Actions behavior, branch protection, or AWS accounts.
- Running Pulumi preview/apply, mutating stacks, reading stack exports, or inspecting secret-bearing configuration.
- Claiming that any Well-Architected gap is remediated by this planning-only PR.

## User Journeys

| Journey | User | Outcome | Requirements |
| --- | --- | --- | --- |
| Roadmap review | Maintainer reviews issue #17 scope. | The maintainer can see which epic owns each P0, P1, and P2 item. | FR-1, FR-2 |
| Implementation planning | SRE selects the next safe PR. | The SRE can choose a bounded story with validation and rollback expectations. | FR-3, FR-4 |
| Security review | Security reviewer evaluates future control changes. | The reviewer can distinguish repo-owned controls from externally enforced controls. | FR-5, FR-6 |
| Cost governance | FinOps owner evaluates cost gaps. | The owner can see required budget, anomaly, transfer-cost, and repo-fanout evidence. | FR-7 |
| Readiness gate | Release reviewer checks if implementation can start. | The reviewer can see dependencies, risks, and missing external inputs. | FR-8 |

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
| FR-2 | The planning package preserves current and target Well-Architected scores. | The scorecard states the issue baseline, target score, and that this PR does not change implemented scores. |
| FR-3 | Each epic can be implemented independently where practical. | Each epic defines deliverables, dependencies, acceptance criteria, and validation evidence. |
| FR-4 | Future implementation stories avoid secret-revealing workflows. | Story validation examples use safe commands and exclude `--show-secrets`, stack exports, secret payload reads, and decrypt operations. |
| FR-5 | External-control candidates require ownership evidence. | Each external-control story requires owner, evidence source, review cadence, and fallback if evidence is unavailable. |
| FR-6 | Security-sensitive future controls require policy or CI coverage. | IAM, region, replication, backup, and public exposure stories require policy-pack, structural, workflow, or metadata validation. |
| FR-7 | Cost remediation is first-class. | Cost stories cover budgets, anomaly detection, PR cost signal, cross-region transfer review, and multi-repo expansion thresholds. |
| FR-8 | Implementation readiness is explicit. | `implementation-readiness-report.md` records readiness status, blockers, sequencing, and no-go conditions. |

## Non-Functional Requirements

- The planning package shall keep all new committed files under `specs/issue-17-well-architected-5-of-5/` as measured by `git diff --name-only`.
- The planning package shall contain no generated BMAD, BMALPH, Ralph, stack export, or secret-bearing files as measured by `git status --ignored` and staged file review.
- Future AWS validation shall use metadata-only commands unless a human explicitly authorizes a secret-management task.
- Future Pulumi CLI examples shall use `pulumi -C pulumi ...` and AWS KMS secrets providers.
- Future implementation PRs shall include the narrowest useful validation for touched files and shall not depend on skipped privileged CI checks for same-repo infrastructure changes.
