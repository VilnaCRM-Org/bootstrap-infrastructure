# Architecture: Well-Architected Remediation Program

## Context
Issue #17 tracks follow-up work from an AWS Well-Architected review of PR #14. The issue documents an overall repository score of 2.63/5 and a target of 5/5 across Operational Excellence, Security, Reliability, Performance Efficiency, Cost Optimization, and Sustainability. The original package was planning-only; the current branch now includes a bounded repo-owned implementation slice. This document records the target architecture, current implementation evidence, and remaining blockers without claiming final 5/5 readiness.

The AWS Well-Architected question set was re-checked during this planning update and is represented in `question-matrix.md`: OPS1-11, SEC1-11, REL1-13, PERF1-5, COST1-11, and SUS1-6. Future implementation work must update that matrix when evidence changes.

## Architecture Principles

- Evidence before claims: every future 5/5 claim needs repository, CI, AWS metadata, or external-control evidence.
- Guardrails before expansion: mandatory preview, destructive-diff, IAM, region, and policy gates must be dependable before broader remediation work scales.
- Least privilege by default: future IAM changes must narrow resources, add conditions where supported, and justify any remaining wildcard permissions.
- Recovery must be tested: backups, replication, and versioning are not complete without restore drills, RTO/RPO, and retained evidence.
- Cost is a control plane: budgets, anomaly detection, transfer-cost review, and fanout thresholds are part of the architecture, not optional reporting.
- External controls need owners: a control outside this repository is acceptable only when evidence, cadence, and fallback behavior are documented.
- Score changes need proof: no future PR should raise a Well-Architected score without question-level evidence, main-branch comparison, owner, cadence, and validation output.

## Target Control Domains

| Domain | Target State | Primary Evidence |
| --- | --- | --- |
| CI and deployment guardrails | Same-repo infrastructure changes run non-skipped AWS-backed preview, destructive diff, and IAM validation before merge. | GitHub required checks, workflow logs, branch protection evidence. |
| Region and replication | Replication regions are explicit or safely defaulted, policy-allowlisted, and documented with RTO/RPO and data residency assumptions. | Pulumi config, policy tests, docs, preview evidence. |
| Automation IAM | Bootstrap automation role permissions are scoped to known prefixes, tags, regions, and service constraints where AWS supports it. | IAM policy tests, Access Analyzer output, wildcard justification. |
| Monitoring and alerting | Backup, replication, KMS, drift, and guardrail failures route to owners with severity and dashboard context. | CloudWatch/EventBridge/SNS resources or external alert evidence. |
| Backup and recovery | Pulumi state and central logs have restore runbooks, scheduled non-production validation, and retained restore evidence. | Restore drill logs, runbooks, RTO/RPO records. |
| Cost management | Repo-managed Budgets, anomaly detection, cost estimation, transfer review, and repo-fanout thresholds limit cost surprises. | AWS Budgets, anomaly monitors, PR cost reports, threshold tests, FinOps review records. |
| Catalog and quotas | Managed repository fanout is estimated before apply and compared with service quotas and configured thresholds. | Preflight output, quota checks, catalog metadata. |
| Sustainability and lifecycle | Retention, replica storage class, region selection, and reporting align resource use with documented sustainability goals. | Lifecycle config, sustainability docs, scheduled reports. |

## Current Repository Functional Requirements

The current repository is the bootstrap control plane for AWS and GitHub-backed infrastructure. Future Well-Architected implementation must preserve these functional duties:

| Function | Current responsibility | Well-Architected implication |
| --- | --- | --- |
| Pulumi state foundation | Create and govern S3 state buckets, logging, versioning, replication, and backup registration. | REL, SEC, COST, and SUS evidence must cover state durability, access control, lifecycle, transfer cost, and restore drills. |
| Pulumi secrets foundation | Create KMS-backed Pulumi secrets infrastructure and keep shared stack guidance KMS-based. | SEC evidence must cover key ownership, rotation, policy posture, incident response, and safe validation without secret exposure. |
| GitHub OIDC foundation | Create per-repo deploy roles and trust policies for CI-based Pulumi operations. | SEC and REL evidence must cover authentication, permissions, fault isolation, branch protection, and same-repo privileged validation. |
| Automation bootstrap role | Provide automation permissions for creating bootstrap-managed resources. | SEC evidence must justify remaining wildcards, prove blast-radius limits, and define permissions boundary or exemption posture. |
| Central logging and audit support | Provide logging buckets and policies for state access and cloud log delivery. | OPS, SEC, and REL evidence must cover alerting, retention, investigation, and event response. |
| Backup control | Register state/log resources for AWS Backup with retention. | REL evidence must include backup health, restore drills, Vault Lock or exemption, and DR targets. |
| Cost control | Create account-level AWS Budget resources and create or reuse Cost Anomaly Detection monitor resources routed to operations alerts. | COST evidence must cover budget/anomaly thresholds, alert route, FinOps owner, activated tags, monthly review, and fallback behavior. |
| Repository catalog expansion | Map managed repositories to tags, state resources, roles, and optional automation resources. | PERF, COST, REL, and SUS evidence must cover fanout, quotas, demand, cleanup, and resource selection. |
| CI guardrail execution | Run quality, policy, preview, destructive-change, IAM, security, and deploy checks. | OPS and REL evidence must cover required checks, non-skipped privileged validation, saved-plan integrity, and CI health. |

## Non-Functional Control Requirements

Future implementation must keep the following properties intact:

| Requirement | Architecture constraint |
| --- | --- |
| Secret safety | No control may require stack exports, decrypted config, secret payload reads, environment dumps, or printing raw credentials as normal validation. |
| KMS-backed Pulumi | Shared stack operations must use AWS KMS secrets providers, not passphrase-backed guidance. |
| Least privilege | IAM must prefer scoped ARNs, tags, regions, and conditions; remaining wildcards require action-level justification. |
| Auditability | Evidence must be retained as repo docs, workflow URLs, metadata-only AWS output, dashboards, or external attestations with freshness requirements. |
| Main comparison | Future review evidence must compare the PR with `main` so improvements and regressions are visible. |
| Test-account proof | Real AWS test validation should use the existing OIDC-backed `Pulumi Test Deploy` workflow unless a local environment is explicitly configured and safe. |

## Repository Surfaces For Future PRs

| Surface | Future Role |
| --- | --- |
| `.github/workflows/*` | Required guardrails, recurring drift, reporting, cost estimation, and same-repo privileged checks. |
| `scripts/pulumi_ci_guardrails.py` | Destructive diff and critical-resource detection. |
| `scripts/run_pulumi_command.py` | Saved-plan manifest and hash verification candidate. |
| `policy/guardrails.py` and `policy/pack.py` | CrossGuard controls for region, backup, encryption, public exposure, lifecycle, and future resource classes. |
| `pulumi/infra/bootstrap_infrastructure.py` | Composition point for new bootstrap-owned resources. |
| `pulumi/infra/cost_controls.py` | Repository-owned AWS Budget, Cost Anomaly Detection, and optional cost allocation tag activation. |
| `pulumi/infra/logging_bucket.py` and `pulumi/infra/pulumi_state.py` | Replication, lifecycle, logging, backup, and restore-related controls. |
| `pulumi/infra/backup.py` | Backup plan, vault lock decision, restore validation hooks. |
| `pulumi/infra/automation.py` | Bootstrap automation IAM blast-radius reduction. |
| `docs/sre-operations.md`, `docs/ci-guardrails.md`, `docs/security-baseline.md`, `docs/cost-performance-sustainability.md` | Runbooks, evidence contracts, external controls, cost controls, and operational process. |
| `specs/issue-17-well-architected-5-of-5/question-matrix.md` | Question-level 5/5 evidence ledger and score-claim gate. |

## Decision Records

### ADR-1: Separate Planning Baseline From Implementation Evidence
The original issue #17 package created the roadmap. The current branch adds
limited repo-owned controls, so specs must identify implemented evidence
separately from final 5/5 claims and external-control blockers.

### ADR-2: Preserve P0/P1/P2 Sequencing
The priority order from issue #17 is retained. P0 closes mandatory safety and blast-radius risks, P1 adds operational proof and financial/quota controls, and P2 completes lifecycle, sustainability, and process maturity.

### ADR-3: Require Evidence Contracts For External Controls
If a control is managed outside this repository, the implementation story must document the owner, evidence location, freshness requirement, review cadence, and fallback if the evidence is missing.

### ADR-4: Keep Secret-Safe Validation As A First-Class Constraint
Future stories must prefer metadata-only validation and must not require stack exports, decrypted Pulumi config, cloud-secret payloads, or environment dumps.

### ADR-5: Distinguish Issue Baseline From Current Branch Evidence
Issue #17 captured the original baseline, but the current branch already has evidence that changes parts of that picture. Replica defaults currently use the allowlisted `eu-west-1` paired region, automation IAM is already partly scoped with resource patterns and tag conditions, operations alerts have repo-owned SNS/EventBridge and CloudTrail management-event foundations, and cost controls now include AWS Budget plus Cost Anomaly Detection resources. Future stories should target the remaining proof gaps: explicit region policy evidence, RTO/RPO and transfer-cost rationale, residual wildcard justification, confirmed alert routes, FinOps ownership, restore evidence, and external-control attestations.

### ADR-6: Use CI For Real Test-Account Apply Evidence
Because local developer machines may not have Pulumi installed or KMS backend variables configured, real AWS test-account validation should normally run through the existing `Pulumi Test Deploy` workflow on the PR branch. That path uses configured GitHub OIDC, environment metadata, saved plans, destructive diff checks, IAM validation, apply, and post-apply drift checks without printing secret values.

## Dependency Model

1. Mandatory CI guardrails must be trustworthy before implementation PRs rely on GitHub checks as safety evidence.
2. Region and replication controls should land before restore and sustainability work because they define residency, transfer cost, and RTO/RPO assumptions.
3. Automation IAM narrowing should land before adding more bootstrap-managed AWS resources.
4. Monitoring, restore, cost, and quota controls can progress in parallel after P0 safety controls are specified.
5. Policy-pack extensions should follow concrete resource introductions, except for preventive guardrails that can be tested with synthetic resources.

## Validation Architecture

Documentation/spec validation:
- Review the staged diff and confirm documentation changes stay under the
  intended `docs/` and `specs/` ownership boundaries for the current task.
- Run structural docs placement validation after removing ignored generated BMAD/BMALPH/Ralph tooling from the worktree.
- Run markdown or repository hygiene checks if available and narrow.
- Confirm `question-matrix.md` contains all 57 AWS Well-Architected questions and no implementation score increase claims.

Future implementation validation:
- Use local tests for policy, structural, workflow, and helper changes.
- Use AWS metadata-only checks for account, bucket, KMS, IAM, Budget, Backup, EventBridge, and CloudWatch resources.
- Use ephemeral validation stacks such as `pr-<number>` or `smoke` for risky infrastructure changes, then destroy them after validation.
- For branch-level test validation, dispatch `Pulumi Test Deploy` against the PR branch and retain the workflow URL, head SHA, stack names, preview result, apply result, and post-apply drift result as non-secret evidence.

## Non-Goals

- This architecture document does not itself add AWS resources; the current
  branch's Pulumi resources still require safe preview/apply evidence before
  live-resource claims are accepted.
- This architecture document does not change branch protection.
- This architecture document does not add committed Pulumi preview or apply behavior; external validation may dispatch the existing `Pulumi Test Deploy` workflow to prove the PR branch still deploys to the configured test account.
- This architecture does not inspect raw secrets, stack exports, or decrypted config.
- This architecture does not replace the issue #17 source assessment; it converts it into implementation-ready planning.
