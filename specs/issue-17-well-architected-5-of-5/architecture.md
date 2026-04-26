# Architecture: Well-Architected Remediation Program

## Context
Issue #17 tracks follow-up work from an AWS Well-Architected review of PR #14. The issue documents an overall repository score of 2.63/5 and a target of 5/5 across Operational Excellence, Security, Reliability, Performance Efficiency, Cost Optimization, and Sustainability. The requested PR is planning-only, so this document defines the target remediation architecture without changing live infrastructure.

## Architecture Principles

- Evidence before claims: every future 5/5 claim needs repository, CI, AWS metadata, or external-control evidence.
- Guardrails before expansion: mandatory preview, destructive-diff, IAM, region, and policy gates must be dependable before broader remediation work scales.
- Least privilege by default: future IAM changes must narrow resources, add conditions where supported, and justify any remaining wildcard permissions.
- Recovery must be tested: backups, replication, and versioning are not complete without restore drills, RTO/RPO, and retained evidence.
- Cost is a control plane: budgets, anomaly detection, transfer-cost review, and fanout thresholds are part of the architecture, not optional reporting.
- External controls need owners: a control outside this repository is acceptable only when evidence, cadence, and fallback behavior are documented.

## Target Control Domains

| Domain | Target State | Primary Evidence |
| --- | --- | --- |
| CI and deployment guardrails | Same-repo infrastructure changes run non-skipped AWS-backed preview, destructive diff, and IAM validation before merge. | GitHub required checks, workflow logs, branch protection evidence. |
| Region and replication | Replication regions are explicit or safely defaulted, policy-allowlisted, and documented with RTO/RPO and data residency assumptions. | Pulumi config, policy tests, docs, preview evidence. |
| Automation IAM | Bootstrap automation role permissions are scoped to known prefixes, tags, regions, and service constraints where AWS supports it. | IAM policy tests, Access Analyzer output, wildcard justification. |
| Monitoring and alerting | Backup, replication, KMS, drift, and guardrail failures route to owners with severity and dashboard context. | CloudWatch/EventBridge/SNS resources or external alert evidence. |
| Backup and recovery | Pulumi state and central logs have restore runbooks, scheduled non-production validation, and retained restore evidence. | Restore drill logs, runbooks, RTO/RPO records. |
| Cost management | Budgets, anomaly detection, cost estimation, transfer review, and repo-fanout thresholds limit cost surprises. | AWS Budgets, anomaly monitors, PR cost reports, threshold tests. |
| Catalog and quotas | Managed repository fanout is estimated before apply and compared with service quotas and configured thresholds. | Preflight output, quota checks, catalog metadata. |
| Sustainability and lifecycle | Retention, replica storage class, region selection, and reporting align resource use with documented sustainability goals. | Lifecycle config, sustainability docs, scheduled reports. |

## Repository Surfaces For Future PRs

| Surface | Future Role |
| --- | --- |
| `.github/workflows/*` | Required guardrails, recurring drift, reporting, cost estimation, and same-repo privileged checks. |
| `scripts/pulumi_ci_guardrails.py` | Destructive diff and critical-resource detection. |
| `scripts/run_pulumi_command.py` | Saved-plan manifest and hash verification candidate. |
| `policy/guardrails.py` and `policy/pack.py` | CrossGuard controls for region, backup, encryption, public exposure, lifecycle, and future resource classes. |
| `pulumi/infra/bootstrap_infrastructure.py` | Composition point for new bootstrap-owned resources. |
| `pulumi/infra/logging_bucket.py` and `pulumi/infra/pulumi_state.py` | Replication, lifecycle, logging, backup, and restore-related controls. |
| `pulumi/infra/backup.py` | Backup plan, vault lock decision, restore validation hooks. |
| `pulumi/infra/automation.py` | Bootstrap automation IAM blast-radius reduction. |
| `docs/sre-operations.md`, `docs/ci-guardrails.md`, `docs/security-baseline.md` | Runbooks, evidence contracts, external controls, and operational process. |

## Decision Records

### ADR-1: Treat This PR As Planning Only
No infrastructure, workflow, policy, stack, or AWS-resource behavior changes are included. The PR creates a roadmap that future implementation PRs can execute incrementally.

### ADR-2: Preserve P0/P1/P2 Sequencing
The priority order from issue #17 is retained. P0 closes mandatory safety and blast-radius risks, P1 adds operational proof and financial/quota controls, and P2 completes lifecycle, sustainability, and process maturity.

### ADR-3: Require Evidence Contracts For External Controls
If a control is managed outside this repository, the implementation story must document the owner, evidence location, freshness requirement, review cadence, and fallback if the evidence is missing.

### ADR-4: Keep Secret-Safe Validation As A First-Class Constraint
Future stories must prefer metadata-only validation and must not require stack exports, decrypted Pulumi config, cloud-secret payloads, or environment dumps.

## Dependency Model

1. Mandatory CI guardrails must be trustworthy before implementation PRs rely on GitHub checks as safety evidence.
2. Region and replication controls should land before restore and sustainability work because they define residency, transfer cost, and RTO/RPO assumptions.
3. Automation IAM narrowing should land before adding more bootstrap-managed AWS resources.
4. Monitoring, restore, cost, and quota controls can progress in parallel after P0 safety controls are specified.
5. Policy-pack extensions should follow concrete resource introductions, except for preventive guardrails that can be tested with synthetic resources.

## Validation Architecture

Planning-only validation:
- Review the staged diff and confirm only `specs/issue-17-well-architected-5-of-5/` files are committed.
- Run structural docs placement validation after removing ignored generated BMAD/BMALPH/Ralph tooling from the worktree.
- Run markdown or repository hygiene checks if available and narrow.

Future implementation validation:
- Use local tests for policy, structural, workflow, and helper changes.
- Use AWS metadata-only checks for account, bucket, KMS, IAM, Budget, Backup, EventBridge, and CloudWatch resources.
- Use ephemeral validation stacks such as `pr-<number>` or `smoke` for risky infrastructure changes, then destroy them after validation.

## Non-Goals

- This architecture does not add AWS resources.
- This architecture does not change branch protection.
- This architecture does not run Pulumi preview or apply.
- This architecture does not inspect raw secrets, stack exports, or decrypted config.
- This architecture does not replace the issue #17 source assessment; it converts it into implementation-ready planning.
