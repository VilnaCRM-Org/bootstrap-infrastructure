# Trusted controller installation PRD

> **Installation decision, updated 2026-09-06:** The repository owner subsequently instructed: “if you can’t satisfy something currently, because it’s blocked - skip it and approve/merge” and “Do not ask me, merge PRs.” For PR #193 this supersedes the earlier installation hold described below. Record blocked controller-dependent deployments, unavailable external AI reviews and outstanding legacy live verification as explicit deferrals. Fixable source or test failures still require correction. A temporary PR-only exception for the exact Kravalg user may permit this installation after current available checks and code review; restore the original ruleset immediately after this one merge. No skipped check or deferred test becomes a passing result. Full bootstrap acceptance remains outstanding until its real operational requirements are verified.

## Decision and scope

This bundle specifies PR #193 as the installation prerequisite for the full bootstrap completion. On 2026-09-06 the user explicitly permitted manual acceptance that is impossible before installation to be completed after PR #193 merges. The user retained green GitHub CI, resolved actionable review comments, substantive AI review approvals, and an organization BMAD FR/NFR PASS for this PR. PR #192 retains full live TEST/PROD comment-driven deployment and manual acceptance.

The shipped scope includes the trusted comment controller and evidence publisher, their complete helper/action closure, and the compatible platform program that references operator-owned controls. It excludes the independently applied operator entrypoint, new governed resources and service scaffold, and new alert processing features. Those remain part of the final bootstrap requirements. The installation review must inspect every changed and directly affected surface; this split does not exempt shipped security or correctness behavior.

## Functional requirements

| ID | Requirement and acceptance criterion |
| --- | --- |
| INSTALL-FR1 | Parse only the documented comment grammar on eligible open same-repository PRs. Bind the request to immutable repository/owner IDs, PR/head/base, actor and comment identity. Reject malformed, unauthorized, forked, stale and edited/replayed requests before credentialed execution. |
| INSTALL-FR2 | Trusted workflow code and its helper/action dependencies must have explicit immutable provenance. PR-controlled configuration loaders or evidence publishers must not gain privileged access. PR preview code receives only its deliberately bounded preview capability. |
| INSTALL-FR3 | Revalidate current repository permission, PR state/head/base, actor, target scope and protected environment at execution and evidence publication. Race, API-error, absent-control and ambiguous states fail closed. |
| INSTALL-FR4 | Route only fixed platform/governance paths and TEST/PROD account/environment contracts. Include every required runtime variable, including AWS account identity. A changed catalog or guessed project cannot expand routing. |
| INSTALL-FR5 | Preview produces a saved plan and a manifest bound to source, runtime, backend, stack, configuration and policy. Apply replays that exact plan; wrong, corrupt, stale or mismatched plans fail. Direct CI up and recovery by cancellation or unsaved apply are forbidden. |
| INSTALL-FR6 | Shared stack configuration preserves the checkpoint KMS provider and encrypted data key across jobs. Account, region, key state and checkpoint version are checked. Missing shared checkpoints require the separate trusted initializer; no silent init or key regeneration is allowed. |
| INSTALL-FR7 | Platform code references operator-owned IAM/OIDC/secrets and retains only its reviewed workload ownership. Enforce exact account, immutable boundaries, state prefix/key isolation, protected dependencies and reviewed complete IAM document pins. Installation source must not be used as the operator deployment program. |
| INSTALL-FR8 | Promotion evidence is issued by the protected dedicated GitHub App for the exact current PR revision and real successful required apply/drift jobs. Scope evaluation must preserve stronger existing service/governance proof. Failed, stale, skipped, replayed or foreign evidence cannot produce success. |
| INSTALL-FR9 | All shipped workflows resolve their actual runtime/test/action dependencies in a clean checkout. Existing unprivileged checks, historical alert-handler responsibilities and mandatory policy/mutation/coverage contracts remain coherent. |
| INSTALL-FR10 | Installation documentation states prerequisites, exact deferred post-installation cases and operational ownership. A source check, operator receipt, skipped bot result or missing required context must not be presented as live deployment or approval. |

## Nonfunctional requirements

| ID | Requirement and acceptance criterion |
| --- | --- |
| INSTALL-NFR1 | Security: short-lived OIDC roles, exact account and immutable repository identities, least privilege and separate preview/apply/configuration/evidence capabilities; no static AWS access keys or App credentials exposed to PR code. |
| INSTALL-NFR2 | Reliability and integrity: explicit single-use request/evidence boundaries, stable checkpoint/plan identity, protected resource ownership, bounded retries/timeouts and no automatic destructive recovery. |
| INSTALL-NFR3 | Verification: applicable unit, integration, policy, structural, CLI, architecture, quality, dependency, security and mutation checks run against the reviewed revision. Preserve repository 100% coverage thresholds and meaningful negative/edge tests. |
| INSTALL-NFR4 | Operability and diagnosability: bounded job concurrency/timeouts, visible actionable failures, metadata-only audit evidence and documented rollout/rollback ownership. Do not suppress a failure to unlock a merge. |
| INSTALL-NFR5 | Maintainability and compatibility: typed modular helpers with explicit dependencies, dependency graph/architecture checks, reproducible lock/runtime versions, clean-checkout dependency closure and deliberate compatibility with migrated platform ownership. |
| INSTALL-NFR6 | Review and release: all applicable requirements and quality categories receive evidence-based BMAD scores; no unresolved actionable findings, required CI failures or requested changes remain. Substantive AI approvals and repository merge enforcement are separate requirements. |

## Release boundary

A scoped installation PASS is not a full bootstrap PASS. Deferred live controller/governance/service cases must be completed against installed trusted code and the final PR #192 revision before PR #192 approval. Current main rules remain authoritative, including their required checks, reviews and deployment records. Any inability to satisfy them is an explicit installation blocker, not an implied rules exception.
