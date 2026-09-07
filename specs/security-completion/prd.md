# Bootstrap security completion — 2026-09-05

Status: requirements retained for PR192 closeout after the implementation
merged through PR193, PR204, PR74 and PR213. This document defines acceptance;
the current PR head requires its own CI, deployment and final BMAD results.

## Scope and precedence

Complete the AWS/GitHub bootstrap and multi-repository governance delivery path
in `VilnaCRM-Org`, with separate test and production accounts. Investigate all
open organization PRs; merge only changes relevant to this bootstrap goal after
their applicable checks and reviews pass. Preserve unrelated application work.

This amendment takes precedence over contradictory implementation details in
issue 59 and issue 77 planning documents. Their functional goals remain binding.
Historical review results and operational attestations remain historical; they
must never be redated or presented as current evidence.

## Functional acceptance

| ID | Required behavior | Inherited requirement |
| --- | --- | --- |
| SEC-FR1 | Test and prod independently assert the intended AWS account before allocating resources or issuing deployment credentials. | Issue 18 isolation; issue 59 CI bootstrap; issue 77 FR21 |
| SEC-FR2 | GitHub uses OIDC and short-lived role sessions. No AWS IAM access keys or administrator policies are introduced for CI or application workloads. | Issue 59 OIDC-only CI; issue 77 FR3/FR22 |
| SEC-FR3 | Apply requires the intended protected environment; preview and PR tokens cannot assume apply roles. Service test/prod roles and bootstrap governance roles are distinct. | Issue 77 FR11–FR13, FR20 |
| SEC-FR4 | Dispatch execution validates the original unedited comment, current permissions, immutable PR/base/head comparison, requested command/environment, trusted intake artifact, freshness, and a single-use claim. Invalid, stale, replayed, moved, incomplete or wrongly routed requests stop before credentials. Apply requester must be a current writer distinct from sole protected-environment approver Kravalg; validate the original comment author, not the dispatch actor. | Issue 77 FR13/FR14; PR-comment promotion |
| SEC-FR5 | Every apply replays a fresh saved plan for the same nonempty commit SHA, project, policy pack, backend and stack. Corrupt/decryption/lock/provider failures stop; recovery never silently cancels or falls back to direct apply. | Issue 77 FR16; PR-comment promotion |
| SEC-FR6 | Preview/drift may read their state and write backend locks only. A separate trusted, protected initializer handles a confirmed missing stack without running PR resource code. | Issue 77 FR3/FR16/FR20 |
| SEC-FR7 | A governed service cannot administer its own trust, permissions boundary, another repository, the OIDC provider or platform roles. Bootstrap owns immutable boundaries; governance cannot widen its own authority. | Issue 77 FR2–FR7/NFR5 |
| SEC-FR8 | Governance merge success requires the exact PR commit to complete test apply/drift followed by prod apply/drift. A dedicated evidence App publishes this success; ordinary GitHub Actions or writer statuses cannot satisfy the required issuer. | Issue 77 FR15/E2.S3 |
| SEC-FR9 | Repository protection covers every workflow and executable helper. Environment branches/reviewers, current code-owner approval, stale-review dismissal, last-push approval and required checks are verified from live GitHub metadata. | Issue 77 FR10–FR15 |
| SEC-FR10 | A generated downstream repository contains the complete runnable dependency closure, comment intake, protected runner, state initialization, policy checks and documentation. Generation refuses an existing destination. | Issue 77 FR17–FR20 |
| SEC-FR11 | New service workload permissions are an explicit reviewed capability change within a bootstrap-owned boundary. A backend-only role is sufficient for metadata smoke validation and must not be advertised as a complete ECS/network/database deployment role. | Issue 77 FR3/NFR5 |
| SEC-FR12 | OIDC onboarding supports current GitHub subject formats and pins immutable repository identity where available; wrong organization/repository, ref and environment claims fail. | Issue 77 FR4/FR7/FR20 |

## Nonfunctional acceptance

| ID | Required evidence |
| --- | --- |
| SEC-NFR1 | Required repository quality, security, policy, structural, unit, integration, CLI and mutation checks pass for the final commit. Retain 100% covered branch/line thresholds; do not suppress findings to make a gate green. |
| SEC-NFR2 | Meaningful positive, negative, edge, replay, race, corrupt-artifact, wrong-account, wrong-role and denied-permission cases execute with traceable outcomes. Static workflow assertions are supporting evidence only. |
| SEC-NFR3 | Real test and prod OIDC runs use the intended roles/accounts, apply only reviewed plans, and finish with no unexpected drift. Repeat no-op execution demonstrates idempotence. |
| SEC-NFR4 | IAM Access Analyzer and effective-policy tests cover cross-repo isolation, self-escalation, secret reads, state integrity and boundary changes. Record simulator limitations separately from real STS/CloudTrail evidence. |
| SEC-NFR5 | Operational monitoring, alert routing, backup/restore, DR, quota, cost and readiness evidence meets the current issue 17 requirements. Expired records cannot satisfy current readiness. |
| SEC-NFR6 | Use the organization's actual Claude-plugin FR/NFR reviewer when authenticated. Record tool/model provenance and the existing iteration ledger; degraded review is labeled explicitly. |
| SEC-NFR7 | No raw secrets, decrypted state, private keys, credential files or auth tokens appear in Git, reports or logs. Retain only nonsecret metadata and evidence references. |

Completion requires all applicable rows to have current evidence and all known
release blockers to be resolved. A green focused suite, a successful preview or
the existence of IAM roles alone does not satisfy completion.

## Bounded PR192 closeout

The original one-time operator bootstrap remains a separately authorized
short-lived AWS login operation. PR213 completed its actual TEST/PROD saved-plan
apply and full drift acceptance. Routine existing platform/governance/service
workflows use their protected OIDC identities; a governance receipt proves only
its own stack. None of these receipts claims hosted operator execution.

Automatic execution of every affected bootstrap stack from an ordinary comment
is tracked separately in [issue215](https://github.com/VilnaCRM-Org/bootstrap-infrastructure/issues/215).
It remains required for the broader autonomous-bootstrap goal, but adds a new
executor/routing capability outside this PR's original one-time bootstrap
architecture. The user explicitly requested that PR192 not expand to include it.
Live deployment-comment progress is separately tracked in issue214.

For this closeout, preserve the installed 25 required checks and App issuers,
two approvals including a CODEOWNER plus an approved AI reviewer, stale-review
dismissal, last-push approval and protected TEST/PROD environments. Never
substitute a historical approval, restore result or deployment for a required
current-head check. See `verification.md` for scope and evidence boundaries.
