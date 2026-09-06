# Installation verification and deferred acceptance

> **Installation decision, updated 2026-09-06:** The repository owner subsequently instructed: “if you can’t satisfy something currently, because it’s blocked - skip it and approve/merge” and “Do not ask me, merge PRs.” For PR #193 this supersedes the earlier installation hold described below. Record blocked controller-dependent deployments, unavailable external AI reviews and outstanding legacy live verification as explicit deferrals. Fixable source or test failures still require correction. A temporary PR-only exception for the exact Kravalg user may permit this installation after current available checks and code review; restore the original ruleset immediately after this one merge. No skipped check or deferred test becomes a passing result. Full bootstrap acceptance remains outstanding until its real operational requirements are verified.

This is a test strategy and evidence contract. It does not record tests as passed merely because they are listed.

| Requirement | Positive | Negative | Edge/race/error |
| --- | --- | --- | --- |
| FR1/FR3 | Current writer requests documented command on open same-repository PR | Foreign repository/fork, unauthorized actor, unsupported command/base | Edited comment, moved head/base, closed PR, revoked permission, unavailable API, duplicate request |
| FR2/NFR1 | Immutable trusted action/helper and isolated credential purpose | PR-local credential loader/publisher, wrong account/role/workflow claims | Incomplete dependency closure, missing runtime, changed validator, mutable provenance |
| FR4 | Each fixed platform/governance TEST/PROD route receives correct metadata | Guessed path/catalog/account/environment or missing account | Empty variables, malformed IDs, retargeted PR, ambiguous routing |
| FR5/FR6 | Same source/config/backend/provider saved plan replays successfully | Direct CI up, corrupt/mismatched plan, foreign KMS/checkpoint | New job with missing YAML, same KMS URL but different encrypted key, concurrent checkpoint version, missing shared checkpoint |
| FR7 | Platform references migrated controls with scoped policy | Control IAM mutation, cross-prefix/key/account access, changed document pin | Legacy imports/ownership dependencies, retained resources, unknown role/key metadata |
| FR8 | Same-head successful TEST then PROD apply/drift yields App evidence | Wrong issuer/run/head/account, failed/skipped job, stale artifact | Scope-event race, existing stronger service proof, current permission/base change before publish, publication API error |
| FR9/NFR3/NFR5 | Clean checkout resolves all shipped runtime/test/action files | Missing helper/import or undeclared dependency | Isolated test collection, offline runtime, deterministic timeout, mutation survivor |
| FR10/NFR4/NFR6 | Traceable scoped report separates installation and live acceptance | Fabricated deployment, skipped bot counted approved, missing context counted green | Stale evidence/head/approval, unresolved review, unavailable native Claude with documented Codex fallback |

Run the repository's canonical nonprivileged CI battery, ordinary and semantic mutation gates, and applicable focused security/behavioral regressions. Record exact source SHA, commands, exits, warnings and artifact hashes. Existing evidence may be reused only when its tested source/input closure remains byte-identical; changed closures require new evidence. The BMAD reviewer must expand this matrix for all actual acceptance criteria, pinned quality categories and related surfaces rather than treating these rows as exhaustive proof.

## Explicit post-installation deferral

The user authorized deferral of manual/live tests that require the new controller to exist on main. Record these as DEFERRED FOR PR #193, REQUIRED BEFORE PR #192 APPROVAL:

- Actual PR-comment request intake through installed trusted code, real account OIDC and protected environment approvals.
- Same-reviewed-revision TEST apply/drift, then PROD apply/drift, with correct GitHub Deployment records and protected App promotion proof.
- Live unauthorized/fork/stale-head/edited-comment/replay/permission-revocation/account/prefix/key denial cases, without unnecessary resource mutation.
- Full governed repository onboarding and its own isolated comment plan/apply/drift lifecycle.
- Full operational backup/restore, alert delivery, disaster recovery and final functional/nonfunctional acceptance associated with the follow-up implementation.

Do not turn a deferred scenario into a PASS row for the full bootstrap goal. Any pre-installation automated or source-based assertion that is possible remains required. Existing GitHub merge enforcement is not deferred by this document. Each manual observation must include tester, date, scenario, steps, observed result, evidence and related requirement IDs.

## Evidence status

The original published installation revision was `39caa513e944f49b4cf270184d596a06237fe7de`. Its supplied local evidence includes 1,094 unit/integration cases, 117 policy cases, 149 structural cases, 72 CLI cases, 100% combined coverage and ordinary/semantic mutation results. These are historical input-bound receipts. Review remediation creates a new revision; do not claim these counts certify changed code. Current substantive AI review, required privileged contexts, scoped BMAD PASS and merge eligibility remain pending.
