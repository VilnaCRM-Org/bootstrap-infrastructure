# Run Summary — Implementation-Readiness Gate (issue #77)

## Security completion amendment — 2026-09-05

This document preserves the original planning decisions and historical evidence.
Where its requirements, design, acceptance criteria, or completion statements
conflict with the security completion amendment, use the amended
[PRD](../security-completion/prd.md),
[architecture](../security-completion/architecture.md), and
[verification ledger](../security-completion/verification.md) as the current
contract. Historical scores and successful runs do not prove current closure.

The amended contract requires current-head `Governance Promotion` evidence for
governance changes, issued by the dedicated environment-protected GitHub App,
with test apply, test drift, production apply, and production drift evidence tied to the same
revision. The earlier informational-only `Governance Apply` interpretation is
superseded. Dedicated governance roles and immutable per-repository permission
boundaries are provisioned through the operator-owned bootstrap stack before
onboarding. Governance consumes the existing account OIDC provider and platform
state key; it cannot widen its own permissions or those boundaries. New service
catalog entries therefore first require the real repository to exist so its
immutable GitHub identity can be pinned, followed by reviewed bootstrap boundary
inventory, complete scaffold, explicit account and backend configuration, and
subsequent workload capability review. Preview and drift can write only Pulumi
locks; initializing new backend state is a separate trusted operation. Apply
must retain its own backend access while explicit secret-read denial targets the
intended CI secret resources. Platform and service trust rules must follow their
amended workflow/environment contracts rather than be copied interchangeably.

Reconcile each original FR, NFR, story, risk acceptance, and readiness assertion
against the amendment and current evidence. Outstanding validation, operational
requirements, and unexecuted checks remain open in the verification ledger;
this notice does not mark them complete.

## Orchestration log

The BMAD Architect ran the implementation-readiness gate against the four planning artifacts
(`research.md`, `prd.md`, `architecture.md`, `epics-stories.md`) and three adversarial critiques
(SECURITY=FAIL, AWS-SRE=CONCERNS, FEASIBILITY=FAIL, 21 blocking findings total). Each finding was
first verified against live code on `feat/multi-repo-governance` (runner triggers + preflight,
`_deployment_role_subjects`, `default_pull_request_rule` flags, intake `client_payload` dispatch) —
all critiques were confirmed accurate. **20 of 21** blocking findings were then fixed by amending
`architecture.md` (new §5.1a env-bound apply subjects, §5.2a apply-role surgical Deny, §7.6
stale-review hardening, rewritten §7.2 dedicated-event governance runner, §7.5 commit-status
success-before-merge, §3.1/§5.2 platform-bootstrap-key removal for FR3, §3.2 OIDC-by-ARN, §4
canonical full-slug naming, §9.2 per-catalog-kind fanout, §9.4 decided import-linter + parametric
account/region mock seam, §10 operator steps incl. cost-anomaly + break-glass, §12.1 disposition
table) and `epics-stories.md` (split E1.S4→E1.S4a/E1.S4b, rewrote E1.S8 as the dedicated env-gated
governance runner, hardened E2.S2/E2.S3, redirected E3.S2/E3.S3 to dedicated-event dispatch, added
the golden parity fixture to E1.S2, the apply-role Deny to E1.S3, the per-catalog fanout + length
guard to E1.S7, preview-blocked to E5.S1, name-parity to E5.S2, and the no-provider-create structural
assertion to E6.S1; updated sequencing, dependencies, and AC traceability). The **1 remaining**
finding (SECURITY-7 within-account cross-repo blast radius) is an accepted property of multi-tenant
governance — now lower because test↔prod are isolated by separate accounts (test `891377212104`, prod
`933245420672`) — documented as a residual risk with recommended hardening. **Verdict: PASS** (conditional
amendments are now in the artifacts). `readiness.md` records the full traceability matrix, per-finding
disposition, residual risks, and operator-only steps.

## Final epic / story order (forward-safe; each leaves main green)

```
E1.S1  Repo-scoped naming + KMS-alias helpers (platform-bootstrap split)
E1.S2  Lift to single _BootstrapBuildContext + golden parity fixture (canonical full-slug project)
E1.S3  ci_config repo override + full secret-read Deny (read-only + config-read + apply-role surgical Deny)
E1.S4a RepoGovernance + governance payload + env-bound apply subjects
E1.S4b GovernanceStack loop + OIDC-by-ARN + account assertion + outputs
E1.S5  pulumi/governance/ project scaffold + __main__.py
E1.S6  Governance catalog (user-service only) + single-source governance_paths
E1.S7  Per-catalog-kind fanout + unique-project + 64-char name guard
E2.S1  CODEOWNERS → @Kravalg (expanded credential-bearing path set)
E2.S2  Protected governance env payload + stale-review hardening
E1.S8  pulumi-governance.yml dedicated-event env-gated runner + server-side re-auth + status-post
       (scheduled AFTER E2.S2: requires the governance environment)
E2.S3  Governance-apply required check + commit-status-post binding
E3.S1  Author/path gate in pulumi_pr_comment.py (defense-in-depth)
E3.S2  Intake changed-paths + dedicated-event dispatch (pulumi-governance-command)
E3.S3  Existing runner ignores governance event; ordering regression guard
E5.S1  user-service scaffold assets (preview-blocked, structure-only tests)
E5.S2  self-deploy.yml template (OIDC only, name-parity to rendered roles)
E4.S1  AGENTS.md 3-PR onboarding flow
E4.S2  Operator runbook + two-account correctness verify + cost-anomaly-matches-stack note
E6.S1  Governance test suite + structural (zero-provider-create) test
E6.S2  100% combined coverage + mutation hardening
E6.S3  import-linter contract (decided) + static suite green
E6.S4  CrossGuard + IAM Access Analyzer + no-escape-hatch verification
```

## Stories needing operator access

**None.** Every story is pure CODE / IaC / docs, implementable and testable with **no live AWS or
GitHub-admin credentials** (the rule for all stories). All operator actions (one-time
AdministratorAccess apply, protected-environment PUT, repo variables, OIDC-ARN pinning, cost-anomaly
monitor creation, repo create + push, real applies, break-glass) are documented in the **E4.S2**
operator runbook and executed by the operator outside the implementer loop. E1.S5/E1.S8/E5.S1 are
tagged "real apply / live env PUT / preview is N/A — operator runbook"; their **tests assert
structure only** and never call live APIs or `pulumi preview`/`up`.
