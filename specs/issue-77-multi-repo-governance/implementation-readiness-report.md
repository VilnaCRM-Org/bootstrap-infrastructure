# Implementation-Readiness Gate — Multi-Repo IAM/OIDC Governance Stack

## PR78 successor amendment — 2026-09-06

This document retains historical requirements and evidence. The active
interpretation is [the successor verification](pr78-successor-verification.md)
and the installed trusted-controller/operator contracts. Historical approvals,
readiness scores, direct administrator apply examples and claims about completed
service deployment are not current acceptance. State-only initialization is
separate from resource updates; real updates replay a reviewed saved plan through
the protected comment runner. Preserve operator ownership and the existing
service repository. Backend-only service boundaries require explicit reviewed
workload capabilities before an existing service can deploy. Do not infer a full
BMAD PASS or actual TEST/PROD evidence from this source installation.


## Security completion amendment — 2026-09-05

This document preserves the original planning decisions and historical evidence.
Where its requirements, design, acceptance criteria, or completion statements
conflict with the security completion amendment, use the amended
[PRD](pr78-successor-verification.md),
[architecture](pr78-successor-verification.md), and
[verification ledger](pr78-successor-verification.md) as the current
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

**Phase:** 3 — Solutioning gate (BMAD Architect)
**Source of truth:** GitHub issue [#77](https://github.com/VilnaCRM-Org/bootstrap-infrastructure/issues/77) (AC-1..AC-9)
**Inputs:** `research.md`, `prd.md`, `architecture.md`, `epics-stories.md` (all amended in place)
**Adversarial lenses:** SECURITY (FAIL), AWS-SRE (CONCERNS), FEASIBILITY (FAIL)

---

## Verdict: **PASS** (conditional on the amendments below, which are now in the artifacts)

All **21 blocking findings** across the three lenses are dispositioned: **20 fixed in-artifact**
(architecture.md / epics-stories.md amended), **1 accepted-with-rationale** (SECURITY-7, the
within-account cross-repo IAM blast radius inherent to multi-tenant governance — now lower because
test↔prod are isolated by separate accounts — documented as a residual risk with recommended
hardening).

The plan is implementation-ready: every central mechanism that was previously under-specified to the
point of being non-buildable — the governance deploy-gating path (FR12), the success-before-merge
check (FR15), the OIDC-provider ownership, the cross-repo KMS isolation (FR3), and the role-naming
source — now has a single, concrete, testable design. The forward-safe story queue compiles
bottom-up with a golden parity gate protecting NFR6.

This PASS is **not** a claim that the system can be applied to AWS now — it cannot, by design. The
operator-only steps (reviewed operator prerequisites through protected GitHub/OIDC
saved plans, protected-environment controls, repo creation,
cost-anomaly-ARN-matches-stack verification, verification of committed per-account OIDC ARNs) are enumerated below and
are out of the implementer loop. The PASS means: **the CODE deliverables are fully specified, internally consistent, and
testable without live credentials.**

---

## Requirement traceability (FR/NFR → covering story → gating test)

| Req | Covering story | Gating test / gate |
|---|---|---|
| FR1 config-driven repo list | E1.S6, E1.S7 | catalog resolves synthetic repo; `validate_repository_catalogs.py` |
| FR2 preview/apply/drift trio + trust | E1.S2, E1.S4a | `test_governance.py`: 3N roles, service apply subjects test/prod only; dedicated governor uses governance (§5.1a) |
| FR3 deploy policy repo-scoped, no platform key | E1.S1, E1.S4a | `test_governance.py`: A≠B isolation; **no `pulumi-platform-bootstrap` in service docs** (AWS-SRE-1) |
| FR4 config-read role + CI secret | E1.S3, E1.S4a | `test_governance.py`: own-ARN-only Allow + per-suffix trust |
| FR5 per-repo S3 state bucket | E1.S4a | `test_governance.py`: primary+replica per repo/env |
| FR6 per-repo KMS key + alias | E1.S4a | `test_governance.py`: 1 key + alias, rotation, deterministic |
| FR7 single shared OIDC provider | E1.S4b | `test_project_structure.py`: **zero provider create, `.get()` only** (AWS-SRE-2) |
| FR8 generic `-infrastructure` support | E1.S6, E1.S7 | parametrized catalog test; dup-`project` + >64-char rejected |
| FR9 project scaffold + stacks | E1.S5 | `test_project_structure.py`: name `governance`, test stack pins 891377212104 / prod stack pins 933245420672, `awskms://` |
| FR10 CODEOWNERS → @Kravalg | E2.S1 | `test_codeowners.py`: globs→Kravalg, unrelated unowned, drift-equality (SECURITY-4) |
| FR11 protected `governance` env | E2.S2 | `test_repository_controls.py`: 1 reviewer, `prevent_self_review`, branch-only |
| FR12 governance apply under `environment: governance` | E1.S8, E3.S2 | workflow-lint: BOTH apply jobs `environment: governance` + `PULUMI_DIR=pulumi/governance` |
| FR13 current-write requester != @Kravalg | E3.S1 (+E1.S8 runner re-check) | `test_pr_comment_gate.py` matrix; runner re-resolves author (SECURITY-1) |
| FR14 path-aware detection | E3.S2, E1.S6 | `governance_paths.py` predicate; intake dispatches dedicated event |
| FR15 test→prod, success-before-merge | E2.S3, E1.S8 | App-bound `Governance Promotion` **AND** verified all-four-stage publisher (FEASIBILITY-1) |
| FR16 IaC-only apply (reject direct up) | E1.S8 | workflow uses `make pulumi-up-plan`; reject path reused |
| FR17 AGENTS.md onboarding flow | E4.S1 | doc-presence test: PR-A/B/create/PR-C + CODE/OPERATOR labels |
| FR18 operator runbook | E4.S2 | doc-presence: each operator step enumerated incl. committed OIDC-pin verification, monitor, separate break-glass authorization |
| FR19 user-service scaffold | E5.S1 | asset-presence (structure only, **no preview**, FEASIBILITY-6) |
| FR20 self-deploy uses bootstrap roles only | E5.S2 | template-lint: OIDC only, name-parity to rendered names (AWS-SRE-4) |
| FR21 two-account correctness | E4.S2 | no account literal in component Python (`pulumi/infra/**/*.py`); test stack pins `891377212104`, prod pins `933245420672`; `costAnomalyMonitorArn` account matches its stack if present |
| FR22 full secret-read Deny | E1.S3 | read-only/config-read Deny set; **apply-role surgical Deny** (SECURITY-5) |
| FR23 no wildcard Allow; Analyzer+CrossGuard clean | E1.S4a, E6.S4 | `make test-policy`; `pulumi_ci_guardrails.py validate-iam` |
| FR24 test coverage of contract | E6.S1 | `test_governance.py` full matrix + structural |
| NFR1 100% combined coverage | E6.S2 | `make test-coverage` (account-assertion mock seam makes both branches reachable) |
| NFR2 mutation | E6.S2 | `make test-mutation` (gate-decision + Deny-list mutants killed) |
| NFR3 static suite | E6.S3 | `make ci-pr`; import-linter `infra.governance ↛ {policy,app}` plus AST guard for `{policy,app,scripts}`; scripts intentionally ungraphed |
| NFR4 CrossGuard pack | E6.S4 | `make test-policy` zero violations |
| NFR5 no escape hatches | E6.S4 | no wildcard allowlist / `AllowWildcardIam` tag |
| NFR6 backward-compat bootstrap | E1.S2 (golden parity), E6.S1 | byte-equal golden fixture; existing tests intact |
| NFR7 determinism | E1.S4a/b | `sort_keys` snapshot; saved-plan hash validates |
| NFR8 secrets handling | E5.S2, E1.S4a | gitleaks; `awskms://`; `write_secret_values` gated |

---

## Disposition of every blocking finding

### SECURITY (verdict was FAIL → resolved)
| # | Finding | Disposition |
|---|---|---|
| S1 | Author gate only in intake; runner never re-checks → bypassable via direct `repository_dispatch` | **fixed-in-architecture §7.2 / epics E1.S8**: governance runner re-derives author from `comment_id` (current-write requester `!=Kravalg`), recomputes scope server-side, drops `workflow_dispatch`; all `client_payload` untrusted. |
| S2 | `test_apply` ungated; trust decoupled from env reviewer | **fixed-in-architecture §7.2 + §5.1a**: dedicated `pulumi-governance.yml` with BOTH apply jobs under static `environment: governance`; apply-role OIDC trust requires `sub==environment:governance` (no bare branch-ref). |
| S3 | Stale review survives push (approve-then-swap) | **fixed-in-architecture §7.6 / epics E2.S2**: `dismiss_stale_reviews_on_push=True`, `require_last_push_approval=True`; plan-manifest SHA==approved SHA. |
| S4 | Untrusted governance boolean; CODEOWNERS/glob drift; incomplete path set | **fixed-in-architecture §7.1/§7.2**: scope recomputed server-side; CODEOWNERS single-source with drift-equality CI failure; glob set expanded to all credential-bearing code. |
| S5 | Full secret-read Deny omitted from apply role | **fixed-in-architecture §5.2a / epics E1.S3**: surgical apply-role Deny (`secretsmanager/ssm/ec2/lambda/ecr-auth/sts/cognito`) except own CI secret; keeps `kms:Decrypt`. |
| S-KMS | Alias condition forgeable; region/key wildcard | **fixed (partial)+hardening §5.2**: region pinned eu-central-1; no alias-mutation grant on repo keys (tested); concrete-key-ARN scope recommended follow-up. |
| S7 | Account-pinning not in trust; within-account cross-repo blast radius | **accepted-because** test↔prod are isolated by separate accounts (D1: test `891377212104`, prod `933245420672`), central authority is limited to exact catalog identities and operator-owned boundaries; service roles have no IAM administration (see current residual-risk tests). |

### AWS-SRE (verdict was CONCERNS → resolved)
| # | Finding | Disposition |
|---|---|---|
| A1 | Platform-bootstrap KMS key decryptable by every repo (FR3 false) | **fixed-in-architecture §3.1/§5.2 / epics E1.S1**: platform-bootstrap alias removed from per-repo deploy policies (`include_platform_bootstrap=False`); reserved for governance stack's own apply role. |
| A2 | Two stacks own the single OIDC provider | **fixed-in-architecture §3.2 step 2 / epics E1.S4b**: governance consumes by pinned ARN via `.get()`, zero create; raises if ARN unset; structural test asserts no create. |
| A3 | FR12 env-gating has no working mechanism | **fixed-in-architecture §7.2 / epics E1.S8**: dedicated event type + dedicated workflow + static env-gated jobs + `PULUMI_DIR=pulumi/governance`. |
| A4 | Role-naming contradiction (slug vs project_name) | **fixed-in-architecture §4 / epics E1.S2,E5.S2**: canonical `{project}`=full sanitized slug everywhere; template names corrected; byte-equality test. |
| A5 | 100%-coverage vs account happy-path under mocks | **fixed-in-architecture §3.2 step 1 / epics E1.S4b**: injectable `expected_account_id`/`region`; both branches reachable under mock account; ARNs interpolated. |
| A6 | Fanout model wrong/inseparable for governance | **fixed-in-architecture §9.2 / epics E1.S7**: per-catalog-kind fanout; governance counts; quota-headroom report; deployment guard not loosened. |

### FEASIBILITY (verdict was FAIL → resolved)
| # | Finding | Disposition |
|---|---|---|
| F1 | "Governance Apply" required check → permanently unmergeable | **fixed-in-architecture §7.5 / epics E1.S8,E2.S3**: dedicated App issues required `Governance Promotion` after all four apply/drift stages; `Governance Apply` remains informational. |
| F2 | FR12 routing not a real GH Actions capability | **fixed** — same as A3: routing happens at intake via dedicated event type; "route to another workflow" framing removed. |
| F3 | D1 assertion + eu-central-1 ARNs untestable under mocks | **fixed** — same as A5: parametric ARNs + injectable account/region. |
| F4 | `_RepoCiContext` dual-context fragility / NFR6 | **fixed-in-architecture §3.1 / epics E1.S2**: extend existing `_BootstrapBuildContext` (single context); golden byte-equal parity fixture is the gate. |
| F5 | import-linter either/or unresolved | **fixed-in-architecture §9.4 / epics E6.S3**: current contract forbids policy/app; `test_governance_import_isolation.py` covers scripts outside the graph. Preserve §9.4 AST-only fallback if graphing infra exposes existing violations. |
| F6 | Operator-only deps mislabeled deliverable-now | **fixed-in-architecture §8/§10 / epics E4.S2,E5.S1**: scaffold preview-blocked tagged; cost-anomaly-ARN-matches-stack is an operator apply-time verification (no repoint); FR21 verify tolerates ARN absence. |

---

## Residual risks (accepted / to monitor)

1. **Central catalog authority remains privileged.** Platform roles, central
   `GitHubGovernanceApply` roles and service apply roles are separate. The central
   governor manages exact catalogued identities under operator-owned immutable
   boundaries; it cannot change its own delegation or the shared OIDC provider.
   Service apply roles are backend-only and have no account-global IAM grants.
   Existing `test_governance_service_permissions.py` covers both environments and
   forbids CreateRole/PutRolePolicy/AttachRolePolicy/UpdateAssumeRolePolicy/
   CreatePolicyVersion/PassRole/CreateOpenIdProvider. `test_governance_automation.py`
   checks exact managed-role resources, required GovernanceBoundary, boundary
   deletion/provider-change denials and disjoint service boundaries. Live access
   verification remains pending; this correction records no new human risk acceptance.

2. **KMS sole-control residual:** until the governance stack plumbs the concrete per-repo key ARN
   into the deploy `Resource`, `kms:ResourceAliases` remains the primary control (now hardened: no
   alias-mutation grant, region-pinned). Concrete-key-ARN scoping is a recommended follow-up.
3. **`*:GetAuthorizationToken` coverage:** the Deny enumerates `ecr:GetAuthorizationToken`; if
   CodeArtifact or another token-vending service enters the account the Deny must be extended (a
   test flags new `*:GetAuthorizationToken`-style Allows — non-blocking watch item).
4. **Bus factor:** sole approver @Kravalg + `prevent_self_review` means no governance apply if
   unavailable; mitigated by the documented audited break-glass (§10 step 7), not eliminated.
5. **Single-source glob maintenance:** the CODEOWNERS↔`GOVERNANCE_PATH_GLOBS` equality test prevents
   drift, but a new credential-bearing module must be added to CODEOWNERS (the test catches omission
   only relative to the glob constant, not relative to newly-created files — periodic review advised).
6. **64-char naming headroom:** `prod-preview` config-read role for `user-service-infrastructure` is
   59 chars (5 spare); the catalog length-guard rejects longer repos at validation, but the
   `-infrastructure` suffix convention is tight — long service names need a shorter slug.

---

## Operator-only manual steps (out of the implementer loop; runbook = E4.S2 / arch §10)

These are live prerequisites, separate from credential-free source readiness:

1. Verify operator-owned boundary/role inventory and exact account/backend/KMS bindings.
   Explicit trusted state-only initialization may create a genuinely absent encrypted
   empty checkpoint; it runs no Pulumi program and authorizes no local root apply.
2. Verify already committed per-account OIDC provider ARNs against live metadata;
   stop on mismatch instead of repinning configuration implicitly.
3. Verify any configured cost-anomaly ARN matches its account; absence is permitted.
4. Configure/read back protected environments and dedicated App-bound branch controls.
5. Install verified nonsecret account-specific GitHub variables.
6. Bind the real repository identity and publish the generated complete scaffold.
7. A current-write requester other than Kravalg requests test/prod up; Kravalg
   separately approves. Record real apply/drift evidence and Governance Promotion.
8. If the sole reviewer is unavailable, halt. A break-glass proposal requires separate
   explicit authorization and logged audit evidence; no local root apply or reviewer
   change is authorized by this document.

See `docs/governance-stack.md` for exact state-only setup and saved-plan safeguards.

---

## Why PASS and not FAIL

The three lenses failed the **original** artifacts on five structurally non-buildable items (deploy
gating, required-check source, OIDC ownership, KMS isolation, naming) plus high/critical
least-privilege gaps. Every one is now a concrete, single-mechanism, testable design with an explicit
gating test named in the story. No blocking finding is left as "implementer decides" — the two
previously-open either/or items (import-linter, context refactor) are decided. The current source bounds central catalog authority and removes service IAM
administration as described above. This historical design-readiness verdict is not
a live AWS, SRE/DR, security-owner or production acceptance attestation.
