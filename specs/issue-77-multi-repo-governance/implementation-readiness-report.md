# Implementation-Readiness Gate — Multi-Repo IAM/OIDC Governance Stack

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
operator-only steps (one-time AdministratorAccess apply, protected-environment PUT, repo creation,
cost-anomaly-ARN-matches-stack verification, per-account OIDC-ARN pinning) are enumerated below and
are out of the implementer loop. The PASS means: **the CODE deliverables are fully specified, internally consistent, and
testable without live credentials.**

---

## Requirement traceability (FR/NFR → covering story → gating test)

| Req | Covering story | Gating test / gate |
|---|---|---|
| FR1 config-driven repo list | E1.S6, E1.S7 | catalog resolves synthetic repo; `validate_repository_catalogs.py` |
| FR2 preview/apply/drift trio + trust | E1.S2, E1.S4a | `test_governance.py`: 3N roles, subjects (apply==`environment:governance`, §5.1a) |
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
| FR13 author gate to @Kravalg | E3.S1 (+E1.S8 runner re-check) | `test_pr_comment_gate.py` matrix; runner re-resolves author (SECURITY-1) |
| FR14 path-aware detection | E3.S2, E1.S6 | `governance_paths.py` predicate; intake dispatches dedicated event |
| FR15 test→prod, success-before-merge | E2.S3, E1.S8 | required-check tuple **AND** runner posts status to head SHA (FEASIBILITY-1) |
| FR16 IaC-only apply (reject direct up) | E1.S8 | workflow uses `make pulumi-up-plan`; reject path reused |
| FR17 AGENTS.md onboarding flow | E4.S1 | doc-presence test: PR-A/B/create/PR-C + CODE/OPERATOR labels |
| FR18 operator runbook | E4.S2 | doc-presence: each operator step enumerated incl. OIDC-pin, monitor, break-glass |
| FR19 user-service scaffold | E5.S1 | asset-presence (structure only, **no preview**, FEASIBILITY-6) |
| FR20 self-deploy uses bootstrap roles only | E5.S2 | template-lint: OIDC only, name-parity to rendered names (AWS-SRE-4) |
| FR21 two-account correctness | E4.S2 | no account literal in component Python (`pulumi/infra/*.py`); test stack pins `891377212104`, prod pins `933245420672`; `costAnomalyMonitorArn` account matches its stack if present |
| FR22 full secret-read Deny | E1.S3 | read-only/config-read Deny set; **apply-role surgical Deny** (SECURITY-5) |
| FR23 no wildcard Allow; Analyzer+CrossGuard clean | E1.S4a, E6.S4 | `make test-policy`; `pulumi_ci_guardrails.py validate-iam` |
| FR24 test coverage of contract | E6.S1 | `test_governance.py` full matrix + structural |
| NFR1 100% combined coverage | E6.S2 | `make test-coverage` (account-assertion mock seam makes both branches reachable) |
| NFR2 mutation | E6.S2 | `make test-mutation` (gate-decision + Deny-list mutants killed) |
| NFR3 static suite | E6.S3 | `make ci-pr`; import-linter `infra.governance ↛ {policy,app,scripts}` (decided) |
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
| S1 | Author gate only in intake; runner never re-checks → bypassable via direct `repository_dispatch` | **fixed-in-architecture §7.2 / epics E1.S8**: governance runner re-derives author from `comment_id` (`==Kravalg`), recomputes scope server-side, drops `workflow_dispatch`; all `client_payload` untrusted. |
| S2 | `test_apply` ungated; trust decoupled from env reviewer | **fixed-in-architecture §7.2 + §5.1a**: dedicated `pulumi-governance.yml` with BOTH apply jobs under static `environment: governance`; apply-role OIDC trust requires `sub==environment:governance` (no bare branch-ref). |
| S3 | Stale review survives push (approve-then-swap) | **fixed-in-architecture §7.6 / epics E2.S2**: `dismiss_stale_reviews_on_push=True`, `require_last_push_approval=True`; plan-manifest SHA==approved SHA. |
| S4 | Untrusted governance boolean; CODEOWNERS/glob drift; incomplete path set | **fixed-in-architecture §7.1/§7.2**: scope recomputed server-side; CODEOWNERS single-source with drift-equality CI failure; glob set expanded to all credential-bearing code. |
| S5 | Full secret-read Deny omitted from apply role | **fixed-in-architecture §5.2a / epics E1.S3**: surgical apply-role Deny (`secretsmanager/ssm/ec2/lambda/ecr-auth/sts/cognito`) except own CI secret; keeps `kms:Decrypt`. |
| S-KMS | Alias condition forgeable; region/key wildcard | **fixed (partial)+hardening §5.2**: region pinned eu-central-1; no alias-mutation grant on repo keys (tested); concrete-key-ARN scope recommended follow-up. |
| S7 | Account-pinning not in trust; within-account cross-repo blast radius | **accepted-because** test↔prod are isolated by separate accounts (D1: test `891377212104`, prod `933245420672`), so only the narrower within-account cross-repo IAM blast radius remains — inherent to multi-tenant governance; documented residual risk §10 with recommended tag-scoping + cross-repo IAM test. |

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
| F1 | "Governance Apply" required check → permanently unmergeable | **fixed-in-architecture §7.5 / epics E1.S8,E2.S3**: runner posts commit status to head SHA via `gh api .../statuses/{sha}`; required check resolves. |
| F2 | FR12 routing not a real GH Actions capability | **fixed** — same as A3: routing happens at intake via dedicated event type; "route to another workflow" framing removed. |
| F3 | D1 assertion + eu-central-1 ARNs untestable under mocks | **fixed** — same as A5: parametric ARNs + injectable account/region. |
| F4 | `_RepoCiContext` dual-context fragility / NFR6 | **fixed-in-architecture §3.1 / epics E1.S2**: extend existing `_BootstrapBuildContext` (single context); golden byte-equal parity fixture is the gate. |
| F5 | import-linter either/or unresolved | **fixed-in-architecture §9.4 / epics E6.S3**: decided sequence — add `infra` root pkg → forbidden contract, with AST-test fallback if graph destabilizes. |
| F6 | Operator-only deps mislabeled deliverable-now | **fixed-in-architecture §8/§10 / epics E4.S2,E5.S1**: scaffold preview-blocked tagged; cost-anomaly-ARN-matches-stack is an operator apply-time verification (no repoint); FR21 verify tolerates ARN absence. |

---

## Residual risks (accepted / to monitor)

1. **R-S7 (accepted, lower than originally framed): within-account cross-repo IAM blast radius.**
   test↔prod blast radius is **isolated by separate accounts** (test `891377212104`, prod
   `933245420672`) — a compromised test apply role cannot touch the prod account at all. The
   remaining risk is narrower: repos that share an account (e.g. repoA-prod and repoB-prod both in
   `933245420672`) share the apply role's account-global automation grants (OIDC-provider create,
   account-level IAM — CrossGuard-exempt `Resource:*` Allows). FR3 isolation holds for **state
   buckets + KMS keys**, NOT account-global IAM **within the same account**. *Recommended hardening
   (not blocking):* `aws:RequestTag`/`aws:ResourceTag` binding created IAM/KMS to the repo + a test
   that repo A's apply role cannot `iam:PutRolePolicy` on same-account `GitHubCi*-{repoB}-*`. Inherent
   to multi-tenant governance (decided D1), now per-account scoped.
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

Ordered; each requires AWS admin or GitHub org/repo-admin creds:

1. **One-time governance bootstrap apply** (local, direct `pulumi up` allowed — no `GITHUB_ACTIONS`),
   from a **hardware-MFA admin session, logged**; diff resulting roles vs committed program. Test
   stack then prod stack.
2. **Pin the per-account OIDC provider ARN** (`governance:githubOidcProviderArn`) into
   `pulumi/governance/Pulumi.{test,prod}.yaml` from **each account's** bootstrap stack
   `oidcProviderArn` output (test←`891377212104` provider, prod←`933245420672` provider) **before**
   the first governance apply (the stack raises if unset — AWS-SRE-2).
3. **Verify each stack's `costAnomalyMonitorArn` matches its account** (test→`891377212104`,
   prod→`933245420672`; absence permitted) — both monitors already exist and are correct in the live
   config; do NOT repoint prod away from `933245420672` (FEASIBILITY-6 / FR21).
4. **Configure protected `governance` environment + branch protection** via
   `configure_github_repository_controls.py --apply` (repo-admin token).
5. **Set GitHub repo variables** from the governance `githubVariables` output (`gh variable set`).
6. **Create `user-service-infrastructure` in `VilnaCRM-Org` + push scaffold** (org-admin).
7. **Real AWS applies** (test then prod) via the gated PR-comment flow — @Kravalg comments
   `/pulumi test up` then `/pulumi prod up`; capture real ARNs/outputs.
8. **Break-glass (only if @Kravalg unavailable):** time-boxed temporary second reviewer on the
   `governance` env (org-admin, logged, reverted), OR operator-local apply from a hardware-MFA admin
   session with role-diff before re-enabling the PR-comment path.

---

## Why PASS and not FAIL

The three lenses failed the **original** artifacts on five structurally non-buildable items (deploy
gating, required-check source, OIDC ownership, KMS isolation, naming) plus high/critical
least-privilege gaps. Every one is now a concrete, single-mechanism, testable design with an explicit
gating test named in the story. No blocking finding is left as "implementer decides" — the two
previously-open either/or items (import-linter, context refactor) are decided. The only un-fixed
item (S7) is a documented, accepted property of multi-tenant governance — the within-account
cross-repo IAM blast radius, now lower because test↔prod are isolated by separate accounts (decided
D1) — not a defect of this increment, and carries a recommended hardening that does not block
implementation.
