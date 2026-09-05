# Product Brief — Multi-Repo IAM/OIDC Governance Stack

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

**Phase:** 2 — Planning (BMAD PM)
**Source of truth:** GitHub issue [#77](https://github.com/VilnaCRM-Org/bootstrap-infrastructure/issues/77)
**Inputs:** `_bmad-output/planning-artifacts/research.md` (current-state + gap analysis, Phase 1)
**Base branch:** `feat/multi-repo-governance` (off `codex/issue59-github-ci-bootstrap-stack`, PR #60)
**Companion artifact:** `_bmad-output/planning-artifacts/prd.md` (FR/NFR with traceability)

---

## 1. Problem statement

`bootstrap-infrastructure` is the privileged control plane that mints every AWS IAM role,
S3 Pulumi-state bucket, KMS key, and GitHub OIDC trust relationship that any managed
`*-infrastructure` repository needs in order to deploy itself. Today that minting is
**single-repo and manual**:

- The rich, correct primitive — per-repo `preview | apply | drift` deploy roles with
  per-suffix OIDC trust, CI-config secrets, a Pulumi-backend policy scoped to one repo's
  state bucket + KMS, and read-only roles — exists **only** in the one-time, operator-applied
  `pulumi/github-ci-bootstrap` project (`pulumi/infra/ci_bootstrap.py`, `ci_config.py`). It
  hard-requires a single `repoSlug` and produces exactly one repo's roles per stack.
- A *separate, weaker* multi-repo model (`PulumiDeploy-*` via `GitHubOidcRoles`, plus
  per-repo state buckets/KMS) already fans out across a repo catalog, but it lacks the
  preview/apply/drift split, the `repository`-pinned `StringEquals` trust, the CI-config
  secrets, and the least-privilege deny set.
- Onboarding a new service-infra repo therefore means hand-editing `managedRepositories` and
  running privileged Pulumi locally with **AdministratorAccess** — which does not scale and
  violates least privilege.
- The approval boundary is too coarse: anyone with `OWNER|MEMBER|COLLABORATOR` association
  can trigger `/pulumi up` (`scripts/pulumi_pr_comment.py`). There is **no** `CODEOWNERS`
  file, **no** governance protected environment, and **no** single-approver gate. Permission
  and role changes — the highest-blast-radius changes in the org — are not gated to one
  trusted human.
- The least-privilege read surface leaks: the read-only role denies only
  `secretsmanager:GetSecretValue`, while the AWS managed `ReadOnlyAccess` shape still exposes
  secret material via `kms:Decrypt`, `ssm:GetParameter*`, `lambda:GetFunction`,
  `ec2:GetPasswordData`, `*:GetAuthorizationToken`, `sts:GetSessionToken`, and
  `cognito-identity:Get*`.

The result: scaling to many `*-infrastructure` repos is gated on manual admin toil and an
un-auditable approval path.

## 2. The opportunity / solution shape (one increment)

Generalize the proven `github-ci-bootstrap` foundation into a **reusable, multi-repo,
Kravalg-gated governance stack** driven by configuration alone. Onboarding any
`*-infrastructure` repo becomes a documented, IaC-only, PR-comment-driven flow with a single
approver — no manual admin action. This is an **extension** of existing components, not a
rewrite: lift the bootstrap's role/policy/secret richness into a per-repo loop, compose the
already-present gating primitives (protected environments, PR-comment runner, IaC-only apply
guard) into a governance boundary, and add the missing `CODEOWNERS`, governance environment,
author gate, onboarding doc, and the first real consumer repo.

## 3. Users / personas

| Persona | Who | What they need from this increment |
|---|---|---|
| **Platform / SRE (governance owner)** | `@Kravalg` (Yaroslav Kravtsov), sole approver of permission/role PRs | A single, auditable approval choke point: CODEOWNERS over governance/IAM paths, a protected `governance` Environment requiring them as sole reviewer, and `/pulumi up` on governance-touching PRs restricted to them. Least-privilege evidence (Access Analyzer + CrossGuard) on every role. |
| **Platform / SRE (operator / PR author)** | `@dmytrocraft` opens governance PRs; operators run the one-time bootstrap apply | A repeatable onboarding runbook; clear separation of operator-only steps (AWS admin / GitHub org-admin) from pure code/IaC/docs deliverables; a self-service config-only path to add a repo. |
| **Service teams** (consumers) | Teams owning `user-service`, `core-service`, and future `*-infrastructure` repos | Their repo's deploy/preview/apply/drift roles + OIDC trust + scoped state bucket/KMS provisioned for them by config, so their own GitHub Actions can `/pulumi test up` / `/pulumi prod up` without ever holding admin credentials. `user-service-infrastructure` is the first concrete consumer. |

## 4. Goals

1. **One governance project** that, for any repo in a managed governance list, provisions the
   full least-privilege set: OIDC deploy/preview/apply/drift roles, a deploy policy scoped to
   that repo's state bucket + KMS key, the S3 state bucket, the KMS key, and a config-read
   role. Adding a repo is **config-only**, works for any `-infrastructure` suffix and for
   repos added later.
2. **A single, enforced approval boundary** for permission/role changes: `CODEOWNERS` scoping
   the governance path + IAM code to `@Kravalg`, plus a protected `governance` GitHub
   Environment requiring `@Kravalg` as sole reviewer — with other paths unaffected.
3. **PR-comment deploy gating** for governance-touching PRs: `/pulumi test up` then
   `/pulumi prod up` restricted to `@Kravalg`, run in test-then-prod order, success required
   before merge.
4. **IaC-only apply** preserved end-to-end: humans never `pulumi up` deployment projects in
   CI; only GitHub OIDC Actions apply, via the existing saved-plan guard.
5. **Least privilege verified**: every role/policy passes IAM Access Analyzer + CrossGuard,
   no wildcard `Allow` on deployment roles, and the full secret-read deny set enforced on
   read-only / config-read roles.
6. **First real consumer onboarded**: `user-service-infrastructure` scaffolding + self-deploy
   wiring delivered (the repo creation/push itself is an operator step, clearly marked).
7. **A documented onboarding flow** in `AGENTS.md` (the PR A / PR B / repo-create / PR C
   sequence) so the process is repeatable by any operator.
8. **Quality bar held**: the full strict suite stays green, including 100% combined coverage
   across `pulumi/` + `policy_pack/`.

## 5. Non-goals (explicitly out of scope this increment)

- **Standing up new accounts.** The system uses TWO AWS accounts (test `891377212104`, prod
  `933245420672`), region `eu-central-1` for both; `test`/`prod` are Pulumi **stacks** that map to
  **separate** accounts (AWS-best-practice prod blast-radius isolation). Keeping component code
  account-parametric (no hardcoded account literals; the live two-account config is already correct)
  is in scope; standing up any *additional* account beyond these two is a non-goal.
- **Designing the trust/role model from scratch.** This increment **generalizes** the existing
  `GitHubCiBootstrap` + `CiConfiguration` components; it does not invent a new IAM model.
- **Performing the operator-only live actions** as part of the code deliverable: the one-time
  `AdministratorAccess` bootstrap apply (test then prod), the GitHub branch-protection /
  protected-environment reviewer configuration, the actual creation + `git push` of
  `user-service-infrastructure` in `VilnaCRM-Org`, and setting GitHub repo variables. These are
  delivered as **documented runbooks / dry-run payloads**, executed by the operator.
- **Onboarding additional repos** beyond `user-service-infrastructure` in this increment
  (`core-service-infrastructure` and others arrive later via config only).
- **Replacing the PR-comment runner / saved-plan mechanics.** Those exist and are reused
  unchanged; this increment composes and gates them, it does not rebuild them.
- **Broadening approver set or changing the bus-factor.** `@Kravalg` remains the sole approver;
  multi-approver workflows are out of scope.

## 6. Success metrics

| # | Metric | Target | How verified |
|---|---|---|---|
| SM1 | Config-only onboarding | Adding a `*-infrastructure` repo to the governance list provisions its full role/bucket/KMS set with **zero** code changes | A new repo added only to the governance config produces the expected per-repo resources in `pulumi preview`; structural/unit tests assert fan-out. |
| SM2 | Single approval choke point | 100% of governance/IAM-path PRs require `@Kravalg` review; 0 unrelated paths require it | CODEOWNERS path-glob tests; protected-`governance`-environment reviewer = `@Kravalg`, `prevent_self_review=true`. |
| SM3 | Author-gated deploy | `/pulumi … up` on a governance-touching PR by anyone other than `@Kravalg` is rejected; by `@Kravalg` runs test→prod | Author-gate unit tests over the intake parser + path signal; runner job-graph enforces test-before-prod and success-before-merge. |
| SM4 | No manual admin onboarding | 0 `AdministratorAccess` actions required for steady-state onboarding (only the one-time bootstrap, clearly marked operator-only) | Onboarding runbook in `AGENTS.md`; CI rejects direct `pulumi up` when `GITHUB_ACTIONS=true`. |
| SM5 | Least-privilege evidence | 0 IAM Access Analyzer `ERROR`/`SECURITY_WARNING` findings; 0 CrossGuard wildcard-`Allow` violations on deployment roles; full secret-read deny present on read-only/config-read roles | `validate-iam` over preview files; CrossGuard `iam-no-wildcards`; deny-set unit tests. |
| SM6 | Quality gate | Full suite green: ruff (max-complexity 12), mypy, ty, import-linter, deptry, bandit, pip-audit, gitleaks, CrossGuard, mutation, structural, IAM validation; **100% combined coverage** | `make ci-pr` + coverage/mutation targets. |
| SM7 | First consumer ready | `user-service-infrastructure` scaffolding + self-deploy workflow templates present and catalog entry active | Scaffold asset presence tests; catalog validation (`scripts/validate_repository_catalogs.py`). |

## 7. Key constraints carried into the PRD (decided — not relitigated)

- Two accounts (test `891377212104`, prod `933245420672`), region `eu-central-1`; `test`/`prod` =
  stacks mapping to separate accounts; component code account-parametric (no account literals).
- Generalize `github-ci-bootstrap` (`GitHubCiBootstrap` + `CiConfiguration`); do not design anew.
- Sole approver `@Kravalg`; `@dmytrocraft` opens PRs; `prevent_self_review=true`.
- IaC-only apply via the existing `scripts/run_pulumi_command.py` guard (rejects direct `up`
  when `GITHUB_ACTIONS=true`; saved-plan-only).
- Deploy is PR-comment driven (`/pulumi test up`, `/pulumi prod up` → `issue_comment` →
  `repository_dispatch` trusted runner → ECR image → OIDC role).
- Least privilege everywhere; the secret-read deny set applies to **read-only / config-read**
  roles only (never the apply/deploy backend, which legitimately needs `kms:Decrypt`).
  CrossGuard exempts `Effect: Deny`; deployment roles carry no wildcard `Allow`.
- Must work generically for any `-infrastructure` repo and for repos added later, via config.

## 8. Open questions deferred to the Architect

These were raised in research §8 and are not resolved here; the PRD encodes the **constraint
decisions** but the *mechanism* is the architect's to finalize:

1. Keep component code account-parametric across the two accounts (test `891377212104`, prod
   `933245420672`); the live two-account config is already correct (R1, resolved 2026-06-13).
2. New separate Pulumi project dir vs. a multi-repo *mode* of the existing bootstrap project.
3. Whether to unify the weaker `PulumiDeploy-*` trust onto the stronger bootstrap shape (R2),
   incl. import/replace handling.
4. Exact CODEOWNERS path globs that hit governance/IAM only (R4).
5. Author-gate mechanism: changed-path computation in intake + `--author-login` to the parser,
   vs. relying solely on the protected-environment reviewer (or both).
6. Whether new governance `infra` code gets its own import-linter contract (R8).
