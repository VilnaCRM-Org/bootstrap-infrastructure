# Epics & Stories — Multi-Repo IAM/OIDC Governance Stack

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

**Phase:** 3→4 handoff — BMAD PM/SM forward-safe implementation breakdown
**Source of truth:** issue [#77](https://github.com/VilnaCRM-Org/bootstrap-infrastructure/issues/77) (AC-1..AC-9)
**Inputs:** `_bmad-output/planning-artifacts/prd.md`, `_bmad-output/planning-artifacts/architecture.md`
**Base branch:** `feat/multi-repo-governance`

## How to read this document

- Each **story** is atomic, independently implementable, and independently testable against the
  repo's quality gates (`make ci-pr`, `make test-coverage`, `make test-policy`, `make test-mutation`).
- **Files** lists the exact paths to create (`+`) or modify (`~`).
- **AC** verify against the listed PRD FR/NFR; the implementer must run the named gate.
- **Operator access:** `NO` = pure CODE, deliverable now with no live creds (the rule for *every*
  story below). `N/A` = the live AWS/GitHub-admin action is out of scope for the implementer and is
  documented in the operator runbook (E4.S2) instead — implementers never need real creds.
- **Forward-safe ordering rule:** a story may only depend on stories with a lower id. Each story
  leaves `main` green; nothing is half-wired.

## Sequencing summary (recommended implementation order)

```
E1.S1 → E1.S2 → E1.S3 → E1.S4a → E1.S4b → E1.S5 → E1.S6 → E1.S7        (generic component, bottom-up)
E2.S1 → E2.S2 → E2.S3                                                  (Kravalg gating: CODEOWNERS, env+stale-review, App-issued Governance Promotion requirement)
E1.S8                                                                  (governance runner and informational Governance Apply status — AFTER E2.S2: needs `governance` env)
E3.S1 → E3.S2 → E3.S3                                                  (PR-comment author/path gate + dedicated-event dispatch)
E5.S1 → E5.S2                                                          (user-service scaffold templates — preview-blocked until operator apply)
E4.S1 → E4.S2                                                          (AGENTS.md flow + operator runbook + docs + cost-anomaly note)
E6.S1 → E6.S2 → E6.S3 → E6.S4                                          (test/quality closeout: coverage, mutation, import-linter, account grep)
```
Note: E1.S8 (governance runner) is moved to run **after E2.S2** so the `governance` environment it
references exists first (forward-safe ordering — the earlier queue placing E1.S8 before E2.x
contradicted its own stated dependency; this is corrected per the AWS-SRE/sizing non-blocking note).

Rationale: E1 builds the reusable component bottom-up (settings helpers → lifted helpers → ci_config
Deny → new component → project scaffold → catalog → CI wiring), so each layer compiles and tests
before the next consumes it. E2/E3 (GitHub-control surface) are independent of E1 internals and can
run in parallel after E1.S6 lands the shared `governance_paths` constant — but are ordered after E1
to keep a single linear queue for solo subagents. E5 depends only on the output **shape** (E1.S4),
not on E1 being applied. E4 documents what E1–E5 built. E6 is the final quality ratchet that asserts
the whole contract.

---

## Epic 1: Generic governance component (generalize bootstrap into a per-repo loop)

Covers FR1–FR9, FR21, FR22 (config-read half), FR23, NFR6, NFR7. Builds all reusable logic in
`pulumi/infra/`, then a thin `pulumi/governance/` project entrypoint.

### Story 1.1: [E1.S1] Repo-scoped naming + KMS-alias helpers (additive, no behavior change)

- **Atomic scope:** Confirm/strengthen the repo-scoped name helpers the loop depends on and add a
  repo-scoped KMS-alias condition builder. Pure helper layer; no component touches yet.
- **Files:**
  - `~ pulumi/infra/bootstrap_settings.py` — ensure `state_bucket_name_for_repo(repo)` and
    `pulumi_secrets_alias_name_for_repo(repo)` exist and are public; add a `secrets_alias_for_repo`
    convenience if missing (additive only).
  - `~ pulumi/infra/ci_bootstrap.py` — change `_pulumi_secrets_alias_conditions` to
    `_pulumi_secrets_alias_conditions(repo, env, *, include_platform_bootstrap: bool)`. With
    `include_platform_bootstrap=False` (governance service-repo path, AWS-SRE-1) it returns
    **only** `[alias/pulumi-{repo}-{env}-secrets]` — NO platform-bootstrap alias. With
    `include_platform_bootstrap=True` (single-repo bootstrap entrypoint back-compat) it returns
    `[alias/pulumi-{repo}-{env}-secrets, alias/pulumi-platform-bootstrap-{env}]` so the existing
    `bootstrap-infrastructure` output stays byte-identical. (Replaces the `alias/pulumi-*-{env}-secrets`
    wildcard either way.)
- **Acceptance criteria:** FR3 (alias scoping + platform-bootstrap isolation, AWS-SRE-1),
  NFR6 (single-repo output unchanged), NFR7 (deterministic). `make test-unit` green;
  `tests/unit/test_components.py` unchanged-and-passing.
- **Test cases:**
  - positive: `pulumi_secrets_alias_name_for_repo("user-service-infrastructure")` →
    `alias/pulumi-user-service-infrastructure-{env}-secrets`;
    `_pulumi_secrets_alias_conditions(repo, env, include_platform_bootstrap=False)` contains **no**
    `pulumi-platform-bootstrap` substring.
  - positive (back-compat): `include_platform_bootstrap=True` matches the pre-change two-alias list
    byte-for-byte.
  - negative: alias-condition list for repo A contains no repo-B alias substring.
  - edge: empty/blank repo name raises (matches existing `_require_repo` guard).
- **Dependencies:** none.
- **Operator access:** NO.

### Story 1.2: [E1.S2] Lift bootstrap role/policy helpers to a per-repo context

- **Atomic scope:** Introduce the `_RepoCiContext` dataclass and thread `repo`/`project` through the
  pure role/policy helpers, keeping the single-repo entrypoint byte-identical (NFR6). No new
  component, no new project yet.
- **Files:**
  - `+ tests/unit/test_governance_parity.py` (or fixture under `tests/unit/`) — **golden parity
    snapshot captured BEFORE the refactor** (FEASIBILITY-4): current single-repo
    `bootstrap-infrastructure` rendered role names (preview/apply/drift + config-read + automation),
    trust JSON per role, backend/read-only/apply policy JSON, and the `Repository` tag value. This is
    the gating artifact for E1.S2–E1.S4b.
  - `~ pulumi/infra/ci_bootstrap.py` — **extend the EXISTING `_BootstrapBuildContext`** with
    `repo: str` and `project: str` fields (single source of truth — do NOT add a parallel
    `_RepoCiContext`). `project` = `sanitize_bucket_component(repo)` (full slug, canonical source,
    AWS-SRE-4 — NOT `project_name`). Re-point `_ci_role_name`, `_repo_subject`,
    `_deployment_role_subjects`, `_state_bucket_resources`, `_pulumi_backend_policy_document`,
    `_role_policy_documents`, `_role_specs`, `_create_role` (which reads `context.settings.repo` at
    lines 482/489/508 → `context.repo`), `_create_roles` to read from `context.repo`/`context.project`.
    `GitHubCiBootstrap.__init__` builds one context from `settings.repo` internally.
  - `~ pulumi/infra/__init__.py` — no export change yet (internal refactor only).
- **Acceptance criteria:** FR2 (subjects/trust unchanged for single repo), FR3 (backend policy
  repo-scoped), AWS-SRE-4 (canonical `{project}`=full slug), NFR6 (byte-equal golden parity).
  `make test-unit` + `make test-pulumi` green with **zero diff** against the golden parity fixture.
- **Test cases:**
  - positive: single-repo build produces **byte-identical** role names + trust JSON + policy JSON +
    `Repository` tag vs the golden fixture (incl. the `_automation_policy_documents(..., repo)` apply
    branch and the tag derivation).
  - negative: passing repo B context produces B-scoped bucket ARNs, never A's.
  - edge: `apply`+`prod` purpose yields only `environment:prod` subject; non-prod yields
    `environment:test` only for test apply; prod apply uses `environment:prod` only
    (§5.1a). Neither service apply subject accepts a bare branch ref.
- **Dependencies:** E1.S1.
- **Operator access:** NO.

### Story 1.3: [E1.S3] `ci_config.py`: repo override + full secret-read Deny on config-read

- **Atomic scope:** Add `repo: str | None` to `CiConfigurationArgs` (None = unchanged behavior) and
  add the full secret-read Deny statement to the config-read policy (FR22, D4), excluding
  `secretsmanager:GetSecretValue` from the Deny.
- **Files:**
  - `~ pulumi/infra/ci_config.py` — add `repo` arg; when set, `_ci_config_project` uses
    `sanitize_bucket_component(repo)` (full slug, canonical, AWS-SRE-4), secret IDs and trust
    subjects become repo-scoped. Add second `Effect: Deny` statement `DenySecretLeakingReads`
    (`ssm:GetParameter*`, `lambda:GetFunction`, `ec2:GetPasswordData`,
    `ecr:GetAuthorizationToken`, `sts:GetSessionToken`, `cognito-identity:Get*`) to
    `_ci_config_read_policy`; preserve conditional Decrypt Denies for regional
    Secrets Manager and exact owned-secret context. The general Deny excludes
    Decrypt. Also add the read-only Deny set (excluding Decrypt) (including `secretsmanager:GetSecretValue`)
    to `_read_only_policy_document` in `ci_bootstrap.py`.
  - `~ pulumi/infra/ci_bootstrap.py` — replace the single-action Deny in `_read_only_policy_document`
    with the full Deny block (§5.3). **Add the surgical APPLY-role Deny (§5.2a, SECURITY-5):** a
    `DenySecretLeakingReadsApply` statement on the **apply role only** denying
    `secretsmanager:GetSecretValue`, `ssm:GetParameter*`, `ec2:GetPasswordData`, `lambda:GetFunction`,
    `ecr:GetAuthorizationToken`, `sts:GetSessionToken`, `cognito-identity:Get*` with
    `NotResource=[arn:aws:secretsmanager:eu-central-1:{account_id}:secret:/{project}/ci/*]`. `kms:Decrypt`
    is NOT in this Deny (apply needs it; bounded by the §5.2 alias condition). NOT attached to the
    pulumi-backend policy.
- **Acceptance criteria:** FR22, D4, SECURITY-5, NFR6 (repo=None path unchanged). `make test-unit` +
  `make test-policy` green (Deny is CrossGuard-exempt).
- **Test cases:**
  - positive: config-read policy contains all Deny actions **except** `secretsmanager:GetSecretValue`,
    and keeps its `secretsmanager:GetSecretValue` Allow on the repo's own ARN.
  - positive: read-only policy Deny **includes** `secretsmanager:GetSecretValue`.
  - positive (SECURITY-5): apply role denies `secretsmanager:GetSecretValue` on an arbitrary other
    secret ARN but allows it on its own `/{project}/ci/*`; apply role retains `kms:Decrypt` on its key.
  - negative: pulumi-backend policy contains no Deny block and retains `kms:Decrypt` Allow.
  - edge: `repo=None` yields the pre-change config-read policy shape (back-compat).
- **Dependencies:** E1.S2.
- **Operator access:** NO.

### Story 1.4: [E1.S4a] `RepoGovernance` component + governance payload + service apply subjects

- **Atomic scope:** The per-repo half of `governance.py` (split from the original E1.S4 — sizing
  note): one `RepoGovernance` wiring state bucket (FR5), KMS key/alias (FR6), CI-config secret +
  config-read role (FR4), preview/apply/drift trio (FR2/FR3), the governance CI-config payload
  builder (no operations-triage requirement), and the **service apply subjects**
  (`_deployment_role_subjects`, §5.1a: test uses `environment:test`, prod uses
  `environment:prod`, without bare branch refs). Dedicated central governor roles
  separately use `environment:governance` and exact bounded catalog authority. Receives `provider_arn`/`account_id`/`region` as inputs (no provider
  creation here).
- **Files:**
  - `+ pulumi/infra/governance.py` (part 1) — `GovernanceStackArgs` (incl. `oidc_provider_arn`,
    injectable `region`), `RepoGovernance` (type token `bootstrap:governance:RepoGovernance`),
    `_governance_payloads(...)`, existing `_deployment_role_subjects`. Delegating helpers keep
    ruff `max-complexity ≤ 12`. ARNs use `{account_id}`/`{region}` interpolation (no
    `891377212104`/`eu-central-1` literal — FEAS-3).
- **Acceptance criteria:** FR2, FR3, FR4, FR5, FR6, FR23, SECURITY-1/2/5, NFR7. `make test-unit`
  green for a single synthetic repo under the Pulumi mocks.
- **Test cases:**
  - positive: per-repo bucket+replica, KMS key+alias, 3 deploy roles + config-read; apply-role trust
    subject == `environment:test` for test and `environment:prod` for prod; neither
    service apply role has IAM administration.
  - negative: repo A deploy policy contains no substring of repo B's bucket/alias; no
    `pulumi-platform-bootstrap` reference (AWS-SRE-1); no `Effect:Allow` wildcard (FR23).
  - edge: `write_secret_values=False` → no secret-version resource; ARNs render under mock account
    `123456789012` (no hardcoded literal).
- **Dependencies:** E1.S3.
- **Operator access:** NO.

### Story 1.5: [E1.S4b] `GovernanceStack` loop + OIDC-by-ARN + account assertion + outputs

- **Atomic scope:** The stack half: `GovernanceStack` consumes its account's OIDC provider **by pinned
  ARN via `.get()`** (zero create branch — AWS-SRE-2, FR7), asserts the live account against the
  injectable, **per-stack** `expected_account_id` (D1: test stack expects `891377212104`, prod stack
  expects `933245420672`; sourced from `governance:awsAccountId`, never a literal in component code;
  mock seam AWS-SRE-5/FEAS-3), loops one `RepoGovernance` per catalog repo, registers the stable
  outputs map (§3.4).
- **Files:**
  - `~ pulumi/infra/governance.py` (part 2) — `GovernanceStack` (type token
    `bootstrap:governance:GovernanceStack`). Provider consumed via
    `aws.iam.OpenIdConnectProvider.get(...)` / adopt-by-ARN; **raises** if `oidc_provider_arn` unset.
    Account assertion uses `args.expected_account_id`. Delegating helpers keep complexity ≤ 12.
  - `~ pulumi/infra/__init__.py` — export `GovernanceStack`, `GovernanceStackArgs`, `RepoGovernance`.
- **Acceptance criteria:** FR7, D1, NFR7. `make test-unit` green; component renders for a 2-repo
  synthetic catalog under the Pulumi mocks (`tests/conftest.py`).
- **Test cases:**
  - positive: N repos → exactly 3N deploy roles; **zero** `OpenIdConnectProvider` *create* resources
    (provider `.get()` only).
  - negative: `oidc_provider_arn` unset → raises; provider create attempted → structural test fails.
  - edge: `expected_account_id == "123456789012"` (mock) → proceeds (non-raise branch covered);
    mismatch → `ValueError` (both branches reachable under mocks — AWS-SRE-5/FEAS-3).
- **Dependencies:** E1.S4a.
- **Operator access:** NO (account assertion is mock-driven; real apply is N/A here).

### Story 1.6: [E1.S5] `pulumi/governance/` project scaffold + `__main__.py` (two accounts, test/prod stacks)

- **Atomic scope:** New thin Pulumi project that resolves settings + catalog from config and builds
  `GovernanceStack`, with manifest + 3 stack files + non-discovered example (FR9, FR21, D1/D2).
- **Files:**
  - `+ pulumi/governance/Pulumi.yaml` (`name: governance`)
  - `+ pulumi/governance/Pulumi.test.yaml` (account `891377212104`, region `eu-central-1`, env=test,
    `repositoryCatalogPath: ../repositories.governance.json`, `awskms://` secrets provider)
  - `+ pulumi/governance/Pulumi.prod.yaml` (mirror, env=prod, **separate** account `933245420672`,
    its account's OIDC provider ARN + `pulumi-platform-bootstrap-prod` secrets provider)
  - `+ pulumi/governance/Pulumi.example.yaml` (non-discovered example for structural-test parity)
  - `+ pulumi/governance/__main__.py` (resolve settings → `GovernanceStack(args=...)` → export
    `perRepo`, `oidcProviderArn`, `managedRepositories`)
  - `+ pulumi/governance/requirements.txt` (parity with `github-ci-bootstrap/requirements.txt`)
- **Acceptance criteria:** FR9, FR21, D1. `tests/pulumi/test_project_structure.py` governance assertion
  (added in E6.S? — here just ensure files satisfy: manifest name `governance`, both stacks declare
  `aws:region: eu-central-1`, the test stack config pins account `891377212104` and the prod stack
  config pins `933245420672`, `awskms://` secrets provider, example not discovered). `make test-pulumi`
  green.
- **Test cases:**
  - positive: manifest name == `governance`; the test stack resolves to `891377212104` and the prod
    stack resolves to `933245420672`; secrets provider starts `awskms://`.
  - negative: the test stack file contains no `933245420672` and the prod stack file contains no
    `891377212104` (each pins only its own account); `Pulumi.example.yaml` excluded from committed
    stack discovery.
  - edge: stack files contain no inline secret/passphrase metadata.
- **Dependencies:** E1.S4b.
- **Operator access:** NO (stack init / real `up` is N/A — operator runbook, E4.S2).

### Story 1.7: [E1.S6] Governance catalog file + shared governance-paths constant

- **Atomic scope:** Add the active governance catalog (config-only repo add, FR1/FR8) and the single
  source-of-truth glob constant consumed by both CODEOWNERS test and the author/path gate.
- **Files:**
  - `+ pulumi/repositories.governance.json` (active: `user-service-infrastructure` only;
    **`bootstrap-infrastructure` is EXCLUDED** — it self-manages via `github-ci-bootstrap`, listing
    it would double-manage the same IAM roles/secret, AWS-SRE non-blocking). `project` = full slug
    `user-service-infrastructure` (canonical naming, AWS-SRE-4). Validated by existing
    `repositories.schema.json` — no schema change.
  - `+ scripts/governance_paths.py` — `GOVERNANCE_PATH_GLOBS` derived from / asserted byte-equal to
    the CODEOWNERS `@Kravalg` globs (single source of truth, SECURITY-4) +
    `paths_touch_governance(files) -> bool` (fnmatch) + a `--files-stdin` CLI that prints
    `governance_touched=true|false`. The glob set covers ALL credential-bearing code (§7.1 expanded
    list: incl. `bootstrap_settings.py`, `github_oidc.py`/`iam/`, `pulumi_state.py`,
    `pulumi_secrets.py`, `run_pulumi_command.py`, intake workflow).
- **Acceptance criteria:** FR1, FR8, FR14, SECURITY-4 (path predicate; single-source glob).
  `python scripts/validate_repository_catalogs.py` passes (catalog auto-discovered by glob);
  `make test-unit` covers `paths_touch_governance`.
- **Test cases:**
  - positive: a `*-infrastructure` repo added to the catalog resolves into
    `ManagedRepositoryCatalog`; `paths_touch_governance(["pulumi/governance/x"])` → True;
    `paths_touch_governance(["pulumi/infra/bootstrap_settings.py"])` → True (expanded set).
  - negative: `paths_touch_governance(["docs/readme.md", "tests/x.py"])` → False;
    `bootstrap-infrastructure` absent from the governance catalog.
  - edge: empty file list → False; duplicate `project` values rejected by catalog validation.
- **Dependencies:** E1.S4b (catalog model used), E1.S5 (catalog path referenced by the project).
- **Operator access:** NO.

### Story 1.8: [E1.S7] `validate_repository_catalogs.py` per-catalog-kind fan-out + unique `project` + name-length guard

- **Atomic scope:** Make fanout **per-catalog-kind** (AWS-SRE-6) so the governance catalog validates
  with governance-specific counts WITHOUT relaxing the shared deployment-catalog guard; add the
  unique-`project` guard (§4) AND the role-name-length guard (FEASIBILITY-4: reject any repo whose
  `sanitize_bucket_component(name) + "-prod-preview"` would exceed 64 chars at validation time).
- **Files:**
  - `~ scripts/validate_repository_catalogs.py`:
    - Detect catalog kind (by filename `repositories.governance.json` → `governance`, else
      `deployment`/`central`) and apply a **separate** governance fanout — NO central-stack resources;
      `iamRoles = 3 (trio) + config_read_count + 1 (replication)`; `managedPolicies = 2 × repos`;
      `secrets = suffix_count × repos`; with its own thresholds. Do NOT bump the shared
      `PER_ENVIRONMENT_FANOUT` used by `repositories.bootstrap.json`.
    - Add an account-quota headroom report (1000 roles, 1500 managed policies, 10
      managed-policies-per-role; report service apply's 2/10 usage separately from central governor limits).
    - Add unique-`project` structural check and the over-64-char role-name rejection.
- **Acceptance criteria:** FR1, FR8, §4 uniqueness, AWS-SRE-6, FEASIBILITY-4.
  `python scripts/validate_repository_catalogs.py --fanout-report` succeeds for
  `repositories.governance.json`; existing catalogs still pass with the **unchanged** deployment
  fanout.
- **Test cases:**
  - positive: governance catalog fanout report within governance-specific thresholds; quota-headroom
    report emitted.
  - negative: two repos sharing one `project` value → validation error; a repo whose name makes the
    `prod-preview` role exceed 64 chars → validation error (not an apply-time raise).
  - edge: a catalog with one repo still validates (fanout scales linearly); the deployment catalog's
    thresholds are not loosened by the governance addition.
- **Dependencies:** E1.S6.
- **Operator access:** NO.

### Story 1.9: [E1.S8] CI wiring: `pulumi-governance.yml` (dedicated event, env-gated apply, server-side re-auth)

- **Atomic scope:** New **dedicated** governance runner workflow keyed to its own
  `repository_dispatch` event type `pulumi-governance-command` (NOT `pulumi-pr-command`; NO
  `workflow_dispatch`). It re-derives author + scope server-side, then runs plan/up-plan with
  `PULUMI_DIR=pulumi/governance` under **two static env-gated apply jobs**
  (`governance_test_apply`, `governance_prod_apply`, both `environment: governance`). Reuses
  `run_pulumi_command.py` reject-direct-`up` + saved-plan validation; no new enforcement code beyond
  the preflight re-auth. (Architecture §7.2, §7.5; resolves AWS-SRE-3, FEASIBILITY-1/2, SECURITY-1/2.)
- **Files:**
  - `+ .github/workflows/pulumi-governance.yml`:
    - `on: repository_dispatch: types: [pulumi-governance-command]` only (no `workflow_dispatch`).
    - `preflight` job (no `id-token`): re-validate PR number/head SHA/open-not-merged/same-repo head;
      resolve `client_payload.comment_id` → author via `gh api .../issues/comments/{id}`, assert
      current write permission and `login!=Kravalg` for the original requester; recompute `governance_touched` server-side from head SHA changed files via
      `scripts/governance_paths.py`, reject if not governance. All `client_payload` fields treated as
      untrusted.
    - `governance_test_apply`: `environment: governance`, `PULUMI_DIR=pulumi/governance`,
      `make pulumi-up-plan` (test stack), `awskms://` provider.
    - `governance_test_post_apply_drift` → `governance_prod_apply`
      (`needs: [governance_test_apply, governance_test_post_apply_drift]`, `environment: governance`,
      `PULUMI_DIR=pulumi/governance`, `make pulumi-up-plan` prod stack).
    - final `comment_result` / status job: `gh api -X POST repos/{repo}/statuses/{head_sha}`
      with informational context `"Governance Apply"`. The dedicated main-only evidence
      App issues required `"Governance Promotion"` only after authenticated preflight
      and all four test/prod apply/drift stages succeed, with verified saved-plan
      artifacts and immutable base/head (FR15, FEASIBILITY-1).
- **Acceptance criteria:** FR16, FR12 (env on BOTH apply jobs), FR13/SECURITY-1 (runner author
  re-check), SECURITY-2 (both applies gated), FEASIBILITY-1 (status posted to head SHA).
  actionlint/yamllint green; workflow lint test asserts: both apply jobs `environment: governance`
  + `PULUMI_DIR=pulumi/governance`; preflight resolves the original comment author and verifies current write permission
  plus requester != Kravalg; no
  `workflow_dispatch`; status-post step present with context `"Governance Apply"`.
- **Test cases:**
  - positive: both apply jobs declare `environment: governance` and `PULUMI_DIR=pulumi/governance`;
    status-post step targets `{head_sha}` with context `"Governance Apply"`.
  - negative: workflow has no `workflow_dispatch`; does not invoke `make pulumi-up` (direct apply);
    preflight rejects a sole-reviewer requester, revoked write permission or non-governance scope.
  - edge: `governance_prod_apply` depends on `governance_test_*` success (ordering preserved); plan
    job uploads the saved-plan artifact consumed by up-plan.
- **Dependencies:** E1.S5 (project exists), E1.S6 (`governance_paths.py`), E2.S2 (the `governance`
  environment exists). Strictly forward-safe: schedule **after E2.S2**.
- **Operator access:** NO.

---

## Epic 2: Kravalg gating via CODEOWNERS + protected environment

Covers FR10, FR11, FR12 (control half), FR15 (required-check half), D5.

### Story 2.1: [E2.S1] `.github/CODEOWNERS` scoping governance/IAM/policy to `@Kravalg`

- **Atomic scope:** Add CODEOWNERS with the exact §7.1 globs, no catch-all `*` line, using the
  `GOVERNANCE_PATH_GLOBS` set as conceptual source of truth (FR10, D5).
- **Files:**
  - `+ .github/CODEOWNERS` (the §7.1 glob list → `@Kravalg`)
- **Acceptance criteria:** FR10, D5 (no over-scoping). `make test-unit` via new
  `tests/unit/test_codeowners.py` (created here).
- **Test cases:**
  - positive: each governance/IAM/policy glob resolves to `@Kravalg`.
  - negative: `docs/`, app code, `tests/` resolve to **no** owner (no catch-all).
  - edge: `.github/CODEOWNERS` itself is owned by `@Kravalg`.
- **Dependencies:** E1.S6 (path set defined).
- **Operator access:** NO.

### Story 2.2: [E2.S2] Protected `governance` environment payload + verification (dry-run code)

- **Atomic scope:** Emit and verify a protected `governance` GitHub Environment requiring `@Kravalg`
  sole reviewer, `prevent_self_review: true`, protected-branch-only (FR11). Code + `--dry-run`
  payload only; the live `PUT` is operator (N/A here).
- **Files:**
  - `~ scripts/_github_repository_controls.py` — add `GOVERNANCE_ENVIRONMENT = "governance"`,
    `governance_environment_payload(reviewer_id)`, `governance_environment_verification_blockers(...)`.
    **Preserve `default_pull_request_rule()` hardening (SECURITY-3, architecture §7.6):**
    `dismiss_stale_reviews_on_push=True` and `require_last_push_approval=True` are
    already implemented and tested; live readback remains a separate prerequisite.
  - `~ scripts/configure_github_repository_controls.py` — emit
    `payloads["governanceEnvironment"]` in dry-run + apply branches; add
    `PUT repos/{repo}/environments/governance` to the apply branch; add a governance blocker to
    `_verify_applied_controls`.
- **Acceptance criteria:** FR11, SECURITY-3. `make test-unit` via `tests/unit/test_repository_controls.py`
  (extended here).
- **Test cases:**
  - positive: payload lists exactly one reviewer (`@Kravalg`), `prevent_self_review=true`,
    protected-branch-only; `default_pull_request_rule()` returns `dismiss_stale_reviews_on_push=True`
    AND `require_last_push_approval=True`.
  - negative: more than one reviewer / self-review allowed → verification blocker raised; either
    stale-review flag left `False` → controls test fails.
  - edge: `--dry-run` output snapshot includes the `governanceEnvironment` payload (no live call).
- **Dependencies:** E2.S1 (Kravalg as the owner concept) — soft; can run independently of S1.
- **Operator access:** NO (live `PUT` is N/A — operator runbook E4.S2).

### Story 2.3: [E2.S3] App-issued Governance Promotion merge gate

- **Atomic scope:** `REQUIRED_STATUS_CHECKS` requires `Governance Promotion` from
  the verified dedicated evidence App. `Governance Apply` remains informational.
  The installed main publisher resolves the source run, verifies saved-plan
  artifacts and immutable base/head, and requires authenticated preflight plus
  successful test apply, test post-apply drift, prod apply and prod post-apply drift.
- **Files:** `scripts/_github_repository_controls.py`, trusted promotion publisher
  and associated controls/workflow tests; E1.S8 supplies the governance run evidence.
- **Acceptance criteria:** FR15, FEASIBILITY-1. The required context and App issuer
  match the verified publisher. A successful prod apply alone cannot promote.
- **Test cases:** positive — all four stages and bound artifacts allow promotion;
  negative — wrong issuer, missing/skipped/failed stage, moved base/head or missing
  artifact rejects success; edge — informational `Governance Apply` cannot satisfy
  the required check and existing required checks remain intact.
- **Dependencies:** E2.S2, E1.S8 and the installed trusted-main evidence App.
- **Operator access:** NO for source validation; live App/control installation and
  real apply/drift evidence remain explicit operator prerequisites.

---

## Epic 3: PR-comment governance deploy gate (author + path aware)

Covers FR13, FR14, D6 (gate-code layer). The `environment: governance` backstop is E1.S8 + E2.S2.
**Note (SECURITY-1):** the intake author gate (E3.S1) is now **defense-in-depth**, not the sole
control — the *trusted* governance runner (E1.S8) re-derives the comment author and recomputes the
governance scope server-side before assuming AWS credentials. A direct `repository_dispatch` cannot
bypass the author check because the runner re-resolves it from `comment_id`.

### Story 3.1: [E3.S1] Requester/path gate in `scripts/pulumi_pr_comment.py`

- **Atomic scope:** Intake rejects `up` with an empty login or the sole reviewer's
  login `Kravalg`, then applies existing association checks. The trusted runner
  independently verifies the original comment author's current write permission.
  Plan retains association authorization; path detection selects the controller.
- **Files:** parser and installed main preflight; no change to AGENTS requester rules.
- **Acceptance criteria:** FR13, D6; current-write requester != protected reviewer.
- **Test cases:** positive — verified dmytrocraft may request up and Kravalg separately
  approves; negative — Kravalg, empty login, revoked permission or forged original
  comment fails; edge — comparison is case-insensitive and non-governance up retains
  requester/reviewer separation.
- **Dependencies:** E1.S6 and trusted runner re-authorization in E1.S8.
- **Operator access:** NO.

### Story 3.2: [E3.S2] Intake workflow computes changed paths + passes author login (FR14)

- **Atomic scope:** Add a changed-paths detection step to the intake workflow that calls
  `scripts/governance_paths.py` and passes `governance_touched` + the comment author login into the
  parse step (FR14).
- **Files:**
  - `~ .github/workflows/pulumi-pr-commands.yml` — add a `Detect governance-touching changes` step
    (`gh api .../pulls/{n}/files` → `governance_paths.py --files-stdin`), then pass
    `--author-login` + `--governance-touched` to the parse step. Confirm `pull-requests: read`
    permission is present. **Dispatch the dedicated event type (architecture §7.2):** when
    `governance_touched=true`, dispatch `event_type=pulumi-governance-command` to
    `pulumi-governance.yml`; otherwise keep `event_type=pulumi-pr-command` to the existing runner.
    Include `comment_id` in `client_payload` (already present) so the governance runner can
    re-resolve the author server-side.
- **Acceptance criteria:** FR14. actionlint/yamllint green; workflow lint test asserts the changed-
  paths step + inputs + the conditional event-type dispatch.
- **Test cases:**
  - positive: PR modifying `pulumi/governance/**` sets `governance_touched=true` and dispatches
    `pulumi-governance-command`.
  - negative: PR touching only `docs/**` sets `governance_touched=false` and dispatches
    `pulumi-pr-command` (existing runner).
  - edge: paginated file lists handled (`--paginate`); intake has `pull-requests: read`;
    `client_payload.comment_id` present for server-side author re-resolution.
- **Dependencies:** E3.S1, E1.S6 (`governance_paths.py`), E1.S8 (governance runner + event type).
- **Operator access:** NO.

### Story 3.3: [E3.S3] Existing runner ignores governance event; ordering/guard regression check

- **Atomic scope:** **Routing now happens at the intake via the dedicated event type (E3.S2 →
  `pulumi-governance.yml`), NOT by the monolithic runner handing off mid-flow** (the
  "route to another workflow" primitive does not exist — AWS-SRE-3/FEASIBILITY-2). This story is
  therefore reduced to: confirm the existing `pulumi-pr-command-runner.yml` continues to handle
  **only** `pulumi-pr-command` (non-governance) unchanged, and add the regression guard that its
  `prod_* → test_*` ordering and success-before-merge graph are not weakened. No new routing code in
  the monolithic runner.
- **Files:**
  - `~ .github/workflows/pulumi-pr-command-runner.yml` — (only if needed) ensure it does not also
    listen for `pulumi-governance-command`; otherwise no change. Add no governance apply job here.
- **Acceptance criteria:** FR15 (ordering preserved). Workflow-graph lint test asserts `prod_*`
  still depends on `test_*` success in the existing runner and that the runner does not handle
  `pulumi-governance-command`.
- **Test cases:**
  - positive: governance `up` is handled exclusively by `pulumi-governance.yml` (E1.S8), not this
    runner.
  - negative: non-governance `up` keeps the existing routing unchanged.
  - edge: `prod_*` jobs still gated on `test_*` success (no ordering regression).
- **Dependencies:** E3.S2, E1.S8, E2.S2.
- **Operator access:** NO.

---

## Epic 4: AGENTS.md onboarding flow + operator runbook + docs

Covers FR17, FR18, FR21 (docs half).

### Story 4.1: [E4.S1] `AGENTS.md` 3-PR onboarding flow (CODE vs OPERATOR labeled)

- **Atomic scope:** Document the PR-A / PR-B / create-repo / PR-C onboarding sequence for a new
  `X-infrastructure` service, each step labeled CODE or OPERATOR, referencing the governance commands
  (FR17).
- **Files:**
  - `~ AGENTS.md` — add the onboarding section (§11 flow).
- **Acceptance criteria:** FR17. Doc presence test asserts the PR-A/PR-B/create-repo/PR-C sequence +
  CODE/OPERATOR labels + governance command references.
- **Test cases:**
  - positive: all four steps present with operator-vs-code labels.
  - negative: no step omits its CODE/OPERATOR tag.
  - edge: references `/pulumi test up` then `/pulumi prod up` and `repositories.governance.json`.
- **Dependencies:** E1.S6 (catalog), E3 (gate exists, referenced).
- **Operator access:** NO.

### Story 4.2: [E4.S2] Operator runbook + account-model correctness verification (two accounts)

- **Atomic scope:** Add the operator runbook (trusted state-only initialization, protected saved-plan apply, branch/env config, repo
  variables, repo create + push, gated real applies) and the account-model correctness work: keep
  component code account-parametric (no account literals) and verify the per-stack account facts
  (FR18, FR21 docs/verify half). There is **no** single-account reconciliation and no stripping of
  `933245420672` — committed account pins must be verified against live metadata.
- **Files:**
  - `+ docs/governance-stack.md` — design + operator runbook (§10).
  - `~ AGENTS.md` — link the operator runbook section.
  - (`docs/github-ci-bootstrap-stack.md` and `pulumi/Pulumi.prod.yaml` are already
    two-account-correct — left unchanged. Do NOT repoint the prod `costAnomalyMonitorArn` away from
    `933245420672`.)
- **Acceptance criteria:** FR18, FR21, FEASIBILITY-6. Doc presence test asserts each operator step
  (incl. verification of committed per-account OIDC ARNs, cost-anomaly-ARN-matches-stack verification, break-glass) is
  enumerated + tagged operator-only. A test asserts no account-number literal appears in component
  Python under `pulumi/infra/**/*.py`; the test stack config pins `891377212104` and the prod stack
  config pins `933245420672`.
- **Test cases:**
  - positive: runbook enumerates each operator step (state-only init and saved-plan apply, env/branch config, repo vars,
    committed per-account OIDC-ARN verification, cost-anomaly-ARN-matches-stack check, repo create+push, gated applies,
    break-glass) with a `gh api`/Pulumi command reference.
  - negative: no hardcoded `891377212104`/`933245420672` literal in component Python; **if**
    `costAnomalyMonitorArn` is present its account matches its stack (test→`891377212104`,
    prod→`933245420672`; absence permitted, FEASIBILITY-6).
  - edge: the test stack resolves to `891377212104` and the prod stack resolves to `933245420672`.
- **Dependencies:** E4.S1, E1.S5, E5.S1 (scaffold referenced in step 4).
- **Operator access:** NO (documents operator steps; runs none).

---

## Epic 5: `user-service-infrastructure` repo scaffold (template assets)

Covers FR19, FR20.

### Story 5.1: [E5.S1] Scaffold Pulumi project + AGENTS.md/README template assets

- **Atomic scope:** Deliver the in-repo template assets for `user-service-infrastructure`: its own
  `pulumi/` skeleton (manifest + test/prod stacks + thin `__main__.py`) plus repo-local AGENTS.md and
  README, two-account (test `891377212104` / prod `933245420672`), consuming governance-provided
  bucket/KMS (FR19).
- **Files:**
  - `+ pulumi/user-service-infrastructure/pulumi/Pulumi.yaml`
  - `+ pulumi/user-service-infrastructure/pulumi/Pulumi.test.yaml` (account `891377212104`,
    `awskms://alias/pulumi-user-service-infrastructure-test?region=eu-central-1`)
  - `+ pulumi/user-service-infrastructure/pulumi/Pulumi.prod.yaml` (account `933245420672`)
  - `+ pulumi/user-service-infrastructure/pulumi/__main__.py` (thin baseline; consumes, never creates,
    state bucket + KMS key)
  - `+ pulumi/user-service-infrastructure/AGENTS.md`
  - `+ pulumi/user-service-infrastructure/README.md`
- **Acceptance criteria:** FR19, FEASIBILITY-6 (preview-blocked). Asset-presence test asserts the
  scaffold exists and references the governance-provided backend URL + secrets alias; catalog lists
  the repo (E1.S6). **Tests assert STRUCTURE ONLY — never run `pulumi preview`** (the scaffold
  consumes governance-provided resources/vars that exist only after the operator apply, so preview is
  blocked until then). gitleaks clean.
- **Test cases:**
  - positive: scaffold stack files reference `s3://pulumi-user-service-infrastructure-{env}-state` +
    the governance secrets alias.
  - negative: scaffold does not create its own IAM roles / OIDC trust.
  - edge: no inline secrets/passphrase; `Pulumi.example.yaml` absent from discovery (or marked
    non-discovered if present).
- **Dependencies:** E1.S4a/E1.S4b (output shape), E1.S6 (catalog entry).
- **Operator access:** NO (repo create + push is N/A — operator runbook E4.S2).

### Story 5.2: [E5.S2] Self-deploy workflow template (OIDC, saved-plan, no admin creds)

- **Atomic scope:** Add `self-deploy.yml` template that assumes only the governance-provided
  preview/apply/drift roles via the CI-config secret and routes applies through the IaC-only
  saved-plan path; no static or admin creds (FR20).
- **Files:**
  - `+ pulumi/user-service-infrastructure/.github/workflows/self-deploy.yml` (PR-comment → test plan →
    test apply (saved-plan) → prod; `load-aws-ci-env` → OIDC role assume → `make pulumi-up-plan`).
- **Acceptance criteria:** FR20, AWS-SRE-4 (name parity). Template lint/test asserts OIDC role
  assumption (no static AWS keys, no `AdministratorAccess`) + `up-plan` apply path; gitleaks finds no
  embedded secrets. **Name-parity test:** the role names the template references
  (`GitHubCiApply-user-service-infrastructure-test`, `GitHubCiConfigRead-user-service-infrastructure-test`,
  etc.) are byte-equal to the names the governance component renders for that repo (single source of
  truth — no `user-service` short-name mismatch).
- **Test cases:**
  - positive: workflow references `configure-aws-credentials` with `role-to-assume` from the
    governance CI-config role output; referenced role names match the rendered governance names exactly.
  - negative: no `aws_access_key_id`/`aws_secret_access_key` literals; no `AdministratorAccess`;
    a `GitHubCiApply-user-service-test` (short-name) reference would fail the name-parity test.
  - edge: apply step calls `make pulumi-up-plan` (saved-plan only), never `make pulumi-up`.
- **Dependencies:** E5.S1, E1.S4a/E1.S4b (consumes `deploymentRoleArns`/`configReadRoleArns`/`stateBackendUrl`).
- **Operator access:** NO.

---

## Epic 6: Tests + quality closeout (the contract ratchet)

Covers FR24, NFR1–NFR5, NFR7, D7, plus the structural-shape lockstep (R6).

### Story 6.1: [E6.S1] Governance component test suite + structural project-shape test

- **Atomic scope:** Author the exhaustive `tests/unit/test_governance.py` covering the §9.1 matrix and
  add the governance structural test mirroring the bootstrap test (FR24, R6).
- **Files:**
  - `+ tests/unit/test_governance.py` (FR2/FR3/FR4/FR5/FR6/FR7/FR8/FR22/FR23/FR1 fan-out + isolation;
    plus the amended verifies: service apply subjects == `environment:test` / `environment:prod` (§5.1a), no
    `pulumi-platform-bootstrap` in service deploy docs (AWS-SRE-1), apply-role surgical Deny
    (SECURITY-5), account-assertion both branches under mocks (AWS-SRE-5))
  - `~ tests/pulumi/test_project_structure.py` (add `test_governance_project_*`: name `governance`,
    stacks {example,test,prod}, `awskms://`, the test stack config pins `891377212104` and the prod
    stack config pins `933245420672` (each pins its own account), no account literal in component
    Python under `pulumi/infra/**/*.py`; **assert the governance project registers ZERO
    `aws.iam.OpenIdConnectProvider` create — provider consumed by `.get()` only** (AWS-SRE-2))
- **Acceptance criteria:** FR24, FR7 (no-provider-create), NFR6 (bootstrap test intact + golden parity
  fixture from E1.S2). `make test-unit` + `make test-pulumi` green.
- **Test cases:**
  - positive: 3N roles, 1 OIDC provider, per-repo bucket/KMS, repo-isolation, no-wildcard-Allow.
  - negative: duplicate `project` rejected; cross-repo ARN substring absent.
  - edge: account-mismatch raise path covered; `write_secret_values=False` path covered.
- **Dependencies:** E1.S5 (project), E1.S4a/E1.S4b (component).
- **Operator access:** NO.

### Story 6.2: [E6.S2] 100% combined coverage + mutation hardening

- **Atomic scope:** Close coverage gaps for all new modules and harden the mutation-sensitive logic
  (governance role/policy builders + author-gate decision) so mutants are killed (NFR1, NFR2).
- **Files:**
  - `~ tests/unit/test_governance.py`, `~ tests/unit/test_pr_comment_gate.py`,
    `~ tests/unit/test_repository_controls.py`, `~ tests/unit/test_codeowners.py` (add branch-coverage
    + mutation-killing assertions).
  - `~ tests/test_mutation_targets.py` if the new modules need registering.
- **Acceptance criteria:** NFR1, NFR2. `make test-coverage` reports 100% combined; `make test-mutation`
  passes for changed modules.
- **Test cases:**
  - positive: every branch in `governance.py` hit (each suffix, each purpose, mismatch raise).
  - negative: flipping `governance_touched`/`action == "up"` mutants are killed.
  - edge: each Deny action individually asserted (mutation on the Deny list is caught).
- **Dependencies:** E6.S1, E3.S1, E2.S2, E2.S1.
- **Operator access:** NO.

### Story 6.3: [E6.S3] import-linter contract + static suite green

- **Atomic scope:** Add one additive forbidden import-linter contract `infra.governance ↛ {policy, app}`
  (and not `scripts`) and confirm the full static suite (ruff ≤12, mypy, ty, import-linter, deptry,
  bandit, pip-audit, gitleaks) is green (NFR3, D7).
- **Files:**
  - `~ pyproject.toml` (or the import-linter config file) — add the forbidden contract; if `infra`
    is not a root package, scope minimally per §9.4.
- **Acceptance criteria:** NFR3, D7. `make ci-pr` green; import-linter contracts unbroken; ruff reports
  no complexity > 12 on the new modules.
- **Test cases:**
  - positive: `infra.governance` importing `policy` or `app` fails the contract.
  - negative: legitimate `infra.governance` → `infra.*` imports pass.
  - edge: existing `app`/`policy` contracts remain green (no destabilization).
- **Dependencies:** E1.S4a/E1.S4b (module exists), E6.S2.
- **Operator access:** NO.

### Story 6.4: [E6.S4] Policy-pack + IAM Access Analyzer + no-escape-hatch verification

- **Atomic scope:** Confirm CrossGuard green (incl. `iam-no-wildcards`), no wildcard-allowlist /
  `AllowWildcardIam` escape hatches, and IAM Access Analyzer clean over the governance preview files
  (NFR4, NFR5, FR23).
- **Files:**
  - `~ tests/pulumi/test_ci_guardrails.py` (or the appropriate policy test) — assert governance roles
    produce zero `iam-no-wildcards` violations and appear in no wildcard allowlist / carry no
    `AllowWildcardIam` tag.
- **Acceptance criteria:** NFR4, NFR5, FR23. `make test-policy` zero violations;
  `scripts/pulumi_ci_guardrails.py validate-iam <governance preview files>` reports zero
  `ERROR`/`SECURITY_WARNING`.
- **Test cases:**
  - positive: zero `iam-no-wildcards` violations on governance roles.
  - negative: a synthetic governance role with `Action:*` Allow fails the scan.
  - edge: Deny statements with `Resource:*` are correctly exempt (not flagged).
- **Dependencies:** E1.S4a/E1.S4b, E6.S1.
- **Operator access:** NO (the Analyzer entrypoint is the static validator, not a live AWS call).

---

## Cross-cutting notes for implementer subagents

- **One story = one focused subagent.** Each story's Files list is the editable surface; do not
  touch files outside it. The single-source-of-truth glob set (`scripts/governance_paths.py`) is
  produced once in E1.S6 and only consumed thereafter (E2.S1, E3.S1/S2).
- **NFR6 is a hard gate on E1.S1–E1.S4b:** the single-repo `bootstrap` outputs must stay byte-identical
  (enforced by the golden parity fixture captured in E1.S2);
  run `tests/unit/test_components.py` + `tests/pulumi/test_project_structure.py` after each.
- **No story needs live AWS/GitHub creds.** Every operator action (real `up`, live env `PUT`, repo
  create/push, repo variables) is captured in the E4.S2 runbook and is out of the implementer loop.
- **Quality gate per story:** at minimum `make ci-pr` for the touched surface; E6 stories additionally
  require `make test-coverage`, `make test-mutation`, `make test-policy`.

## AC traceability (epic → AC)

| Issue #77 AC | Stories |
|---|---|
| AC-1 generic governance project | E1.S1, E1.S2, E1.S3, E1.S4a, E1.S4b, E1.S5, E1.S6, E1.S7 |
| AC-2 any `*-infrastructure` / config-only | E1.S6, E1.S7 |
| AC-3 Kravalg-only approval | E2.S1, E2.S2, E2.S3 |
| AC-4 PR-comment deploy gating | E3.S1, E3.S2, E3.S3, E2.S2, E1.S8 |
| AC-5 IaC-only apply | E1.S8, E5.S2 |
| AC-6 user-service-infrastructure + self-deploy | E5.S1, E5.S2, E4.S1, E4.S2 |
| AC-7 least privilege verified | E1.S3, E1.S4a, E1.S4b, E6.S4 |
| AC-8 tests cover the contract; 100% coverage | E6.S1, E6.S2 |
| AC-9 full quality suite green | E6.S2, E6.S3, E6.S4 |
