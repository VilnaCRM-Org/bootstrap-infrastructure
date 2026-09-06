# PRD — Multi-Repo IAM/OIDC Governance Stack

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

**Phase:** 2 — Planning (BMAD PM)
**Source of truth:** GitHub issue [#77](https://github.com/VilnaCRM-Org/bootstrap-infrastructure/issues/77) (Acceptance Criteria AC-1..AC-9)
**Inputs:** `_bmad-output/planning-artifacts/research.md`, `_bmad-output/planning-artifacts/brief.md`
**Base branch:** `feat/multi-repo-governance` (off `codex/issue59-github-ci-bootstrap-stack`, PR #60)

## How to read this document

- **FR** = Functional Requirement; **NFR** = Non-Functional Requirement. Each is atomic and
  independently testable.
- **AC↔** column traces each requirement to the numbered Acceptance Criterion in issue #77.
- **Verify** gives a concrete, testable verification note (the gate that proves the requirement).
- **Foundation** cites the existing code being generalized/reused (do not design from scratch).
- **Deliverability** tags each requirement: **CODE** (pure code/IaC/docs, deliverable now,
  no live creds) or **OPERATOR** (needs AWS admin / GitHub org-admin; delivered as
  runbook/dry-run payload now, executed by operator). Mixed items state both halves.

## Hard constraints (decided — do not relitigate)

- **Two AWS accounts (test `891377212104`, prod `933245420672`), region `eu-central-1` for both.**
  `test`/`prod` are Pulumi **stacks** AND map to **separate** AWS accounts (AWS-best-practice prod
  blast-radius isolation). Component Python stays account-parametric (via
  `aws.get_caller_identity().account_id` + `{account_id}` interpolation); account-number literals
  live only in per-stack Pulumi config (`Pulumi.test.yaml`→891377212104, `Pulumi.prod.yaml`→933245420672)
  and the per-stack `awsAccountId` assertion value (see FR21 / research R1).
- **Generalize, don't rewrite.** Build on `GitHubCiBootstrap` (`pulumi/infra/ci_bootstrap.py`)
  + `CiConfiguration` (`pulumi/infra/ci_config.py`); reuse `PulumiStateBuckets`
  (`pulumi/infra/pulumi_state.py`), `PulumiSecretsKeys` (`pulumi/infra/pulumi_secrets.py`),
  `GitHubOidcRoles` (`pulumi/infra/iam/github_oidc.py`), the repo catalog
  (`pulumi/infra/repository_catalog.py`), and the policy pack (`policy/`).
- **Sole approver `@Kravalg`**; `@dmytrocraft` opens PRs; `prevent_self_review=true`.
- **IaC-only apply** via `scripts/run_pulumi_command.py` (rejects direct `pulumi up` when
  `GITHUB_ACTIONS=true`; saved-plan-only). Reuse unchanged.
- **Secret-read deny set** applies to read-only / config-read roles ONLY (never apply/deploy
  backend roles, which need `kms:Decrypt`). CrossGuard exempts `Effect: Deny`; deployment
  roles carry no wildcard `Allow`.
- Must work generically for any `-infrastructure` suffix repo and repos added later, via config.

---

## A. Generic governance Pulumi project (generalized from `github-ci-bootstrap`)

### FR1 — Config-driven governance repo list
**[CODE]** The governance project SHALL resolve its set of managed repositories from
configuration (a governance repo list / catalog), not from a hard-coded single `repoSlug`.
Adding or removing a repo SHALL require a config change only — no Python code change.
- **AC↔:** AC-1, AC-2
- **Foundation:** `ManagedRepositoryCatalog.from_settings`
  (`pulumi/infra/repository_catalog.py:101-131`); resolution order
  `managed_repo_overrides → repositoryCatalogPath JSON → managedRepositories → repoSlug`.
  The bootstrap's single-`repoSlug` requirement (`ci_bootstrap.py:808-812`) is removed in the
  generalized loop.
- **Verify:** Unit test adds a synthetic repo to the governance config and asserts the resolved
  catalog contains it; a second test asserts no Python source under the project changed between
  the one-repo and two-repo cases (diff-free except config).

### FR2 — Per-repo preview/apply/drift deploy roles
**[CODE]** For every repo in the governance list, the project SHALL create the three deployment
roles keyed by purpose `preview | apply | drift`, with the bootstrap's per-suffix OIDC trust
(branch ref + `pull_request` + `environment:test` for test-preview; `environment:prod` only for
prod-apply; etc.), `aud=sts.amazonaws.com`, `sub IN subjects`, and `repository == org/repo`
pinned with `StringEquals`.
- **AC↔:** AC-1, AC-2
- **Foundation:** `_role_specs` (`ci_bootstrap.py:447-467`), `_create_roles` (`:540-551`),
  `_deployment_role_subjects` (`:244-257`), `_deployment_assume_role_policy` (`:260-289`),
  `_ci_role_name` (`:208-217`) lifted into a per-repo loop.
- **Verify:** Unit test asserts that for N repos exactly 3N deployment roles are produced with
  correct names (`GitHubCiPreview|Apply|Drift-{project}-{env}`) and that each role's trust
  document contains the expected subjects and the `repository` claim pin (`StringEquals`).

### FR3 — Deploy policy scoped to the repo's own state bucket + KMS key
**[CODE]** Each repo's deployment (Pulumi-backend) policy SHALL grant S3 state access
(`state/*`, `.pulumi/*`) and KMS secrets-provider use scoped to **that repo's** state bucket
ARN and secrets-key alias only — no access to other repos' state or keys.
- **AC↔:** AC-1, AC-7
- **Foundation:** `_pulumi_backend_policy_document` (`ci_bootstrap.py:313-352`),
  `_state_bucket_resources` (`:292-301`), `_pulumi_secrets_alias_conditions` (`:304-310`),
  naming via `state_bucket_name_for_repo` / `pulumi_secrets_alias_name_for_repo`
  (`bootstrap_settings.py:220-252`).
- **Verify:** Unit test renders repo A's and repo B's backend policies and asserts A's policy
  references only A's bucket ARN + A's KMS alias condition and contains no reference to B's
  resources (cross-repo isolation).

### FR4 — Per-repo config-read role + CI-config secret
**[CODE]** For every repo, the project SHALL create the CI-config Secrets Manager secret(s)
(`/{project}/ci/{suffix}`) and a config-read role (`GitHubCiConfigRead-{project}-{suffix}`)
whose policy permits `secretsmanager:DescribeSecret` + `GetSecretValue` on exactly that repo's
CI secret ARN pattern, with per-suffix OIDC trust.
- **AC↔:** AC-1
- **Foundation:** `CiConfiguration` (`ci_config.py:251-362`): `_ci_secret_id` (`:55-59`),
  `_ci_config_read_role_name` (`:76-89`), `_github_actions_subjects` (`:92-107`),
  `_ci_config_read_policy` (`:180-209`), `_ci_secret_arn_patterns` (`:61-73`) lifted per repo.
- **Verify:** Unit test asserts each repo gets a config-read role scoped to only its own secret
  ARN pattern, with the correct per-suffix trust subjects, and zero cross-repo secret access.

### FR5 — Per-repo S3 state bucket
**[CODE]** For every repo, the project SHALL provision the repo's S3 Pulumi-state bucket
(versioned, encrypted, public-access-blocked, TLS-only, with cross-region replica) using the
deterministic name `pulumi-{repo}-{env}-state`.
- **AC↔:** AC-1
- **Foundation:** `PulumiStateBuckets` (`pulumi/infra/pulumi_state.py:289`, fan-out `:327-338`,
  `_register_repository:347-423`); naming `state_bucket_name_for_repo`
  (`bootstrap_settings.py:220-231`).
- **Verify:** Structural/unit test asserts one primary + one replica bucket per repo per env
  with versioning, AES256/KMS encryption, public-access block, and TLS-only bucket policy
  (consistent with `scripts/validate_repository_catalogs.py` fan-out expectations: 2 S3/env).

### FR6 — Per-repo KMS key + alias
**[CODE]** For every repo, the project SHALL provision the repo's customer-managed KMS key with
rotation enabled and alias `alias/pulumi-{repo}-{env}-secrets`, with a key policy that enables
account-root IAM delegation.
- **AC↔:** AC-1
- **Foundation:** `PulumiSecretsKeys` (`pulumi/infra/pulumi_secrets.py:66`, fan-out `:97-151`,
  `_key_policy:30-45`); naming `pulumi_secrets_alias_name_for_repo`
  (`bootstrap_settings.py:242-252`).
- **Verify:** Unit test asserts one KMS key + alias per repo per env, rotation enabled, alias
  matches the deterministic pattern (1 KMS/env per `validate_repository_catalogs.py`).

### FR7 — Account-level OIDC provider (single, shared)
**[CODE]** The project SHALL ensure exactly one GitHub OIDC provider for the account (shared
across all governance repos), reused rather than duplicated per repo.
- **AC↔:** AC-1
- **Foundation:** `GitHubOidcRoles._provider_resource` (`github_oidc.py:175-200`) /
  bootstrap `GitHubOidcRoles(..., repositories=[])` provider-only usage (`ci_bootstrap.py:833-838`).
- **Verify:** Unit test with ≥2 governance repos asserts exactly one OIDC provider resource is
  registered (no per-repo duplication).

### FR8 — Generic `-infrastructure` suffix support, no code change for new repos
**[CODE]** The project SHALL apply the full per-repo set (FR2–FR6) to any repo whose name carries
the `-infrastructure` suffix, and to repos added to the governance config later, with no code
change beyond config.
- **AC↔:** AC-2
- **Foundation:** catalog model (`repository_catalog.py`), `repositories.example.json` (already
  lists `user-service-infrastructure`, `core-service-infrastructure`),
  `repositories.schema.json`.
- **Verify:** Parametrized unit test feeds an arbitrary new `*-infrastructure` repo via config
  and asserts the complete resource set (roles, policy, bucket, KMS, config-read) is produced;
  a guard test asserts repo names are validated against expected suffix/shape.

### FR9 — Project scaffold + per-stack config (test/prod stacks, two accounts)
**[CODE]** The governance project SHALL ship its own `Pulumi.yaml` and per-stack
`Pulumi.test.yaml` / `Pulumi.prod.yaml`, targeting region `eu-central-1`, with `test`/`prod` as
stacks mapping to separate accounts (`Pulumi.test.yaml`→`891377212104`,
`Pulumi.prod.yaml`→`933245420672`) and per-stack `awskms://` secrets providers.
- **AC↔:** AC-1
- **Foundation:** parity with `pulumi/github-ci-bootstrap/Pulumi*.yaml`; structural expectations
  in `tests/pulumi/test_project_structure.py:51-83` (updated in lockstep — research R6).
- **Verify:** Structural test asserts the project manifest + both stack configs exist, declare
  `aws:region: eu-central-1`, that the test stack config pins account `891377212104` and the prod
  stack config pins `933245420672`, and set an `awskms://` secrets provider per stack.

---

## B. Kravalg-only approval (CODEOWNERS + protected environment)

### FR10 — CODEOWNERS scopes governance + IAM code to `@Kravalg`
**[CODE]** A `CODEOWNERS` file SHALL assign review ownership of the governance project path, the
IAM code (`pulumi/infra/iam/`, `pulumi/infra/ci_bootstrap.py`, `pulumi/infra/ci_config.py`,
`pulumi/infra/automation.py`), and the policy pack (`policy/`) to `@Kravalg` — and SHALL leave
all other repository paths unowned/unaffected.
- **AC↔:** AC-3
- **Foundation:** none today (no CODEOWNERS in repo — research §4.2); branch ruleset already sets
  `require_code_owner_review: true` (`scripts/_github_repository_controls.py:58`).
- **Verify:** Test parses `CODEOWNERS` and asserts (a) every governance/IAM/policy glob maps to
  `@Kravalg`, and (b) a sample of unrelated paths (e.g. `docs/`, app code) resolves to no owner
  (research R4 — no accidental over-scoping).

### FR11 — Protected `governance` GitHub Environment with `@Kravalg` as sole reviewer
**[CODE deliverable now + OPERATOR apply]** The repository-controls configuration SHALL define a
protected `governance` GitHub Environment requiring `@Kravalg` as the **sole** required reviewer,
with `prevent_self_review: true` and protected-branch-only deployments. The payload + dry-run are
delivered as code now; the live API `PUT` is an operator (repo-admin) action.
- **AC↔:** AC-3
- **Foundation:** `scripts/configure_github_repository_controls.py` (`DEFAULT_PROD_REVIEWER="Kravalg"`
  `:68`; `protected_reviewer_environment_payload` `_github_repository_controls.py:94-104`,
  `prevent_self_review=True` `:99`) extended to emit a `governance` environment alongside
  `prod` / `operations-alert-reconcile` (`:224-235`).
- **Verify:** Unit test asserts the generated `governance` environment payload lists exactly one
  reviewer (`@Kravalg`), `prevent_self_review=true`, and protected-branch-only; `--dry-run`
  output snapshot covers it. Operator step documented (FR18).

### FR12 — Governance apply jobs run under the `governance` protected environment
**[CODE]** The CI runner job(s) that apply governance changes SHALL declare
`environment: governance` so the protected-environment reviewer gate (FR11) is enforced before
any governance apply proceeds.
- **AC↔:** AC-3, AC-4
- **Foundation:** runner pattern where `prod_apply` declares `environment: prod`
  (`.github/workflows/pulumi-pr-command-runner.yml:649-661`); add governance-scoped apply gating.
- **Verify:** Workflow lint/test asserts the governance apply job(s) reference
  `environment: governance`; an integration-shaped test asserts a governance apply cannot run
  without the environment declaration present.

---

## C. PR-comment deploy gating to `@Kravalg` (test-then-prod-before-merge)

### FR13 — Author gate: only `@Kravalg` may `/pulumi … up` on governance-touching PRs
**[CODE]** For a PR that touches governance/IAM paths, `/pulumi test up` and `/pulumi prod up`
SHALL be accepted **only** when the comment author login is `@Kravalg`; any other author SHALL be
rejected. Non-governance PRs retain the existing association-based authorization.
- **AC↔:** AC-4
- **Foundation:** `scripts/pulumi_pr_comment.py` (`AUTHORIZED_ASSOCIATIONS` `:9`,
  `author_is_authorized:43-44`) extended with a login input + a path-touched signal; intake
  workflow `.github/workflows/pulumi-pr-commands.yml` extended to compute changed paths.
- **Verify:** Unit tests over the parser: (governance path + author=`Kravalg` + `up`) → authorized;
  (governance path + author≠`Kravalg` + `up`) → rejected; (non-governance path) → existing
  association rule unchanged. `@dmytrocraft` opening the PR is allowed; only the `up` trigger is
  gated (research R5).

### FR14 — Path-aware detection of governance-touching PRs
**[CODE]** The intake workflow SHALL determine whether a PR touches the governance/IAM paths
(the same path set as FR10) and pass that signal into the author gate (FR13).
- **AC↔:** AC-4
- **Foundation:** intake workflow has no diff step today (research §4.3); add a changed-paths
  computation feeding the parser input.
- **Verify:** Test asserts the path-detection logic flags PRs that modify any governance/IAM glob
  and does not flag PRs that touch only unrelated paths (shares the FR10 glob set — single source
  of truth).

### FR15 — Test-then-prod ordering with success required before merge
**[CODE]** A governance deploy triggered by `@Kravalg` SHALL run `test` then `prod` in order,
with prod gated on test success, and the PR SHALL NOT be mergeable until the required governance
deploy checks succeed.
- **AC↔:** AC-4
- **Foundation:** runner job graph already enforces test-before-prod and success-before-merge
  (`pulumi-pr-command-runner.yml:325-731`); required status checks list
  (`_github_repository_controls.py:8-33`). This requirement composes/reuses, plus adds the
  governance checks to the required set.
- **Verify:** Workflow-graph test asserts `prod_*` jobs depend on `test_*` success; a controls
  test asserts the governance apply check is in the required-status-checks set for the protected
  branch.

---

## D. IaC-only apply enforcement (reuse)

### FR16 — Direct `pulumi up` rejected in CI; OIDC Actions are the sole apply path
**[CODE]** The governance project SHALL route applies exclusively through the saved-plan path so
that `scripts/run_pulumi_command.py` rejects any direct `pulumi up` when `GITHUB_ACTIONS=true`;
only GitHub OIDC Actions may apply. The governance project SHALL be wired into CI with its own
`PULUMI_DIR` and per-stack `awskms://` secrets provider.
- **AC↔:** AC-5
- **Foundation:** `scripts/run_pulumi_command.py:672-679` (reject direct `up`),
  saved-plan manifest validation (`:378-397`), `awskms://` secrets-provider check (`:92-105`),
  policy-pack prep (`:108-113`). The bootstrap project is not wired into CI today (research §1.1,
  §4.4) — add the wiring.
- **Verify:** Test/asserts that invoking `up` for the governance project with `GITHUB_ACTIONS=true`
  is rejected with the saved-plan-required message, and that the only accepted apply path is
  `up-plan` with a valid signed manifest. CI workflow references the governance `PULUMI_DIR`.

---

## E. Onboarding flow documentation (AGENTS.md)

### FR17 — Documented 3-PR onboarding flow in `AGENTS.md`
**[CODE]** `AGENTS.md` SHALL document the end-to-end onboarding flow for a new service `X` needing
`X-infrastructure`: **PR A** (grant deploy roles in the governance project; `@Kravalg` reviews,
`/pulumi test up` then `/pulumi prod up`, verify, merge) → **PR B** (bootstrap generic infra using
PR-A roles) → **create the `X-infrastructure` repo** + scaffold → **PR C** (grant OIDC apply
permissions; same gated flow) → repo can self-deploy. Each step SHALL state whether it is operator
(AWS/GitHub-admin) or pure code/IaC.
- **AC↔:** AC-6 (flow), supports AC-3/AC-4/AC-5
- **Foundation:** issue #77 "Target onboarding flow"; `AGENTS.md` has no onboarding section today
  (research §4 inventory).
- **Verify:** Doc test asserts `AGENTS.md` contains the PR-A/PR-B/create-repo/PR-C sequence with
  the operator-vs-code labeling and references to the governance commands.

### FR18 — Operator runbook for the manual steps
**[CODE deliverable now: the runbook]** The documentation SHALL include an operator runbook for
the OPERATOR-only steps with the exact `gh api` / Pulumi commands and dry-run payloads: one-time
`AdministratorAccess` governance bootstrap apply (test then prod), branch-protection +
protected-`governance`-environment reviewer configuration, creating
`user-service-infrastructure` in `VilnaCRM-Org`, and setting GitHub repo variables from outputs.
- **AC↔:** AC-3, AC-6 (out-of-scope/operator section)
- **Foundation:** `docs/github-ci-bootstrap-stack.md:78-152`,
  `configure_github_repository_controls.py` `--dry-run`/`--apply`.
- **Verify:** Doc presence test asserts the runbook section exists and enumerates each operator
  step with a command/payload reference; each step is explicitly tagged operator-only.

---

## F. `user-service-infrastructure` creation + self-deploy wiring

### FR19 — `user-service-infrastructure` scaffolding + self-deploy workflow templates
**[CODE deliverable now: templates/scaffold + catalog entry; OPERATOR: repo create + git push]**
The increment SHALL deliver, as in-repo template assets, the generic infra scaffolding for
`user-service-infrastructure` (its own `pulumi/` skeleton + `Pulumi.test.yaml`/`Pulumi.prod.yaml`)
and a self-deploy workflow that assumes the governance-provided OIDC roles. The repo SHALL be
present in the governance catalog. Creating the repo in `VilnaCRM-Org` and the actual `git push`
are OPERATOR steps (documented per FR18).
- **AC↔:** AC-6
- **Foundation:** `repositories.example.json:4-12` (metadata already present);
  `pulumi/repositories.bootstrap.json`; existing per-repo workflow/action patterns
  (`./.github/actions/load-aws-ci-env`).
- **Verify:** Asset-presence test asserts the scaffold templates + self-deploy workflow template
  exist and reference the governance-provided role ARNs/secret pattern; catalog test
  (`scripts/validate_repository_catalogs.py`) passes with `user-service-infrastructure` active.

### FR20 — Self-deploy wiring uses bootstrap-provided roles only (no admin creds)
**[CODE]** The `user-service-infrastructure` self-deploy workflow template SHALL assume only the
governance-provided OIDC deploy/preview/apply/drift roles (via the CI-config secret), never
embed long-lived or admin credentials, and route applies through the IaC-only saved-plan path.
- **AC↔:** AC-6, AC-5
- **Foundation:** CI-config secret payload shape (`ci_bootstrap.py:642-726`), `load-aws-ci-env`
  action, `run_pulumi_command.py` saved-plan path.
- **Verify:** Template lint/test asserts the workflow references OIDC role assumption (no static
  AWS keys, no `AdministratorAccess`) and uses the `up-plan` apply path; gitleaks finds no
  embedded secrets.

---

## G. Least privilege + secret-deny + account-model correction

### FR21 — Account-model correctness (two accounts)
**[CODE]** The system uses **TWO** AWS accounts: test `891377212104`, prod `933245420672`; the
`test`/`prod` Pulumi stacks deploy to **separate** accounts (cross test↔prod isolation by separate
accounts). Component code SHALL carry **no** hardcoded account-number literals — it is
account-parametric via `aws.get_caller_identity().account_id` + `{account_id}` interpolation. Each
stack SHALL assert its live account equals its configured `awsAccountId`. Account literals appear
ONLY in per-stack Pulumi config (`Pulumi.test.yaml`→`891377212104`,
`Pulumi.prod.yaml`→`933245420672`). The live config (`pulumi/Pulumi.prod.yaml` cost-anomaly ARN in
`933245420672`, `docs/github-ci-bootstrap-stack.md:75-76`) is already two-account-correct and is left
as-is.
- **AC↔:** AC-1 (correct account substrate for all governance resources)
- **Foundation:** research R1 (resolved 2026-06-13: two-account model is correct;
  `Pulumi.prod.yaml` cost-anomaly ARN `933245420672`, `docs/github-ci-bootstrap-stack.md:75-76`
  already two-account-correct).
- **Verify:** A test asserts no account-number literal appears in component Python under
  `pulumi/infra/*.py`; the test stack config pins `891377212104` and the prod stack config pins
  `933245420672`; if `costAnomalyMonitorArn` is present its account matches its stack's account
  (test→`891377212104`, prod→`933245420672`).

### FR22 — Full secret-read deny set on read-only / config-read roles
**[CODE]** The read-only and config-read roles SHALL carry an explicit `Effect: Deny` for the full
secret-leaking surface: `secretsmanager:GetSecretValue`, `kms:Decrypt`, `ssm:GetParameter*`,
`lambda:GetFunction`, `ec2:GetPasswordData`, `*:GetAuthorizationToken` (incl.
`ecr:GetAuthorizationToken`), `sts:GetSessionToken`, `cognito-identity:Get*`. This deny SHALL NOT
be attached to the apply/deploy backend roles (which legitimately need `kms:Decrypt`).
- **AC↔:** AC-7
- **Foundation:** today only `secretsmanager:GetSecretValue` is denied
  (`ci_bootstrap.py:355-380`, verified `_read_only_policy_document`); read-only ALLOW list
  currently includes `kms:Get*`/`ecr:Get*` (`:73-74,82-84`) — Deny wins (research R3).
- **Verify:** Unit test asserts every deny action is present in the read-only/config-read policy
  documents AND absent (as a deny) from apply/deploy backend policies; a regression test asserts
  the apply role retains its needed `kms:Decrypt` on the secrets key.

### FR23 — No wildcard `Allow` on deployment roles; Access Analyzer + CrossGuard clean
**[CODE]** No governance deployment role policy SHALL contain a wildcard `Allow` (`Action:*` or
unscoped `Resource:*` outside the CrossGuard-exempt allowlist). Every governance role/policy SHALL
pass IAM Access Analyzer validation (no `ERROR`/`SECURITY_WARNING`) and CrossGuard
`iam-no-wildcards`.
- **AC↔:** AC-7
- **Foundation:** CrossGuard `wildcard_iam_violations` flags only `Effect == "Allow"` wildcards,
  exempting `Deny` (`policy/guardrails.py:711-727`); unscopable `Resource:*` allowlist
  (`:580-601`); IAM validation via `scripts/pulumi_ci_guardrails.py validate-iam`
  (research §5.1 — note: NOT `validate_iam_policies.py`).
- **Verify:** `make test-policy` (CrossGuard) reports zero `iam-no-wildcards` violations on
  governance roles; `pulumi_ci_guardrails.py validate-iam` over the governance preview files
  reports zero `ERROR`/`SECURITY_WARNING`; a unit test scans deploy-role documents for any
  `Effect:Allow` wildcard and fails if found.

---

## H. Tests + quality (cross-cutting)

### FR24 — Test coverage of the governance contract
**[CODE]** Unit + structural + policy tests SHALL cover: per-repo trust scopes, policy contents,
naming determinism, generic repo expansion (fan-out for N repos), cross-repo isolation, the
CODEOWNERS scoping, the author-gate decision matrix, the governance-environment payload, and the
IaC-only apply rejection.
- **AC↔:** AC-8
- **Foundation:** session-scoped Pulumi mocks (`tests/conftest.py:33-58`); existing component
  tests (`tests/unit/test_components.py`), structural tests (`tests/pulumi/`).
- **Verify:** New tests exist for each listed concern and pass; structural assertions for the new
  project shape are updated in lockstep (research R6).

---

## Non-Functional Requirements

### NFR1 — 100% combined coverage maintained
**[CODE]** New code under `pulumi/` and `policy/` SHALL maintain 100% combined branch coverage.
- **AC↔:** AC-8
- **Verify:** `make test-coverage` (combined `pulumi/` + `policy_pack/`) reports 100% (research
  R7 — coverage cliff is enforced; `AGENTS.md:21`, `Makefile:234`).

### NFR2 — Mutation tests pass on new logic
**[CODE]** New governance/policy logic SHALL withstand the mutation-testing gate.
- **AC↔:** AC-9
- **Verify:** `make test-mutation` passes for the changed modules.

### NFR3 — Strict static-analysis suite green
**[CODE]** All changes SHALL pass ruff (format + lint, `max-complexity ≤ 12`), mypy, ty (Astral,
strict None-narrowing), import-linter, deptry, bandit, pip-audit, gitleaks.
- **AC↔:** AC-9
- **Verify:** `make ci-pr` is green; `ruff` reports no complexity > 12; import-linter contracts
  (`app`/`policy`) unbroken (research R8 notes `infra` is not currently contract-governed —
  architect to confirm whether to add one).

### NFR4 — CrossGuard policy pack green
**[CODE]** Every governance resource SHALL satisfy the registered CrossGuard policies, including
the MANDATORY `iam-no-wildcards`, required-default-tags, region-allowlist (eu-central-1),
s3-no-public-exposure, critical-storage-encrypted, logging-enabled.
- **AC↔:** AC-7, AC-9
- **Verify:** `make test-policy` reports zero violations (`policy/pack.py:171-216`).

### NFR5 — Least-privilege evidence preserved (no escape hatches)
**[CODE]** Governance roles SHALL NOT use the CrossGuard wildcard escape hatches
(`wildcard_iam_allowlist`, `AllowWildcardIam` tags) — least privilege achieved by scoping, not
suppression.
- **AC↔:** AC-7
- **Verify:** Policy scan asserts no governance role appears in the wildcard allowlist and carries
  no `AllowWildcardIam` tag (research §5.2).

### NFR6 — Backward compatibility for the existing bootstrap consumer
**[CODE]** Generalizing `GitHubCiBootstrap`/`CiConfiguration` SHALL NOT regress the existing
single-repo `bootstrap-infrastructure` behavior (role names, trust, secrets); the account-model
correctness work (FR21) keeps component code account-parametric and does not change account
references in the live two-account config.
- **AC↔:** AC-1
- **Verify:** Existing foundation tests (`tests/unit/test_components.py`,
  `tests/pulumi/test_project_structure.py`) still pass after generalization, updated only where
  the project-shape change requires (research R6).

### NFR7 — Determinism / idempotency
**[CODE]** Resource names and policy documents SHALL be deterministic (sorted keys, deterministic
naming helpers) so repeated previews/plans produce stable diffs and saved plans validate.
- **AC↔:** AC-5, AC-8
- **Verify:** Snapshot/diff tests assert identical rendered policy JSON across runs;
  `run_pulumi_command.py` saved-plan hash validation (`:357-375`) succeeds.

### NFR8 — Secrets handling
**[CODE]** No long-lived AWS credentials or secret values SHALL be committed; secrets-provider
SHALL be `awskms://`; CI-config secret values written only when explicitly enabled.
- **AC↔:** AC-5, AC-7
- **Verify:** gitleaks clean; `_validate_secrets_provider` (`run_pulumi_command.py:92-105`)
  enforces `awskms://`; secret-version writes gated on `write_secret_values`
  (`ci_bootstrap.py:736-737`).

---

## Traceability matrix (AC → requirements)

| Issue #77 AC | Requirements |
|---|---|
| **AC-1** Generic governance project (full least-privilege set, config-only add) | FR1, FR2, FR3, FR4, FR5, FR6, FR7, FR9, FR21, NFR6 |
| **AC-2** Works for any `*-infrastructure` repo / new repos, config-only | FR1, FR2, FR8 |
| **AC-3** Kravalg-only approval (CODEOWNERS + protected env) | FR10, FR11, FR12, FR18 |
| **AC-4** PR-comment deploy gating (Kravalg, test→prod, success before merge) | FR12, FR13, FR14, FR15 |
| **AC-5** IaC-only apply (reject direct `up`; OIDC sole apply path) | FR16, FR20, NFR7, NFR8 |
| **AC-6** `user-service-infrastructure` created + self-deploy | FR17, FR19, FR20, FR18 |
| **AC-7** Least privilege verified (Access Analyzer + CrossGuard, no wildcard Allow, secret denies) | FR3, FR22, FR23, NFR4, NFR5, NFR8 |
| **AC-8** Tests cover trust/policy/naming/expansion/gating; 100% coverage | FR24, NFR1, NFR2, NFR7 |
| **AC-9** Full quality suite green | NFR1, NFR2, NFR3, NFR4 |

## Deliverability split (this increment)

| Deliverable now (CODE — no live creds) | Operator-only (AWS admin / GitHub org-admin) |
|---|---|
| Governance project + per-repo loop (FR1–FR9), account-model correctness — two accounts (FR21) | One-time `AdministratorAccess` bootstrap apply, test then prod (runbook in FR18) |
| CODEOWNERS (FR10), governance-env payload + dry-run (FR11), runner env wiring (FR12) | Live `PUT` of branch protection + protected `governance` environment reviewer (FR11) |
| Author/path gate (FR13, FR14), test→prod required-check wiring (FR15) | — |
| IaC-only CI wiring (FR16) | — |
| AGENTS.md onboarding flow + operator runbook (FR17, FR18) | — |
| `user-service-infrastructure` scaffold/templates + catalog entry + self-deploy template (FR19, FR20) | Create repo in `VilnaCRM-Org` + actual `git push`; set GitHub repo variables (runbook in FR18) |
| Secret-deny set (FR22), no-wildcard validation (FR23), all tests (FR24), all NFRs | Real AWS applies + capturing real ARNs/outputs |

## Architect decisions still open (carried from research §8)

1. Account-model correctness — keep component code account-parametric across the two accounts
   (test `891377212104`, prod `933245420672`) (R1 / FR21).
2. New project dir vs. multi-repo *mode* of the existing bootstrap project (FR9).
3. Whether to unify `PulumiDeploy-*` onto the stronger bootstrap trust shape (R2) and how to
   handle import/replace.
4. Exact CODEOWNERS path globs (R4 / FR10) — must hit governance/IAM only.
5. Author-gate mechanism: changed-path compute + `--author-login` vs. environment-reviewer only
   (FR13/FR14).
6. Whether new governance `infra` code gets its own import-linter contract (R8 / NFR3).
