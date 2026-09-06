# Architecture — Multi-Repo IAM/OIDC Governance Stack

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

**Phase:** 3 — Solutioning (BMAD Architect)
**Source of truth:** GitHub issue [#77](https://github.com/VilnaCRM-Org/bootstrap-infrastructure/issues/77) (AC-1..AC-9)
**Inputs:** `_bmad-output/planning-artifacts/research.md`, `_bmad-output/planning-artifacts/prd.md`
**Base branch:** `feat/multi-repo-governance` (off `codex/issue59-github-ci-bootstrap-stack`, PR #60)

This document is the implementable design. Every component has exact file paths, class
names, dataclass fields, constructor signatures, and JSON shapes so an implementer (Ralph)
can build without re-deciding. It **extends** `GitHubCiBootstrap` + `CiConfiguration`; it
does not redesign from scratch. All `file:line` anchors trace to current code on this branch.

---

## 0. Resolved decisions (closing research §8 / PRD open items)

| # | Open question | Decision |
|---|---|---|
| D1 | Account model (R1) | **Two accounts, region `eu-central-1`: the `test` stack asserts/deploys account `891377212104`, the `prod` stack asserts/deploys account `933245420672`.** `awsAccountId` is per-stack config; the component asserts `aws.get_caller_identity().account_id == configured awsAccountId` (no hardcoded literal in component code). Cross test↔prod blast radius is isolated by separate accounts (AWS best practice). The per-env KMS alias suffix (`-test`/`-prod`) and per-stack secrets providers are retained. |
| D2 | Project shape (FR9) | **New separate Pulumi project `pulumi/governance/`**, parity with `pulumi/github-ci-bootstrap/`. The existing bootstrap project is left intact for backward compat (NFR6). The new project hosts a multi-repo loop built from the **same generalized component code** in `pulumi/infra/`. |
| D3 | Trust unification (R2) | **Do NOT migrate the weak `PulumiDeploy-*` roles.** The governance project emits the *strong* trio (`GitHubCiPreview/Apply/Drift-*`) per repo using the bootstrap trust shape (`StringEquals` + `repository` pin + per-suffix subjects). `PulumiDeploy-*` is untouched (avoids import/replace churn). |
| D4 | Deny scoping (R3) | The shared read-only secret-read **Deny** attaches to `read-only` (preview/drift) and `config-read` policy documents; apply roles carry the separate surgical `DenySecretLeakingReadsApply` described in §5.2a. `kms:Decrypt` is **excluded from the `read-only` Deny** because preview/drift roles also carry the pulumi-backend policy's alias-scoped `kms:Decrypt` Allow (needed to decrypt the stack's encrypted config during `pulumi preview`/drift); a broad `kms:Decrypt` Deny would override that Allow and break preview/drift on encrypted-secret stacks. The apply role and the pulumi-backend policy likewise keep `kms:Decrypt`. Config-read uses separate conditional Decrypt Denies requiring both the regional Secrets Manager service and the exact owned CI-secret encryption context; it adds no KMS Allow. |
| D5 | CODEOWNERS precision (R4) | Exact globs in §7.1 scope **only** governance/IAM/policy paths to `@Kravalg`; no catch-all `*` line, so unrelated paths stay unowned. |
| D6 | Author-gate mechanism (FR13/FR14) | **Both layers, defense-in-depth:** (a) path-aware + login-aware gate in `scripts/pulumi_pr_comment.py` rejects `up` from the sole reviewer `@Kravalg`; the trusted runner independently verifies that the original requester still has repository write permission; (b) governance apply jobs declare `environment: governance` so the protected-environment reviewer gate is the hard backstop. |
| D7 | Import isolation (R8) | **Implemented split:** `infra` is a root package; Import Linter forbids `infra.governance` from `policy`/`app`. `tests/pulumi/test_governance_import_isolation.py` separately checks the AST for `policy`/`app`/`scripts`; CLI `scripts` is intentionally outside the import graph. Preserve the documented AST-only fallback for graphing failures (§9.4). |

---

## 1. Component & file map (what changes, what is new)

```
pulumi/
  governance/                          # NEW Pulumi project (D2)
    Pulumi.yaml                        # NEW  name: governance
    Pulumi.test.yaml                   # NEW  env=test, account 891377212104
    Pulumi.prod.yaml                   # NEW  env=prod, account 933245420672
    Pulumi.example.yaml                # NEW  non-discovered example (structural test parity)
    __main__.py                        # NEW  builds GovernanceStack from config
  infra/
    governance.py                      # NEW  GovernanceStack + RepoGovernance components
    ci_bootstrap.py                    # CHANGED  lift helpers to module-level reuse (no behavior change for single-repo)
    ci_config.py                       # CHANGED  add full secret-read Deny to read policy (config-read); accept repo override
    bootstrap_settings.py              # CHANGED  add repo-scoped role-name + secrets-alias helpers (additive)
    __init__.py                        # CHANGED  export GovernanceStack, GovernanceStackArgs, RepoGovernance
  repositories.governance.json         # NEW  governance catalog (active list) — config-only repo add (FR1/FR8)
  user-service-infrastructure/         # NEW  scaffold template assets (FR19) — see §8
    pulumi/Pulumi.yaml
    pulumi/Pulumi.test.yaml
    pulumi/Pulumi.prod.yaml
    pulumi/__main__.py
    .github/workflows/self-deploy.yml
    AGENTS.md
    README.md
policy/                                # unchanged (CrossGuard already correct)
scripts/
  pulumi_pr_comment.py                 # CHANGED  add --author-login + --governance-paths-touched gate (FR13)
  _github_repository_controls.py       # CHANGED  add governance_environment_payload + verification blockers (FR11)
  configure_github_repository_controls.py  # CHANGED  emit + apply governance environment (FR11)
.github/
  CODEOWNERS                           # NEW  scope governance/IAM/policy to @Kravalg (FR10)
  workflows/
    pulumi-pr-commands.yml             # CHANGED  compute changed paths, pass author login (FR14)
    pulumi-pr-command-runner.yml       # CHANGED  governance apply jobs add environment: governance (FR12)
    pulumi-governance.yml              # NEW  CI wiring for PULUMI_DIR=pulumi/governance plan/up-plan (FR16)
AGENTS.md                             # CHANGED  add onboarding flow + operator runbook (FR17/FR18)
docs/
  governance-stack.md                 # NEW  design + operator runbook (FR18)
  github-ci-bootstrap-stack.md         # unchanged (already two-account-correct, FR21)
tests/
  unit/test_governance.py              # NEW  per-repo trust/policy/naming/isolation (FR24)
  unit/test_pr_comment_gate.py         # CHANGED/NEW  author-gate matrix (FR13)
  unit/test_repository_controls.py     # CHANGED  governance env payload (FR11)
  pulumi/test_project_structure.py     # CHANGED  assert governance project shape (R6)
  unit/test_codeowners.py              # NEW  CODEOWNERS scoping (FR10)
```

The design principle: **all reusable logic lives in `pulumi/infra/`**; the two project
entrypoints (`github-ci-bootstrap/__main__.py`, `governance/__main__.py`) are thin. The
governance project is the bootstrap component lifted into a per-repo loop.

---

## 2. Pulumi project layout, stack model, config shape (FR1, FR9)

### 2.1 Project

`pulumi/governance/Pulumi.yaml`:
```yaml
name: governance
runtime:
  name: python
description: Kravalg-gated multi-repo IAM/OIDC governance stack for *-infrastructure repos.
```

### 2.2 Stacks (two accounts, test/prod as stacks — D1)

`pulumi/governance/Pulumi.test.yaml` (the `test` stack, account `891377212104`):
```yaml
config:
  aws:region: eu-central-1
  governance:githubOrg: VilnaCRM-Org
  governance:environment: test
  governance:githubBranch: main
  governance:owner: platform
  governance:costCenter: core
  governance:dataClassification: internal
  governance:criticality: high
  governance:retentionClass: standard
  governance:loggingPrefix: company
  governance:awsAccountId: "891377212104"           # per-stack: test account (FR21)
  governance:githubOidcProviderArn: arn:aws:iam::891377212104:oidc-provider/token.actions.githubusercontent.com  # consumed, never created (AWS-SRE-2); per-account, sourced from this account's bootstrap stack output
  governance:repositoryCatalogPath: ../repositories.governance.json
  governance:replicationRegion: eu-west-1            # pin explicitly (AWS-SRE non-blocking: do not rely on DEFAULT_REPLICATION_REGION)
  governance:pulumiSecretsProvider: awskms://alias/pulumi-platform-bootstrap-test?region=eu-central-1
  governance:writeSecretValues: "true"
  governance:protectResources: "true"
secretsprovider: awskms://alias/pulumi-platform-bootstrap-test?region=eu-central-1
```

`pulumi/governance/Pulumi.prod.yaml` (the `prod` stack, **separate** account `933245420672`) mirrors
the test stack with `environment: prod` and the prod-account values:
```yaml
config:
  aws:region: eu-central-1
  governance:environment: prod
  governance:awsAccountId: "933245420672"           # per-stack: prod account (FR21)
  governance:githubOidcProviderArn: arn:aws:iam::933245420672:oidc-provider/token.actions.githubusercontent.com  # consumed, never created; this account already owns its own provider
  governance:pulumiSecretsProvider: awskms://alias/pulumi-platform-bootstrap-prod?region=eu-central-1
  # …all other governance:* keys as in the test stack…
secretsprovider: awskms://alias/pulumi-platform-bootstrap-prod?region=eu-central-1
```
The account-assertion value (`governance:awsAccountId`) is **per-stack**: test→`891377212104`,
prod→`933245420672`. The literal lives only in these stack config files, never in component code.

**Governance stack's own backend.** Each environment uses the existing bootstrap state
bucket at exactly `s3://pulumi-bootstrap-infrastructure-{env}-state/governance`.
The platform backend remains under `/state/{env}`. The governance checkpoint uses
`awskms://alias/pulumi-platform-bootstrap-{env}?region=eu-central-1`; this state
backend and platform KMS alias are not granted to service repositories. Dedicated
governor principals receive only their purpose-specific governance backend access.
The separate per-repository buckets and keys are service-owned resources.

Key shape decisions:
- The managed repo list is configured via **`governance:repositoryCatalogPath`** pointing at
  `pulumi/repositories.governance.json` (reuses `ManagedRepositoryCatalog.from_settings`
  resolution order, `repository_catalog.py:101-131`). Adding a repo = edit JSON only (FR1/FR8).
- No `repoSlug` key — the governance project is intentionally multi-repo. The catalog's
  `repository_catalog_path` branch resolves before the `repo` fallback, so this is clean.
- `awsAccountId` is read by the stack purely for **assertion** (the component validates the
  live `aws.get_caller_identity().account_id` equals the configured one and raises otherwise)
  — this enforces D1 at apply time without trusting the operator's shell. The value is **per-stack**
  (test→`891377212104`, prod→`933245420672`); the literal lives in stack config, never in component
  code, so each stack asserts it is running in its own account.

### 2.3 Governance catalog file

`pulumi/repositories.governance.json` (initial active content):
```json
{
  "$schema": "./repositories.schema.json",
  "repositories": [
    { "name": "user-service-infrastructure", "defaultBranch": "main", "project": "user-service-infrastructure", "owner": "team-user-service", "lifecycleState": "active", "lastReviewed": "2026-06-13", "expectedEnvironments": 2 }
  ]
}
```
**`bootstrap-infrastructure` is excluded from the governance catalog (closes AWS-SRE double-management
non-blocking).** It self-manages via the existing `github-ci-bootstrap` project (D2 keeps that
project intact). If the governance stack also listed `bootstrap-infrastructure`, two Pulumi stacks
would both try to import/manage the SAME IAM role names (`GitHubCi*-bootstrap-infrastructure-*`) and
the same CI secret for that repo — a guaranteed import/ownership collision. The governance catalog
therefore governs only the *other* `*-infrastructure` service repos. `project` is set to the full
slug `user-service-infrastructure` to match the canonical naming source (§4). This is documented in
§8 onboarding and the runbook (§10): `bootstrap-infrastructure` is never added to
`repositories.governance.json`.
Schema `pulumi/repositories.schema.json` already validates this shape (no schema change).
`scripts/validate_repository_catalogs.py` discovers `repositories*.json` by glob, so the new
file is auto-validated; the per-env fanout numbers (§9.2) are extended for the trio.

---

## 3. Generalized Python components (FR1–FR8)

### 3.1 Refactor `ci_bootstrap.py` — lift to a per-repo build path (no behavior change)

The bootstrap's role/policy logic is currently coupled to a single `settings.repo`. We make the
**repo a parameter** of the pure helpers while keeping the existing single-repo entrypoint
working (NFR6). Concretely, add a small immutable context and re-point the existing helpers at it.

New module-level dataclass in `pulumi/infra/ci_bootstrap.py`:
```python
@dataclass(frozen=True)
class _RepoCiContext:
    """Per-repo inputs for the generalized CI role/policy helpers."""
    settings: BootstrapSettings   # stack-level settings (org, env, tags, branch)
    repo: str                     # the specific *-infrastructure repo being governed
    project: str                  # repo.project_name (CI secret/role naming root)
    account_id: str
    partition: str
    region: str
```

Change these existing functions to take `_RepoCiContext` (or an explicit `repo`/`project`)
instead of reading `settings.repo`, **preserving identical output for the single-repo case**:
- `_ci_role_name(settings, purpose)` → `_ci_role_name(ctx, purpose)` using `ctx.project`
  (today it uses `_ci_config_project(settings)`; for the existing project `ctx.project ==
  _ci_config_project(settings)` so names are byte-identical).
- `_repo_subject`, `_deployment_role_subjects`, `_state_bucket_resources`,
  `_pulumi_backend_policy_document`, `_role_policy_documents`, `_role_specs`, `_create_role`,
  `_create_roles` — thread `repo`/`project` through. The single-repo entrypoint builds one
  `_RepoCiContext` from `settings.repo`; the governance loop builds one per catalog repo.
- `_state_bucket_resources` switches `settings.state_bucket_name()` →
  `settings.state_bucket_name_for_repo(ctx.repo)` (already exists, `bootstrap_settings.py:220`).
- `_pulumi_secrets_alias_conditions` becomes repo-scoped: for a **governance-managed service repo**
  it accepts **only** `alias/pulumi-{repo}-{env}-secrets` — and **NOT**
  `alias/pulumi-platform-bootstrap-{env}` (closes AWS-SRE-1). The platform-bootstrap key encrypts
  the governance/bootstrap stack's OWN state (the most sensitive object in the account — it holds
  the encrypted CI-config material for every managed repo). Granting every service repo's
  preview/apply/drift roles `kms:Decrypt` on that alias would mean a compromise of any one repo's
  OIDC trust yields decrypt of the platform master key — exactly the cross-repo blast radius FR3
  forbids. So the platform-bootstrap alias is reserved for the **governance stack's own apply role
  only** (the operator/governance principal that backs the governance stack), and is removed from
  per-repo deploy policies entirely. This is a behavior change for the helper's *governance* call
  site; the single-repo bootstrap entrypoint keeps a `platform_bootstrap=True` flag for byte-identical
  back-compat (the existing `bootstrap-infrastructure` stack legitimately uses the platform key as
  its own backend). Signature: `_pulumi_secrets_alias_conditions(repo, env, *, include_platform_bootstrap: bool)`;
  governance service-repo loop passes `include_platform_bootstrap=False`, the single-repo bootstrap
  entrypoint passes `True`. FR3 verify is amended: assert **no** service repo's deploy doc references
  `pulumi-platform-bootstrap` at all.

Backward-compat guard: keep `_require_repo` and the existing `GitHubCiBootstrap.__init__`
signature; it constructs a single `_RepoCiContext` internally. Existing tests in
`tests/unit/test_components.py` continue to pass (NFR6) — the rename is internal.

**NFR6 parity is enforced by a concrete golden snapshot, not a vague "tests unchanged" claim
(closes FEASIBILITY-4).** Before the refactor, E1.S2 captures a golden fixture of the current
single-repo `bootstrap-infrastructure` output: the rendered role **names** (preview/apply/drift +
config-read + automation role), the rendered **trust JSON** per role, the **backend/read-only/apply
policy JSON**, and the `Repository` tag value (derived via `_ci_config_project(settings)` — which
MUST NOT change). After the refactor the same render is asserted **byte-equal** to the golden. This
parity fixture is the gating artifact for E1.S2–E1.S4 (named explicitly in the story), not just
"`test_components.py` unchanged". The parity test explicitly covers the two easy-to-miss surfaces:
`_automation_policy_documents(account_id, settings, repo)` at the apply branch
(`ci_bootstrap.py:442`) and the `Repository`-tag derivation.

**Single context, not two (closes FEASIBILITY-4 dual-context risk).** `_BootstrapBuildContext`
already exists and carries `settings`. To avoid two overlapping context objects, **extend the
existing `_BootstrapBuildContext`** with `repo: str` and `project: str` fields (single source of
truth) rather than introducing a parallel `_RepoCiContext`. Where the spec above says
`_RepoCiContext`, the implementer MAY instead add the two fields to `_BootstrapBuildContext` — the
governance loop constructs one per catalog repo, the single-repo entrypoint constructs one from
`settings.repo`. The helpers read `context.repo`/`context.project`. `_create_role` (which reads
`context.settings.repo` at lines 482/489/508) is re-pointed to `context.repo`. Either spelling is
acceptable provided there is exactly ONE context type threaded through the chain; the golden parity
test is the gate.

### 3.2 New `pulumi/infra/governance.py`

Two public classes plus a small args dataclass.

```python
@dataclass(frozen=True)
class GovernanceStackArgs:
    settings: BootstrapSettings | None = None      # from_pulumi_config in __main__
    repository_catalog: ManagedRepositoryCatalog | None = None  # resolved from settings/cfg
    expected_account_id: str | None = None         # governance:awsAccountId (D1 assertion)
    oidc_provider_arn: str | None = None           # consumed by .get(), never created (AWS-SRE-2)
    region: str = "eu-central-1"                    # injectable so tests use the mock region (AWS-SRE-5)
    pulumi_dir: str = "pulumi"                      # PULUMI_DIR injected into CI secret payloads
    pulumi_backend_url: str | None = None
    pulumi_secrets_provider: str | None = None
    write_secret_values: bool = True
    protect_resources: bool = True


class RepoGovernance(pulumi.ComponentResource):
    """All governance AWS resources for ONE managed *-infrastructure repo."""
    # type token: "bootstrap:governance:RepoGovernance"
    def __init__(
        self,
        name: str,                                 # f"{stack_name}-{repo_suffix}"
        *,
        repo: ManagedRepository,
        settings: BootstrapSettings,
        provider_arn: pulumi.Input[str],           # shared account OIDC provider (FR7)
        account_id: str,
        partition: str,
        region: str,
        pulumi_dir: str,
        pulumi_backend_url: str | None,
        pulumi_secrets_provider: str | None,
        write_secret_values: bool,
        protect_resources: bool,
        opts: pulumi.ResourceOptions | None = None,
    ) -> None: ...


class GovernanceStack(pulumi.ComponentResource):
    """Account OIDC provider (once) + RepoGovernance per managed repo."""
    # type token: "bootstrap:governance:GovernanceStack"
    def __init__(
        self,
        name: str,
        *,
        args: GovernanceStackArgs | None = None,
        opts: pulumi.ResourceOptions | None = None,
    ) -> None: ...
```

`GovernanceStack.__init__` flow:
1. Resolve `account_id = aws.get_caller_identity().account_id`; if `args.expected_account_id`
   is set and differs, `raise ValueError("governance stack must run in account ...")` (D1).
   **Mock seam (closes AWS-SRE-5 / FEASIBILITY-3).** The session Pulumi mocks resolve
   `get_caller_identity` to account `123456789012` and region `us-east-1` (`tests/conftest.py`
   `TestMocks.call`), and there is no mock for account `891377212104`. To exercise BOTH branches at
   100% coverage without the real-value path being unreachable:
   - `expected_account_id` is **injectable** via `GovernanceStackArgs` (already is). Tests drive the
     **match** branch by passing `expected_account_id="123456789012"` (the mock's account) → proceeds;
     and the **mismatch** branch by passing any other value → raises. Both are covered.
   - `region` is **injectable** via `GovernanceStackArgs.region` (added) and threaded into every
     rendered ARN/secrets-provider, so happy-path tests pass the mock's region and don't assert a
     hardcoded `eu-central-1` that the mock never produces. Policy ARNs use `{account_id}`/`{region}`
     interpolation (§5.2), never a literal `891377212104`/`eu-central-1`, so documents are
     mock-renderable.
   - The **real** account assertion still fires at apply time because the live stack config sets
     `governance:awsAccountId` **per-stack** (test→`891377212104`, prod→`933245420672`) and
     `get_caller_identity` returns the real account — the literal lives in stack config, NOT in
     component code.
   - Extend `tests/conftest.py` `call()` only if a test needs to drive the assertion against a real
     account value (optional fixture override); the injectable-`expected_account_id` approach
     above is the primary seam and requires no conftest change. E1.S4 / E6.S2 test cases explicitly
     add: `expected_account_id == mocked account → proceeds (non-raise branch covered)`.
2. **Consume the per-account OIDC provider by ARN — never create/adopt (closes AWS-SRE-2).** The OIDC
   provider is **per-account**: each account has exactly ONE OIDC provider per URL
   (`token.actions.githubusercontent.com`) — the test account `891377212104` owns its provider, the
   prod account `933245420672` owns its own — and the existing `github-ci-bootstrap` project (run per
   account) already owns each. So the test governance stack consumes
   `arn:aws:iam::891377212104:oidc-provider/...` and the prod governance stack consumes
   `arn:aws:iam::933245420672:oidc-provider/...`. If the governance stack instead called
   `GitHubOidcRoles(..., repositories=[])` (which creates-or-adopts), two independent Pulumi state
   files would reference the same physical provider — whichever stack last refreshes mutates the
   other's `thumbprint_lists`/`client_id_lists`, and a destroy in one orphans the other; on a clean
   account the two stacks race to CREATE and the second hits `EntityAlreadyExists`. Resolution:
   - The **bootstrap stack is the sole owner** of each account's provider.
   - The governance stack **always consumes its account's provider by a pinned ARN**: a per-stack
     config key `governance:githubOidcProviderArn` is set in `Pulumi.test.yaml` (the 891 provider) /
     `Pulumi.prod.yaml` (the 933 provider), sourced from that account's bootstrap stack
     `oidcProviderArn` output, and passed into the loop as
     `GovernanceStackArgs.oidc_provider_arn`. `GovernanceStack` calls
     `aws.iam.OpenIdConnectProvider.get(f"{name}-oidc", id=oidc_provider_arn)` (or
     `GitHubOidcRoles` is given the ARN and uses its existing `.get()` adopt-by-explicit-ARN branch,
     `github_oidc.py:52-62`) — **zero create branch** in the governance project. `repositories=[]`
     stays (no per-repo `PulumiDeploy-*`), but the provider itself is never registered for creation.
   - If `governance:githubOidcProviderArn` is unset, the stack **raises** (it must not fall back to
     create). The operator runbook (§10) adds a step: read `oidcProviderArn` from the bootstrap
     stack output and set it in the governance stack config before the first governance apply.
   - **Structural test (E6.S1):** assert the governance project registers **no**
     `aws.iam.OpenIdConnectProvider` *create* (only `.get`). FR7 verify is amended accordingly:
     exactly one provider per account, owned by that account's bootstrap stack, consumed by
     governance via `.get()`.
3. For each `repo in repository_catalog.repositories`, instantiate one `RepoGovernance` with
   `provider_arn=oidc.provider.arn`. Collect outputs keyed by `repo.name`.
4. `register_outputs` a stable mapping (see §3.4).

`RepoGovernance.__init__` builds, per repo (each parented to this component):
- **Per-repo S3 state bucket + replica** via `PulumiStateBuckets` with a single-repo catalog
  (`pulumi/infra/pulumi_state.py:289`), name `pulumi-{repo}-{env}-state` (FR5).
- **Per-repo KMS key + alias** via `PulumiSecretsKeys` with the same single-repo catalog
  (`pulumi/infra/pulumi_secrets.py:66`), alias `alias/pulumi-{repo}-{env}-secrets` (FR6).
- **Per-repo CI-config secret(s) + config-read role(s)** via `CiConfiguration` (FR4), now with
  a `repo` override (§3.3) so naming uses this repo, not `settings.repo`.
- **The preview/apply/drift trio** via the lifted `_create_roles(_role_specs(...))` from
  `ci_bootstrap.py`, passing a `_RepoCiContext` for this repo (FR2, FR3).
  - Deploy/backend policy scoped to **this repo's** bucket ARN + this repo's KMS alias only.
  - Service `apply` receives only `pulumi-backend` and `secret-read-deny` from
    `_governance_policy_documents`; it inherits no platform automation or IAM
    administration grants. Additional workload capabilities need explicit reviewed
    permissions and operator-owned boundary extensions (FR3, FR23).
- **No `OperationsAlertTriage-*`** here. That role is bootstrap-only and tied to the platform
  account's operations pipeline; governance repos do not own operations triage. (The
  `_payloads` test-environment branch that *requires* the triage ARN is replaced by a
  governance payload builder, §3.5.)

The per-repo component name is derived with the existing `_repo_suffix(repo.name, settings)`
helper (`github_oidc.py:64-75`) so suffixes stay unique and deterministic across the loop.

### 3.3 `ci_config.py` changes (repo override + full Deny)

- Add an optional `repo: str | None` to `CiConfigurationArgs`. When set, `_ci_config_project`
  uses it instead of `settings.repo`; the per-suffix trust subjects and secret IDs become
  repo-scoped (`/{repo-project}/ci/{suffix}`). When `None`, behavior is unchanged (NFR6).
- Add the **full secret-read Deny** to `_ci_config_read_policy` as a second statement (FR22).
  The config-read role legitimately needs `secretsmanager:GetSecretValue` on **its own** CI
  secret ARN (the `Allow`), so the Deny here targets the *other* leaky reads only; do **not**
  deny `secretsmanager:GetSecretValue` in the config-read policy (it would override its own
  Allow — Deny wins). The general config-read Deny set excludes `kms:Decrypt` and starts with `ssm:GetParameter*`,
  `lambda:GetFunction`, `ec2:GetPasswordData`, `*:GetAuthorizationToken`, `sts:GetSessionToken`,
  `cognito-identity:Get*` (see §5.3). `secretsmanager:GetSecretValue` Deny lives only in the
  **read-only** policy (§5.2), which has no Allow for it.

### 3.4 Outputs shape (consumed by operator + self-deploy, §8)

`GovernanceStack` registers and the `__main__.py` exports, keyed by repo name:
```python
{
  "oidcProviderArn": str,
  "managedRepositories": [repo.name, ...],                        # sorted
  "perRepo": {
    repo.name: {
      "stateBucketName": str,
      "stateBackendUrl": "s3://pulumi-{repo}-{env}-state",
      "secretsAlias": "alias/pulumi-{repo}-{env}-secrets",
      "secretsProvider": "awskms://alias/pulumi-{repo}-{env}-secrets?region=eu-central-1",
      "deploymentRoleArns": {"preview": arn, "apply": arn, "drift": arn},
      "configReadRoleArns": {suffix: arn, ...},
      "ciConfigSecretIds": {suffix: "/{repo-project}/ci/{suffix}", ...},
      "githubVariables": {…},                                     # per-env, like ci_bootstrap
    }, ...
  }
}
```
The `perRepo[X].deploymentRoleArns` + `secretsProvider` + `stateBackendUrl` are exactly what
`X-infrastructure`'s self-deploy workflow consumes (§8.4).

### 3.5 Governance CI-config payload builder

Add `_governance_payloads(ctx, role_arns, …)` in `governance.py` mirroring
`ci_bootstrap._payloads` (`ci_bootstrap.py:642-726`) but **without** the operations-triage
requirement. Per suffix it emits `AWS_ACCOUNT_ID`, `AWS_REGION`, `PULUMI_BACKEND_URL`
(`s3://pulumi-{repo}-{env}-state`), `PULUMI_DIR`, `PULUMI_SECRETS_PROVIDER`
(`awskms://alias/pulumi-{repo}-{env}-secrets?region={region}`), `AWS_PREVIEW_ROLE_ARN`,
`AWS_APPLY_ROLE_ARN`, `AWS_DRIFT_ROLE_ARN`, `PULUMI_PREVIEW_STACKS`/`PULUMI_DRIFT_STACKS` =
`{env}`. This payload is what the runner's `load-aws-ci-env` action reads (§8.4).

---

## 4. Naming scheme (deterministic, ≤64-char IAM) (FR2, reuse §4 helpers)

All names derive from `{project}` = `sanitize_bucket_component(repo.name)` (the **full repo slug**,
NOT `project_name` — see canonical-source note below) and `{env}` (`_environment_part`). Helpers
already enforce length guards (raise, not truncate). Example: repo `user-service-infrastructure` →
`{project}` = `user-service-infrastructure`.

| Resource | Pattern | Helper | Guard |
|---|---|---|---|
| Deploy role (preview) | `GitHubCiPreview-{project}-{env}` | `_ci_role_name(ctx,"preview")` `ci_bootstrap.py:208` | 64 |
| Deploy role (apply) | `GitHubCiApply-{project}-{env}` | `_ci_role_name(ctx,"apply")` | 64 |
| Deploy role (drift) | `GitHubCiDrift-{project}-{env}` | `_ci_role_name(ctx,"drift")` | 64 |
| Apply managed policy | `{role_name}-{suffix}` | `_create_role` `ci_bootstrap.py:502` | (≤128 policy) |
| Config-read role | `GitHubCiConfigRead-{project}-{suffix}` | `_ci_config_read_role_name` `ci_config.py:76` | 64 |
| State bucket | `pulumi-{repo}-{env}-state` | `state_bucket_name_for_repo` `bootstrap_settings.py:220` | 63 |
| KMS alias | `alias/pulumi-{repo}-{env}-secrets` | `pulumi_secrets_alias_name_for_repo` `:242` | — |
| CI secret | `/{project}/ci/{suffix}` | `_ci_secret_id` `ci_config.py:55` | — |

**Canonical `{project}` source — the full sanitized repo slug, NOT `project_name` (closes
AWS-SRE-4 / FEASIBILITY-4).** The existing helpers `_ci_role_name` (`ci_bootstrap.py:208-217`) and
`_ci_config_read_role_name` (`ci_config.py:76-89`) derive `{project}` from
`_ci_config_project(settings)` = `sanitize_bucket_component(settings.repo)` = the **full repo slug**
(`ci_config.py:40-48`), e.g. `user-service-infrastructure` — they do **not** use
`ManagedRepository.project_name`. The earlier "short project name" framing was wrong and would have
produced role names that the governance stack never creates, breaking the self-deploy template that
references them. Resolution — **one canonical source, the full sanitized repo slug, used everywhere**:
- `_RepoCiContext.project` is set to `sanitize_bucket_component(repo.name)` (the full slug), NOT
  `repo.project_name`. Both the deploy trio (`_ci_role_name`) and the config-read roles
  (`_ci_config_read_role_name`) consume `ctx.project`, so the trio and config-read roles share the
  same `{project}` token (they would otherwise diverge — one slug, one short name).
- The **real** rendered names are therefore:
  `GitHubCiApply-user-service-infrastructure-test` (46 chars),
  `GitHubCiPreview-user-service-infrastructure-test`,
  `GitHubCiDrift-user-service-infrastructure-test`,
  `GitHubCiConfigRead-user-service-infrastructure-prod-preview` (59 chars — only 5 chars of
  headroom under 64).
- The naming table above and the §8.4 / E5.S2 self-deploy template comments are corrected to these
  exact names (e.g. `GitHubCiApply-user-service-infrastructure-test`). A test asserts the
  self-deploy template's referenced role names are **byte-equal** to the names the governance
  component renders for that repo (single source of truth — closes the code↔template mismatch).
- **Length guard:** `_ci_role_name`/`_ci_config_read_role_name` **raise** (do not truncate) past 64
  chars. With only 5 chars of headroom at `prod-preview`, add an explicit guard test that any future
  repo whose `sanitize_bucket_component(name) + "-prod-preview"` would exceed 64 chars is rejected at
  catalog-validation time with a clear error (`validate_repository_catalogs.py`), not at apply time.
  The digest-truncation pattern in `github_oidc._truncate_role_suffix` (`github_oidc.py:78-89`) is
  **not** applied here — the bootstrap helpers raise, and we keep that. This is documented in §8
  onboarding.

**Uniqueness across repos:** names embed `{project}`, which the catalog validates unique by
name (`repository_catalog._validate_unique_names:273`). Two repos with the same `project`
value would collide; add a structural test asserting catalog `project` values are unique
(extends `validate_repository_catalogs.py`).

---

## 5. IAM trust + policy JSON shapes (FR2, FR3, FR22, FR23)

### 5.1 Deployment role trust (per repo, per purpose) — reuse `_deployment_assume_role_policy`

For repo `org/repo`, purpose `preview` in stack `test`:
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Federated": "<oidc_provider_arn>"},
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {"StringEquals": {
      "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
      "token.actions.githubusercontent.com:sub": [
        "repo:org/repo:ref:refs/heads/main",
        "repo:org/repo:pull_request",
        "repo:org/repo:environment:test"
      ],
      "token.actions.githubusercontent.com:repository": "org/repo"
    }}
  }]
}
```
Subjects per `_deployment_role_subjects` (`ci_bootstrap.py:244-257`): `apply`+`prod` →
`["repo:org/repo:environment:prod"]` only; test apply → `environment:test` only;
other `test` purposes also accept their defined branch/preview-environment subjects;
default → branch ref. `repository` claim is pinned with `StringEquals` (FR2).

### 5.1a Service apply subjects and dedicated governor trust (closes SECURITY-2)

These are distinct role families. `RepoGovernance` uses `_deployment_role_subjects`
for service `GitHubCiApply-{project}-test` and `GitHubCiApply-{project}-prod`:
respectively `repo:org/repo:environment:test` and `repo:org/repo:environment:prod`.
Neither service apply role has a bare branch-ref subject or IAM administration.

The operator-owned `GovernanceAutomation` in `pulumi/infra/governance_automation.py`
creates dedicated `GitHubGovernanceApply-{env}` roles for the bootstrap
repository. Both require `environment:governance` and the trusted main governance
workflow identity. Their catalog authority is capped by operator-owned boundaries.
The protected environment requires separate approval by @Kravalg; this central
reviewer gate must not be confused with service test/prod subjects.

`tests/unit/test_governance_service_permissions.py` verifies service backend-only
permissions for both environments; `tests/unit/test_governance_automation.py`
verifies exact central managed-role resources, required GovernanceBoundary and
boundary/provider tampering denials.

### 5.2 Purpose-specific Pulumi backend policies — repo-scoped (FR3)

`_governance_backend_policy_document(..., purpose=...)` builds separate policies.
The **apply** role receives the following state statement; preview and drift do
not receive its checkpoint write/delete actions:

```json
{"Sid":"UsePulumiStateBucket","Effect":"Allow",
 "Action":["s3:ListBucket","s3:GetObject","s3:GetObjectVersion","s3:PutObject","s3:DeleteObject","s3:DeleteObjectVersion"],
 "Resource":["{bucket_arn}","{bucket_arn}/state/*","{bucket_arn}/.pulumi/*"]}
```

For **preview and drift**, that statement contains only `s3:ListBucket`,
`s3:GetObject` and `s3:GetObjectVersion` on the same resources. The builder also
adds these exact lock-management and explicit-denial statements:

```json
[
 {"Sid":"ManagePulumiLocks","Effect":"Allow",
  "Action":["s3:PutObject","s3:DeleteObject"],
  "Resource":"{bucket_arn}/.pulumi/locks/*"},
 {"Sid":"DenyWritesOutsidePulumiLocks","Effect":"Deny",
  "Action":["s3:PutObject","s3:DeleteObject"],
  "NotResource":"{bucket_arn}/.pulumi/locks/*"},
 {"Sid":"DenyStateVersionDeletion","Effect":"Deny",
  "Action":["s3:DeleteObjectVersion"],"Resource":"*"}
]
```

`{bucket_arn}` is the exact ARN derived from
`settings.state_bucket_name_for_repo(repo)`. Lock objects are confined to that
repository's `.pulumi/locks/` prefix; checkpoint/history writes, foreign-bucket
writes and all object-version deletion remain explicitly denied for the read
roles. The shared service boundary admits an upper limit of backend operations;
it does not override these identity-policy Denies. The executable
`test_read_roles_can_lock_but_cannot_mutate_checkpoints` covers TEST/PROD and both
read purposes, including checkpoint, adjacent-prefix, version and foreign-lock
negative cases.

All three purposes also receive caller-identity read and this KMS statement:

```json
{"Sid":"UsePulumiSecretsProviderKey","Effect":"Allow",
 "Action":["kms:Decrypt","kms:Encrypt","kms:GenerateDataKey","kms:DescribeKey","kms:ReEncrypt*"],
 "Resource":"arn:{partition}:kms:{region}:{account_id}:key/*",
 "Condition":{"ForAnyValue:StringLike":{"kms:ResourceAliases":["{own_repository_alias}"]}}}
```

The code interpolates the verified deployment region/account and partition;
`{own_repository_alias}` is exactly
`settings.pulumi_secrets_alias_name_for_repo(repo)`. For the current TEST service,
these become `arn:aws:kms:eu-central-1:891377212104:key/*` and
`alias/pulumi-user-service-infrastructure-test-secrets`. The Resource is **not**
a computed concrete key ARN: the exact alias condition provides the repository
restriction together with the operator-owned boundary. Neither a platform alias
nor a region wildcard is included. Service policies are built by
`_governance_policy_documents`, not platform automation; they grant no alias
mutation or IAM administration. An exact key-ARN restriction would require a
separately reviewed source change and is not represented as implemented here.

`sts:GetCallerIdentity` requires `Resource: "*"` and uses the existing explicit
CrossGuard exception. No wildcard exception is introduced by this documentation.

### 5.2a Scoped secret-read Deny on the APPLY role (closes SECURITY-5)

D4 attaches the full secret-read Deny only to read-only/config-read roles because the apply role
needs `kms:Decrypt`. But "needs `kms:Decrypt` on its own secrets key" does not justify leaving the
*entire* leak surface open on the highest-privilege role. Within a shared account (repos that map
to the same account), an unconditional-no-Deny apply role can `secretsmanager:GetSecretValue`,
`ssm:GetParameter*`, `ec2:GetPasswordData`, `*:GetAuthorizationToken`, `sts:GetSessionToken`,
`cognito-identity:Get*` across every other same-account repo's CI secrets and any application secret. The apply path is now gated
(§5.1a/§7.2), but a malicious governance PR that *passes* review could still exfiltrate. So the
apply role gets a **surgical** Deny that blocks the leak surface except the minimum it genuinely
needs:
```json
{"Sid": "DenySecretLeakingReadsApply", "Effect": "Deny",
 "Action": [
   "secretsmanager:GetSecretValue",
   "ssm:GetParameter","ssm:GetParameters","ssm:GetParametersByPath",
   "ec2:GetPasswordData",
   "lambda:GetFunction",
   "ecr:GetAuthorizationToken",
   "sts:GetSessionToken",
   "cognito-identity:GetCredentialsForIdentity","cognito-identity:GetId",
   "cognito-identity:GetOpenIdToken","cognito-identity:GetOpenIdTokenForDeveloperIdentity"
 ],
 "NotResource": [
   "arn:aws:secretsmanager:eu-central-1:{account_id}:secret:/{project}/ci/*"
 ]}
```
Notes:
- **`kms:Decrypt` is deliberately NOT in this Deny** — the apply role legitimately decrypts its own
  Pulumi secrets key (already scoped by the §5.2 alias condition). If a concrete-key-ARN scope is
  available, a `kms:Decrypt` Deny with `NotResource` = the repo's own key ARN MAY be added as a
  follow-up; until then the §5.2 alias condition is the `kms:Decrypt` boundary.
- `secretsmanager:GetSecretValue` is denied **except** the apply role's own CI-config secret ARNs
  (`NotResource`), so the apply role cannot read another repo's or an application secret, but its
  own CI bootstrap still works.
- This Deny attaches to the **apply role only**, NOT the pulumi-backend policy (which is alias-scoped
  KMS + S3 only and carries no broad secret Allow).
- FR22 verify is amended (E6.S4 / §9.1): add a unit test asserting the apply role **cannot** read an
  arbitrary secret/parameter ARN (`secretsmanager:GetSecretValue` on
  `arn:...:secret:/other-repo/...` is denied) while it **can** read its own
  `/{project}/ci/*` secret and retains `kms:Decrypt` on its own key.

### 5.3 Secret-read Deny guardrail (read-only + config-read roles only) (FR22, D4)

The read-only policy (`_read_only_policy_document`, `ci_bootstrap.py:355-380`) gains the **full**
Deny block (replacing the single-action Deny). Deny wins over the broad read `Allow`, and is
exempt from CrossGuard wildcard checks (`guardrails.py:711-715` returns False unless
`Effect=="Allow"`):
```json
{"Sid": "DenySecretLeakingReads", "Effect": "Deny",
 "Action": [
   "secretsmanager:GetSecretValue",
   "ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath",
   "lambda:GetFunction",
   "ec2:GetPasswordData",
   "ecr:GetAuthorizationToken",
   "sts:GetSessionToken",
   "cognito-identity:GetCredentialsForIdentity",
   "cognito-identity:GetId",
   "cognito-identity:GetOpenIdToken",
   "cognito-identity:GetOpenIdTokenForDeveloperIdentity"
 ],
 "Resource": "*"}
```
Notes:
- **`kms:Decrypt` is deliberately EXCLUDED from the `read-only` Deny.** The preview/drift roles
  also carry the §5.2 pulumi-backend policy, whose alias-scoped `UsePulumiSecretsProviderKey` Allow
  grants `kms:Decrypt` on the repo's own `alias/pulumi-{repo}-{env}-secrets` key so `pulumi preview`
  and the drift check can decrypt the stack's encrypted config. An explicit `kms:Decrypt` Deny here
  (Resource `*`) wins over that Allow and would break preview/drift on any encrypted-secret stack.
  The alias-scoped Allow is the decryption boundary; the broad Deny was both redundant (the
  read-only policy carries no broad `kms:Decrypt` Allow) and harmful. (Config-read instead uses the conditional Decrypt Denies in §5.4.)
- `ssm:GetParameter*` and `cognito-identity:Get*` are expanded to explicit action names
  (IAM Deny supports the `*` wildcard inside an action, but Access Analyzer prefers explicit;
  we keep `ssm:GetParameter*` / `cognito-identity:Get*` forms acceptable — implementer may use
  the wildcard-in-action form which is **not** a CrossGuard `Action:*` violation since it is a
  prefixed action, not the bare `*`). `*:GetAuthorizationToken` is represented concretely as
  `ecr:GetAuthorizationToken` (the only service exposing it in this account surface);
  add `sts:GetServiceBearerToken`-class only if needed.
- This Deny is **NOT** attached to `apply` or the pulumi-backend policy (they need `kms:Decrypt`)
  — D4. Implementer wires the Deny into `_read_only_policy_document` (used by preview/drift) and
  into a new second statement of `_ci_config_read_policy` (config-read), per §3.3.

### 5.4 Config-read role policy — `_ci_config_read_policy`

The role allows DescribeSecret/GetSecretValue only on its exact CI-secret scope.
`DenySecretLeakingReads` excludes GetSecretValue and Decrypt to preserve that purpose.
Two independent Decrypt Denies require BOTH regional Secrets Manager `kms:ViaService`
and the exact owned `kms:EncryptionContext:SecretARN`; missing either context fails
closed. The AWS-managed Secrets Manager key supplies service-mediated access; this
policy adds no KMS Allow. Direct KMS decrypt and cross-secret decrypt remain denied.

## 6. IaC-only apply (FR16, D — reuse)

The governance project routes applies through the same guard. No new enforcement code:
- New CI workflow `.github/workflows/pulumi-governance.yml` runs `make pulumi-plan` and
  `make pulumi-up-plan` with `PULUMI_DIR=pulumi/governance` (Makefile honors `PULUMI_DIR`,
  `Makefile:6,38`). Direct `make pulumi-up` under `GITHUB_ACTIONS=true` hits the reject at
  `scripts/run_pulumi_command.py:672-679`.
- The saved-plan manifest validation (`run_pulumi_command.py:378-397`), `awskms://`
  secrets-provider check (`:92-105`), and policy-pack prep (`:108-113`) apply unchanged because
  they are `PULUMI_DIR`-agnostic.
- **First setup:** explicit trusted state-only initialization creates encrypted empty
  checkpoint metadata without running the program. Resource updates require the protected
  GitHub OIDC saved-plan path. This design does not authorize local root applies.

---

## 7. Kravalg-gating (FR10–FR15, D5, D6)

### 7.1 CODEOWNERS (`.github/CODEOWNERS`) (FR10, D5)

No catch-all line, so non-listed paths stay unowned (R4). The glob set is **expanded to cover
ALL credential-bearing / trust-or-scope-altering code** (closes SECURITY-4: the original list
omitted `bootstrap_settings.py`, `github_oidc.py`, `pulumi_state.py`, `pulumi_secrets.py`,
`run_pulumi_command.py`, and the intake workflow — each can alter trust/scope or the gate itself):
```
# Governance + IAM + policy + trust/scope code — sole approver @Kravalg
/pulumi/governance/                              @Kravalg
/pulumi/infra/governance.py                      @Kravalg
/pulumi/infra/iam/                               @Kravalg
/pulumi/infra/ci_bootstrap.py                    @Kravalg
/pulumi/infra/ci_config.py                       @Kravalg
/pulumi/infra/automation.py                      @Kravalg
/pulumi/infra/bootstrap_settings.py              @Kravalg
/pulumi/infra/pulumi_state.py                    @Kravalg
/pulumi/infra/pulumi_secrets.py                  @Kravalg
/pulumi/repositories.governance.json             @Kravalg
/policy/                                         @Kravalg
/scripts/governance_paths.py                     @Kravalg
/scripts/run_pulumi_command.py                   @Kravalg
/scripts/pulumi_pr_comment.py                    @Kravalg
/scripts/_github_repository_controls.py          @Kravalg
/scripts/configure_github_repository_controls.py @Kravalg
/.github/CODEOWNERS                              @Kravalg
/.github/workflows/pulumi-governance.yml         @Kravalg
/.github/workflows/pulumi-pr-command-runner.yml  @Kravalg
/.github/workflows/pulumi-pr-commands.yml        @Kravalg
```
The branch ruleset already sets `require_code_owner_review: true`
(`_github_repository_controls.py:58`), so this file is the missing half (FR10).

**CODEOWNERS is the single source of truth; drift is a CI failure (closes SECURITY-4).** The same
path set drives the path-aware author gate (§7.3/§7.4) and the runner's server-side scope recompute
(§7.2). To prevent the two-list drift SECURITY-4 flags, `scripts/governance_paths.py:
GOVERNANCE_PATH_GLOBS` is **derived by parsing the CODEOWNERS lines whose owner is `@Kravalg`** (or,
equivalently, a single literal list that a test asserts is byte-equal to the parsed
`owner==@Kravalg` CODEOWNERS globs). `tests/unit/test_codeowners.py` asserts exact set-equality
between the parsed CODEOWNERS `@Kravalg` globs and `GOVERNANCE_PATH_GLOBS`, **failing CI on any
drift** (a path added to one but not the other). This guarantees a path that requires @Kravalg's
review also trips the author gate, and vice-versa. The glob set is consumed by: (a) the CODEOWNERS
drift test, (b) the intake `governance_touched` step, (c) the governance runner's server-side
recompute. There is exactly one authoritative list.

### 7.2 Protected `governance` GitHub Environment (FR11, FR12)

Reviewer = `@Kravalg`, sole, `prevent_self_review: true`, protected-branch-only — reuse
`protected_reviewer_environment_payload` (`_github_repository_controls.py:94-104`).

Add to `_github_repository_controls.py`:
```python
GOVERNANCE_ENVIRONMENT = "governance"

def governance_environment_payload(reviewer_id: int) -> dict[str, Any]:
    return protected_reviewer_environment_payload(reviewer_id)

def governance_environment_verification_blockers(environment, reviewer_id):
    return protected_environment_verification_blockers(
        environment, reviewer_id, label="Governance environment")
```
Wire into `configure_github_repository_controls.py`:
- `configure(...)` emits `payloads["governanceEnvironment"] =
  governance_environment_payload(reviewer_id)` in both dry-run and apply branches
  (mirrors prod/reconcile, `:208-243`).
- apply branch adds `PUT repos/{repo}/environments/governance` (mirrors `:224-235`).
- `_verify_applied_controls` adds a governance blocker check (mirrors `:154-170`).

Runner wiring (FR12) — **concrete, single-mechanism design (resolves AWS-SRE-3, FEASIBILITY-1/2,
SECURITY-1/2).** GitHub job-level `environment:` is static and a `repository_dispatch` workflow
cannot hand a job off to another workflow's env-gated job. There is **no "route to another
workflow" primitive** — the earlier framing is dropped. Instead the governance apply path is a
**dedicated event type on its own workflow** wired end-to-end:

1. **Dedicated dispatch event.** The intake (`pulumi-pr-commands.yml`) computes
   `governance_touched` server-side (§7.4) and, when true, dispatches
   `event_type=pulumi-governance-command` (NOT `pulumi-pr-command`). The two event types route to
   two different workflows; the runner is no longer asked to do impossible cross-workflow routing.
2. **Dedicated runner workflow** `.github/workflows/pulumi-governance.yml` listens on
   `repository_dispatch: types: [pulumi-governance-command]` ONLY. It has **no `workflow_dispatch`**
   (closes the SECURITY-1 / non-blocking workflow_dispatch escalation: there is no manual
   prod/up entry into the governance apply path). Its preflight re-derives trust server-side (step 3),
   and its apply jobs are **two static env-gated jobs**:
   - `governance_test_apply`: `environment: governance`, `PULUMI_DIR=pulumi/governance`,
     `make pulumi-up-plan` against the `test` stack.
   - `governance_prod_apply`: `environment: governance`, `PULUMI_DIR=pulumi/governance`,
     `needs: [governance_test_apply, governance_test_post_apply_drift]`, `make pulumi-up-plan`
     against the `prod` stack.
   Both apply jobs declare a **literal `environment: governance`** so the @Kravalg reviewer gate
   (FR11) fires before *either* the test apply or the prod apply mutates AWS (closes SECURITY-2:
   the test apply is now gated, not just prod). The `test_* → prod_*` ordering and
   success-before-merge graph mirror the existing runner (FR15).
3. **Trusted-runner re-authorization (closes SECURITY-1, SECURITY-4).** Because `client_payload`
   is attacker-controllable on a raw `repository_dispatch`, the governance runner's preflight
   treats **every** `client_payload` field as untrusted and re-derives them from the verified PR
   head SHA before any `id-token: write` job runs:
   - Resolve `client_payload.comment_id` back to its author via
     `gh api repos/{repo}/issues/comments/{comment_id}` and verify the original
     requester's current repository write permission. Reject missing identity,
     revoked access and `Kravalg` (case-insensitive) for `up`; protected reviewer
     approval remains separate. This moves the requester authorization decision into the
     trusted runner that assumes credentials — the intake gate (§7.3) is now defense-in-depth,
     not the sole control.
   - Recompute `governance_touched` server-side from the verified head SHA's changed files
     (`gh api repos/{repo}/pulls/{n}/files` → `scripts/governance_paths.py`). If a request reaches
     `pulumi-governance-command` but the recomputed scope is **not** governance, reject (prevents a
     non-governance PR from minting governance credentials). The `governance_touched` boolean in
     `client_payload` is never trusted.
   - Re-validate PR number / head SHA / open-not-merged / same-repo head exactly as the existing
     runner preflight already does (`pulumi-pr-command-runner.yml:40-129`).
4. **OIDC trust bound to the protected environment (closes SECURITY-2 trust-decoupling).** The
   governance apply role's OIDC trust for the apply purpose drops the bare branch-ref subject and
   requires `sub == repo:org/repo:environment:governance`. The governance apply jobs deploy under
   `environment: governance`, so GitHub mints a token whose `environment` claim is `governance`
   **only after** the protected-environment reviewer (@Kravalg) approves. This binds the IAM trust
   to the GitHub gate: an OIDC token cannot assume the governance apply role without passing the
   reviewer. See §5.1a for the governance-apply subject set.

   **Which roles the runner assumes.** The installed governance controller uses
   dedicated operator-owned `GitHubGovernancePreview-{env}`,
   `GitHubGovernanceApply-{env}` and `GitHubGovernanceDrift-{env}` roles, supplied
   through the six `AWS_GOVERNANCE_{TEST,PROD}_*` variables per account. It does not
   reuse platform CI-config loaders or service apply roles. Preview/drift run under
   `governance-preview`; apply runs under `governance`. `GovernanceAutomation`
   supplies the purpose-specific trust and exact catalog-bounded permissions.
   This component is already installed source in the operator project; missing
   live roles/boundaries require a separately reviewed protected OIDC installation,
   not manual role JSON or local root applies. The variables also bind exact backend,
   account and KMS provider. Live installation is distinct from source availability.
5. **Non-governance routing remains separate.** Requests use `pulumi-pr-command`
   and the platform controller; all up requests preserve current-write requester
   verification and separation from the sole protected reviewer.

### 7.3 PR-comment requester gate (FR13, D6)

`scripts/pulumi_pr_comment.py:author_is_authorized` rejects every `up` request with
an empty author login or login equal to `Kravalg` (case-insensitive), then applies
the existing association rule. Plan requests retain association checks; they are
not anonymous. Governance path detection selects the dedicated controller.

The trusted main runner independently resolves the original comment, checks its
command and current repository write permission, and verifies immutable PR/base/head
and governance scope before credentials. A workflow dispatcher or association alone
cannot substitute for the original requester. @dmytrocraft may request an apply;
@Kravalg separately reviews the protected environment with `prevent_self_review`.
Tests reject sole-reviewer, missing-login, revoked-permission and forged-scope input.

### 7.4 Path-aware detection (FR14) — `.github/workflows/pulumi-pr-commands.yml`

Before the `Parse Pulumi command` step, add a step that lists changed files for the PR and sets
`governance_touched`:
```yaml
- name: Detect governance-touching changes
  id: scope
  env:
    PR_NUMBER: ${{ github.event.issue.number }}
    GH_TOKEN: ${{ github.token }}
  run: |
    files="$(gh api "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}/files" --paginate --jq '.[].filename')"
    python ./scripts/governance_paths.py --files-stdin <<< "$files"   # prints governance_touched=true|false
```
`scripts/governance_paths.py` (new, tiny) holds `GOVERNANCE_PATH_GLOBS` (the §7.1 set) and a
`paths_touch_governance(files) -> bool` using `fnmatch`. The parse step then passes
`--author-login "${{ github.event.comment.user.login }}"` and
`--governance-touched "${{ steps.scope.outputs.governance_touched }}"`. The intake workflow
needs `pull-requests: read` (already present, `pulumi-pr-commands.yml:19`).

### 7.5 Test-then-prod + success-before-merge (FR15)

Reused unchanged: the governance runner job graph (§7.2) enforces `governance_test_* →
governance_prod_*` ordering and `prod` gated on `test_post_apply_drift` success, mirroring
`pulumi-pr-command-runner.yml:325-731`.

**Success-before-merge mechanism.** `Governance Apply` is an informational status.
The required check is `Governance Promotion`, issued only by the dedicated evidence
App through the installed trusted-main publisher. Success requires authenticated
preflight and all four successful stages: test apply, test post-apply drift, prod
apply and prod post-apply drift. A successful prod apply alone is insufficient.

The publisher verifies saved-plan artifacts, commit SHA and plan hashes, immutable
base/head and source-run provenance. Repository controls pin the check to the
verified App installation identity. Controls and workflow tests must verify both
the required context/issuer and this complete dependency graph; an ordinary status
named `Governance Apply` cannot satisfy the merge gate.

### 7.6 Branch-protection hardening: bind approval to the approved diff (closes SECURITY-3)

`default_pull_request_rule()` already sets `dismiss_stale_reviews_on_push=True`,
`require_last_push_approval=True` and `require_code_owner_review=True`. Current
controls tests enforce those source values. The operator verifies live repository
readback against this contract; source assertions alone do not prove live settings.
Saved-plan and promotion validation bind evidence to the reviewed base/head and
reject a changed head rather than inheriting old approvals.

---

## 8. `user-service-infrastructure` scaffold + self-deploy (FR19, FR20)

Delivered now as in-repo **template assets** under `pulumi/user-service-infrastructure/`
(the operator copies/pushes them to the real repo, §10). Layout:

**Preview-blocked until operator governance apply (closes FEASIBILITY-6).** The scaffold
`__main__.py` *consumes, never creates* the governance-provided state bucket + KMS key + roles, and
its repo-variables (`vars.AWS_TEST_CI_CONFIG_ROLE_ARN`, etc.) only exist after the operator runs the
one-time governance apply AND sets the variables. Therefore the scaffold **cannot `pulumi preview`**
until governance is applied for real. The E5.S1/E5.S2 tests assert **structure only**
(gitleaks/lint/asset-presence/role-name byte-equality) and MUST NOT run `pulumi preview` against the
scaffold. This story is explicitly tagged **"preview-blocked until operator governance apply"** in
the E5 split and the runbook (§10).

### 8.1 Directory
```
pulumi/user-service-infrastructure/      # template assets (this repo)
  pulumi/
    Pulumi.yaml                           # name: user-service-infrastructure
    Pulumi.test.yaml                      # env=test, account 891377212104
    Pulumi.prod.yaml                      # env=prod, account 933245420672
    __main__.py                           # minimal generic baseline (imports infra components)
  .github/workflows/self-deploy.yml       # OIDC, saved-plan, PR-comment-driven
  AGENTS.md                               # repo-local agent rules (mirrors gating)
  README.md
```

### 8.2 `pulumi/Pulumi.test.yaml` (scaffold)
```yaml
config:
  aws:region: eu-central-1
  user-service-infrastructure:githubOrg: VilnaCRM-Org
  user-service-infrastructure:environment: test
  user-service-infrastructure:repoSlug: user-service-infrastructure
  user-service-infrastructure:pulumiSecretsProvider: awskms://alias/pulumi-user-service-infrastructure-test?region=eu-central-1
secretsprovider: awskms://alias/pulumi-user-service-infrastructure-test?region=eu-central-1
```
Backend URL `s3://pulumi-user-service-infrastructure-test-state` and the secrets alias both come
from the governance stack's `perRepo["user-service-infrastructure"]` outputs (§3.4) — the repo
consumes, never creates, those resources.

### 8.3 `__main__.py` (scaffold)
Thin entrypoint that builds the generic per-repo baseline using shared `infra` components
(the standard service-infra baseline). It assumes the **governance-provided** state bucket and
KMS key already exist; it does not create IAM roles for itself.

### 8.4 `self-deploy.yml` (scaffold) — assumes governance roles only (FR20)
Mirrors the deploy pattern: PR-comment → preflight → `test` plan → `test` apply (saved-plan) →
`prod`. AWS creds come **only** via OIDC role assumption using the governance roles, read from
the governance CI-config secret through `./.github/actions/load-aws-ci-env`:
```yaml
- uses: ./.github/actions/load-aws-ci-env
  with:
    environment: test
    config-role-arn: ${{ vars.AWS_TEST_CI_CONFIG_ROLE_ARN }}   # GitHubCiConfigRead-user-service-infrastructure-test
    required-keys: AWS_ACCOUNT_ID,AWS_REGION,AWS_APPLY_ROLE_ARN,PULUMI_BACKEND_URL,PULUMI_SECRETS_PROVIDER,PULUMI_PREVIEW_STACKS
- uses: aws-actions/configure-aws-credentials@…
  with:
    role-to-assume: ${{ steps.ci_config.outputs.aws-apply-role-arn }}  # GitHubCiApply-user-service-infrastructure-test
- run: make pulumi-up-plan        # saved-plan only → IaC-only apply (FR16/FR20)
```
No static AWS keys, no `AdministratorAccess` (gitleaks + template lint assert this, FR20 verify).
The catalog entry already exists (`repositories.example.json:4-12`); it is promoted into the
active `repositories.governance.json` (§2.3).

**Consumed bootstrap outputs (exact):** `perRepo[X].deploymentRoleArns.{preview,apply,drift}`,
`perRepo[X].configReadRoleArns.{test,test-pr,prod,prod-preview}`,
`perRepo[X].stateBackendUrl`, `perRepo[X].secretsProvider`, `perRepo[X].ciConfigSecretIds`.
These flow into the repo's GitHub repo-variables (`AWS_TEST_CI_CONFIG_ROLE_ARN`, etc.) via the
governance `githubVariables` output (operator sets them, §10).

---

## 9. Test strategy + quality gates (FR24, NFR1–NFR8)

### 9.1 Component → test mapping (Pulumi mock pattern)

All unit tests use the session-scoped Pulumi mocks (`tests/conftest.py:33-58`, deterministic
ARNs `:73-75`). New `tests/unit/test_governance.py`:

| FR | Assertion |
|---|---|
| FR2 | For N catalog repos, exactly **3N** deployment roles; names match `GitHubCi{Preview,Apply,Drift}-{project}-{env}` with `{project}`=full slug (e.g. `GitHubCiApply-user-service-infrastructure-test`); trust doc subjects + `repository` pin (`StringEquals`) per purpose/stack; **service apply subjects are `environment:test` / `environment:prod`, with no bare branch ref** (§5.1a). |
| FR3 | Render repo A vs repo B deploy policies; assert A references only A's bucket ARN + A's KMS alias; **no** substring of B's bucket/alias appears in A's doc; **assert no service repo's deploy doc references `pulumi-platform-bootstrap` at all** (AWS-SRE-1); ARNs use `{account_id}`/`eu-central-1`, no `891377212104` literal (FEAS-3). |
| FR4 | Each repo's config-read policy Allow lists only that repo's `/{project}/ci/{suffix}-*` ARN; per-suffix trust subjects correct; Deny present, `secretsmanager:GetSecretValue` absent from Deny. |
| FR5/FR6 | One primary + one replica bucket and one KMS key + alias per repo per env; deterministic names; replication region == `eu-west-1` (pinned). |
| FR7 | With ≥2 repos, **zero** `OpenIdConnectProvider` *create* resources registered (provider consumed by `.get()` from pinned ARN); raises if `oidc_provider_arn` unset (AWS-SRE-2). |
| FR8 | Parametrized: feed an arbitrary `foo-infrastructure` via catalog → full set produced; guard test asserts duplicate `project` rejected AND over-64-char role name rejected at validation (FEAS-4). |
| FR22 | Read-only + config-read docs contain every Deny action (read-only includes `secretsmanager:GetSecretValue`); **apply role carries the surgical §5.2a Deny** (cannot read an arbitrary secret/parameter ARN) while retaining `kms:Decrypt` on its own key and `GetSecretValue` on its own `/{project}/ci/*`; pulumi-backend policy carries no Deny. |
| AccountAssertion | `expected_account_id`==mock account `123456789012` → proceeds (non-raise branch); mismatch → `ValueError`; both branches covered (AWS-SRE-5/FEAS-3). |
| NamingParity | Self-deploy template's referenced role names are byte-equal to the names the governance component renders for the repo (AWS-SRE-4). |
| FR23 | Scan every deploy-role document: no `Effect:Allow` with `Action:*` or unscoped `Resource:*` outside the CrossGuard exempt allowlist. |
| FR1 | Catalog with 1 vs 2 repos: assert no Python source under `pulumi/governance/` differs (config-only add). |

### 9.2 Structural / policy / catalog gates
- `tests/pulumi/test_project_structure.py`: add a `test_governance_project_*` mirroring the
  bootstrap test (`:49-85`) — manifest name `governance`, stacks `{example,test,prod}`,
  `awskms://` secrets provider, each stack's committed config pins its OWN account (test stack
  config → `891377212104`, prod stack config → `933245420672`), no hardcoded account literal in
  component Python under `pulumi/infra/*.py`, no secrets in committed stacks (R6).
- `scripts/validate_repository_catalogs.py` — **per-catalog-kind fanout, not a shared constant
  (closes AWS-SRE-6).** The current model unconditionally merges `CENTRAL_STACK_FANOUT` (budgets,
  guardduty, cloudtrail, ecr, …) into every catalog and uses `PER_ENVIRONMENT_FANOUT =
  {s3Buckets:2, kmsKeys:1, iamRoles:2, backupSelections:1}`. The governance catalog creates
  **none** of the central-stack resources and **more** than 2 IAM roles per repo (preview/apply/drift
  trio = 3 + config-read roles 2–4/env + the `PulumiStateRepl-*` replication role = ~6–8 IAM roles
  per repo per env), plus the apply role's customer-managed policies. Bumping the shared constant
  would silently relax the quota guard for the existing `repositories.bootstrap.json` too. Resolution:
  - Detect catalog kind (by filename — `repositories.governance.json` → `governance`; otherwise
    `deployment`/`central`) or by a `kind` field, and apply a **governance-specific fanout** with its
    own thresholds: no central-stack resources; `iamRoles = 3 (trio) + config_read_count + 1
    (replication)`; `managedPolicies = 2 × repos` (backend plus scoped secret-read policy; service
    apply has no inherited platform automation groups); `secrets =
    suffix_count × repos`. Raising governance limits must NOT loosen the deployment-catalog guard.
  - Add an **account-quota headroom report**: assert per-repo IAM role count and customer-managed
    policy count against AWS account defaults (1000 roles, 1500 managed policies, 10
    managed-policies-per-role) with explicit headroom for the plausible ~30-repo `-infrastructure`
    fleet. The service apply role uses 2/10 managed-policy attachments; central governor
    attachment limits and its four-repository ceiling are checked separately.
  - Add the **unique-`project` guard** (§4) AND a **role-name-length guard**: reject any catalog repo
    whose `sanitize_bucket_component(name) + "-prod-preview"` would exceed 64 chars at validation
    time (closes the FEASIBILITY-4 apply-time-raise trap — fail in CI, not at apply).
- `make test-policy` (CrossGuard): governance roles produce zero `iam-no-wildcards` violations
  (NFR4); Deny statements are exempt (`guardrails.py:711-715`). No escape hatches (NFR5).
- `scripts/pulumi_ci_guardrails.py validate-iam <governance preview files>`: zero
  `ERROR`/`SECURITY_WARNING` (FR23). Note: this is the IAM Access Analyzer entrypoint — **not**
  `validate_iam_policies.py` (research §5.1 naming correction).

### 9.3 Gate-specific tests
- `tests/unit/test_pr_comment_gate.py`: the FR13 decision matrix.
- `tests/unit/test_codeowners.py`: every §7.1 glob → `@Kravalg`; sample of `docs/`, app code,
  `tests/` → no owner (FR10/R4).
- `tests/unit/test_repository_controls.py`: governance env payload has one reviewer
  (`@Kravalg`), `prevent_self_review=true`, protected-branch-only; `--dry-run` snapshot includes
  it (FR11). Governance check is in `REQUIRED_STATUS_CHECKS` (FR15).
- Workflow lint (actionlint/yamllint already in `REQUIRED_STATUS_CHECKS`): `pulumi-governance.yml`
  apply job declares `environment: governance` (FR12); intake computes changed paths (FR14).

### 9.4 Coverage, mutation, static (NFR1–NFR3, D7)
- 100% combined branch coverage (`make test-coverage`, `Makefile:234`): exhaustive tests above;
  every branch in `governance.py` (account-mismatch raise, each suffix, each purpose) is hit.
- Mutation (`make test-mutation`): governance role/policy builders and the author-gate decision
  function are mutation-tested (assert mutants like flipping `governance_touched` or `action ==
  "up"` are killed).
- Import isolation (D7/R8) — **implemented split (closes FEASIBILITY-5).**
  `pyproject.toml` lists `root_packages = ["app", "policy", "infra"]`.
  The forbidden contract has `source_modules=["infra.governance"]` and
  `forbidden_modules=["policy","app"]`. `scripts` is intentionally not graphed.
  `tests/pulumi/test_governance_import_isolation.py` independently parses the AST
  and forbids `policy`, `app` and `scripts` imports. The scripts prohibition is
  therefore enforced by the AST test, not by Import Linter.
  Run `lint-imports` and the AST guard; preserve all existing app/policy contracts.
  The historical AST-only fallback remains explicit: if graphing infra exposes
  pre-existing violations, do not relax existing contracts. Use the narrow AST
  guard for all three forbidden roots, document the limitation and retain the
  unaffected Import Linter contracts. Current source uses the combined split,
  not that fallback; neither outcome permits scripts imports.
- ruff max-complexity ≤ 12: `GovernanceStack.__init__` and `RepoGovernance.__init__` delegate to
  small helpers (the per-repo loop body is one helper call) to stay under 12.
- gitleaks/bandit/deptry/pip-audit: scaffold templates carry no secrets; secret values written
  only when `write_secret_values` (NFR8, `ci_bootstrap.py:736-737`).

### 9.5 Determinism (NFR7)
All policy JSON uses `json.dumps(..., sort_keys=True)` (existing helpers already do). Resource
names from deterministic helpers. Snapshot tests assert byte-stable rendered policy across runs
so saved plans validate (`run_pulumi_command.py:357-375`).

---

## 10. Deliverable-now vs operator-only split

### 10.1 Pure CODE / IaC / docs — deliverable now (no live creds)
- New `pulumi/governance/` project (manifest + 3 stack files + `__main__.py`) (FR9).
- `pulumi/infra/governance.py` (`GovernanceStack`, `RepoGovernance`, `GovernanceStackArgs`)
  and the `ci_bootstrap.py`/`ci_config.py`/`bootstrap_settings.py` generalization (FR1–FR8).
- Full secret-read Deny set (FR22); repo-scoped KMS-alias deploy policy (FR3/FR23).
- `pulumi/repositories.governance.json` catalog (FR1/FR8) + `validate_repository_catalogs.py`
  fanout extension.
- `.github/CODEOWNERS` (FR10); `scripts/governance_paths.py` shared glob constant.
- Author/path gate in `scripts/pulumi_pr_comment.py` + intake changed-paths step (FR13/FR14).
- Governance env payload + verification in `_github_repository_controls.py` /
  `configure_github_repository_controls.py`, plus `--dry-run` output (FR11).
- `pulumi-governance.yml` CI workflow (`PULUMI_DIR=pulumi/governance`, `environment: governance`)
  (FR12/FR16); runner governance-routing changes.
- `pulumi/user-service-infrastructure/**` scaffold + `self-deploy.yml` template (FR19/FR20).
- `AGENTS.md` onboarding flow + operator runbook (FR17/FR18); `docs/governance-stack.md`;
  account-model correctness verified two-account (FR21) — `docs/github-ci-bootstrap-stack.md` and
  `pulumi/Pulumi.prod.yaml` are already two-account-correct and unchanged.
- All tests (§9). `make ci-pr` green; dry-run previews.

### 10.2 Operator-only prerequisites and live verification

Follow [the governance runbook](../../docs/governance-stack.md) in order:

1. Verify operator-owned dedicated governor roles, immutable boundary inventory,
   account/backend/KMS bindings and real repository identity. Use an explicitly
   authorized trusted state-only initializer for a genuinely absent checkpoint;
   this does not execute the Pulumi program. Resource changes use protected GitHub
   OIDC and reviewed saved plans; no local root apply is authorized.
2. Configure and read back protected environments and App-bound branch controls
   using `uv run --frozen python scripts/configure_github_repository_controls.py`
   with the verified `--promotion-app-id`; review `--dry-run` before `--apply`.
3. Install verified nonsecret GitHub variables from the matching account outputs.
4. Publish the complete generated scaffold using
   `scripts/scaffold_infrastructure_repository.py`, after binding the real repo ID.
5. Verify the already committed per-account `githubOidcProviderArn` against live
   metadata. A mismatch stops setup; it does not authorize changing the pin.
6. Verify any configured `costAnomalyMonitorArn` matches its stack account. Absence
   is permitted; do NOT repoint prod away from `933245420672`.
7. If @Kravalg is unavailable, halt applies. Any emergency proposal requires separate
   explicit authorization and an audit record; this runbook grants neither a local
   root apply nor a reviewer change. Any authorized intervention must be logged.
8. A current-write requester other than @Kravalg requests `/pulumi test up` and
   `/pulumi prod up`; @Kravalg separately approves. Capture real apply/drift evidence
   and App-issued Governance Promotion. Source tests do not satisfy live acceptance.

**Residual authority.** Platform roles, dedicated central governor roles and service
roles are distinct. Central `GitHubGovernanceApply` can manage the exact catalogued
resources within operator-owned permission boundaries, not account-global IAM.
It cannot remove boundaries, change its own delegation or create the shared OIDC
provider. Service apply roles are backend-only with no IAM administration, including
no `iam:PutRolePolicy`/`iam:AttachRolePolicy` on another repository's roles.
`test_service_apply_cannot_escalate_or_modify_other_repositories` and
`test_governance_automation.py` enforce these distinctions. Central compromise still
risks its bounded catalog within one account; protected review and saved-plan
verification remain mandatory. This is not a new human risk acceptance.

---

## 11. Onboarding flow (for `AGENTS.md`, FR17) — service `X`

First resolve or create the real `VilnaCRM-Org/X-infrastructure` repository and
verify its immutable repository/owner IDs (OPERATOR). Before the catalog grant,
install its reviewed operator-owned boundaries and exact delegation inventory
through protected GitHub/OIDC saved plans (CODE plus OPERATOR execution).

1. **PR A — Grant deploy roles:** add the verified identity to the governance
   catalog (CODE). A current-write maintainer other than @Kravalg requests TEST then
   PROD up; @Kravalg separately reviews and approves `environment: governance`.
   Verify saved-plan apply, drift and promotion before merge (OPERATOR execution).
2. **PR B — Prepare generic infrastructure:** generate the complete reviewed
   scaffold using the PR-A backend-only roles (CODE). Additional workload deployment
   requires explicit capability and boundary extensions.
3. **Publish scaffold to the identified repository:** preserve existing content,
   publish the reviewed generated dependency closure, and configure account-local
   variables and protected environments (OPERATOR).
4. **PR C — Grant reviewed workload capabilities:** review the actual service
   resource/task-role inventory, extend operator-owned boundaries and grant only
   the required capabilities through the same protected flow (CODE plus OPERATOR).
5. **Verify self-deployment:** exercise the service's own TEST/PROD comment plan,
   saved-plan apply, drift and promotion at the same source revision (OPERATOR).
   Governance retains service roles/state/key ownership; the operator retains
   immutable boundaries and its own delegation.

Each step is labeled CODE vs OPERATOR in `AGENTS.md` per FR17/FR18.

---

## 12. Risk dispositions (from research §5.4)

| Risk | Disposition |
|---|---|
| R1 account model | Resolved by D1/FR21: two accounts (test `891377212104`, prod `933245420672`); each stack asserts its live account == its per-stack configured `awsAccountId`; component code carries no account literal. |
| R2 trust divergence | D3: governance uses the strong trust shape; `PulumiDeploy-*` untouched (no import/replace). |
| R3 Deny/Allow collision | D4: shared Deny on read-only/config-read; separate surgical apply Deny (§5.2a); apply + backend keep `kms:Decrypt`; `secretsmanager:GetSecretValue` Deny excluded from config-read. |
| R4 CODEOWNERS over-scope | D5: explicit globs, no catch-all; test asserts unrelated paths unowned. |
| R5 single-approver/self-review | `prevent_self_review:true`; `@dmytrocraft` may request plan/up with current write permission; @Kravalg separately approves and cannot self-request `up`. |
| R6 structural-test brittleness | §9.2 adds governance structural test; bootstrap test left intact. |
| R7 coverage cliff | §9.4 exhaustive branch tests on `governance.py` + gate functions; account-assertion mock seam (§3.2 step 1) makes both branches reachable. |
| R8 import-linter blind spot | D7: Import Linter enforces `infra.governance ↛ {policy, app}`; the AST guard enforces `{policy, app, scripts}` with scripts outside the graph. Preserve §9.4 AST-only fallback without relaxing existing contracts. |

### 12.1 Adversarial-review dispositions (implementation-readiness gate)

| Finding | Lens | Disposition |
|---|---|---|
| Author gate enforced only in intake; trusted runner never re-checks author | SECURITY-1 | **Fixed** §7.2: governance runner re-derives author from `comment_id` and requires a current-write requester other than `Kravalg`, recomputes scope server-side, drops `workflow_dispatch`; client_payload fully untrusted. |
| `test_apply` ungated by a protected environment | SECURITY-2 | **Fixed** §7.2/§5.1a: dedicated `pulumi-governance.yml` with BOTH `governance_test_apply` and `governance_prod_apply` under static `environment: governance`; apply-role OIDC trust bound to `environment:governance` (no bare branch-ref). |
| Stale-review survives new pushes (approve-then-swap) | SECURITY-3 | **Fixed** §7.6: `dismiss_stale_reviews_on_push=True`, `require_last_push_approval=True`, plan-manifest SHA == approved SHA assertion. |
| Governance scope is an untrusted boolean; CODEOWNERS/glob drift | SECURITY-4 | **Fixed** §7.1/§7.2: scope recomputed server-side; CODEOWNERS is single source, drift-equality test fails CI; glob set expanded to all credential-bearing code. |
| Full secret-read Deny omitted from apply role | SECURITY-5 | **Fixed** §5.2a: surgical Deny on apply role (secretsmanager/ssm/ec2/lambda/ecr-auth/sts/cognito) except own CI secret; keeps `kms:Decrypt` on own key. |
| KMS alias-condition forgeable + region/key wildcard | SECURITY-KMS-med | **Fixed (partial) + hardening** §5.2: region pinned to eu-central-1; no alias-mutation grant on repo keys (verified+tested); concrete-key-ARN scope recommended as follow-up. |
| Account-pinning not enforced in trust; within-account cross-repo blast radius | SECURITY-7 | **Accepted + documented** §10 residual-risk note; test↔prod isolated by separate accounts (prod `933245420672` ≠ test `891377212104`); central authority is restricted to exact catalog resources and immutable boundaries; service roles are backend-only, verified by existing permission tests. |
| Platform-bootstrap KMS key decryptable by every repo (FR3 false) | AWS-SRE-1 | **Fixed** §3.1/§5.2: platform-bootstrap alias removed from per-repo deploy policies; reserved for governance stack's own apply role. |
| Two stacks own the per-account OIDC provider | AWS-SRE-2 | **Fixed** §3.2 step 2: the OIDC provider is per-account; governance consumes its account's provider by pinned ARN via `.get()` (test→891 provider, prod→933 provider), zero create branch; structural test asserts no create. |
| FR12 env-gating has no working mechanism | AWS-SRE-3/FEAS-2 | **Fixed** §7.2: dedicated event type + workflow + static env-gated jobs + `PULUMI_DIR=pulumi/governance`; routing-to-another-workflow framing dropped. |
| Role-naming contradiction (slug vs project_name) | AWS-SRE-4/FEAS-4 | **Fixed** §4: canonical `{project}` = full sanitized repo slug everywhere; template names corrected; byte-equality test. |
| 100%-coverage vs account happy-path under mocks | AWS-SRE-5/FEAS-3 | **Fixed** §3.2 step 1: injectable `expected_account_id`/`region`; both branches covered; ARNs interpolated. |
| Fanout model wrong for governance project | AWS-SRE-6 | **Fixed** §9.2: per-catalog-kind fanout, governance-specific counts, quota-headroom report, no shared-constant relaxation. |
| "Governance Apply" required check unmergeable | FEASIBILITY-1 | **Fixed** §7.5: dedicated App issues required `Governance Promotion` after all four apply/drift stages; `Governance Apply` remains informational. |
| `_RepoCiContext` dual-context fragility / NFR6 | FEASIBILITY-4 | **Fixed** §3.1: extend existing `_BootstrapBuildContext`; golden byte-equal parity fixture is the gate. |
| import-linter either/or unresolved | FEASIBILITY-5 | **Fixed** §9.4: implemented Import Linter policy/app contract plus AST scripts guard; documented AST-only fallback preserves existing contracts. |
| Operator-only deps mislabeled deliverable-now | FEASIBILITY-6 | **Fixed** §8/§10: scaffold preview-blocked tagged; cost-anomaly monitor is an operator apply-time step; FR21 verify tolerates absence. |
