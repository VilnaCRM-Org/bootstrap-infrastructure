# Research — Multi-Repo IAM/OIDC Governance Stack (GitHub issue #77)

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

**Phase:** 1 — Analysis (BMAD Analyst)
**Scope of this document:** Current-state mapping + gap analysis ONLY. No design proposals.
Every claim is grounded with `file:line` citations. Where the codebase contradicts the
stated hard constraints, the contradiction is flagged as a RISK rather than silently resolved.

Base branch: `feat/multi-repo-governance` (off `codex/issue59-github-ci-bootstrap-stack`, PR #60).
Issue source of truth: `gh issue view 77` (mirrored at `.tmp/governance-issue.md:1-45`).

---

## 0. Executive summary of findings

1. The foundation to generalize is `GitHubCiBootstrap` (`pulumi/infra/ci_bootstrap.py:815`) +
   `CiConfiguration` (`pulumi/infra/ci_config.py:251`), wired by the one-time, operator-applied
   project `pulumi/github-ci-bootstrap/__main__.py:26`. It is single-repo: it requires `repoSlug`
   and produces exactly one repo's roles/secrets per stack
   (`pulumi/infra/ci_bootstrap.py:808-812`, `pulumi/infra/ci_config.py:40-48`).
2. The main deployment project `pulumi/__main__.py` ALREADY has a generic multi-repo model
   (`managedRepositories` / `repositoryCatalogPath`) that fans state buckets, KMS keys, and
   `PulumiDeploy-*` roles out per repo (`pulumi/infra/bootstrap_infrastructure.py:163`,
   `pulumi/infra/repository_catalog.py:73`). But that multi-repo model creates a DIFFERENT,
   weaker role set than the bootstrap (`PulumiDeploy-*` with branch-only trust, no preview/apply/
   drift split, no CI-config secrets). The two models are not unified.
3. The governance gating primitives MOSTLY EXIST but are not composed for "@Kravalg-only governance":
   - PR-comment intake/runner (`.github/workflows/pulumi-pr-commands.yml`,
     `pulumi-pr-command-runner.yml`) gates on `OWNER|MEMBER|COLLABORATOR`, NOT on a single user
     (`scripts/pulumi_pr_comment.py:9`).
   - Protected-environment + reviewer config already defaults to `Kravalg`
     (`scripts/configure_github_repository_controls.py:68`,
     `scripts/_github_repository_controls.py:94-116`) but only for `prod` and
     `operations-alert-reconcile`, not for a governance environment.
   - There is NO `CODEOWNERS` file anywhere in the repo (verified: `find ... -name CODEOWNERS`
     returns nothing).
4. IaC-only apply enforcement is real and reusable: `scripts/run_pulumi_command.py:672-679`
   rejects direct `pulumi up` when `GITHUB_ACTIONS=true`, forcing the saved-plan path.
5. Least-privilege denies for the secret-leaking read surface are PARTIAL: the read-only policy
   denies only `secretsmanager:GetSecretValue` (`pulumi/infra/ci_bootstrap.py:355-380`), NOT the
   full Deny set the constraint requires (kms:Decrypt, ssm:GetParameter*, lambda:GetFunction,
   ec2:GetPasswordData, *:GetAuthorizationToken, sts:GetSessionToken, cognito-identity:Get*).
6. CrossGuard already exempts `Effect: Deny` and only flags `Effect == "Allow"` wildcards
   (`policy/guardrails.py:711-727`), matching the constraint exactly.
7. **CRITICAL CONTRADICTION:** the repo today is a TWO-ACCOUNT model (test=`891377212104`,
   prod=`933245420672`), contradicting the hard constraint of a single account `891377212104`
   with test/prod as STACKS. See RISK R1.

---

## 1. Current-state: the `github-ci-bootstrap` foundation (to GENERALIZE)

### 1.1 Project wiring (one-time, operator-only)
- Project manifest `pulumi/github-ci-bootstrap/Pulumi.yaml:1-4` — name `github-ci-bootstrap`,
  python runtime.
- Entrypoint `pulumi/github-ci-bootstrap/__main__.py:19-36` builds ONE `GitHubCiBootstrap(...)`
  from `BootstrapSettings.from_pulumi_config(cfg)`; exports OIDC ARN, secret IDs, read-role ARNs,
  deployment-role ARNs, triage role ARN, `githubVariables`, secret payload keys/version IDs
  (lines 38-59).
- Stacks are per-environment, single-repo: `Pulumi.test.yaml:8` (`environment: test`,
  `repoSlug: bootstrap-infrastructure`) and `Pulumi.prod.yaml:8,14` (`environment: prod`,
  `repoSlug: bootstrap-infrastructure`). Secrets provider differs per stack:
  `awskms://alias/pulumi-platform-bootstrap-{test|prod}` (`Pulumi.test.yaml:14,19`).
- This project is NOT wired into any CI workflow or Makefile target (verified: grep of
  `github-ci-bootstrap` across `.github/workflows/`, `Makefile`, `scripts/` returns nothing).
  It is applied locally by an admin operator only — `docs/github-ci-bootstrap-stack.md:1-11,78-122`.

### 1.2 What `GitHubCiBootstrap` creates today (`pulumi/infra/ci_bootstrap.py`)
The component (`class GitHubCiBootstrap`, `:815`) requires a repo
(`_require_repo`, `:808-812`) and produces, per (single) repo + environment:

- **OIDC provider** via `GitHubOidcRoles(..., repositories=[])` — provider only, no per-repo roles
  here (`:833-838`).
- **CI configuration** via `CiConfiguration(...)` (`:839-847`) — secrets + read roles (see §1.3).
- **Three deployment roles** keyed by purpose `preview | apply | drift`
  (`_role_specs`, `:447-467`; `_create_roles`, `:540-551`):
  - Role names from `_ci_role_name` (`:208-217`):
    `GitHubCiPreview-{project}-{env}`, `GitHubCiApply-{project}-{env}`, `GitHubCiDrift-{project}-{env}`
    (prefixes `_CI_ROLE_PREFIX_BY_PURPOSE`, `:28-32`); 64-char guard at `:212-216`.
  - Trust subjects from `_deployment_role_subjects` (`:244-257`) — this is the **per-suffix
    trust model** the task calls out:
    - `preview` + `test`: branch ref + `pull_request` + `environment:test` (`:247-252`).
    - other `test` purposes: branch ref + `environment:test` (`:253-254`).
    - `apply` + `prod`: `environment:prod` ONLY (`:255-256`).
    - otherwise: branch ref only (`:257`).
  - Trust policy `_deployment_assume_role_policy` (`:260-289`) pins `aud=sts.amazonaws.com`,
    `sub IN subjects`, and `repository == org/repo`.
  - Policies attached per purpose (`_role_policy_documents`, `:425-444`):
    - `preview`/`drift`: `pulumi-backend` + `read-only` (`:433-437`).
    - `apply`: `pulumi-backend` + the FULL automation managed policies
      (`_automation_policy_documents`, imported from `automation.py`) + `iam-managed-policies`
      (`:438-444`). Apply role uses customer-managed `aws.iam.Policy` + attachment
      (`_create_role`, `:500-525`); preview/drift use inline `RolePolicy` (`:526-536`).
- **Pulumi backend policy** `_pulumi_backend_policy_document` (`:313-352`): S3 state bucket +
  state objects (`state/*`, `.pulumi/*`) (`_state_bucket_resources`, `:292-301`) and KMS
  secrets-provider use scoped by `kms:ResourceAliases` LIKE `alias/pulumi-*-{env}-secrets`
  (`_pulumi_secrets_alias_conditions`, `:304-310`).
- **Read-only policy** `_read_only_policy_document` (`:355-380`): a large `Allow` list
  (`_READ_ONLY_ACTIONS`, `:52-104`) on `Resource:*` PLUS a single `Deny` of
  `secretsmanager:GetSecretValue` (`:372-377`). **This is the only secret-read Deny today.**
- **`OperationsAlertTriage-*`** role — TEST environment only
  (`_create_operations_alert_triage`, `:589-639`; gated `:593-594`).
- **CI secret payloads** `_payloads` (`:642-726`): per fixed suffix
  (`test` → `test-pr`,`test`; `prod` → `prod-preview`,`prod`; `_CI_SECRET_SUFFIXES_BY_ENVIRONMENT`,
  `:33-36`). Payloads carry `AWS_ACCOUNT_ID`, `AWS_REGION`, `PULUMI_BACKEND_URL`, `PULUMI_DIR`,
  `PULUMI_SECRETS_PROVIDER`, preview/apply/drift role ARNs, stack lists, and operations metadata.
- **Secret versions** `_create_secret_versions` (`:729-755`) — written only when
  `write_secret_values` (`:736-737`).
- **GitHub repo variables** `_github_variables` (`:758-781`): `AWS_TEST_REGION`,
  `AWS_TEST_PR_CI_CONFIG_ROLE_ARN`, `AWS_TEST_CI_CONFIG_ROLE_ARN` (test) / prod equivalents.

### 1.3 What `CiConfiguration` creates today (`pulumi/infra/ci_config.py`)
- Requires `repoSlug` (`_ci_config_project`, `:40-48`).
- Per fixed suffix (`_ci_secret_suffixes`, `:50-52`; `CI_CONFIG_SECRET_SUFFIXES_BY_STACK`,
  `:18-21`) it creates (`class CiConfiguration`, `:251`, loop `:284-354`):
  - **Secrets Manager secret** `aws.secretsmanager.Secret` named `/{project}/ci/{suffix}`
    (`_ci_secret_id`, `:55-59`), 30-day recovery, import-if-exists (`:286-307`).
  - **Read role** `GitHubCiConfigRead-{project}-{safe_suffix}` (`_ci_config_read_role_name`,
    `:76-89`) with per-suffix trust (`_github_actions_subjects`, `:92-107`) — `test-pr`→
    `pull_request`; `test`→branch+`environment:test`; `prod`→`environment:prod`; else branch
    (`:98-107`). Allowed workflow names are also encoded per suffix
    (`_github_actions_workflows`, `:110-143`) but only as metadata, not as a trust condition.
  - **Read policy** `_ci_config_read_policy` (`:180-209`): `secretsmanager:DescribeSecret` +
    `GetSecretValue` on EXACTLY the one CI secret ARN pattern (`_ci_secret_arn_patterns`, `:61-73`).
- Outputs `secret_ids`, `secret_arns`, `read_role_arns` (`:356-362`).

### 1.4 Naming helpers (single-repo, deterministic) — `pulumi/infra/bootstrap_settings.py`
- `state_bucket_name_for_repo` → `pulumi-{repo}-{env}-state`, 63-char guard (`:220-231`).
- `pulumi_secrets_alias_name_for_repo` → `alias/pulumi-{repo}-{env}-secrets` (`:242-252`).
- `pulumi_secrets_provider_for_repo` → `awskms://{alias}?region={region}` (`:254-260`).
- `runner_ecr_repository_name` → `pulumi-runner/{repo}-{env}` (`:262-269`).
- `automation_role_name` → `PulumiAutomation-{repo}-{env}`, 64-char guard (`:271-284`).
- `central_logging_bucket_name` → `{prefix}-central-logs-{region}-{env}` (`:286-300`).
- `sanitize_bucket_component` enforces DNS-safe S3 segments (`:184-218`).

---

## 2. Current-state: the existing per-repo onboarding (the OTHER multi-repo model)

The MAIN project `pulumi/__main__.py` already supports generic multi-repo, but with a
DIFFERENT and narrower role/resource shape than the bootstrap. This is the model the issue
describes as "hand-editing `managedRepositories`" (`.tmp/governance-issue.md:11`).

### 2.1 Repo catalog model
- `ManagedRepository` dataclass (`pulumi/infra/managed_repository.py:79-149`): name,
  default_branch, project, owner, lifecycle_state, last_reviewed, expected_environments.
- `ManagedRepositoryCatalog.from_settings` (`pulumi/infra/repository_catalog.py:101-131`)
  resolves repos from (in order): `managed_repo_overrides` → `repositoryCatalogPath` JSON →
  inline `managedRepositories` config → single `repoSlug` fallback.
- JSON catalog files exist: `pulumi/repositories.bootstrap.json` (active stack uses
  bootstrap-infrastructure), `pulumi/repositories.example.json` (already lists
  `user-service-infrastructure` + `core-service-infrastructure`), schema at
  `pulumi/repositories.schema.json`. Catalog fanout is validated by
  `scripts/validate_repository_catalogs.py:16-31` (per-env: 2 s3, 1 kms, 2 iam, 1 backup).
- `BootstrapInfrastructure` (`pulumi/infra/bootstrap_infrastructure.py:163-261`) composes:
  central logging → `PulumiStateBuckets` → `PulumiSecretsKeys` → `GitHubOidcRoles` →
  `CiConfiguration` (only if `repoSlug` set, `:212-217`/`_create_ci_config:28-45`) →
  `GitHubAutomation` (only if `repoSlug` set, `:218-222`/`_create_automation:48-64`) →
  backup/monitoring/cost/security.

### 2.2 Per-repo state buckets + KMS (already generic, fan-out per repo)
- `PulumiStateBuckets` (`pulumi/infra/pulumi_state.py:289`) iterates managed repos
  (`:327-338`), creating per repo: primary + cross-region replica state bucket
  (`_register_repository`, `:347-423`), versioning/logging/lifecycle/AES256 encryption
  (`:468-509`), public-access block + ownership + TLS-only bucket policy (`:511-543`),
  `PulumiStateRepl-*` replication role + config (`:557-593`). Replica region defaults
  `eu-west-1` (`:22`, `_resolved_replication_region:173-191`).
- `PulumiSecretsKeys` (`pulumi/infra/pulumi_secrets.py:66`) iterates repos (`:97-151`),
  creating per repo a CMK with rotation + `alias/pulumi-{repo}-{env}-secrets`
  (`:113-139`), key policy = account-root-enables-IAM (`_key_policy`, `:30-45`).

### 2.3 Per-repo deploy roles (the WEAKER role set — KEY DIFFERENCE)
- `GitHubOidcRoles` (`pulumi/infra/iam/github_oidc.py:216`) creates the account OIDC provider
  (`_provider_resource:175-200`) + ONE `PulumiDeploy-{suffix}` role per repo
  (`_create_deploy_role:250-290`).
- Trust is **branch-ref only** via `StringLike sub = repo:{org}/{repo}:ref:refs/heads/{branch}`
  (`_assume_role_policy:92-116`) — NO `pull_request`/`environment:test`/`environment:prod`
  subjects, NO `repository` claim pin, and uses `StringLike` not `StringEquals`.
  This is materially weaker/narrower than the bootstrap's `_deployment_role_subjects`
  (§1.2) and the apply-role trust.
- Policy `_deploy_policy` (`:119-156`): S3 state (`ListBucket` prefix `state/*`, object RW) +
  optional KMS RW on the repo's secrets key ARN. NO automation/management surface, NO read-only
  deny set, NO preview/apply/drift split.

### 2.4 The automation surface (shared by bootstrap apply role) — `pulumi/infra/automation.py`
- `GitHubAutomation` (`:1575`) builds `PulumiAutomation-{repo}-{env}` role + ECR runner repo +
  the large split managed policies (`_automation_policy:774-1182`, grouped/sized by
  `_AUTOMATION_MANAGED_POLICY_GROUPS:26-102`, split in `_automation_policy_documents:1285-1294`).
- The bootstrap apply role reuses these documents via
  `_automation_policy_documents(account_id, settings, settings.repo)`
  (`ci_bootstrap.py:442`). All automation grants are ARN-scoped and tag-conditioned; wildcard
  `Resource:*` appears only for unscopable APIs (e.g. `iam:CreateOpenIDConnectProvider:934-938`,
  `kms:CreateKey:871-876`), which CrossGuard explicitly allows (see §5.2).
- Trust `_automation_assume_role_policy:658-695`: prod→`environment:prod`; else
  branch-ref + `pull_request`, with `repository` claim pinned.

### 2.5 How §2 differs from §1 (the bootstrap)
| Dimension | Bootstrap `GitHubCiBootstrap` (§1) | Main multi-repo `GitHubOidcRoles` (§2) |
| --- | --- | --- |
| Multi-repo | NO (single `repoSlug`) | YES (catalog fan-out) |
| Roles per repo | preview + apply + drift (+triage in test) | ONE `PulumiDeploy-*` |
| Trust subjects | branch + PR + env:test/env:prod, `repository` pinned, `StringEquals` | branch-ref only, `StringLike`, no `repository` pin |
| CI-config secrets | YES (`/{repo}/ci/{suffix}` + read roles) | only when `repoSlug` set (single) |
| Read-only Deny | `secretsmanager:GetSecretValue` only | none |
| Apply surface | full automation managed policies | none |
| State bucket / KMS | references existing | CREATES them |

The generalization target is the UNION: bootstrap's role richness + main project's per-repo
fan-out, parameterized by a governance repo list.

---

## 3. Current-state: PR-comment deploy flow + IaC-only enforcement

### 3.1 PR-comment intake (`.github/workflows/pulumi-pr-commands.yml`)
- Trigger `issue_comment: created` (`:3-6`), concurrency per issue (`:8-10`).
- Parses comment via `scripts/pulumi_pr_comment.py` (`:42-50`).
- Authorization gate: `authorized != 'true'` is rejected (`:56-67`). Authorization is
  association-based, NOT user-based (see §3.4).
- Resolves PR head SHA/repo/state (`:69-83`); rejects closed/merged (`:85-97`) and forked PRs
  (`:99-116`); only same-repo heads proceed.
- Dispatches `repository_dispatch event_type=pulumi-pr-command` with client_payload
  (PR number, head_sha, target_environment, command, comment_id) (`:118-141`), then posts a
  "Queued" comment (`:143-161`).

### 3.2 Trusted runner (`.github/workflows/pulumi-pr-command-runner.yml`)
- Trigger `repository_dispatch: pulumi-pr-command` + `workflow_dispatch` (`:3-30`).
- `preflight` re-validates inputs and RE-CHECKS the live PR head SHA against the queued SHA
  (`:75-129`) — rejects if PR moved/closed/forked.
- Job graph enforces **test-before-prod**:
  `test_preview` → `test_destructive_diff` → `test_iam_validation` → `test_apply`
  (only on `up` or any prod, `:325-330`) → `test_post_apply_drift` →
  `prod_preview` (only if prod AND test drift succeeded, `:446-450`) →
  `prod_destructive_diff` → `prod_iam_validation` → `prod_apply`
  (`environment: prod`, `:649-661`) → `prod_post_apply_drift` → `comment_result`.
- AWS creds via OIDC config roles loaded by `./.github/actions/load-aws-ci-env`
  (action dir confirmed present); preview/apply/drift role ARNs come from the CI-config secret.
- `prod_apply` runs under `environment: prod` (`:661`) — this is the GitHub protected-environment
  hook that the existing `Kravalg` reviewer config protects (see §3.3).

### 3.3 Protected environment + reviewer config (`scripts/configure_github_repository_controls.py`)
- `DEFAULT_PROD_REVIEWER = "Kravalg"` (`:68`). `configure(...)` builds and (with `--apply`)
  PUTs a branch ruleset + `prod` and `operations-alert-reconcile` protected environments
  (`:182-245`), each requiring the single reviewer (`prod_environment_payload:107-109` →
  `protected_reviewer_environment_payload:94-104`: `prevent_self_review=True`,
  `reviewers=[{User,id}]`, protected-branch-only deployments).
- Verification blockers ensure the reviewer is present and self-review prevented
  (`_github_repository_controls.py:266-310`). Requires repo admin (`_repo_admin_allowed:122-128`).
- Required status checks list (`REQUIRED_STATUS_CHECKS`, `_github_repository_controls.py:8-33`)
  includes Preview, Destructive Diff Gate, IAM Validation, Policy, Coverage, Mutation, etc.

### 3.4 IaC-only apply enforcement (`scripts/run_pulumi_command.py`) — REUSABLE
- `_run_up_stack` rejects direct `pulumi up` when `GITHUB_ACTIONS == "true"`
  (`:672-679`): "direct Pulumi up is disabled in GitHub Actions; generate and apply a reviewed
  saved plan". So CI may only apply via `up-plan` (saved plan).
- `up-plan` path validates a signed plan MANIFEST: schema/age/commit-SHA/backend/plan-hash
  (`_validate_plan_manifest:378-397`, entry hash check `:357-375`). Plans are produced by
  `plan` (`_run_plan_command:452-487`) which also writes the manifest (`_write_plan_manifest`).
- Secrets provider must be `awskms://` (`_validate_secrets_provider:92-105`).
- Policy pack is prepared for preview/plan/up/drift (`COMMANDS_WITH_POLICY_PACK:48`,
  `_prepare_policy_pack:108-113`).
- This is the exact mechanism the issue's AC-5 ("IaC-only apply") relies on; it already works for
  the deployment projects and must be REUSED unchanged for the new project's deploy flow.

### 3.5 Comment-command parser (`scripts/pulumi_pr_comment.py`)
- Accepts `/pulumi [test|prod] [plan|up]` (or `pulumi ...`), defaults env to `test`
  (`parse_command:24-40`).
- `AUTHORIZED_ASSOCIATIONS = {OWNER, MEMBER, COLLABORATOR}` (`:9`) →
  `author_is_authorized:43-44` → `authorized` output (`:47-62`). **No concept of a single
  governance approver / @Kravalg gate.** This is the exact gap for AC-4 (see §4.3).

---

## 4. Gap analysis — what is MISSING for issue #77

### 4.1 Generic governance Pulumi project (AC-1, AC-2) — MISSING
- There is NO multi-repo governance project. Today `GitHubCiBootstrap` is single-`repoSlug`
  (`ci_bootstrap.py:808-812`, `__main__.py:26`) and only created for ONE repo per stack.
- MISSING: a project that iterates a governance repo list and, per repo, produces the bootstrap's
  FULL set (preview/apply/drift/config-read roles + OIDC trust + deploy policy scoped to that
  repo's state bucket + KMS key + state bucket + KMS key + config-read role). The richest existing
  per-repo loops live in DIFFERENT components (`GitHubOidcRoles:241-246`,
  `PulumiStateBuckets:327-338`, `PulumiSecretsKeys:97`) — none of them emit the preview/apply/drift
  trio. The trio is only in `GitHubCiBootstrap` and is single-repo. Generalization = lift
  `_role_specs`/`_create_roles`/`CiConfiguration` into a per-repo loop keyed by a governance list.
- MISSING: project scaffold parity — a new `Pulumi.yaml` + per-stack `Pulumi.{test,prod}.yaml`
  in a new project dir, matching the structural-test expectations currently hard-coded for
  `pulumi/github-ci-bootstrap` (`tests/pulumi/test_project_structure.py:51-83`).
- MISSING: "any `-infrastructure` suffix, config-only add" wiring. The catalog model exists
  (`repository_catalog.py`) and `repositories.example.json` already lists
  `user-service-infrastructure`, but it feeds the WEAK `PulumiDeploy-*` model (§2.3), not the
  governance trio.

### 4.2 @Kravalg governance gating — PARTIALLY PRESENT, NOT COMPOSED (AC-3) — MISSING pieces
- **CODEOWNERS: entirely MISSING** (no file in repo). Need a `CODEOWNERS` scoping the governance
  project path + IAM code (`pulumi/infra/iam/`, `pulumi/infra/ci_bootstrap.py`,
  `pulumi/infra/automation.py`, the new project dir, `policy/`) to `@Kravalg`, leaving other
  paths unaffected. The branch ruleset already sets `require_code_owner_review: true`
  (`_github_repository_controls.py:58`), so a CODEOWNERS file is the missing half.
- **Protected governance ENVIRONMENT: MISSING.** `configure_github_repository_controls.py` only
  provisions `prod` + `operations-alert-reconcile` environments (`:224-235`). A new protected
  environment (e.g. `governance`) requiring `@Kravalg` as sole reviewer is not created, and the
  runner's governance apply job would need to declare `environment: <governance>` (today only
  `prod_apply` declares `environment: prod`, runner `:661`).

### 4.3 PR-comment author gate to @Kravalg (AC-4) — MISSING
- `scripts/pulumi_pr_comment.py:9,43-44` authorizes by association, not by login. There is no
  signal of WHICH paths a PR touches, so governance PRs cannot today be restricted to `@Kravalg`
  for `/pulumi ... up`. MISSING: a path-aware + login-aware gate ("if PR touches governance/IAM
  paths, only `@Kravalg` may `/pulumi up`"). The intake workflow does not compute changed paths
  (`pulumi-pr-commands.yml` has no diff step), and the parser has no login input
  (only `--author-association`, `:81-83`).
- The runner already enforces test-then-prod and success-before-merge mechanics
  (`pulumi-pr-command-runner.yml` job graph §3.2), so AC-4's "run test then prod, require success"
  is satisfied; only the AUTHOR restriction for governance PRs is missing.

### 4.4 IaC-only apply for the new project (AC-5) — REUSE, minor wiring
- `run_pulumi_command.py:672-679` already blocks direct `up` in CI. The new governance project
  must route through the same `make pulumi-plan` / `make pulumi-up-plan` path so this guard
  applies. MISSING: CI workflow wiring for the new project's `PULUMI_DIR` (the bootstrap project
  is currently NOT wired into CI at all — §1.1), plus per-stack secrets-provider env.

### 4.5 `user-service-infrastructure` repo creation + scaffolding + self-deploy (AC-6) — MISSING
- The repo does not exist in `VilnaCRM-Org` (operator action). MISSING deliverables: generic infra
  scaffolding for that repo (its own `pulumi/` + `Pulumi.{test,prod}.yaml`), and a self-deploy
  workflow that assumes the bootstrap-provided roles. `repositories.example.json:5-12` already has
  the metadata to seed it. There is no template/scaffold generator in `scripts/` for a new
  service-infra repo (verified by `scripts/` listing).

### 4.6 Least-privilege Deny set (AC-7) — PARTIALLY PRESENT
- Only `secretsmanager:GetSecretValue` is denied today (`ci_bootstrap.py:372-377`). MISSING explicit
  Deny for: `kms:Decrypt`, `ssm:GetParameter*`, `lambda:GetFunction`, `ec2:GetPasswordData`,
  `*:GetAuthorizationToken` (e.g. `ecr:GetAuthorizationToken`), `sts:GetSessionToken`,
  `cognito-identity:Get*`. NOTE conflict: the read-only ALLOW list currently INCLUDES
  `kms:Get*`/`kms:Describe*` (`:82-84`) and `ecr:Get*` (`:73-74`) — a Deny of `kms:Decrypt`/
  `*:GetAuthorizationToken` would need to coexist (Deny wins), and the deploy backend policy
  legitimately needs `kms:Decrypt` on the secrets key (`_PULUMI_KMS_ACTIONS:45-51`), so the Deny
  must be scoped to the read-only roles, not the apply/deploy roles. This is the subtlest gap.
- "No wildcard Allow on deployment roles": the apply role's automation policies already avoid
  `Action:*` and use ARN-scoped resources (`docs/github-ci-bootstrap-stack.md:51-55`); the
  unscopable `Resource:*` cases are CrossGuard-exempt (§5.2). The new deploy roles must keep this.

### 4.7 Tests + 100% combined coverage (AC-8) — MISSING for new surface
- Existing tests deeply cover the foundation: `tests/unit/test_components.py` references
  `GitHubCiBootstrap`/`CiConfiguration`/`GitHubOidcRoles`/`deploy_role`/`managed_repositor*`
  81 times; structural tests assert the bootstrap project shape
  (`tests/pulumi/test_project_structure.py:51-83`, doc presence `:452,471,530`). MISSING: tests for
  the new governance project (trust scopes, per-repo expansion, policy contents, naming, gating
  contract), and parity coverage so the 100% combined-coverage gate
  (`AGENTS.md:21`, Makefile `test-coverage:234`) stays green.

---

## 5. Constraints, quality-gate surface, and risk catalog

### 5.1 Quality-gate surface every change must pass (`AGENTS.md`, `Makefile`, `pyproject.toml`)
- ruff (format+lint, max-complexity 12), mypy, ty (Astral strict), import-linter, deptry, bandit,
  pip-audit, gitleaks — run via `make ci-pr` (`Makefile:591`) and the python-quality / security
  workflows. Coverage gate `make test-coverage` (`:234`) expects 100% combined branch coverage
  (`AGENTS.md:21`). Mutation `make test-mutation` (`:345`). Structural `tests/pulumi/`. Policy
  `make test-policy` (`:192`). IAM validation `make test-iam-validation` (`:299`).
- **IMPORTANT naming correction:** there is NO `scripts/validate_iam_policies.py`. IAM Access
  Analyzer validation is `scripts/pulumi_ci_guardrails.py validate-iam <preview_files...>`
  (`:298,507-508,550-561,643-644`); it fails on findingTypes `{ERROR, SECURITY_WARNING}`
  (`:32,410-412`) using `access-analyzer:ValidatePolicy` (which the preview role already allows,
  `ci_bootstrap.py:53`). Plan accordingly.
- **import-linter scope gotcha:** `root_packages = ["app", "policy"]` only
  (`pyproject.toml:120`). The `infra` package and the `github-ci-bootstrap`/new project dirs are
  NOT currently governed by import-linter contracts. The constraint mentions
  "infra/policy_pack/scripts separation" — that separation is enforced by directory convention +
  the app/policy contracts (`:123-181`), not by an `infra` contract. Any new governance code under
  `pulumi/infra/` inherits no import-linter contract today (gap to confirm with architect).
- CrossGuard pack registered policies: required-default-tags, region-allowlist,
  s3-no-public-exposure, critical-storage-encrypted, logging-enabled, **iam-no-wildcards**
  (MANDATORY, `policy/pack.py:201-206`), production-database-safety, security-group ports
  (`policy/pack.py:171-216`).

### 5.2 CrossGuard wildcard rule confirms the "Deny is exempt" constraint
- `wildcard_iam_violations` (`policy/guardrails.py:412-442`) → per-statement
  `_statement_contains_wildcard_permissions` (`:711-727`) which **returns False unless
  `Effect == "Allow"`** (`:713-715`). So `Effect: Deny` statements with `Resource:*` are exempt
  exactly as the constraint states.
- Unscopable `Resource:*` Allow is permitted only for a fixed action allowlist
  (`_UNSCOPABLE_RESOURCE_WILDCARD_ACTIONS:580-601`) and some require tag conditions
  (`_RESOURCE_WILDCARD_ACTION_REQUIRED_CONDITION_KEYS:604-...`). S3-bucket-policy and KMS-key
  resource policies are document-exempt (`_wildcard_iam_document_exempt:567-577`).
- The former name-only allowlist and `AllowWildcardIam` tag bypasses have been removed.
  Platform exceptions require exact identity and reviewed full-document SHA256 pins
  (`docs/reviewed-iam-policies.md`). Governance and service roles use no such exceptions,
  preserving NFR5 through scoped permissions and AWS-required unscopable actions.

### 5.3 Test mocks available (for TDD parity) — `tests/conftest.py`
- Session-scoped Pulumi mocks cover S3 bucket, IAM role/policy, OIDC provider, ECR repo, KMS
  key/alias, Secrets Manager secret, etc. (`tests/conftest.py:33-58`), with deterministic ARNs
  (e.g. roles → `arn:aws:iam::123456789012:role/{name}`, `:73-75`). New governance components can
  be unit-tested with the same fixtures.

### 5.4 RISK catalog
- **R1 (CRITICAL — account-model contradiction):** The hard constraint says SINGLE account
  `891377212104`, test/prod as STACKS. But the live config and docs encode TWO accounts:
  `pulumi/Pulumi.prod.yaml:6` and the bootstrap prod stack reference prod account
  `933245420672` (cost-anomaly ARN), and `docs/github-ci-bootstrap-stack.md:75-76` literally states
  "test → `891377212104`; prod → `933245420672`". The bootstrap's secrets providers and stacks are
  also per-environment (`Pulumi.test.yaml`/`Pulumi.prod.yaml`). If the governance stack must live in
  ONE account with test/prod as stacks, the existing two-account assumptions (alias suffixes
  `-{env}`, account-scoped ARNs, `_default_secrets_provider:571-576`) need reconciliation. MUST be
  resolved by architect before design; do not assume.
  - **RESOLVED (user-confirmed 2026-06-13):** two-account model is correct (test `891377212104`,
    prod `933245420672`); the single-account framing was an erroneous inherited constraint.
    Component code stays account-parametric.
- **R2 (trust-model divergence):** Two incompatible trust shapes coexist — bootstrap uses
  `StringEquals` + `repository` pin + per-suffix subjects (`ci_bootstrap.py:260-289`); the main
  `PulumiDeploy-*` uses `StringLike` branch-only with no `repository` pin
  (`github_oidc.py:92-116`). Unifying on the stronger shape may change existing role trust and
  require import/replace handling.
- **R3 (Deny vs Allow collision):** The required Deny set overlaps with currently-Allowed read
  actions (`kms:Get*`, `ecr:Get*`) and with the deploy backend's needed `kms:Decrypt`
  (`ci_bootstrap.py:45-51,82-84`). The Deny must be applied only to read-only (preview/drift/
  config-read) roles, never the apply/deploy backend, or applies will break.
- **R4 (CODEOWNERS coverage drift):** With no CODEOWNERS today and
  `require_code_owner_review:true` already in the ruleset, adding a CODEOWNERS that scopes only
  governance/IAM paths to @Kravalg must NOT accidentally require @Kravalg on unrelated paths
  (issue AC-3: "other paths unaffected").
- **R5 (single-approver bus factor / self-review):** `@dmytrocraft` opens PRs, `@Kravalg`
  approves; `prevent_self_review:True` (`_github_repository_controls.py:99`) means @Kravalg cannot
  also be the PR author for governance applies — operationally fine, but the runner author-gate
  must allow @dmytrocraft to OPEN while restricting `/pulumi up` approval/trigger to @Kravalg.
- **R6 (structural-test brittleness):** `tests/pulumi/test_project_structure.py` hard-codes
  `github-ci-bootstrap` project name/keys/doc paths (`:51-83,452,471,530`). A new project +
  generalization may require updating these structural assertions in lockstep.
- **R7 (coverage cliff):** 100% combined branch coverage is enforced; large new IAM/policy code
  needs exhaustive tests or the gate fails (`AGENTS.md:21`, `Makefile:234`).
- **R8 (import-linter blind spot):** New governance code in `pulumi/infra/` has no import-linter
  contract today; the "infra/policy_pack/scripts separation" the constraint cites is convention +
  app/policy contracts, not an `infra` contract (`pyproject.toml:119-181`). Confirm intended
  enforcement with architect.

---

## 6. Operator-only manual steps vs pure code/IaC/docs deliverable now

### 6.1 Operator-only (needs AWS admin or GitHub org-admin) — NOT deliverable as code now
- **One-time `AdministratorAccess` apply of the governance bootstrap per stack** (test, then prod)
  — operator/@Kravalg runs locally or via the gated PR-comment path. Direct `pulumi up` is
  permitted ONLY for this local bootstrap step (`docs/github-ci-bootstrap-stack.md:78-122`,
  and `run_pulumi_command.py:672-679` blocks it only when `GITHUB_ACTIONS=true`).
- **GitHub branch-protection + protected governance ENVIRONMENT required-reviewer (@Kravalg)
  configuration** — requires repo/org admin token (`_repo_admin_allowed`,
  `configure_github_repository_controls.py:122-128,186-190`). Deliver as documented `gh api`
  payloads via the existing `--dry-run`/`--apply` script extended for a governance environment.
- **Creating the `user-service-infrastructure` repo in `VilnaCRM-Org`** and the real `git push`
  of scaffolding — needs org-admin/repo-create + write creds (issue "Out of scope",
  `.tmp/governance-issue.md:37-41`).
- **Setting GitHub repo variables** from `githubVariables`/governance outputs
  (`docs/github-ci-bootstrap-stack.md:143-152`) — needs `gh variable set` write access.
- **Real AWS applies** (test then prod) and capturing real ARNs/outputs — needs operator creds.

### 6.2 Pure code / IaC / docs — DELIVERABLE NOW (no live creds)
- The generic governance Pulumi project/component code (Python `ComponentResource`), its
  `Pulumi.yaml` + per-stack config, generalized from `GitHubCiBootstrap`/`CiConfiguration`.
- The `CODEOWNERS` file scoping governance/IAM paths to `@Kravalg`.
- The PR-comment author-gate enhancement (path-aware + login-aware) in
  `scripts/pulumi_pr_comment.py` + intake workflow changes, plus governance `environment:` wiring
  in the runner.
- Extending `configure_github_repository_controls.py` to emit a governance protected-environment
  payload (deliver the payload + docs; apply is operator).
- The least-privilege Deny set added to read-only/config-read roles (scoped per R3).
- `user-service-infrastructure` scaffolding files + self-deploy workflow templates (in-repo as
  template assets) and the catalog entry (`repositories.example.json` already has it).
- The `AGENTS.md` onboarding-flow documentation (the 5-step PR A/B/C flow,
  `.tmp/governance-issue.md:15-23`).
- All unit/structural/policy tests, dry-run previews, and updated docs (incl. reconciling
  `docs/github-ci-bootstrap-stack.md` account model per R1).

---

## 7. Authoritative current-state inventory (quick reference)

| Concern | Exists today? | Location |
| --- | --- | --- |
| Single-repo preview/apply/drift roles | YES | `pulumi/infra/ci_bootstrap.py:447-551` |
| Per-suffix trust (test-pr/test/prod-preview/prod) | YES | `ci_bootstrap.py:244-257`, `ci_config.py:92-107` |
| CI-config secrets + read roles | YES (single repo) | `pulumi/infra/ci_config.py:251-362` |
| Multi-repo state buckets + KMS | YES | `pulumi_state.py:289`, `pulumi_secrets.py:66` |
| Multi-repo deploy roles (weak) | YES | `pulumi/infra/iam/github_oidc.py:216-329` |
| Repo catalog / config-only add | YES | `repository_catalog.py:73-131`, `repositories.example.json` |
| Generic GOVERNANCE project (rich trio per repo) | **NO** | — |
| CODEOWNERS | **NO** | (none in repo) |
| Protected `prod` env + @Kravalg reviewer | YES | `configure_github_repository_controls.py:68,224-235` |
| Protected GOVERNANCE env | **NO** | — |
| PR-comment intake + trusted runner | YES | `pulumi-pr-commands.yml`, `pulumi-pr-command-runner.yml` |
| test-then-prod + success-before-merge | YES | `pulumi-pr-command-runner.yml:325-731` |
| Author gate = association (not @Kravalg) | YES (gap) | `scripts/pulumi_pr_comment.py:9,43-44` |
| IaC-only apply (block direct `up` in CI) | YES (reuse) | `scripts/run_pulumi_command.py:672-679` |
| Saved-plan manifest validation | YES | `run_pulumi_command.py:378-397` |
| CrossGuard `Deny`-exempt wildcard rule | YES | `policy/guardrails.py:711-727` |
| IAM Access Analyzer validation | YES (`validate-iam`) | `scripts/pulumi_ci_guardrails.py:298,550` |
| Full secret-read Deny set | **PARTIAL** (only GetSecretValue) | `ci_bootstrap.py:372-377` |
| `user-service-infrastructure` repo/scaffold | **NO** | metadata only in `repositories.example.json` |
| AGENTS.md onboarding flow doc | **NO** | `AGENTS.md` (no onboarding section) |

---

## 8. Open questions for the architect (must resolve before design)

1. **Account model (R1):** Single account `891377212104` with test/prod as stacks vs the live
   two-account config/docs (`933245420672`). Which is authoritative for the governance stack?
2. **Project shape:** New separate Pulumi project dir (parity with `pulumi/github-ci-bootstrap`)
   vs folding the governance loop into the existing bootstrap project as a multi-repo mode?
3. **Trust unification (R2):** Migrate `PulumiDeploy-*` to the stronger bootstrap trust shape, or
   keep them separate and only enrich the governance project?
4. **Deny scoping (R3):** Confirm the secret-read Deny applies only to preview/drift/config-read
   roles and never to apply/deploy backend roles.
5. **CODEOWNERS precision (R4):** Exact governance/IAM path globs that must map to `@Kravalg`
   without affecting unrelated paths.
6. **Author gate mechanism (§4.3):** Compute changed paths in intake + add `--author-login` to
   `pulumi_pr_comment.py`, or enforce purely via a governance protected-environment reviewer?
7. **import-linter (R8):** Should new governance `infra` code get its own import-linter contract?
