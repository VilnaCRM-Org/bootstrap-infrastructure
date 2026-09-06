# AWS Well-Architected Review

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

Scope: issue [#77](https://github.com/VilnaCRM-Org/bootstrap-infrastructure/issues/77)
— the multi-repo IAM/OIDC governance stack (`GovernanceStack` / `RepoGovernance`)
that mints per-repo OIDC deploy/preview/apply/drift roles, repo-scoped
least-privilege policies, per-repo state-bucket + KMS isolation, and @Kravalg
gating for every `*-infrastructure` service repo.

This is an engineering review against the AWS Well-Architected Framework's six
pillars, not an AWS Well-Architected Tool workload review. It assesses the
**design and the code/IaC deliverables** specified for this increment; it does
**not** claim anything has been applied to AWS. By design, the live applies
(one-time `pulumi up`, protected-environment `PUT`, repo creation, per-account
OIDC-ARN pinning, real gated applies) are operator-only steps outside the
implementer loop (architecture §10, readiness "Operator-only manual steps").

Source references:

- https://aws.amazon.com/architecture/well-architected/
- https://docs.aws.amazon.com/wellarchitected/latest/framework/welcome.html
- https://docs.aws.amazon.com/wellarchitected/latest/framework/sec-design.html
- https://docs.aws.amazon.com/wellarchitected/2022-03-31/framework/oe-design-principles.html
- https://docs.aws.amazon.com/wellarchitected/latest/framework/sus-design.html

Primary design inputs:

- `specs/issue-77-multi-repo-governance/architecture.md` (the implementable design)
- `specs/issue-77-multi-repo-governance/implementation-readiness-report.md`
  (21 dispositioned adversarial findings + residual risks)

## Score Summary

Scores are engineering judgements against this bootstrap/governance repo's
context, not an automated AWS tool result. The "PR (design + code deliverables)"
column reflects the design as specified and the component code already on the
`feat/multi-repo-governance` branch; the "operator-completed" column is the
target once the operator-only steps (§10) are executed with current evidence.

| Pillar | `main` (no governance stack) | PR (design + code deliverables) | Operator-completed target | Rationale |
| --- | ---: | ---: | ---: | --- |
| Operational Excellence | 3.4 | 4.2 | 4.5 | Config-only repo onboarding, an account-parametric component family with a golden parity gate, a documented onboarding flow + operator runbook, and a labeled break-glass; residual bus-factor on the sole approver. |
| Security | 3.5 | 4.4 | 4.6 | Per-repo OIDC trust pinned with `StringEquals` repository claim, env-bound apply trust, repo-scoped least-privilege with secret-read Deny sets, per-repo state/KMS isolation, defense-in-depth gating; residual within-account cross-repo IAM blast radius (accepted) and KMS concrete-key-ARN follow-up. |
| Reliability | 3.5 | 4.0 | 4.2 | Per-repo state-bucket + replica and per-repo KMS keys isolate failure domains; saved-plan/drift reuse; per-catalog-kind quota-headroom report; DR drills + state restore remain operator evidence. |
| Performance Efficiency | 3.0 | 3.6 | 3.8 | Deterministic per-repo fanout with a governance-specific quota model and IAM length guards; managed services only; no runtime hot path in this control-plane repo. |
| Cost Optimization | 3.0 | 3.4 | 3.6 | Reuse of existing budget/anomaly resources, per-stack cost-anomaly-ARN account verification, tag-bearing resources; per-repo bucket/KMS growth needs the FinOps refresh on catalog growth. |
| Sustainability | 2.7 | 2.9 | 3.1 | Pinned `eu-west-1` paired replica region, reuse-over-create for the OIDC provider, lifecycle inheritance; sustainability is not yet a first-class requirement for this control plane. |

Overall (engineering): `main` ~3.2 / PR design+code ~3.75 / operator-completed
target ~4.0.

## Account & Blast-Radius Model (load-bearing for every pillar)

Two AWS accounts, region `eu-central-1`:

- `test` stack → account `891377212104`
- `prod` stack → account `933245420672`

The test and prod stacks map to **separate accounts**, so the test↔prod blast
radius is isolated at the account boundary (AWS best practice — a compromised
test apply role cannot touch the prod account at all). The component code is
**account-parametric**: there is no hardcoded account literal in
`pulumi/infra/*.py`. Each stack asserts the live
`aws.get_caller_identity().account_id` equals its **per-stack** configured
`governance:awsAccountId` and raises otherwise — the literal lives only in
`pulumi/governance/Pulumi.{test,prod}.yaml`, never in component code
(architecture §0/D1, §2.2; readiness FR21; account assertion implemented in
`pulumi/infra/governance.py` `_resolve_oidc_provider_arn` / account-assert path,
`raise ValueError` at `governance.py:533`).

This model is the reason SECURITY-7 (cross-account blast radius) is downgraded
to the narrower within-account cross-repo IAM residual risk (readiness §"Residual
risks" item 1).

---

## Operational Excellence

### Design decisions

- **Config-only repo onboarding (FR1/FR8).** Adding a governed
  `*-infrastructure` repo is a single edit to
  `pulumi/repositories.governance.json`; the multi-repo loop is built from the
  same generalized component code in `pulumi/infra/` (architecture §2.3, §3).
  No Python changes are needed to onboard a repo — a structural test asserts
  that a 1-repo vs 2-repo catalog produces no diff in `pulumi/governance/`
  Python (architecture §9.1, FR1).
- **One generalized component family, thin project entrypoints.** All reusable
  logic lives in `pulumi/infra/` (`governance.py`, lifted `ci_bootstrap.py`
  helpers); the `governance/__main__.py` entrypoint is thin (architecture §1).
- **NFR6 backward-compat protected by a golden parity gate, not a vague "tests
  unchanged" claim.** The single-repo `bootstrap-infrastructure` rendered role
  names, trust JSON, and policy JSON are captured as a byte-equal golden fixture;
  the refactor to a single `_BootstrapBuildContext` (`ci_bootstrap.py:174`,
  extended with `repo`/`project`) must reproduce it byte-for-byte (architecture
  §3.1; readiness NFR6/FEASIBILITY-4; the lift is committed — `ci_bootstrap.py`
  threads `_BootstrapBuildContext` through `_create_role`/`_create_roles`).
- **Documented onboarding flow + operator runbook (FR17/FR18).** Every step is
  labeled CODE vs OPERATOR; the operator runbook enumerates the one-time apply,
  the OIDC-ARN pin, the protected-environment PUT, repo creation, variable
  setting, and the audited break-glass (architecture §10, §11).
- **IaC-only apply (FR16).** No human `pulumi up` in CI: the governance workflow
  runs `make pulumi-plan` + `make pulumi-up-plan` (saved-plan only) with
  `PULUMI_DIR=pulumi/governance`; a direct `make pulumi-up` under
  `GITHUB_ACTIONS=true` hits the existing reject at
  `scripts/run_pulumi_command.py:672-679`. The only permitted direct
  `pulumi up` is the operator's one-time local bootstrap (architecture §6, §10.2).
- **Deterministic, length-guarded naming.** All resource names derive from the
  full sanitized repo slug + env via existing helpers that **raise rather than
  truncate** past the 64-char IAM limit; the canonical `{project}` source is one
  value used by both the deploy trio and config-read roles (architecture §4;
  readiness AWS-SRE-4).

### How it satisfies the pillar

Operations as code, small reversible changes (config-only onboarding), and
documented runbooks are the core OpEx tenets. The golden parity gate makes the
single-repo regression a CI failure rather than a production surprise. The
required-status-check wiring posts a real commit status to the approved head SHA
so the merge gate is a genuine signal, not a phantom "expected, waiting" check
(architecture §7.5; readiness FEASIBILITY-1).

### Evidence / where enforced

| Control | Evidence |
| --- | --- |
| Config-only onboarding | `pulumi/repositories.governance.json` (catalog); 1-vs-2-repo no-diff test (architecture §9.1 FR1) |
| Generalized component | `pulumi/infra/governance.py` (`GovernanceStack`, `RepoGovernance`); lifted helpers in `pulumi/infra/ci_bootstrap.py` |
| Golden parity (NFR6) | byte-equal golden fixture, E1.S2 (architecture §3.1); single `_BootstrapBuildContext` at `ci_bootstrap.py:174` |
| Runbook / onboarding | architecture §10, §11; `AGENTS.md` + `docs/governance-stack.md` (FR17/FR18) |
| IaC-only apply | `make pulumi-up-plan`; reject at `scripts/run_pulumi_command.py:672-679`; `pulumi-governance.yml` (FR16) |
| Naming guards | `_ci_role_name` raises >64 chars (`ci_bootstrap.py:268`); catalog length guard in `validate_repository_catalogs.py` (architecture §4) |
| Required-check resolves | runner posts `gh api .../statuses/{head_sha}` context `"Governance Apply"` (architecture §7.5) |

### Residual risk

- **Bus factor / single approver.** @Kravalg is the sole reviewer with
  `prevent_self_review: true` (`_github_repository_controls.py:98`); if
  unavailable, no governance apply can proceed. Mitigated — not eliminated — by
  the documented, audited break-glass (architecture §10.2 step 7; readiness
  residual risk 4): a time-boxed temporary second reviewer (org-admin, logged,
  reverted) or an operator-local hardware-MFA admin apply with role-diff.
- **Wiring layer still to be delivered.** The component family
  (`governance.py`) is committed, but the governance Pulumi project, catalog,
  CODEOWNERS, `pulumi-governance.yml`, and scaffold are pending in this branch;
  the runbook steps cannot be exercised end-to-end until they land and the
  operator completes §10.

---

## Security

### Design decisions

- **Per-repo OIDC trust with a pinned `repository` claim (FR2).** Each
  preview/apply/drift role trusts `sts:AssumeRoleWithWebIdentity` only from the
  shared per-account OIDC provider with `StringEquals` on
  `token.actions.githubusercontent.com:repository == org/repo` plus
  per-purpose `sub` subjects (architecture §5.1).
- **Apply trust bound to the protected environment (closes SECURITY-2).** The
  governance `apply` role does **not** reuse the bare branch-ref subject; both
  the test-stack and prod-stack apply roles trust **only**
  `repo:org/repo:environment:governance`, which GitHub mints solely after
  @Kravalg approves the protected `governance` environment. The IAM trust and
  the GitHub reviewer gate are no longer decoupled (architecture §5.1a;
  implemented `_governance_apply_subjects` at `governance.py:101`).
- **Repo-scoped least privilege, no wildcard Allow (FR3/FR23).** The deploy /
  pulumi-backend policy is scoped to exactly this repo's bucket ARN and this
  repo's KMS alias; the KMS `Resource` is region-pinned to `eu-central-1` (no
  region wildcard); ARNs interpolate `{account_id}` (no literal). The
  platform-bootstrap alias is **removed** from per-repo deploy policies and
  reserved for the governance stack's own apply role, so no service repo can
  decrypt the platform master key or another repo's secrets (architecture
  §5.2; implemented `_governance_backend_policy_document` at `governance.py:117`
  with `include_platform_bootstrap=False`; closes AWS-SRE-1). The only
  `Resource:*` Allow is `sts:GetCallerIdentity`, which is CrossGuard-exempt
  (`policy/guardrails.py:599`).
- **Secret-read Deny sets (FR22).** Deny wins over broad read Allows and is
  CrossGuard-exempt (`policy/guardrails.py:711-715`). Three placements:
  - read-only (preview/drift) policy carries the full Deny including
    `secretsmanager:GetSecretValue` and `kms:Decrypt`
    (`ci_bootstrap.py:473`, `DenySecretLeakingReads`);
  - config-read policy carries the Deny **without** `secretsmanager:GetSecretValue`
    (else it would void the role's own purpose) (`ci_config.py:270`);
  - the **apply** role carries a surgical Deny (`DenySecretLeakingReadsApply`,
    `ci_bootstrap.py:544`) on
    `secretsmanager/ssm/ec2/lambda/ecr-auth/sts/cognito` reads **except** its own
    `/{project}/ci/*` CI secret via `NotResource`, while deliberately keeping
    `kms:Decrypt` on its own scoped key (architecture §5.2a/§5.3; closes
    SECURITY-5).
- **Per-repo state + KMS isolation (FR5/FR6).** Each repo gets its own
  `pulumi-{repo}-{env}-state` bucket (+ replica) and its own
  `alias/pulumi-{repo}-{env}-secrets` KMS key; repo A's deploy role cannot reach
  repo B's bucket or key (architecture §3.2, §5.2; `state_bucket_name_for_repo`
  `bootstrap_settings.py:220`, `pulumi_secrets_alias_name_for_repo:254`).
- **OIDC provider consumed, never created (FR7, closes AWS-SRE-2).** The
  governance stack consumes its account's OIDC provider by pinned ARN via
  `.get()` (zero create branch) and **raises** if the ARN is unset, so two
  stacks never race to own one physical provider (architecture §3.2 step 2;
  `_resolve_oidc_provider_arn` at `governance.py:523`, `raise` at `:533`).
- **Defense-in-depth gating (FR10–FR15).** CODEOWNERS scopes all
  credential-bearing / trust-or-scope-altering code to @Kravalg with no
  catch-all line; the path-aware author gate in `scripts/pulumi_pr_comment.py`
  rejects governance `up` unless the author is @Kravalg; the trusted runner
  re-derives the author from `comment_id` and recomputes scope server-side
  (all `client_payload` untrusted, `workflow_dispatch` dropped); the protected
  `governance` environment is the hard reviewer backstop; and
  `dismiss_stale_reviews_on_push` + `require_last_push_approval` bind the
  approval to the exact approved diff (architecture §7; closes SECURITY-1/3/4).

### How it satisfies the pillar

This is identity-foundation + least-privilege + defense-in-depth: short-lived
OIDC credentials (no static keys), repository-pinned trust, per-repo blast-radius
isolation for state and secrets, Deny guardrails that survive even a
review-passing malicious PR on the apply path, and a multi-layer human gate whose
final authority lives in the trusted runner that assumes credentials rather than
in attacker-controllable inputs. @dmytrocraft may open PRs and run read-only
`plan`; only the governance `up` is gated to the sole approver @Kravalg.

### Evidence / where enforced

| Control | Evidence |
| --- | --- |
| Repository-pinned trust (FR2) | `StringEquals … :repository` (architecture §5.1); `test_governance.py` subject assertions |
| Env-bound apply trust (FR2/§5.1a) | `_governance_apply_subjects` → `environment:governance` only (`governance.py:101`) |
| Repo-scoped deploy policy (FR3) | `_governance_backend_policy_document` (`governance.py:117`); A≠B isolation test; **no `pulumi-platform-bootstrap`** in service docs |
| No wildcard Allow (FR23) | only exempt `sts:GetCallerIdentity` `Resource:*` (`guardrails.py:599`); `make test-policy` zero `iam-no-wildcards` |
| Secret-read Deny (FR22) | read-only `ci_bootstrap.py:473`; config-read `ci_config.py:270`; apply surgical `ci_bootstrap.py:544` |
| State/KMS isolation (FR5/FR6) | `bootstrap_settings.py:220`, `:254`; per-repo `PulumiStateBuckets`/`PulumiSecretsKeys` (architecture §3.2) |
| OIDC consume-not-create (FR7) | `.get()` only; raise if unset (`governance.py:523-533`); structural no-create test |
| CODEOWNERS → @Kravalg (FR10) | `.github/CODEOWNERS` glob set (architecture §7.1); drift-equality test vs `GOVERNANCE_PATH_GLOBS` |
| Author + runner re-check (FR13) | `author_is_authorized` (architecture §7.3); runner re-derives author from `comment_id` (architecture §7.2) |
| Protected env (FR11) | `protected_reviewer_environment_payload` (`_github_repository_controls.py:94`, `prevent_self_review:true` `:98`) |
| Approval-bound-to-diff (SECURITY-3) | `dismiss_stale_reviews_on_push`/`require_last_push_approval` (architecture §7.6; flags currently `False` at `_github_repository_controls.py:57-59` — flip pending E2.S2) |

### Residual risk

- **Within-account cross-repo IAM blast radius (accepted — readiness residual
  risk 1, SECURITY-7).** FR3 isolation holds for state buckets and KMS keys but
  **not** for account-global automation IAM grants shared by same-account apply
  roles (e.g. `iam:CreateOpenIDConnectProvider`, `kms:CreateKey` — CrossGuard-exempt
  `Resource:*` Allows). Two repos in the same account (e.g. repoA-prod and
  repoB-prod, both in `933245420672`) share these. Materially lower than
  originally framed because test↔prod are isolated by separate accounts.
  *Recommended (non-blocking) hardening:* `aws:RequestTag`/`aws:ResourceTag`
  binding of created IAM/KMS to the repo, plus a test that repo A's apply role
  cannot `iam:PutRolePolicy`/`iam:AttachRolePolicy` on same-account
  `GitHubCi*-{repoB}-*` roles (architecture §10 residual-risk note).
- **KMS concrete-key-ARN follow-up (readiness residual risk 2, S-KMS).** Until
  the stack plumbs the concrete per-repo key ARN into the deploy `Resource`, the
  `kms:ResourceAliases` condition is the primary control. It is already hardened
  (region-pinned; no alias-mutation grant on repo keys, so the condition cannot
  be self-satisfied by re-aliasing an attacker key), but scoping `Resource` to
  the concrete key ARN is a recommended follow-up (architecture §5.2).
- **`*:GetAuthorizationToken` coverage (readiness residual risk 3).** The Deny
  enumerates `ecr:GetAuthorizationToken`; if another token-vending service
  (e.g. CodeArtifact) enters the account, the Deny must be extended — a test
  flags new `*:GetAuthorizationToken`-style Allows (non-blocking watch item).
- **Single-source glob maintenance (readiness residual risk 5).** The
  CODEOWNERS↔`GOVERNANCE_PATH_GLOBS` equality test prevents two-list drift, but a
  newly created credential-bearing module must still be added to CODEOWNERS;
  periodic review is advised.

---

## Reliability

### Design decisions

- **Per-repo failure-domain isolation (FR5/FR6).** Each governed repo has its
  own state bucket + cross-region replica and its own KMS key; corruption,
  throttling, or a destructive change in one repo's state does not affect
  another's (architecture §3.2).
- **Explicit, allowlisted replication region.** The replica region is pinned to
  `eu-west-1` per stack rather than relying on a default
  (`governance:replicationRegion: eu-west-1`, architecture §2.2; a test asserts
  the replication region equals `eu-west-1`, architecture §9.1 FR5/FR6).
- **Saved-plan integrity + drift reuse.** Applies go through the existing
  saved-plan manifest validation (stack/backend/SHA/SHA-256) and post-apply
  drift checks unchanged — they are `PULUMI_DIR`-agnostic (architecture §6;
  `run_pulumi_command.py` plan-manifest validation). The plan-manifest commit
  SHA is asserted to equal the approved head SHA (architecture §7.6).
- **Per-catalog-kind quota model with a headroom report (closes AWS-SRE-6).**
  `validate_repository_catalogs.py` applies a governance-specific fanout
  (no central-stack resources; ~6–8 IAM roles/repo/env; ~7 managed policies/repo)
  and an account-quota headroom report against AWS defaults (1000 roles, 1500
  managed policies, 10 managed-policies-per-role) for the plausible ~30-repo
  fleet; raising governance limits does not loosen the deployment-catalog guard
  (architecture §9.2).
- **Determinism (NFR7).** All policy JSON uses `json.dumps(sort_keys=True)` and
  names come from deterministic helpers, so saved plans validate byte-stably
  across runs (architecture §9.5).

### How it satisfies the pillar

Isolated failure domains per repo, an explicitly chosen and validated DR region,
saved-plan integrity tying applies to a verified diff, and a quota-headroom model
that prevents the fanout from silently exhausting account limits all support the
"anticipate failure / limit blast radius / manage change" reliability tenets.

### Evidence / where enforced

| Control | Evidence |
| --- | --- |
| Per-repo state + replica (FR5) | `test_governance.py`: primary+replica per repo/env (architecture §9.1) |
| Per-repo KMS key (FR6) | `test_governance.py`: 1 key + alias, rotation, deterministic |
| Replica region pinned | `governance:replicationRegion: eu-west-1` (architecture §2.2); FR5/FR6 region assertion |
| Saved-plan integrity | `run_pulumi_command.py` plan-manifest validation; plan-SHA == approved-SHA (architecture §7.6) |
| Quota-headroom report | governance fanout in `validate_repository_catalogs.py` (architecture §9.2) |
| Determinism (NFR7) | `sort_keys=True` snapshots (architecture §9.5) |

### Residual risk

- **State restore drill + RTO/RPO are operator evidence.** Replication exists,
  but a documented restore drill for the per-repo Pulumi state buckets and
  explicit RTO/RPO targets are operator/owner evidence not produced by this
  code increment (consistent with the issue-17/18 reviews' standing gap).
- **Backup Vault Lock / WORM for state** is not in scope for this increment.
- **Account-quota proof is a model, not a live check.** The headroom report
  validates against AWS default limits; the live account's actual limits/usage
  remain an operator verification.

---

## Performance Efficiency

### Design decisions

- **Bounded, deterministic per-repo fanout.** For N catalog repos the stack
  renders exactly 3N deployment roles plus a fixed per-repo set of config-read
  roles, one state bucket (+replica), and one KMS key — a known, linear resource
  count with a governance-specific quota model and a headroom report (architecture
  §9.2).
- **IAM name-length guard at validation time.** Repos whose
  `sanitize_bucket_component(name) + "-prod-preview"` would exceed 64 chars are
  rejected at catalog validation, not at apply time — failures surface in CI, not
  mid-deploy (architecture §4; closes FEASIBILITY-4).
- **Control-plane only, managed services.** This is an IAM/OIDC control plane;
  there is no application runtime hot path. S3 + KMS + IAM are managed services
  with no capacity tuning required for this workload.
- **Mock-renderable, account/region-parametric documents** let the full test
  suite render every policy under the session Pulumi mocks without live
  credentials, keeping the CI feedback loop fast and self-contained
  (architecture §3.2 step 1; readiness AWS-SRE-5/FEASIBILITY-3).

### How it satisfies the pillar

For a control-plane repo, "performance efficiency" is control-plane efficiency:
a bounded fanout with explicit quota thresholds, validation-time rejection of
names that would break apply, and managed-service selection. The design avoids
the failure mode flagged in the issue-17 baseline (unmodeled multi-repo fanout).

### Evidence / where enforced

| Control | Evidence |
| --- | --- |
| Bounded fanout (3N + fixed per-repo) | `test_governance.py` count assertions (architecture §9.1 FR2) |
| Governance-specific quota model | `validate_repository_catalogs.py` governance fanout + headroom (architecture §9.2) |
| Name-length guard | validation-time reject >64 chars (architecture §4) |
| Mock-renderable docs | injectable `expected_account_id`/`region`; `{account_id}` interpolation (architecture §3.2) |

### Residual risk

- **No runtime performance model** is expected or provided for this bootstrap
  control plane (consistent with the issue-18 review). Replication latency and
  storage-access assumptions remain documentation gaps rather than first-class
  controls.

---

## Cost Optimization

### Design decisions

- **Reuse, not new spend, for cost controls.** The increment does not provision
  new budgets/anomaly monitors; it relies on the existing per-account AWS Budget
  and Cost Anomaly Detection. Each stack's `costAnomalyMonitorArn`, **if present**,
  is verified to match its own account (test→`891377212104`, prod→`933245420672`),
  with absence permitted; there is no single-account repoint (architecture §10.2
  step 6; readiness FR21/FEASIBILITY-6).
- **Tag-bearing resources for allocation.** Governed resources carry the
  owner/cost-center/criticality tags from stack config
  (`governance:owner`, `governance:costCenter`, etc., architecture §2.2),
  feeding existing cost-allocation tagging.
- **Per-repo isolation has a known cost shape.** Each repo adds one state bucket
  + replica and one KMS key — a linear, predictable cost per onboarded repo that
  the quota/headroom model makes visible (architecture §9.2).
- **Minimal idle footprint.** IAM roles, S3 buckets, and KMS keys incur no
  standing compute cost; the governance stack creates no servers.

### How it satisfies the pillar

Cost-aware design through reuse of existing budget/anomaly controls, per-account
anomaly-ARN correctness, allocation tagging, and a predictable linear cost shape
per onboarded repo, with no idle compute.

### Evidence / where enforced

| Control | Evidence |
| --- | --- |
| Anomaly-ARN account match | per-stack `costAnomalyMonitorArn` account assertion, absence permitted (architecture §10.2 step 6; FR21) |
| Allocation tags | `governance:owner`/`costCenter`/`criticality` config keys (architecture §2.2) |
| Predictable per-repo cost | linear fanout + headroom (architecture §9.2) |

### Residual risk

- **FinOps refresh on growth.** Per-repo bucket + replica + KMS key counts grow
  with the catalog; FinOps ownership, thresholds, transfer, and monthly-cost
  evidence must be refreshed on catalog growth, new replicated data classes, or
  region changes (consistent with the issue-17 FinOps gate). Budgets/anomaly
  detection remain reused, not added, by this increment.
- **No per-repo budget caps.** Cost caps per governed repo are not in scope.

---

## Sustainability

### Design decisions

- **Reuse-over-create for the OIDC provider.** The per-account OIDC provider is
  consumed by ARN via `.get()` rather than re-created per stack — no duplicate
  identity-provider object, no churn from competing refreshes (architecture
  §3.2 step 2).
- **Pinned, allowlisted paired replica region.** Replication targets the
  allowlisted `eu-west-1` paired region explicitly rather than spreading data to
  arbitrary regions (architecture §2.2).
- **Lifecycle inheritance.** Per-repo state buckets reuse `PulumiStateBuckets`
  and per-repo KMS keys reuse `PulumiSecretsKeys`, inheriting the repo's existing
  versioning/lifecycle/retention rationale rather than introducing new unmanaged
  storage (architecture §3.2).
- **No idle compute.** The governance stack provisions only IAM/S3/KMS — no
  always-on servers or schedulers added by this increment.

### How it satisfies the pillar

Minimizing provisioned resources (consume-don't-create the provider, no idle
compute), choosing an allowlisted paired region, and reusing established
lifecycle controls reduce the per-repo resource and data footprint.

### Evidence / where enforced

| Control | Evidence |
| --- | --- |
| Consume-not-create provider | `.get()` only, zero create (architecture §3.2; `governance.py:523`) |
| Allowlisted replica region | `governance:replicationRegion: eu-west-1` (architecture §2.2) |
| Lifecycle inheritance | reuse of `PulumiStateBuckets`/`PulumiSecretsKeys` (architecture §3.2) |
| No idle compute | IAM/S3/KMS only (architecture §1) |

### Residual risk

- **Sustainability is not yet a first-class requirement** for this control plane
  (consistent with the issue-18 review). Region-selection goals, retention /
  storage-class rationale for the per-repo replicas, and bucket/KMS growth
  reporting remain documentation evidence rather than enforced controls.

---

## Cross-Cutting Residual Risks (consolidated from the readiness report)

| # | Residual risk | Status | Source |
| --- | --- | --- | --- |
| 1 | Within-account cross-repo IAM blast radius | Accepted (lower since test↔prod are separate accounts); tag-scoping + cross-repo IAM test recommended | readiness residual risk 1 / SECURITY-7 |
| 2 | KMS sole-control = `kms:ResourceAliases` until concrete key ARN is plumbed | Hardened (region-pinned, no alias-mutation grant); concrete-key-ARN scope recommended follow-up | readiness residual risk 2 / S-KMS |
| 3 | `*:GetAuthorizationToken` Deny coverage if a new token-vending service enters | Watch item; test flags new such Allows | readiness residual risk 3 |
| 4 | Bus factor: sole approver @Kravalg + `prevent_self_review` | Mitigated by audited break-glass, not eliminated | readiness residual risk 4 |
| 5 | CODEOWNERS ↔ glob single-source maintenance | Drift-equality test prevents two-list drift; periodic review advised | readiness residual risk 5 |
| 6 | 64-char IAM naming headroom (`prod-preview` config-read = 59 chars) | Catalog length-guard rejects longer repos at validation | readiness residual risk 6 |

## Scope Boundary (what this review does and does not claim)

- **Does claim:** the design is implementation-ready (readiness verdict PASS,
  conditional on the in-artifact amendments), the component family
  (`pulumi/infra/governance.py` + lifted `ci_bootstrap.py`/`ci_config.py`/
  `bootstrap_settings.py` helpers) is committed on `feat/multi-repo-governance`,
  and the security/least-privilege properties above are verifiable by the named
  tests under the session Pulumi mocks **without live credentials**.
- **Does not claim:** that anything has been applied to AWS. The governance
  Pulumi project, catalog, CODEOWNERS, `pulumi-governance.yml`, and scaffold are
  the remaining code deliverables in this branch, and the live applies,
  protected-environment PUT, repo creation, per-account OIDC-ARN pinning, and
  cost-anomaly-ARN verification are operator-only steps enumerated in
  architecture §10.2 and the readiness "Operator-only manual steps" list. No
  score in this review is a live-AWS attestation.

## Highest-Priority Follow-Ups

1. Land the remaining wiring deliverables (governance Pulumi project + catalog,
   CODEOWNERS + `GOVERNANCE_PATH_GLOBS` drift test, `pulumi-governance.yml` with
   both apply jobs under `environment: governance`, the protected-env payload,
   and the scaffold) so the §10 runbook is exercisable end-to-end.
2. Flip `dismiss_stale_reviews_on_push` and `require_last_push_approval` to
   `True` in `default_pull_request_rule()` (currently `False` at
   `_github_repository_controls.py:57-59`) and add the controls test (SECURITY-3).
3. Plumb the concrete per-repo KMS key ARN into the deploy `Resource` to demote
   `kms:ResourceAliases` to a defense-in-depth condition (S-KMS follow-up).
4. Add the `aws:RequestTag`/`aws:ResourceTag` binding + cross-repo IAM negative
   test for the within-account residual risk (SECURITY-7 recommended hardening).
5. Produce operator evidence — state restore drill + RTO/RPO, FinOps refresh on
   catalog growth, and the break-glass exercise record — before production
   approval.
