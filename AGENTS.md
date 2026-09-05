# AGENTS

This repository is a Pulumi-based infrastructure template. Agents should keep changes minimal, preserve the local developer workflow, and avoid introducing hidden cloud dependencies into CI.

## Working rules

1. Make the smallest change that satisfies the task.
2. Prefer updating tests, docs, and examples before widening release or deployment behavior.
3. Run the narrowest useful validation for the files you touched.
4. Use `pulumi -C pulumi ...` for direct Pulumi CLI commands.
5. Use `uv run ...` for Python CLI commands instead of invoking tools directly from the global environment.
6. Seed local `uv` environments with `export UV_PROJECT_ENVIRONMENT="${HOME}/.venvs/bootstrap-infrastructure"; uv venv --seed "${UV_PROJECT_ENVIRONMENT}"` before syncing if you need to run Pulumi Automation outside Docker.
7. Keep the structural, policy, quality, unit, integration, mutation, CLI, and aggregate local-battery suites runnable without live AWS credentials.
8. Use `make ci-pr` when you want the non-mutation GitHub PR battery, `make ci` for the full local superset including mutation, and `make test` for the faster non-mutation developer battery.
9. Use `make doctor` before debugging local Docker or Compose issues.
10. Run `make start` when changing Docker-backed CI jobs so workspace preparation stays consistent across workflows and local runs.
11. Keep `./scripts/prepare_policy_pack.py`, `policy/PulumiPolicy.yaml`, `policy/.venv`, and the shared `uv` environment contract aligned when changing Pulumi policy-pack behavior.
12. Reproduce PR safety checks with `make test-security`, `make test-repo-hygiene`, `make test-guardrails`, or `make ci-pr` before pushing infra-related workflow or policy changes.
13. Do not add long-lived static AWS credentials to workflows; use the documented OIDC role variables instead.
14. Treat `allow-destructive-infra-change` as the only supported override for destructive Pulumi diffs.
15. Keep `make test-coverage` green when changing Python code; the repo expects 100% branch coverage across the covered Pulumi, policy, and helper modules, with the unit, integration, and policy suites each held to 100% line coverage.
16. Keep `make test-dependency-hygiene` green when editing `pyproject.toml`, `uv.lock`, or import relationships.
17. Use `make report-quality` when you need the scheduled Wily, Vulture, docstring-coverage, and SBOM reports locally.
18. If local Pulumi plugin downloads hit GitHub rate limits, pass `GITHUB_TOKEN="$(gh auth token)"` only to the specific preview-oriented Make command you are running.
19. Prefer Make targets plus Python helpers under `scripts/*.py`; do not introduce new repository bash helper scripts for CI orchestration.
20. Treat shared Pulumi backends as KMS-backed for CI and maintainer docs; do not document passphrase-backed shared backends as the default path.

## BMAD/BMALPH planning

1. Keep BMAD and BMALPH planning artifacts under `specs/`.
2. Create one `specs/<issue-or-feature-slug>/` directory per planned change, and put PRDs, architecture notes, epics/stories, readiness reports, and review scorecards there.
3. When asking BMAD agents or BMALPH workflows to create or update planning docs, explicitly tell them to use `specs/<issue-or-feature-slug>/` as the planning output directory.
4. If a local BMAD installation generates `_bmad/config.yaml`, set `output_folder: specs` and `planning_artifacts: specs` before generating planning documents.
5. Treat `.ralph/specs/` as BMALPH/Ralph generated implementation input only; do not use it as the canonical planning source.
6. Do not commit generated BMAD/BMALPH/Ralph framework or state files such as `_bmad/`, `_bmad-output/`, `bmalph/`, `.ralph/`, or `.agents/skills/bmad-*`.
7. Do not commit alternate planning roots such as `docs/planning/`, top-level `planning/`, `.bmad/`, or `.bmad-core/`.

## Multi-repo governance onboarding flow

This repository hosts the Kravalg-gated multi-repo IAM/OIDC governance stack in
`pulumi/governance/`. It provisions per-repo state buckets, KMS keys, and
`GitHubCiPreview/Apply/Drift` + `GitHubCiConfigRead` roles for every
`*-infrastructure` service repo listed in `pulumi/repositories.governance.json`.
Two separate AWS accounts give test/prod isolation: the `test` stack deploys
account `891377212104` and the `prod` stack deploys account `933245420672`, both
in `eu-central-1`. `@Kravalg` is the sole approver (CODEOWNERS + the protected
`governance` GitHub Environment); `@dmytrocraft` opens PRs and may always run
`plan`. Applies are IaC-only and saved-plan based — there is no human `pulumi up`
in CI; the governance runner only replays a `make pulumi-up-plan` saved plan.

Each step below is tagged **CODE** (reviewed committable IaC/docs) or
**OPERATOR** (an authorized live AWS/GitHub operation). The runbook is
`docs/governance-stack.md`. Never add `bootstrap-infrastructure` to
`pulumi/repositories.governance.json`: it self-manages through
`github-ci-bootstrap`, and a catalog entry would double-manage its identities.

The real platform entrypoint uses `manage_control_resources=False`. Only
`github-ci-bootstrap` owns platform CI secrets, the OIDC provider, CI deployment
and configuration roles, legacy `PulumiAutomation`/`PulumiDeploy` roles, Config
recorder IAM, and fixed platform state/log replication IAM. The platform reads
those identities with `get()` and retains workload resources. Immutable control
boundaries cap legacy role grants; platform apply cannot mutate these identities
or their boundaries. Existing deployments require the reviewed ownership
migration and encrypted state backups before the first operator apply; a code
mode switch alone does not resolve existing duplicate state owners.

First resolve the actual GitHub repository identity **[OPERATOR]**. Inspect an
existing repository, or create the empty repository when absent, and record its
immutable repository/owner identifiers and current OIDC subject contract. This
precedes the catalog grant and boundary provisioning because trust must bind the
real identity. Preserve existing content; do not guess IDs from a repository name.

Before a new repository's first governance apply, the operator must preview and
apply the reviewed `github-ci-bootstrap` change that provisions its immutable
service/replication boundaries and extends the dedicated governor's exact
resource inventory. Those boundaries and runner policies are bootstrap-owned;
the governor cannot widen them or modify its own roles. This is an explicit
privileged prerequisite, including when a later repository is added by catalog
configuration. Do not claim zero operator work for new delegation inventory.

1. **PR A — Grant deploy roles (governance) [CODE]:** add `X-infrastructure`
   to `pulumi/repositories.governance.json`; `project` is the full repo slug.
   After the reviewed bootstrap boundary/inventory prerequisite **[OPERATOR]**,
   A current write-permission maintainer other than `@Kravalg` requests
   `/pulumi test up`, then `/pulumi prod up`; `@Kravalg` reviews and approves
   the protected environment. Both apply jobs use `environment: governance` and replay
   saved plans. The stack provisions X's state bucket, replica, KMS key/alias,
   bounded preview/apply/drift roles, config-read roles and fixed CI secrets.
   Merge only after current-head `Governance Promotion` proof and all required
   reviews/checks pass.
2. **PR B — Bootstrap generic infra for `X-infrastructure` [CODE, gated apply]:** prepare
   the complete repository scaffold and reviewed baseline. Include its comment
   intake, local CI action, Make/helper tooling, dependency files and deployment
   workflow. The initial service boundary permits backend/configuration access
   only; existing workload resources need explicit reviewed capability and
   boundary extensions before they can be deployed. Do not apply a downstream
   scaffold before its repo, variables and protected environments exist.
3. **Publish scaffold to the identified repo [OPERATOR]:** use the repository
   resolved before PR A and preserve any existing content. Push the reviewed,
   complete scaffold modelled on
   `pulumi/user-service-infrastructure/`. Configure the account-local variables
   from governance outputs and the required protected environments. Prove all
   local-action, helper and dependency references resolve in a clean checkout.
4. **PR C — Grant OIDC apply permissions [CODE, @Kravalg-gated]:** review the
   final service role capabilities and protected-environment OIDC subjects
   against the actual service resource inventory. Apply the reviewed grants
   through the same gated test-then-prod flow **[OPERATOR]**, then prove the
   downstream comment intake, exact-SHA plan, saved-plan apply and drift path.

After PR C, X may self-deploy through its own
`.github/workflows/self-deploy.yml` only when the complete setup has passed the
same-head test/prod smoke. Maintainers use `/pulumi test up` and
`/pulumi prod up`; no static/admin credentials or platform IAM privileges are
inherited. Service roles, state buckets and keys live in the governance stack;
immutable boundaries and dedicated governance runners live in the operator
bootstrap stack.

The required **Governance Promotion** check enforces success before merge for
governance-touching PRs. It is bound to the dedicated environment-protected GitHub App issuer and exact PR
head, and requires successful test apply, test drift, prod apply and prod drift with an
immutable proof artifact. Non-governance PRs receive a scope-based success.
A test-only apply, plan, stale head or failed/skipped production cannot satisfy
this promotion gate. CODEOWNERS review and protected environment approvals
remain additional controls. Any informational `Governance Apply` status is not
a substitute for the required promotion proof.

The governance runner consumes only dedicated
`AWS_GOVERNANCE_{TEST,PROD}_{PREVIEW,DRIFT,APPLY}_ROLE_ARN` variables and the
matching account, region, backend and KMS metadata. Preview/drift run under
`governance-preview`, apply under `governance`. Preview/drift can read the
isolated governance backend but can write only Pulumi lock objects. Follow the
operator runbook for provisioning, provider pinning, variables, real applies,
metadata-only evidence and audited break-glass.

## Secret handling

These rules are mandatory for AI coding agents in this repository.

1. Never read, print, summarize, diff, or copy raw secret material.
2. Treat the following as off-limits unless the user explicitly asks for a secret-management task:
   - `.env`, `.env.*`, and shell files that export credentials
   - AWS shared credentials/config files, access keys, session tokens, and STS credentials
   - Pulumi stack files or exports containing `secure:` values or `encryptedkey` metadata
   - GitHub Actions secrets, deploy keys, private keys, certificates, kubeconfigs, and token files
3. Never run commands that reveal secrets in terminal output. This includes `env`, `printenv`, `docker compose config`, `docker inspect`, `pulumi config --show-secrets`, `pulumi stack output --show-secrets`, and cloud-secret fetch commands unless the user explicitly requests that exact action.
4. Prefer metadata-only checks such as `aws sts get-caller-identity`, `pulumi stack ls`, and `pulumi config` without secret-revealing flags.
5. When a secret must be set, write it directly with `pulumi config set --secret ...` or the relevant cloud secret store command without echoing the value back into the terminal transcript.
6. Never commit secret values, decrypted outputs, copied stack exports, or temporary files containing secrets.

## Pulumi workflow

1. Structural, quality, unit, integration, mutation, and CLI checks should stay local-backend-friendly.
2. Preview before apply when working against a real stack.
3. Prefer ephemeral validation stacks such as `pr-<number>` or `smoke` for manual checks.
4. Destroy ephemeral validation stacks after the check completes.

## Review-driven changes

1. Use `gh pr view <PR>` and `gh pr checks <PR>` for context.
2. Pull review threads with `gh api graphql` and resolve every actionable thread.
3. Keep refactors minimal and directly tied to review feedback.
4. Update `docs/` whenever the developer workflow, CI surface, or credential contract changes.
5. Re-run the relevant checks before pushing.
6. Keep the Pulumi policy pack under `policy/` aligned with the runtime guardrails in `pulumi/app/`.

## Finish PR

1. Confirm the current branch still matches the target PR head before making changes.
2. Review unresolved, non-outdated human and CodeRabbit comments before widening the patch.
3. Keep fixes scoped to the active review feedback and the failing checks.
4. Re-run the narrowest local validation that proves the comment or failure is addressed.
5. Reply on every human and CodeRabbit review thread after fixing it, including brief verification context when useful.
6. When a CodeRabbit comment is fixed, explicitly ask CodeRabbit on that same thread to re-check the comment because the fix is now present.
7. Wait until CodeRabbit has answered every per-comment reply before asking for a new PR-wide bot review.
8. After all fixed comments have been re-checked, ask `@coderabbitai review` or `@coderabbitai full review` on the PR only once the new head is ready for another full pass.
9. Do not call the PR finished until all required GitHub CI checks are green, current review threads are resolved, and CodeRabbit has approved the PR.
10. If CodeRabbit still withholds approval, inspect the latest current-head CodeRabbit review summary with `gh pr view <PR> --json reviews`, address any current-head findings even when no inline thread remains open, then repeat the per-comment recheck flow before requesting another PR-wide review.
