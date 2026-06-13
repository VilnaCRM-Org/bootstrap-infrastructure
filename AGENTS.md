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

Each step below is tagged **CODE** (a committable change a non-privileged agent
makes, applied through the gated PR-comment flow) or **OPERATOR** (an action
requiring live AWS/GitHub-admin credentials, performed by the operator per the
runbook in `docs/governance-stack.md`). Onboarding a new service `X` that needs
its `X-infrastructure` repo is config-only on the governance side: add the repo
to `pulumi/repositories.governance.json` and run the multi-PR flow below. Never
add `bootstrap-infrastructure` to `pulumi/repositories.governance.json` — it
self-manages via the `github-ci-bootstrap` project, and listing it would
double-manage the same IAM roles and CI secret.

1. **PR A — Grant deploy roles (governance) [CODE]:** add `X-infrastructure` to
   `pulumi/repositories.governance.json` (config-only; `project` is the full repo
   slug). `@Kravalg` reviews via CODEOWNERS, then comments `/pulumi test up`
   followed by `/pulumi prod up` on the PR **[OPERATOR]**. Those `up` commands are
   gated: the author must be `@Kravalg` and the apply jobs run under the protected
   `environment: governance`. The governance stack provisions X's per-repo state
   bucket, KMS key + alias, the preview/apply/drift trio, the config-read role,
   and the repo-scoped OIDC trust. `@Kravalg` verifies the rendered roles, then
   merges.
2. **PR B — Bootstrap generic infra for `X-infrastructure` [CODE, gated apply]:**
   stand up the generic baseline infrastructure for the repo using the deploy
   roles created by PR A. It is applied through the same gated flow
   (`/pulumi test up` then `/pulumi prod up`, `@Kravalg`-only, saved-plan).
3. **Create `X-infrastructure` repo + push scaffold [OPERATOR]:** create
   `VilnaCRM-Org/X-infrastructure` and push the scaffold modelled on
   `pulumi/user-service-infrastructure/` (its `pulumi/` project plus
   `.github/workflows/self-deploy.yml`). This is an org-admin action, not a
   committable change in this repo.
4. **PR C — Grant OIDC apply permissions [CODE, @Kravalg-gated]:** grant the
   OIDC apply permissions that let `X-infrastructure`'s own GitHub Actions assume
   its governance-provided apply role. Reviewed and merged by `@Kravalg` (gated
   exactly like PR A/PR B).

After PR C merges, **X self-deploys** through its own
`.github/workflows/self-deploy.yml`: maintainers comment `/pulumi test up` then
`/pulumi prod up` on `X-infrastructure`'s PRs, and the workflow assumes only the
governance-provided preview/apply/drift roles (no static or admin AWS keys) and
applies via the saved-plan path. The roles, trust, buckets, and keys all live in
`bootstrap-infrastructure`'s governance stack.

The governance merge gate is CODEOWNERS (`@Kravalg` review of every
governance/IAM/policy path) plus the protected `governance` environment
(`@Kravalg` approves the apply); `@Kravalg` merges after the gated test+prod
apply succeeds. The governance apply runner triggers on `repository_dispatch`
and posts a `Governance Apply` commit status to the PR head SHA as an
informational signal of that gated-apply result — it is not a global required
check. See `docs/governance-stack.md` for the full operator runbook
(one-time bootstrap apply, protected-environment + branch-protection setup, repo
variables, per-account OIDC-ARN pinning, repo create + push, gated real applies,
and break-glass).

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
