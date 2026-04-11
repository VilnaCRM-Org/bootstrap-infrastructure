# CI Quality Gates

This repository uses a layered CI model: fast PR-blocking checks for code,
workflow, and infrastructure safety, plus scheduled checks that track longer-
term drift in maintainability and supply-chain posture.

Use this guide together with [CI guardrails](ci-guardrails.md). That document
focuses on Pulumi preview, IAM, destructive diff, and OIDC. This document
covers the broader engineering-quality system around those infra-specific
guardrails.

## PR-blocking checks

These checks should be required in branch protection:

| Check | Local command | Purpose |
| --- | --- | --- |
| `Ruff` | `make test-ruff` | Lint, import-order, formatting drift, and McCabe complexity |
| `Ty` | `make test-ty` | Fast static typing diagnostics |
| `Maintainability` | `make test-maintainability` | Radon/Xenon complexity and maintainability gates |
| `Architecture` | `make test-architecture` | Import Linter contracts for package isolation and dependency direction |
| `Dependency Hygiene` | `make test-dependency-hygiene` | `uv lock --check` plus Deptry for missing, misplaced, and unused dependencies |
| `Coverage` | `make test-coverage` after `make test-unit`, `make test-integration`, `make test-policy` | Combined branch-coverage gate |
| `Secrets Scan` | `make test-secrets` | Gitleaks against tracked Git content |
| `Dependency Audit` | `make test-deps-security` | `pip-audit --strict` for known Python vulnerabilities |
| `Bandit` | `make test-bandit` | Python security linting for runtime and helper code |
| `Dependency Review` | GitHub-native | Pull-request dependency risk review against GitHub advisories |
| `Actionlint` | `make test-actionlint` | Workflow syntax and common GitHub Actions mistakes |
| `Yamllint` | `make test-yaml` | GitHub workflow YAML, Pulumi stack YAML, and operational YAML hygiene |
| `Hadolint` | `make test-dockerfile` | Dockerfile quality and safety linting |
| `Preview` | `make test-preview` | Non-destructive Pulumi preview artifact generation |
| `Destructive Diff Gate` | `make test-destructive-diff` | Blocks risky deletes and replacements |
| `IAM Validation` | `make test-iam-validation` | AWS IAM Access Analyzer validation of rendered policies |
| `Policy` | `make test-policy` | Custom Pulumi CrossGuard policy pack enforcement |
| `CodeQL (python)` | GitHub-native | Static security/code scanning for Python |
| `CodeQL (actions)` | GitHub-native | Static security/code scanning for workflows |

`make ci-pr` is the canonical local equivalent of the non-mutation pull-request
battery. The structural, policy, quality, unit, integration, mutation, CLI,
and aggregate local suites remain runnable without live AWS credentials, but
`make test-iam-validation` stays a separate privileged step and is
intentionally excluded from `make ci-pr`. `make ci` adds the slower mutation
layer on top, and IAM validation still runs separately when credentials are
available.

## Scheduled quality monitoring

These checks are intentionally visible but do not block pull requests:

| Check | Local command | Purpose |
| --- | --- | --- |
| `Wily Maintainability Trends` | `make report-maintainability-trends` | Tracks maintainability drift over repository history |
| `Vulture Dead Code` | `make report-dead-code` | Reports likely dead code in reusable modules |
| `Docstring Coverage` | `make report-docstrings` | Reports docstring coverage on reusable modules and utilities |
| `CycloneDX SBOM` | `make report-sbom` | Generates a Python environment SBOM artifact |
| `SBOM provenance` | GitHub-native in `nightly-quality.yml` | Attests the generated SBOM artifact |
| `Drift Detection` | `make test-drift` | Non-destructive shared-stack drift detection run separately from `make report-quality` / `make nightly-quality` |
| `Scorecard` | GitHub-native | OpenSSF repository-health monitoring |

`make report-quality` runs the scheduled local report battery, and
`make nightly-quality` is an alias for the same command. Neither target runs
`make test-drift`; drift detection stays in the separate infra-oriented nightly
workflow and local `make test-drift` path.

## Thresholds

The current gates are intentionally strict:

- Ruff McCabe complexity: maximum `10`
- Xenon block complexity: maximum rank `B`
- Xenon module complexity: maximum rank `B`
- Xenon average complexity: maximum rank `A`
- Radon maintainability index: minimum rank `B`
- Combined branch coverage: `100%`
- Unit, integration, and policy suite line coverage: `100%`
- `docstr-coverage` docstring coverage for reusable modules: `100%`
- Vulture minimum confidence: `80`

These thresholds reflect the current repository state. Lowering them should be
treated as a deliberate design decision, not as a convenience fix for a noisy
change.

## Architecture contracts

Import Linter currently enforces:

- `app` must not import `policy`
- `policy` must not import `app`
- `app.environment` may depend on `app.guardrails`, but not the other way
  around
- `policy.__main__` may depend on `policy.pack`
- `policy.pack` may depend on `policy.guardrails` and `policy.config`
- `policy.guardrails` may depend on `policy.config`
- `app.guardrails` must stay free of `pulumi` and `pulumi_policy`
- `policy.config` and `policy.guardrails` must stay free of `pulumi` and `pulumi_policy`

This keeps runtime code, policy code, and guardrail helpers from collapsing
into one another as AI-generated refactors expand the repo. The standalone
`pulumi/__main__.py` entrypoint stays under structural-test coverage rather than
Import Linter because it is not a package module, but it still uses the `app`
package surface instead of reaching into `app.environment` directly.

When a downstream Pulumi repository grows into a componentized layout such as
`stacks.<stack>`, `components.<domain>`, and `shared`, extend the same
orchestration-to-reusable dependency direction there too: stack entrypoints may
depend on components and shared helpers, components may depend on shared
helpers, and shared helpers must not depend back on stack entrypoints or
service-specific components.

## Dependency hygiene rules

`make test-dependency-hygiene` combines two checks:

1. `uv lock --check`
   - prevents dependency or metadata changes from landing without a refreshed `uv.lock`
2. `deptry`
   - flags missing direct dependencies
   - flags runtime dependencies incorrectly placed in dev-only groups
   - flags transitive imports that should be explicit
   - flags unused dependencies

Current explicit exceptions are minimal and documented in `pyproject.toml`:

- `pulumi-aws` is ignored for DEP002 because this is an AWS template and the
  provider SDK is intentionally predeclared for downstream stacks even when the
  starter code does not yet import it
- `config`, `guardrails`, and `pack` are ignored for DEP001 because the policy
  pack supports both package imports and direct-module startup under the Pulumi
  CLI
- CLI-only developer tools are ignored for DEP004 because they are executed via
  `uv run` rather than imported from repository code

## Security and supply-chain notes

- All AWS access in GitHub Actions remains OIDC-based; do not add long-lived
  static AWS keys
- Dependency Review, CodeQL, and SBOM artifact attestation are GitHub-native only, so
  there is no exact local Make equivalent for those specific services
- `yamllint` now covers `.github/workflows/` as well as the Pulumi stack and
  operational YAML surface, while `actionlint` and CodeQL still provide the
  workflow-specific semantics and security checks
- `hadolint` keeps only `DL3059` globally ignored; the Dockerfile uses narrow
  inline `DL3008` suppressions only on the Debian package-install steps where
  patch-level pinning is impractical without a snapshot repository

## Path filtering strategy

The blocking workflows currently run on every pull request instead of relying on
aggressive path filters. This template is small, and AI-generated changes to
workflows, docs, tooling, Docker, or Pulumi helpers can affect repository
behavior far outside the file that changed. The bias here is safety over clever
skip logic.

The only scoped lint exception today is `.pulumi-backend/`, which is local
state rather than committed configuration.

## Safe exception handling

If a change genuinely requires an exception:

1. document the reason in code or config next to the suppression
2. keep the scope to the smallest rule and module possible
3. update this guide or `docs/ci-guardrails.md` if the exception changes the
   maintainer workflow
4. avoid blanket disables for whole tools or whole categories

## Maintainer follow-up

After pulling these workflows into a downstream repo:

1. mark the blocking checks as required in branch protection
2. configure the OIDC role and repository variables described in
   [CI guardrails](ci-guardrails.md)
3. decide whether scheduled quality workflows should notify a team channel or
   issue tracker
4. keep `uv.lock` and the Docker image refreshed as new tools are added

## Current limitations

- The repo does not publish a long-lived release artifact today, so provenance
  is currently attached to the generated SBOM artifact rather than to a shipped
  OCI image or release bundle
- Dependency Review and CodeQL are GitHub-native services and cannot be fully
  reproduced inside the Docker workspace
- Wily trends depend on available git history; very shallow clones reduce the
  usefulness of the report, and local worktrees without a resolvable `HEAD`
  write an advisory note instead of failing the scheduled report battery
