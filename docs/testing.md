# Testing and Validation

This repository uses multiple test types so bootstrap-infrastructure changes are checked from configuration shape down to the developer CLI surface.

Run `make doctor` first if you suspect the problem is your local Docker or
Compose setup rather than the repository itself.

All coverage-bearing Python suites in this repository are locked to 100% line
coverage. The combined quality gate is also locked to 100% branch coverage
across the Pulumi runtime, policy pack, and Python helper scripts. If unit,
integration, or policy changes reduce coverage, the corresponding `make` target
fails locally and in CI.

## Structural tests

Run with:

```bash
make test-pulumi
make test-repository-catalogs
make test-repository-fanout
```

Coverage:

- Every public Make target is exercised through dry-run or help-output assertions
- `pulumi/Pulumi.yaml`
- `pulumi/repositories.schema.json` and committed `pulumi/repositories*.json` catalogs
- Static repository fanout estimates for cost and quota review
- `policy/PulumiPolicy.yaml`
- Release workflow contracts
- Dockerfile supply-chain safeguards

## Policy tests

Run with:

```bash
make test-policy
```

Coverage:

- `policy/guardrails.py`
- `policy/pack.py`
- Pulumi policy pack registration in `policy/__main__.py`
- Required tag, public S3 ACL, and open admin-port guardrails
- 100% line coverage for the policy-pack Python surface

`make test-crossguard` is an alias for this same suite.

## Quality checks

Run with:

```bash
make test-quality
```

Coverage:

- `ruff check` for fast linting
- `ruff format --check` for formatting drift
- `ty check` for static typing diagnostics on the `pulumi`, `policy`, and `scripts` Python surfaces
- Ruff McCabe complexity with a maximum score of 10
- `radon mi` and `xenon` gates for maintainability and cyclomatic complexity
- Import Linter contracts that keep runtime code and policy code isolated
- Deptry and `uv lock --check` for dependency hygiene

Ty currently ignores a small set of false positives caused by Pulumi's dynamic
`Output.apply` API and the coverage bootstrap shim. The CI command keeps those
exceptions explicit instead of silently disabling the type check.

## Repo hygiene checks

Run with:

```bash
make test-repo-hygiene
```

Coverage:

- `make test-actionlint` for GitHub workflow linting
- `make test-yaml` for GitHub workflow YAML, Pulumi stacks, and operational YAML
- `make test-dockerfile` for Hadolint

## Security and preview guardrails

Run with:

```bash
make test-security
make test-guardrails
```

Coverage:

- `make test-secrets` runs Gitleaks against tracked Git content
- `make test-deps-security` runs `pip-audit --strict`
- `make test-bandit` runs Bandit against repository Python code
- `make test-preview` generates the Pulumi preview artifact consumed by later checks
- `make test-preview-unprivileged` generates the fallback artifact used when AWS-backed preview variables are absent
- `make test-destructive-diff` blocks deletes and replacements of critical infrastructure without an explicit PR override label
- `make test-cost-proxy` flags unusual durable-resource fanout from preview JSON
- `make test-guardrails` keeps the real preview, destructive-diff, and cost-proxy flow reproducible locally
- `make test-guardrails-unprivileged` keeps the fallback preview, destructive-diff, cost-proxy, and IAM-input extraction path reproducible locally
- `make test-iam-validation` validates previewed IAM policies with AWS IAM Access Analyzer when AWS credentials are intentionally configured

Dependency Review, CodeQL, SBOM attestations, and OpenSSF Scorecard are
GitHub-native only. The repository keeps those workflow definitions under
structural test coverage, but there is no local Docker equivalent for the
services themselves.

## Unit tests

Run with:

```bash
make test-unit
```

Coverage:

- `pulumi/app/environment.py`
- `pulumi/app/guardrails.py`
- `pulumi/sitecustomize.py`
- Config fallback behavior for `environment` and `serviceName`
- Identifier validation and fail-fast guardrails
- Best-effort coverage bootstrap behavior when the dependency is present, fails, or is absent
- Component type token and exported outputs
- 100% line coverage for the Pulumi application layer

## Integration tests

Run with:

```bash
make test-integration
```

Use `make test-integration-unprivileged` when AWS-backed Pulumi secrets
provider access is not configured. That target runs the credential-free
integration contracts and still produces `.coverage.integration` for the
combined coverage gate.

Coverage:

- The real `pulumi/__main__.py` entrypoint
- Pulumi Automation lifecycle behavior with a local backend
- Real Pulumi policy-pack startup and enforcement through `pulumi preview --policy-pack`
- Guardrail resolution contracts for explicit, configured, and default metadata
- Output wiring for environment metadata
- 100% line coverage enforced for the integration-covered Pulumi runtime files in `pulumi/__main__.py` and `pulumi/app`

The integration suite does not enforce coverage on `pulumi/sitecustomize.py`.
That bootstrap shim is exercised to 100% line coverage in the unit suite,
where its import-failure and startup-failure branches can be tested directly.

The Docker workspace keeps its `uv` virtual environment outside the bind-mounted
repository tree so Pulumi always sees a stable interpreter with `pip`
available for plugin discovery. The policy-pack bootstrap keeps `policy/.venv`
pointed at the shared `uv` workspace environment and repairs that shared
interpreter with `uv sync --frozen --all-groups` when policy imports drift, so
policy troubleshooting should start from the main workspace environment.

## Combined coverage gate

Run with:

```bash
make test-unit
make test-integration
make test-policy
make test-coverage
```

Coverage:

- merges `.coverage.unit`, `.coverage.integration`, and `.coverage.policy`
- enforces 100% branch coverage across `pulumi/*`, `policy/*`, and `scripts/*`
- prevents hidden branch regressions even when each individual suite still has
  100% line coverage

## Mutation tests

Run with:

```bash
make test-mutation
```

Coverage:

- Mutation analysis of `pulumi/app`
- Regression resistance for unit and integration assertions

Set non-empty `MUTATION_*` overrides to customize the suite. Blank exports are
ignored so the default mutation paths, coverage targets, and runner stay active.

Mutation testing is the slowest suite and is usually best left to CI unless you are changing component logic directly.

## CLI tests

Run with:

```bash
make test-cli
```

Coverage:

- `make help`
- `make all`
- `make start`
- `make pulumi-preview`
- `make pulumi-up`
- `make pulumi-refresh`
- `make pulumi-destroy`
- `make sh`
- `make down`
- `make test-unit`
- `make test-integration`
- `make test-pulumi`
- `make test-crossguard`
- `make test-quality`
- `make test-repo-hygiene`
- `make test-ruff`
- `make test-ty`
- `make test-maintainability`
- `make test-architecture`
- `make test-dependency-hygiene`
- `make test-lockfile`
- `make test-coverage`
- `make test-bandit`
- `make test-yaml`
- `make test-dockerfile`
- `make test-mutation`
- `make test-cli`
- `make test`
- `make report-quality`
- `make nightly-quality`
- `make clean`

## Full local run

Run the standard local validation battery with:

```bash
make test
make ci-pr
make ci
```

Run `make test` during normal iteration when you want the fast structural,
policy, quality, repo-hygiene, unit, integration, coverage, and CLI suites after
a prerequisite sanity check. For the real non-mutation battery, run
`make ci-pr`; when AWS-backed Pulumi variables are not configured, run
`make ci-pr-unprivileged`, which mirrors the default pull-request fallback path.
Before pushing, execute `make ci` to run the full local equivalent of every
GitHub check, including the prerequisite check, Docker build, and mutation
suite.

GitHub Actions now runs either `make ci-pr` or `make ci-pr-unprivileged`
through the `Pulumi Local Test Battery` workflow, while `Pulumi Mutation Tests`
keeps mutation analysis isolated as a separate check.
The `Pulumi Policy Tests` workflow runs the policy-pack coverage suite, and the
`Python Quality Checks` workflow runs Ruff, Ty, maintainability, architecture,
dependency-hygiene, and coverage gates. `Pulumi PR Guardrails` runs preview,
destructive diff, and IAM validation. The `Security Scans` workflow runs
Gitleaks, Bandit, dependency audit/review, workflow linting, YAML linting, and
Hadolint. `Nightly Quality` publishes Wily, Vulture,
docstring-coverage, and SBOM artifacts.

If Pulumi provider plugin downloads hit GitHub rate limits during local preview
or drift commands, pass `GITHUB_TOKEN="$(gh auth token)"` only to that single
invocation.

Use `make pulumi-preview` before any real cloud deployment. The preview and
apply targets automatically enable the repository policy pack.
