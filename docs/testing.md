# Pulumi Testing Matrix

This repository uses runtime tests plus static and security guardrails to validate the Pulumi stack and its operator interface.
The Python toolchain is managed with `uv`, and the locked dependency graph lives in `uv.lock`.

## Static Quality

Goal: catch formatting drift, lint regressions, typing mistakes, and packaging issues before the runtime tests start.

Local commands:
```bash
make check-format
make check-lint
make check-radon
make check-xenon
make check-imports
make check-deptry
make check-spelling
make check-toml
make check-types
make check-ty
make check-package
make check-qlty
```

Coverage:
- Ruff formatting
- Ruff lint rules, including McCabe complexity (`C901`)
- Radon maintainability index enforcement with minimum rank `B`
- Xenon complexity ceilings: average `A`, modules `A`, blocks `C`
- Import Linter architecture contracts between `infra`, `policy_pack`, and `scripts`
- Deptry dependency hygiene checks
- Typos spelling checks across code, docs, and workflows
- Taplo lint and formatting checks for `pyproject.toml`
- mypy type checking for Pulumi Python modules
- Ty analysis across Pulumi modules and tests
- `uv lock --check`
- `uv sync --check`
- Python bytecode compilation
- Qlty repo-local code health scan parity with the external Qlty status

## Security and Supply Chain

Goal: fail fast on insecure Python code, vulnerable dependencies, broken workflows, and weak IaC/build definitions.

Local commands:
```bash
make check-bandit
make check-deps
make check-sbom
make check-secrets
make check-iam
make check-preview
make check-yaml
make check-actionlint
make check-docker
make check-shell
make check-iac
```

Coverage:
- Bandit static security analysis
- pip-audit dependency CVE detection against the `uv.lock` graph
- CycloneDX SBOM export from the locked dependency graph
- Gitleaks secret scanning with the committed `.gitleaks.toml` configuration
- IAM Access Analyzer validation for generated IAM/resource policies when AWS credentials are available
- local Pulumi preview parity with destructive-diff analysis when `PULUMI_STATE_BUCKET` plus a KMS-backed secrets provider are configured
- yamllint on workflows and stack manifests
- actionlint on GitHub Actions workflows
- hadolint on the Dockerfile
- ShellCheck on repository shell scripts
- `shfmt` shell formatting validation
- Checkov policy scanning for GitHub Actions and Dockerfile definitions
- Qlty multi-tool code health/security scan using the committed `.qlty/` config

## Structural

Goal: catch drift in manifests, workflow wiring, exported outputs, and repository documentation.

Local command:
```bash
make test-pulumi
```

Coverage:
- Pulumi project manifest shape
- stack file conventions
- policy pack repository wiring
- local-to-CI target mapping
- required docs in `docs/`

## CrossGuard

Goal: enforce repo-specific Pulumi guardrails during previews and updates, not only in tests.

Local command:
```bash
make test-policy
make test-crossguard
```

Coverage:
- Pulumi CrossGuard rule construction
- disallowed service-family enforcement
- S3, KMS, ECR, backup, and FinOps-tag guardrails
- policy-pack entrypoint wiring

## Cost Guardrails

Goal: keep the bootstrap stack inside low-cost AWS service families and require FinOps tags on taggable resources.

Local command:
```bash
make test-cost
```

Coverage:
- blocks introduction of high-cost compute/data-plane resource families such as EC2, RDS, EKS, NAT gateways, and Redshift
- verifies `Owner` and `CostCenter` tags on taggable bootstrap resources

## Unit

Goal: validate helper functions, policy builders, naming rules, and component-specific behavior with Pulumi mocks.

Local command:
```bash
make test-unit
```

Coverage:
- config sanitization
- IAM policy generation
- KMS alias/provider generation
- component assembly with Pulumi mocks

## Integration

Goal: exercise the real stack entrypoint with the full component graph while still using Pulumi mocks.

Local command:
```bash
make test-integration
```

Coverage:
- `pulumi/__main__.py`
- combined component wiring
- exported outputs

## Mutation

Goal: keep a deterministic mutation-guard suite around the helper logic that is most vulnerable to review regressions.

Local command:
```bash
make test-mutation
```

Scope:
- `pulumi/infra/config.py`
- `pulumi/infra/iam/github_oidc.py`

Implementation notes:
- the suite runs targeted tests that were written to kill likely helper-level mutations in config normalization, secrets-provider URI construction, IAM role naming, and IAM policy JSON generation
- the guard runner does not enable coverage instrumentation because Pulumi package registration collides with coverage startup in the containerized test environment; coverage for the same modules remains enforced by the unit and integration suites
- `infra.pulumi_secrets` still has dedicated fast unit assertions, but its Pulumi-oriented startup and policy generation paths are validated via unit, integration, and e2e tests instead of a mutator tool because the containerized Pulumi runtime produced persistent false timeout noise

## E2E

Goal: run a real Pulumi CLI lifecycle against a temporary local backend and AWS KMS-backed secrets provider.

Local command:
```bash
PULUMI_E2E_SECRETS_PROVIDER='awskms://alias/your-bootstrap-key?region=eu-central-1' make test-e2e
```

Coverage:
- `pulumi login`
- `pulumi stack init --secrets-provider`
- `pulumi preview`
- `pulumi preview --json`
- `pulumi up`
- `pulumi stack output`
- `pulumi destroy`
- `pulumi stack rm`
- `./scripts/run_pulumi_command.sh plan`
- `./scripts/run_pulumi_command.sh up`
- `scripts/analyze_pulumi_preview.py`
- `pulumi preview --policy-pack ...` failure on a disallowed AWS resource

The e2e suite uses a temporary fixture project instead of the full bootstrap stack so it can validate the Pulumi CLI flow without creating application infrastructure.

## Coverage

Goal: require 100% combined coverage for Pulumi stack code and Pulumi policy code across the Python test matrix.

Local command:
```bash
make check-coverage
```

Coverage:
- combines structural, cost, policy, unit, integration, and e2e Python suites
- fails if `pulumi/` plus `policy_pack/` drops below 100% combined line+branch coverage
- keeps mutation and Bats as separate non-coverage guardrails

## Monitoring

Goal: track maintainability and documentation drift over time without turning high-noise reports into daily PR blockers.

Local commands:
```bash
make report-wily
make report-vulture
make report-docstrings
make report-sbom
make report-drift
make ci-nightly
```

Coverage:
- Wily trend reports for maintainability and cyclomatic drift across recent revisions
- Vulture dead-code reporting at confidence `80`
- `docstr-coverage` reporting for reusable modules with an advisory floor of `80%`
- scheduled CycloneDX SBOM snapshots
- local drift detection parity via `./scripts/run_pulumi_command.sh drift` when the same preview env vars are configured

Implementation note:
- `make report-wily` uses [run_wily_report.py](/home/kravtsov/Projects/bootstrap-infrastructure/scripts/run_wily_report.py). In CI it analyzes the clean checkout directly; on a dirty local worktree it falls back to a temporary clone of `HEAD` so the advisory report remains runnable.

## Bats

Goal: validate the repository's operator interface by covering every public `make` target.

Local command:
```bash
make test-bats
```

Coverage:
- help and default targets
- every Pulumi command wrapper
- the CI-oriented Pulumi command wrappers (`pulumi-plan-ci`, `pulumi-up-ci`, `pulumi-drift-ci`)
- runner image operator commands (`runner-image-build`, `runner-image-smoke`, `runner-image-push`)
- test command wrappers
- cleanup and shell targets

## CI Mapping

GitHub Actions mirrors the local targets:
- `python-quality.yml` -> `make check-format`, `make check-lint`, `make check-radon`, `make check-xenon`, `make check-imports`, `make check-deptry`, `make check-spelling`, `make check-toml`, `make check-types`, `make check-ty`, `make check-package`
- `devsecops-guardrails.yml` -> `make check-bandit`, `make check-deps`, `make check-sbom`, `make check-secrets`, `make check-yaml`, `make check-actionlint`, `make check-docker`, `make check-shell`, `make check-iac`, `make check-qlty`, `make test-cost`
- `dependency-review.yml` -> GitHub dependency review for changes to dependency metadata
- `pulumi-preview.yml` -> `make check-preview`, `scripts/analyze_pulumi_preview.py`, `make check-iam`
- `codeql.yml` -> GitHub CodeQL for `python` and `actions`
- `pulumi-structural.yml` -> `make test-pulumi`
- `pulumi-policy.yml` -> `make test-crossguard`
- `pulumi-unit.yml` -> `make test-unit`
- `pulumi-integration.yml` -> `make test-integration`
- `pulumi-mutation.yml` -> `make test-mutation`
- `pulumi-e2e.yml` -> `make test-e2e`
- `pulumi-coverage.yml` -> `make check-coverage`
- `bats-tests.yml` -> `make test-bats`
- `pulumi-runner-image.yml` -> `make runner-image-build`, `make runner-image-smoke`, `make runner-image-push`
- `pulumi-pr-commands.yml` -> validate and dispatch trusted PR command runs from `issue_comment`
- `quality-monitoring.yml` and `pulumi-drift.yml` -> `make ci-nightly`
- `pulumi-pr-command-runner.yml` -> `./scripts/run_pulumi_command.sh plan|up` inside the published ECR runner image
- `pulumi-drift.yml` -> `./scripts/run_pulumi_command.sh drift` inside the published ECR runner image
- `quality-monitoring.yml` -> `make report-wily`, `make report-vulture`, `make report-docstrings`, `make report-sbom`
- `repo-health.yml` -> OpenSSF Scorecard on a schedule

The aggregate local command is:
```bash
make ci
```
