# Pulumi Testing Matrix

This repository uses runtime tests plus static and security guardrails to validate the Pulumi stack and its operator interface.
The Python toolchain is managed with `uv`, and the locked dependency graph lives in `uv.lock`.

## Static Quality

Goal: catch formatting drift, lint regressions, typing mistakes, and packaging issues before the runtime tests start.

Local commands:
```bash
make check-format
make check-lint
make check-spelling
make check-toml
make check-types
make check-ty
make check-package
```

Coverage:
- Ruff formatting
- Ruff lint rules
- Typos spelling checks across code, docs, and workflows
- Taplo lint and formatting checks for `pyproject.toml`
- mypy type checking for Pulumi Python modules
- Ty analysis across Pulumi modules and tests
- `uv lock --check`
- `uv sync --check`
- Python bytecode compilation

## Security and Supply Chain

Goal: fail fast on insecure Python code, vulnerable dependencies, broken workflows, and weak IaC/build definitions.

Local commands:
```bash
make check-bandit
make check-deps
make check-sbom
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
- yamllint on workflows and stack manifests
- actionlint on GitHub Actions workflows
- hadolint on the Dockerfile
- ShellCheck on repository shell scripts
- Checkov policy scanning for GitHub Actions and Dockerfile definitions

## Structural

Goal: catch drift in manifests, workflow wiring, exported outputs, and repository documentation.

Local command:
```bash
make test-pulumi
```

Coverage:
- Pulumi project manifest shape
- stack file conventions
- local-to-CI target mapping
- required docs in `docs/`

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
- `pulumi up`
- `pulumi stack output`
- `pulumi destroy`
- `pulumi stack rm`

The e2e suite uses a temporary fixture project instead of the full bootstrap stack so it can validate the Pulumi CLI flow without creating application infrastructure.

## Bats

Goal: validate the repository's operator interface by covering every public `make` target.

Local command:
```bash
make test-bats
```

Coverage:
- help and default targets
- every Pulumi command wrapper
- test command wrappers
- cleanup and shell targets

## CI Mapping

GitHub Actions mirrors the local targets:
- `python-quality.yml` -> `make check-format`, `make check-lint`, `make check-spelling`, `make check-toml`, `make check-types`, `make check-ty`, `make check-package`
- `devsecops-guardrails.yml` -> `make check-bandit`, `make check-deps`, `make check-sbom`, `make check-yaml`, `make check-actionlint`, `make check-docker`, `make check-shell`, `make check-iac`, `make test-cost`
- `pulumi-structural.yml` -> `make test-pulumi`
- `pulumi-unit.yml` -> `make test-unit`
- `pulumi-integration.yml` -> `make test-integration`
- `pulumi-mutation.yml` -> `make test-mutation`
- `pulumi-e2e.yml` -> `make test-e2e`
- `bats-tests.yml` -> `make test-bats`

The aggregate local command is:
```bash
make ci
```
