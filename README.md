# Infrastructure Template for Modern DevOps applications

[![SWUbanner](https://raw.githubusercontent.com/vshymanskyy/StandWithUkraine/main/banner2-direct.svg)](https://supportukrainenow.org/)

[![Pulumi Unit Tests](https://github.com/VilnaCRM-Org/bootstrap-infrastructure/actions/workflows/pulumi-unit.yml/badge.svg)](https://github.com/VilnaCRM-Org/bootstrap-infrastructure/actions/workflows/pulumi-unit.yml)
[![Pulumi Integration Tests](https://github.com/VilnaCRM-Org/bootstrap-infrastructure/actions/workflows/pulumi-integration.yml/badge.svg)](https://github.com/VilnaCRM-Org/bootstrap-infrastructure/actions/workflows/pulumi-integration.yml)
[![Pulumi Structural Tests](https://github.com/VilnaCRM-Org/bootstrap-infrastructure/actions/workflows/pulumi-structural.yml/badge.svg)](https://github.com/VilnaCRM-Org/bootstrap-infrastructure/actions/workflows/pulumi-structural.yml)
[![Pulumi Policy Tests](https://github.com/VilnaCRM-Org/bootstrap-infrastructure/actions/workflows/pulumi-policy.yml/badge.svg)](https://github.com/VilnaCRM-Org/bootstrap-infrastructure/actions/workflows/pulumi-policy.yml)
[![Pulumi PR Guardrails](https://github.com/VilnaCRM-Org/bootstrap-infrastructure/actions/workflows/pulumi-pr-guardrails.yml/badge.svg)](https://github.com/VilnaCRM-Org/bootstrap-infrastructure/actions/workflows/pulumi-pr-guardrails.yml)
[![Pulumi Mutation Tests](https://github.com/VilnaCRM-Org/bootstrap-infrastructure/actions/workflows/pulumi-mutation.yml/badge.svg)](https://github.com/VilnaCRM-Org/bootstrap-infrastructure/actions/workflows/pulumi-mutation.yml)
[![CLI Tests](https://github.com/VilnaCRM-Org/bootstrap-infrastructure/actions/workflows/bats-tests.yml/badge.svg)](https://github.com/VilnaCRM-Org/bootstrap-infrastructure/actions/workflows/bats-tests.yml)
[![Python Quality Checks](https://github.com/VilnaCRM-Org/bootstrap-infrastructure/actions/workflows/python-quality.yml/badge.svg)](https://github.com/VilnaCRM-Org/bootstrap-infrastructure/actions/workflows/python-quality.yml)
[![Security Scans](https://github.com/VilnaCRM-Org/bootstrap-infrastructure/actions/workflows/security-scans.yml/badge.svg)](https://github.com/VilnaCRM-Org/bootstrap-infrastructure/actions/workflows/security-scans.yml)

Production-ready scaffold for teams that want to ship infrastructure-as-code with Pulumi and Docker from day zero.

## Possibilities

- Pulumi (Python) starter that exports environment metadata and tagging helpers.
- Reproducible Docker Compose workspace with a Pulumi-ready container and helper `make` tasks.
- CI pipelines for structural, policy, preview, security, unit, integration, mutation, and CLI-level checks.
- Multi-account Pulumi ESC guidance for `test-pr`, `test`, `prod-preview`, and protected `prod` workflows.
- Release and template-sync automations to keep downstream repos aligned.
- Documentation on AWS credential management for secure automation using GitHub OIDC and short-lived credentials.

## Why You Might Need It

Spin up consistent project infrastructure without wiring every component manually. This template gives DevOps teams a single source that:

- Encodes best practices from VilnaCRM’s production stack.
- Works out-of-the-box with AWS and Pulumi.
- Keeps infrastructure changes reviewable with local Pulumi previews, policy-pack guardrails, and CI test suites before deploying.

## License

This software is distributed under the [Creative Commons Zero v1.0 Universal](https://creativecommons.org/publicdomain/zero/1.0/deed) license. Please read [`LICENSE`](LICENSE) for details.

## Documentation

All project docs live under `docs/` to keep everything version controlled. Start with the handbook and jump directly to common topics:

- [Quick Start](docs/README.md#quick-start)
- [Local Tooling](docs/README.md#local-tooling)
- [Development Environment](docs/README.md#development)
- [PyCharm Autocomplete](docs/pycharm-autocomplete.md)
- [CI/CD and Secrets](docs/README.md#cicd-and-secrets)
- [CI Quality Gates](docs/ci-quality-gates.md)
- [CI Guardrails](docs/ci-guardrails.md)
- [CI Architecture](docs/ci-architecture.md)
- [Security Baseline](docs/security-baseline.md)
- [Pulumi Guardrails](docs/pulumi-guardrails.md)
- [uv and Rust-native Python tooling](docs/uv-rust-python-tooling-plan.md)
- [SRE Operations](docs/sre-operations.md)
- [Testing and Validation](docs/README.md#testing-and-validation)
- [Security](docs/README.md#security)
- [Contributing](docs/README.md#contributing)
- [Sponsorship](docs/README.md#sponsorship)

Community Q&A lives under the [`vilnacrm` tag on Stack Overflow](https://stackoverflow.com/questions/tagged/vilnacrm). For questions or feature requests, open an issue.

## Local Pulumi test suites

Docker Compose CLI 2.24.0+ is required because `docker-compose.yml` uses the
`env_file.required` flag (older Compose releases fail to parse it).

## Environment files

The Makefile resolves the effective env file as the first existing file from
`.env` and `.env.empty`.

- `.env` is git-ignored and should hold local secrets or developer-specific overrides.
- `.env.empty` is committed and acts as the minimal fallback so Docker Compose and `make` targets still run in a fresh clone.
- `.env.dist` remains an optional example/template file you can copy from when you want a fuller starting point; unlike `.env.empty`, it is not the automatic fallback used by the Makefile.

For onboarding, create or update `.env` with any local overrides you need, keep
`.env.empty` safe to commit, and refresh `.env.dist` only when the example
values or documented setup flow changes.

If you want a local `uv` environment outside Docker, seed it once so Pulumi's
Automation API can still use `pip` for package discovery:

```sh
export UV_PROJECT_ENVIRONMENT="${HOME}/.venvs/bootstrap-infrastructure"
uv venv --seed "${UV_PROJECT_ENVIRONMENT}"
uv sync --all-groups
```

The Docker workspace already ships with an isolated seeded environment outside
the bind-mounted repository tree, so the `make` targets remain the recommended
way to run the different Pulumi-focused suites (see `docker-compose.yml` for
the canonical workspace layout):

```sh
# Build the dev image used by the local and CI batteries
make build

# Configuration validation
make test-pulumi
make test-repository-catalogs
make test-repository-fanout

# Rust-based quality gates
make test-quality

# Pulumi policy and guardrail validation
make test-policy

# Unit tests (pure Pulumi runtime with mocks)
make test-unit

# Automation-based integration tests
make test-integration

# Mutation analysis (time-consuming)
make test-mutation
```

Use the local batteries that match the scope of your change:

- `make test` runs the faster structural, repository-catalog, policy, quality, repo-hygiene, unit, integration, coverage, and CLI battery.
- `make test-security`, `make test-repository-fanout`, and `make test-guardrails` focus on infrastructure safety controls.
- `make ci-pr` mirrors the non-mutation GitHub pull-request battery before merge.
- `make ci` runs the full local superset, including the prerequisite check, image build, preview guardrails, security scans, and mutation suite.
- `make report-quality` generates the scheduled Wily, Vulture, docstring-coverage, and SBOM reports locally.

If Pulumi provider plugin downloads hit GitHub rate limits during local preview
or drift commands, pass `GITHUB_TOKEN="$(gh auth token)"` explicitly to that
single Make invocation instead of exporting it globally.

Run `make doctor` when you need a fast prerequisite check before debugging local
Docker or Compose behavior.

`make pulumi-preview` and `make pulumi-up` automatically enable the repository
policy pack. If the shared `uv` environment inside the container is missing
core Pulumi Python dependencies, the bootstrap helper resyncs it from
`uv.lock` before Pulumi starts. The policy runtime is refreshed separately in
`policy/.venv` from `policy/requirements.txt` so Pulumi starts the policy pack
consistently in Docker, CI, and local shells. The interactive Pulumi targets
also log into the configured backend automatically, falling back to the local
file backend under `.pulumi-backend/` when no shared backend is configured,
select the first committed `Pulumi.<stack>.yaml` file by default, and expect
shared backends to use an AWS KMS-backed secrets provider. For test/prod CI
setup, store account-local values in AWS Secrets Manager JSON secrets, project
them through Pulumi ESC environments, and configure OIDC roles as described in
[GitHub Actions Secrets and Variables](docs/github-actions-secrets.md).

## Security

Please disclose any vulnerabilities found responsibly – report security issues to the maintainers privately.
