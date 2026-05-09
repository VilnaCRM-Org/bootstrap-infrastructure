# Infrastructure Template Documentation

We follow a docs-as-code workflow: every guide lives alongside the source and evolves through pull requests. Update or add files in this folder whenever you change the infrastructure template so future readers stay aligned with the repository.

## Contents

- [Quick Start](#quick-start)
- [Local Tooling](#local-tooling)
- [Development](#development)
- [Python Tooling](#python-tooling)
- [CI/CD and Secrets](#cicd-and-secrets)
- [CI Quality Gates](#ci-quality-gates)
- [CI Guardrails](#ci-guardrails)
- [CI Architecture](#ci-architecture)
- [Cost, Performance, and Sustainability](#cost-performance-and-sustainability)
- [Pulumi Guardrails](#pulumi-guardrails)
- [Security Baseline](#security-baseline)
- [Project Structure](#project-structure)
- [Testing and Validation](#testing-and-validation)
- [SRE Operations](#sre-operations)
- [Detailed Test Matrix](#detailed-test-matrix)
- [Repository Synchronization](#repository-synchronization)
- [Security](#security)
- [Contributing](#contributing)
- [Sponsorship](#sponsorship)
- [Documentation Workflow](#documentation-workflow)

## Quick Start

1. **Use this template** or clone the repository locally.
2. Install [Docker](https://docs.docker.com/engine/install/) and [Docker Compose](https://docs.docker.com/compose/install/)
   (Docker Compose CLI 2.24.0+ is required because `docker-compose.yml` uses
   `env_file.required`).
3. (Optional) Install the [Pulumi CLI](https://www.pulumi.com/docs/install/) if you plan to run commands outside the container.
4. Launch the local environment:

   ```bash
   make start
   ```

5. Configure your AWS credentials (for example via `aws configure`, environment variables, or GitHub Actions secrets).
6. Run a preview from inside the container to validate infrastructure changes:

   ```bash
   make pulumi-preview
   ```

That is all you need to begin iterating on the sample AWS instance or adapting the stack to your own infrastructure.

## Local Tooling

`make help` prints the available tasks. Most common targets:

```text
all               Display help (default goal).
build             Build the Pulumi development image used by local and CI checks.
ci                Run the full local equivalent of all GitHub checks, including mutation.
ci-pr             Run the non-mutation GitHub pull-request battery locally.
doctor            Check local prerequisites and effective paths without printing secrets.
help              Print the available make targets.
nightly-quality   Run the scheduled quality-report battery locally.
report-quality    Generate the scheduled maintainability, dead-code, docstring, and SBOM reports.
report-sbom       Generate a CycloneDX SBOM for the synced Python environment.
start             Initialize and start the Pulumi development environment.
pulumi-preview    Preview infrastructure changes with the policy pack enforced.
pulumi-up         Apply the current infrastructure plan with the policy pack enforced.
pulumi-refresh    Sync the Pulumi stack with live cloud resources.
pulumi-destroy    Tear down the stack (irreversible; use with caution).
sh                Open a shell inside the Pulumi container.
down              Stop the Docker Compose environment.
test              Run the aggregate structural, policy, quality, repo-hygiene, unit, integration, coverage, and CLI battery.
test-coverage     Combined 100% branch-coverage gate after unit, integration, and policy suites.
test-crossguard   Alias for the Pulumi CrossGuard policy-pack suite.
test-pulumi       Structural validation for manifests, workflows, and supply-chain guards.
test-repository-catalogs  Validate repository catalog JSON against schema and loader rules.
test-repository-fanout  Estimate repository catalog resource fanout against thresholds.
test-policy       Pulumi policy-pack tests and guardrail coverage.
test-quality      Blocking Python quality, maintainability, architecture, and dependency checks.
test-repo-hygiene Workflow, YAML, and Dockerfile linting.
test-ruff         Ruff lint and format drift checks.
test-ty           Ty static typing diagnostics for the Pulumi and policy layers.
test-unit         Pulumi component tests with mocks.
test-integration  Pulumi Automation smoke tests with a local backend.
test-mutation     Mutation analysis of the component layer.
test-cli          Bats-based checks for the Makefile interface.
clean             Remove Docker Compose artifacts and Python build caches.
```

## Development

We recommend editing the project through the Docker workspace so IDEs can reuse
the interpreter that already ships with the repository (Pulumi CLI, Python SDKs,
uv, Ruff, Ty).

- [PyCharm autocomplete guide](pycharm-autocomplete.md) — shows how to attach
  PyCharm to the Docker Compose interpreter or create a local virtualenv
  fallback.
- `docker compose up --build -d` launches the workspace; `docker compose down`
  stops it.

## Python Tooling

The repository now uses `uv` for locking, syncing, and command execution, with
Ruff and Ty as fast Rust-based quality gates.

- The Docker workspace keeps its `uv` environment outside the bind-mounted
  workspace so host mounts cannot replace the interpreter seen by Pulumi
  (see `docker-compose.yml` for the canonical workspace layout).
- If you want a local virtual environment outside Docker, seed it once before
  syncing:

  ```bash
  export UV_PROJECT_ENVIRONMENT="${HOME}/.venvs/bootstrap-infrastructure"
  uv venv --seed "${UV_PROJECT_ENVIRONMENT}"
  uv sync --all-groups
  ```

- The detailed workflow and rationale live in
  [uv and Rust-native Python tooling](uv-rust-python-tooling-plan.md).

## CI/CD and Secrets

CI checks are split into focused workflows that run inside the Docker workspace:

- `pulumi-structural.yml` validates Pulumi project metadata.
- `pulumi-unit.yml` runs unit tests with Pulumi mocks.
- `pulumi-integration.yml` runs Pulumi Automation tests with a local file backend.
- `pulumi-policy.yml` executes the Pulumi policy-pack suite.
- `pulumi-mutation.yml` executes mutation testing.
- `python-quality.yml` runs Ruff, Ty, maintainability, architecture, dependency-hygiene, and coverage checks.
- `security-scans.yml` runs secrets, Bandit, dependency audit/review, workflow linting, YAML linting, and Hadolint.
- `bats-tests.yml` validates the Makefile CLI surface.
- `pulumi-local.yml` runs `make ci-pr`, the non-mutation pull-request battery inside Docker.
- `nightly-quality.yml` publishes maintainability, dead-code, docstring, and SBOM reports.

These checks do not require AWS or Pulumi credentials by default. They use
concurrency groups, bounded job timeouts, pinned actions, and a shared
`make start` bootstrap path so local and GitHub-hosted
validation stay aligned.

Privileged issue 18 workflows use GitHub environments for account separation:
`test` for trusted PR preview, test apply, and test drift; `prod-preview` for
production preview and drift; and protected `prod` for production apply.
Configure account-local variables, OIDC roles, Pulumi backend URLs, and AWS
KMS-backed Pulumi secrets providers in the [GitHub Actions Secrets guide](github-actions-secrets.md).

## CI Quality Gates

Use the [CI quality gates guide](ci-quality-gates.md) for blocking thresholds,
architecture contracts, dependency hygiene, repo-hygiene checks, and scheduled
maintainability monitoring.

## CI Guardrails

Use the [CI guardrails guide](ci-guardrails.md) for the PR-blocking preview,
destructive diff, IAM validation, secret scanning, dependency audit, CodeQL,
nightly drift/Scorecard contracts, production approval boundaries, sanitized
evidence, and OIDC role expectations.

## CI Architecture

Use the dedicated [CI architecture guide](ci-architecture.md) when you need the
workflow matrix, local-to-GitHub mapping, or the checklist for adding a new CI
job safely.

## Cost, Performance, and Sustainability

Use the [cost, performance, and sustainability guide](cost-performance-sustainability.md)
for repository catalog fanout, preview cost proxy evidence, and review
expectations before durable AWS resources are applied.
Use the [2026-05-09 FinOps review](finops-review-2026-05-09.md) for the current
budget, anomaly, active cost allocation tag, monthly cost, and data transfer
evidence.
Use the [performance operating evidence](performance-operating-evidence.md) for
resource-selection, storage, region, network, and fanout ADRs.
Use the [workload applicability evidence](workload-applicability-evidence.md)
for the no-VPC, no-public-endpoint, dependency, and no-idle-compute record.
Use the [data protection and recovery evidence](data-protection-recovery-evidence.md)
for at-rest protection, Vault Lock/Object Lock posture, restore runbooks, and
backup review cadence.
Use the [2026-05-09 operating review](operating-review-2026-05-09.md) for the
current KPI observations, demand review, service review, cost-of-effort notes,
and sustainability governance record.
Use the [region sustainability evidence](region-sustainability-evidence.md) for
the primary/replica region decision matrix and exception gates.
Use the [fault isolation evidence](fault-isolation-evidence.md) for
per-repository state, KMS, IAM, OIDC, and environment boundary tests.
Use the [alert routing evidence](alert-routing-evidence.md) for the current
EventBridge/SNS/SQS inventory, route-test evidence, and alert fallback rules.
Use the [compute runner evidence](compute-runner-evidence.md) for the optional
ECR runner repository posture and future-image SEC6 gate.

## Well-Architected Evidence

Use the [Well-Architected operating evidence register](well-architected-operating-evidence.md)
for the current owner registry, KPI cadence, runbooks, decision matrices, and
fallback actions that support repository-owned Well-Architected score evidence.

## Security Baseline

Use the [security baseline](security-baseline.md) for the template's enforced
controls, extension checklist, and guidance on secrets, token scope, and
supply-chain hygiene.

## Pulumi Guardrails

Use the [Pulumi guardrails guide](pulumi-guardrails.md) for the runtime
identifier rules, policy-pack guardrails, and the local/CI commands that keep
them enforced.

## Project Structure

- `pulumi/__main__.py` – Minimal Pulumi program that exports environment metadata and tags.
- `docker-compose.yml` – Local development environment with Pulumi tooling baked in.
- `Makefile` – Convenience commands for preview, testing, and container management.
- `.github/workflows` – Automation for CI checks, releases, and template synchronization.

## Testing and Validation

Continuous integration runs automatically on every pull request. You can also validate locally:

- Start with `make doctor` if you need a quick sanity check of Docker, Compose, and the effective env file.
- Use the focused suites when you only need one slice: `make build`, `make test-pulumi`, `make test-repository-fanout`, `make test-policy`, `make test-crossguard`, `make test-quality`, `make test-repo-hygiene`, `make test-unit`, `make test-integration`, `make test-coverage`, `make test-mutation`, `make test-cli`, `make test-security`, `make test-guardrails`.
- Use `make test-policy` when you are changing guardrails or adding new AWS resource types that should be covered by the policy pack.
- `make test-mutation` intentionally uses the focused `pulumi/app` unit-test surface by default so the PR mutation check stays fast; override `MUTATION_TEST_TARGETS` or `MUTATION_TESTS_DIR` only when you explicitly need a broader, slower mutation run.
- `make pulumi-preview` and `make pulumi-up` sync the shared `uv` environment if needed, refresh `policy/.venv`, and then run Pulumi with the repository policy pack enabled.
- Run `make test` to execute the faster structural, policy, quality, repo-hygiene, unit, integration, coverage, and CLI checks together after a prerequisite sanity check.
- Use `make ci-pr` to mirror the non-mutation GitHub pull-request battery, including the prerequisite check, image build, security scans, preview generation, and policy suite.
- Execute `make ci` to run the full local equivalent of all GitHub checks, including the prerequisite check, image build, and mutation suite.
- Run `make report-quality` or `make nightly-quality` when you want the scheduled maintainability, dead-code, docstring, and SBOM reports locally.
- If Pulumi plugin downloads hit GitHub rate limits locally, pass
  `GITHUB_TOKEN="$(gh auth token)"` explicitly to the preview-oriented target
  you are running instead of exporting it globally.
- `make pulumi-preview` to review planned resources before applying.
- `make pulumi-up` followed by `pulumi stack output` to inspect applied results.
- GitHub Actions mirrors `make ci-pr` through the `Pulumi Local Test Battery` workflow, while mutation remains isolated in `pulumi-mutation.yml`.
- `Pulumi PR Guardrails` and `Security Scans` also expose their focused Make entrypoints as dedicated CI checks.

## SRE Operations

Use the [SRE operations guide](sre-operations.md) for preview/apply/refresh
flows, stack strategy, replica-region migration, safe AWS metadata validation,
production approval checks, failure triage, release hygiene, and cleanup
guidance.

## Detailed Test Matrix

Use the dedicated [testing guide](testing.md) when you need to know exactly what each suite covers or which local command maps to which CI workflow.

## Repository Synchronization

This template feeds other VilnaCRM infrastructure projects through [`actions-template-sync`](https://github.com/AndreasAugustin/actions-template-sync). For authentication guidance, see the [Template Sync secrets](github-actions-secrets.md#template-sync-secrets).

Remember to grant least privilege, rotate secrets regularly, and monitor workflow logs.

## Security

Report security issues responsibly to the maintainers. Consult [`SECURITY.md`](../SECURITY.md) and the repository’s [security advisories](https://github.com/VilnaCRM-Org/bootstrap-infrastructure/security).

## Contributing

Bug reports, feature requests, and pull requests are welcome via the [issue tracker](https://github.com/VilnaCRM-Org/bootstrap-infrastructure/issues). Documentation updates are highly appreciated—edit the files under `docs/` so improvements travel with the code.

## Sponsorship

Development time and resources for this repository are provided by [VilnaCRM](https://vilnacrm.com/), the free and open-source CRM system.

Donations are very welcome, whether in beer 🍺, T-shirts 👕, or cold, hard cash 💰. Sponsorship through GitHub is a simple and convenient way to say "thank you" to maintainers and contributors – just click the "Sponsor" button [on the project page](https://github.com/VilnaCRM-Org/bootstrap-infrastructure). If your company uses this template, consider taking part in the VilnaCRM's enterprise support program.

## Documentation Workflow

1. Add or edit Markdown inside `docs/`.
2. Cross-link the new material from `README.md` or other docs so it is discoverable.
3. Include documentation updates in the same PR as related code changes whenever possible.
4. Keep `AGENTS.md` aligned with any workflow or secret-handling changes that affect coding agents.

You can organize content as it grows by creating subdirectories (e.g., `docs/pulumi/`).
