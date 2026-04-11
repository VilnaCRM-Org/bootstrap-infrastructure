# CI Architecture

This repository keeps CI intentionally close to the local developer workflow.
Docker-backed pull request checks use the same Docker workspace and the same
`make` entrypoints that developers use locally.

## Design Principles

- local/CI parity over bespoke workflow-only commands
- short feedback loops for structural and unit checks
- explicit isolation for slower suites such as mutation testing
- safe defaults: least privilege, cancellable duplicates, bounded run time

## Workflow Matrix

| Workflow | Primary command | Purpose |
| --- | --- | --- |
| `pulumi-structural.yml` | `make test-pulumi` | Validates Pulumi metadata, workflow contracts, and Dockerfile safeguards |
| `pulumi-policy.yml` | `make test-policy` | Validates the Pulumi policy pack and AWS guardrail coverage |
| `pulumi-pr-guardrails.yml` | `make test-preview`, `make test-destructive-diff`, `make test-iam-validation` | Generates the PR preview artifact and enforces destructive/IAM guardrails |
| `security-scans.yml` | `make test-secrets`, `make test-deps-security`, `make test-bandit`, `make test-actionlint`, `make test-yaml`, `make test-dockerfile` | Runs blocking security and repo-hygiene checks plus GitHub dependency review |
| `codeql.yml` | GitHub-native | Scans Python code and workflow code with CodeQL |
| `python-quality.yml` | `make test-ruff`, `make test-ty`, `make test-maintainability`, `make test-architecture`, `make test-dependency-hygiene`, `make test-coverage` | Blocking Python quality, maintainability, architecture, dependency, and coverage gates |
| `pulumi-unit.yml` | `make test-unit` | Mock-based Pulumi component tests with full coverage |
| `pulumi-integration.yml` | `make test-integration` | Automation API lifecycle tests against a local file backend |
| `pulumi-mutation.yml` | `make test-mutation` | Mutation analysis of the Pulumi component layer |
| `bats-tests.yml` | `make test-cli` | CLI contract tests for the Makefile interface |
| `pulumi-local.yml` | `make ci-pr` | Non-mutation PR-equivalent battery inside Docker |
| `nightly-quality.yml` | `make report-quality` | Publishes maintainability, dead-code, docstring, and SBOM reports |
| `nightly-guardrails.yml` | `make test-drift` | Runs scheduled drift detection and repository-health checks |

## Shared Controls

### Prepared Docker Context

Docker-backed CI workflows call `make start` before running checks. GitHub-native
jobs such as CodeQL, Dependency Review, and Scorecard do not invoke it because
they do not run inside the repository Docker workspace. For the Docker-backed
jobs, `make start` standardizes the expected local state:

- creates `${HOME}/.aws` with restrictive permissions
- materializes `.env` from `.env.empty` when needed
- enforces owner-only permissions on `.env`
- prepares the `.pulumi-backend` directory used by local-backend test flows
- starts the Compose service so later `make` targets share the same prepared workspace

Centralizing the setup keeps workflows consistent and reduces drift between
checks.

### Concurrency

Every pull-request-oriented validation workflow uses a concurrency group based on
the workflow name and PR number or ref. That prevents multiple stale runs from
contending on the same branch after rapid pushes.

### Timeouts

Every CI job declares `timeout-minutes`. Fast suites fail fast; slower suites
such as mutation testing and the full local battery are allowed more time but
still remain bounded.

### Minimal Permissions

Validation workflows use `contents: read`. Release and synchronization workflows
ask for broader access only where automation actually needs to write tags,
releases, or pull requests.

## Local Parity

The repository intentionally avoids workflow-only logic for the core validation
battery.

- `make test` is the fast inner-loop command for the prerequisite sanity check, Pulumi structural tests, policy, quality, repo hygiene, unit, integration, coverage, and CLI checks.
- `make ci-pr` matches the non-mutation GitHub pull-request battery, including preview and security guardrails.
- `make ci` is the full local superset, including the dedicated mutation suite.
- `make report-quality` mirrors the scheduled quality-report workflow locally.
- `make start` prepares the Docker-backed workspace before CI-style checks or manual Docker sessions.
- `make doctor` provides a quick prerequisite check before developers start
  debugging Docker or Pulumi behavior.

If you add a new CI check, prefer adding a Make target first and making GitHub
Actions call that target.

## Adding a New Workflow

Use this checklist:

1. add or reuse a Make target
2. keep the workflow on pinned actions
3. define `permissions`
4. add `concurrency`
5. set `timeout-minutes`
6. call `make start` if the job uses the Docker workspace
7. extend the structural tests and docs in the same PR

## Failure Triage

When a PR check fails:

1. reproduce with the matching local Make target
2. run `make doctor` if the failure looks environment-related
3. inspect the workflow job log only after the local path is understood
4. fix the underlying contract rather than weakening the check

CodeQL, GitHub Dependency Review, artifact attestations, and Scorecard remain
GitHub-native workflows. The repository keeps their definitions under
structural test coverage, but they are not reproduced inside the local Docker
battery.
