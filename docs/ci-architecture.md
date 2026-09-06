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
| `pulumi-structural.yml` | `make test-pulumi`, `make test-repository-catalogs`, `make test-repository-fanout` | Validates Pulumi metadata, workflow contracts, repository catalogs, static fanout, and Dockerfile safeguards |
| `pulumi-policy.yml` | `make test-policy` | Validates the Pulumi policy pack and AWS guardrail coverage |
| `pulumi-pr-guardrails.yml` | `make publish-pulumi-preview-summary`, `make test-preview-unprivileged`, `make test-destructive-diff`, `make test-iam-validation` | Generates the PR preview artifact and enforces destructive/IAM guardrails without giving fork PRs AWS credentials |
| `pulumi-pr-commands.yml` | `scripts/pulumi_pr_comment.py`, `repository_dispatch` | Parses trusted PR comments, rejects forked PRs, and queues exact-SHA Pulumi operations |
| `pulumi-pr-command-runner.yml` | `make pulumi-plan`, destructive diff, IAM validation, apply, drift | Executes PR-comment Pulumi commands with test-first production promotion gates |
| `pulumi-test-deploy.yml` | `make pulumi-plan`, destructive diff, IAM validation, apply, drift | Applies the `test` stack after main merges or manual dispatch |
| `pulumi-prod.yml` | test-deploy SHA check, `make pulumi-plan`, approval, apply | Previews with `prod-preview`, then applies through protected `prod` |
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

## Multi-Account Environments

AWS Secrets Manager stores account-local CI configuration in the fixed suffixes
`test-pr`, `test`, `prod-preview`, and `prod`. Independently pinned repository
variables `AWS_TEST_ACCOUNT_ID` and `AWS_PROD_ACCOUNT_ID` are validated before
configuration-role assumption; all returned role/backend/KMS values must agree.
The protected `test`, `test-preview`, `prod-preview`, `prod`, `governance`,
`governance-preview`, and `operations-alert-reconcile` environments remain in use.
Configuration suffixes do not replace approval or main-only branch restrictions.
The installed trusted main controller validates original comments, current
permissions, scope, fresh PR head and verified same-head deployment evidence.
No apply/drift role fallback is permitted.

The loader reads only the fixed account-local secret and exports validated keys
without logging the payload. Control roles and secret containers are owned by
an independently reviewed operator project; the platform consumes references.
That separate #60 program is not delivered by this alert cutover. Use the
[AWS Secrets Manager CI cutover manual](aws-secrets-manager-ci-cutover.md).
Shared state and saved plans retain the existing checkpoint's KMS provider state.


Production apply is intentionally split from production preview. The preview job
first verifies that the requested commit already has a successful `Pulumi Test
Deploy` run on `main`, then records sanitized evidence for the reviewed commit.
The apply job runs only in the protected `prod` environment after required
reviewers approve it and the commit SHA is still the reviewed SHA.

PR-comment production promotion follows the same account boundaries, but the
trusted runner performs the test sequence inside the command workflow before
any production job can start. `/pulumi prod plan` and `/pulumi prod up` both
save and validate a test plan, apply it to the `test` account, and run
post-apply drift detection for the exact PR head SHA. Only after that succeeds
does the runner enter `prod-preview`; `/pulumi prod up` then waits on the
protected `prod` environment and applies the saved production plan.

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

Privileged infrastructure jobs add `id-token: write` only when they need GitHub
OIDC. Fork pull-request jobs do not bind a GitHub environment and do not request
OIDC token permission. Privileged jobs should pass `allowed-account-ids` with
the active environment's `AWS_ACCOUNT_ID` and use purpose-specific roles:
preview/drift roles for non-mutating checks and apply roles for deployments.

## Local Parity

The repository intentionally avoids workflow-only logic for the core validation
battery.

- `make test` is the fast inner-loop command for the prerequisite sanity check, Pulumi structural tests, repository catalog validation, policy, quality, repo hygiene, unit, integration, coverage, and CLI checks.
- `make ci-pr` matches the non-mutation GitHub pull-request battery, including preview and security guardrails.
- `make ci` is the full local superset, including the dedicated mutation suite.
- `make report-quality` mirrors the scheduled quality-report workflow locally.
- `make start` prepares the Docker-backed workspace before CI-style checks or manual Docker sessions.
- `make doctor` provides a quick prerequisite check before developers start
  debugging Docker or Pulumi behavior.

If you add a new CI check, prefer adding a Make target first and making GitHub
Actions call that target.

Privileged AWS validation is the exception: account checks can be GitHub-only
when they validate the deployed environment, but they must use metadata-only
commands such as `aws sts get-caller-identity`, `aws s3api head-bucket`, and
`aws kms describe-key`. Do not read secret payloads, decrypted parameters, or
raw Pulumi stack exports in CI evidence.

## Adding a New Workflow

Use this checklist:

1. add or reuse a Make target
2. keep the workflow on pinned actions
3. define `permissions`
4. add `concurrency`
5. set `timeout-minutes`
6. call `make start` if the job uses the Docker workspace
7. bind privileged jobs to the correct GitHub environment
8. use OIDC with explicit account allow-listing for AWS jobs
9. extend the structural tests and docs in the same PR

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
