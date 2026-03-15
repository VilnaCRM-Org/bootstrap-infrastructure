# CI Guardrails

This repository treats Pulumi and AWS changes as high-risk changes. The CI layout is designed to catch the failure classes that autonomous agents are most likely to introduce: unsafe previews, destructive diffs, weak IAM, leaked secrets, and workflow-level security mistakes.

## Required PR Checks

These checks should be marked as required in GitHub branch protection or rulesets:

- `Python Quality Checks`
- `DevSecOps Guardrails`
- `Dependency Review`
- `Pulumi Structural Tests`
- `Pulumi CrossGuard Tests`
- `Pulumi Unit Tests`
- `Pulumi Integration Tests`
- `Pulumi Mutation Tests`
- `Pulumi Coverage`
- `CLI testing`
- `Pulumi Preview Guardrails / Preview`
- `Pulumi Preview Guardrails / IAM Policy Validation`
- `CodeQL (python)`
- `CodeQL (actions)`

GitHub repository settings must be updated by a maintainer. Workflows alone do not make checks required.

## Python Quality Checks

The `python-quality.yml` workflow enforces local operator commands:

- `make check-format`
- `make check-lint`
- `make check-radon`
- `make check-xenon`
- `make check-imports`
- `make check-deptry`
- `make check-spelling`
- `make check-toml`
- `make check-types`
- `make check-ty`
- `make check-package`

These checks keep the Pulumi Python code formatted, typed, spell-checked, and locked to the committed `uv.lock`.
The format/lint layer is powered by Rust-native tooling where it gives fast feedback:

- `ruff`
- `typos`
- `taplo`
- Astral `ty`

Additional PR-blocking quality gates in this workflow:

- Ruff McCabe complexity via `C901` with `max-complexity = 12`
- Radon maintainability index with a minimum accepted rank of `B`
- Xenon complexity ceilings of `A` for module/average complexity and `C` for individual blocks
- Import Linter contracts that keep `infra`, `policy_pack`, and `scripts` separated
- Deptry dependency hygiene against `pyproject.toml`, `pulumi/requirements.txt`, and `uv.lock`

Lockfile freshness is enforced inside `make check-package` through `uv lock --check`.

## DevSecOps Guardrails

The `devsecops-guardrails.yml` workflow adds fast security checks that do not require cloud access:

- `make check-bandit`
- `make check-deps`
- `make check-sbom`
- `make check-secrets`
- `make check-yaml`
- `make check-actionlint`
- `make check-docker`
- `make check-shell`
- `make check-iac`
- `make check-qlty`
- `make test-cost`

This combination covers:

- Python security smells with Bandit
- dependency CVEs with `pip-audit`
- CycloneDX SBOM export
- Gitleaks secret scanning
- GitHub Actions linting with `actionlint`
- Dockerfile linting with Hadolint
- shell linting and formatting with ShellCheck plus `shfmt`
- IaC and workflow policy scanning with Checkov
- low-cost guardrails for the bootstrap stack
- parity with the external `qlty check` status

The repo-local `Qlty` command is still part of this layer because it mirrors the external quality gate that GitHub receives from the Qlty service.

The repository commits [`.gitleaks.toml`](/home/kravtsov/Projects/bootstrap-infrastructure/.gitleaks.toml) with a single narrow allowlist for the encrypted Pulumi ciphertext in [Pulumi.test.yaml](/home/kravtsov/Projects/bootstrap-infrastructure/pulumi/Pulumi.test.yaml). Do not expand that allowlist casually.

## Dependency Review

The `dependency-review.yml` workflow runs GitHub's dependency review action on PRs that touch:

- `pyproject.toml`
- `uv.lock`
- `pulumi/requirements.txt`

That check is intentionally path-filtered so dependency review only runs when dependency metadata changes. It fails on newly introduced vulnerabilities with severity `moderate` or higher.

## Pulumi Preview Guardrails

The `pulumi-preview.yml` workflow is the PR safety layer for infrastructure changes.

The `Preview` job:

- runs only when infrastructure-related files changed
- assumes an AWS role through GitHub OIDC
- verifies that the shared state bucket already exists
- runs `pulumi preview` in non-destructive mode
- stores the raw preview JSON as an artifact
- renders a markdown preview summary into the Actions job summary
- blocks deletes or replacements for critical resource types by default

The destructive diff gate fails the preview when Pulumi proposes destructive changes for resource families such as:

- VPC and core networking primitives
- IAM roles and policies
- KMS keys
- S3 buckets
- Route53 resources
- RDS resources
- Secrets Manager resources
- EKS resources

The only supported override is a maintainer-applied PR label:

- `pulumi-allow-destructive`

That label must be used deliberately and only after a human reviews the preview artifact.

The `IAM Policy Validation` job:

- assumes the same AWS role through OIDC
- runs [scripts/validate_iam_policies.py](/home/kravtsov/Projects/bootstrap-infrastructure/scripts/validate_iam_policies.py)
- validates generated IAM/resource policies with AWS IAM Access Analyzer
- fails on `ERROR`, `WARNING`, and `SECURITY_WARNING` findings

Current limitation:

- Access Analyzer validation covers generated identity and resource policies
- KMS key policies are not validated here because `ValidatePolicy` does not currently support `AWS::KMS::Key`
- trust policies are not validated because Access Analyzer does not provide the same validation path for GitHub OIDC assume-role documents

## Pulumi Policy Guardrails

The `pulumi-policy.yml` workflow runs `make test-crossguard` and validates the repo-local Pulumi CrossGuard policy pack in `policy_pack/`.

Those rules are also applied by [run_pulumi_command.sh](/home/kravtsov/Projects/bootstrap-infrastructure/scripts/run_pulumi_command.sh), so the same policy baseline is enforced in:

- `pulumi.yml`
- `pulumi-prod.yml`
- `pulumi-pr-commands.yml`
- `pulumi-pr-command-runner.yml`
- `pulumi-preview.yml`

This keeps local operator flows, deployment workflows, and PR automation on the same guardrail set.

## Code Scanning

The `codeql.yml` workflow runs GitHub CodeQL for:

- Python
- GitHub Actions workflows (`actions`)

This catches code-scanning issues that are not covered by Ruff, Bandit, or actionlint.

## Coverage Gate

The `pulumi-coverage.yml` workflow runs the Python suites that exercise Pulumi and policy code, then executes `make check-coverage`.

That job enforces 100% combined coverage for:

- `pulumi/`
- `policy_pack/`

Coverage is measured with branch coverage enabled. The current PR gate is 100% combined branch+line coverage for the Pulumi runtime and policy-pack code.

## Nightly Checks

These checks are visibility-oriented and do not need to block PR merges:

- `pulumi-drift.yml`
- `quality-monitoring.yml`
- `repo-health.yml`

`pulumi-drift.yml` runs a non-destructive `pulumi refresh --preview-only --expect-no-changes` through the shared runner image so unexpected drift is surfaced without mutating stack state.

## Quality Monitoring

`quality-monitoring.yml` adds scheduled quality-drift reporting that would be too noisy or too expensive to make PR-blocking:

- Wily maintainability trend reports
- Vulture dead-code scans
- docstring coverage for reusable modules via `docstr-coverage`
- a scheduled CycloneDX SBOM snapshot artifact

The Wily report is generated through [run_wily_report.py](/home/kravtsov/Projects/bootstrap-infrastructure/scripts/run_wily_report.py). On GitHub Actions it analyzes the clean checkout directly. On a dirty local worktree it falls back to a temporary clone of `HEAD` so the advisory report still runs instead of failing on Wily's `git` archiver precondition.

The Vulture job is advisory and allowed to report findings without failing the whole monitoring workflow because dead-code detection is inherently more prone to false positives than the blocking PR gates.

## Repository Health

`repo-health.yml` runs OpenSSF Scorecard on a schedule and uploads SARIF so repository-health regressions stay visible in GitHub security surfaces.

CodeQL also runs on a schedule so background analysis continues even when a class of files is not touched in current PRs.

## Workflow Organization

The workflow split is intentionally narrow:

- `python-quality.yml`: formatting, lint, complexity, dependency hygiene, typing, and lockfile integrity
- `devsecops-guardrails.yml`: secret scanning, vuln scanning, shell/YAML/Docker/workflow linting, IaC scanning, and cost controls
- `pulumi-preview.yml`: OIDC-authenticated preview, destructive-diff gate, and IAM validation
- `pulumi-*.yml`: structural, unit, integration, mutation, policy, coverage, and e2e test lanes
- `quality-monitoring.yml`: scheduled maintainability and quality-drift reporting
- `repo-health.yml`: scheduled Scorecard and background security visibility

This keeps required PR gates separate from scheduled observability jobs without duplicating logic across many near-identical workflows.

## OIDC And AWS Setup

All AWS access in GitHub Actions uses GitHub OIDC and short-lived credentials. Static long-lived AWS keys must not be stored in repository secrets.

Maintainers need to configure at least these repository or environment variables:

- `PULUMI_TEST_ROLE_ARN`
- `PULUMI_TEST_SECRETS_PROVIDER`
- `PULUMI_STATE_BUCKET`
- `PULUMI_PREVIEW_STACK` if the preview stack is not `test`

The AWS IAM trust policy for the preview/deploy role must allow:

- `sts:AssumeRoleWithWebIdentity`
- audience `sts.amazonaws.com`
- the repository subject for the GitHub environment or branch pattern used by the workflow

The role must also be allowed to call:

- the AWS APIs required by the bootstrap stack itself
- AWS IAM Access Analyzer `ValidatePolicy`

## Safe Exceptions

Use these escape hatches sparingly:

- destructive preview override: apply the `pulumi-allow-destructive` PR label after human review
- Gitleaks exception: modify [`.gitleaks.toml`](/home/kravtsov/Projects/bootstrap-infrastructure/.gitleaks.toml) only for encrypted or synthetic test material, never for real credentials
- IAM wildcard exception inside CrossGuard: use `VILNACRM_IAM_WILDCARD_ALLOWLIST_SIDS` only for a reviewed statement `Sid`, with the justification kept in code review and docs

Quality thresholds should only be changed after maintainers review the current baseline and explicitly update the accompanying documentation and structural tests. Lowering a threshold to “make CI green” is not an acceptable operating model.

## Current Limitations

- The repo uses a custom Python Pulumi CrossGuard pack rather than the official shared AWS policy packs because the official packs would introduce an additional policy-runtime toolchain for this repository. The current custom pack is the enforced baseline.
- SBOM generation is implemented locally and on schedule. Artifact provenance/attestation for the ECR runner image is not yet enforced because this repository currently publishes to ECR through a custom push path rather than a GitHub-native artifact release flow.
- `docstr-coverage` is used instead of `interrogate` because `interrogate` currently brings in the vulnerable `py` package with no fixed upstream version available. The repo keeps the docstring-coverage signal without carrying a permanent audit suppression.

If an exception is needed repeatedly, the policy should be redesigned instead of growing an unbounded allowlist.
