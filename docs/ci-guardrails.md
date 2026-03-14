# CI Guardrails

This repository treats Pulumi and AWS changes as high-risk changes. The CI layout is designed to catch the failure classes that autonomous agents are most likely to introduce: unsafe previews, destructive diffs, weak IAM, leaked secrets, and workflow-level security mistakes.

## Required PR Checks

These checks should be marked as required in GitHub branch protection or rulesets:

- `Python Quality Checks`
- `DevSecOps Guardrails`
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
- shell linting with ShellCheck
- IaC and workflow policy scanning with Checkov
- low-cost guardrails for the bootstrap stack
- parity with the external `qlty check` status

The repo-local `Qlty` command is still part of this layer because it mirrors the external quality gate that GitHub receives from the Qlty service.

The repository commits [`.gitleaks.toml`](/home/kravtsov/Projects/bootstrap-infrastructure/.gitleaks.toml) with a single narrow allowlist for the encrypted Pulumi ciphertext in [Pulumi.test.yaml](/home/kravtsov/Projects/bootstrap-infrastructure/pulumi/Pulumi.test.yaml). Do not expand that allowlist casually.

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

## Nightly Checks

These checks are visibility-oriented and do not need to block PR merges:

- `pulumi-drift.yml`
- `repo-health.yml`

`pulumi-drift.yml` runs a non-destructive `pulumi refresh --preview-only --expect-no-changes` through the shared runner image so unexpected drift is surfaced without mutating stack state.

## Repository Health

`repo-health.yml` runs OpenSSF Scorecard on a schedule and uploads SARIF so repository-health regressions stay visible in GitHub security surfaces.

CodeQL also runs on a schedule so background analysis continues even when a class of files is not touched in current PRs.

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

If an exception is needed repeatedly, the policy should be redesigned instead of growing an unbounded allowlist.
