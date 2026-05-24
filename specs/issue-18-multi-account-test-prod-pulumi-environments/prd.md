# PRD: Multi-Account Pulumi Environments

> Superseded by issue 20 for privileged CI configuration. GitHub
> non-production environments from this plan have been replaced by fixed Pulumi
> ESC environments; protected GitHub `prod` remains the approval boundary.

## Executive Summary
This change makes the bootstrap infrastructure repository deployable across separate AWS test and production accounts with account-scoped CI configuration, OIDC-only credentials, S3 Pulumi backends, and AWS KMS Pulumi secrets providers. The primary users are maintainers and SREs who need auditable preview, apply, drift, and smoke-validation paths without sharing state or credentials between environments.

## Success Criteria

| ID | Criterion | Measurement |
| --- | --- | --- |
| SC-1 | Pull requests from trusted same-repo branches run a real test-account Pulumi preview. | `pulumi-pr-guardrails.yml` binds privileged preview and IAM validation to the fixed test PR account configuration and fails fast when required variables are absent. |
| SC-2 | Pull requests from forks never receive AWS credentials. | The PR guardrail workflow selects an unprivileged path for fork PRs in a job without a GitHub environment or `id-token: write`. |
| SC-3 | Merges to `main` deploy only to the test account before any production path. | A merge workflow uses the fixed test account configuration, validates preview artifacts, applies the `test` stack, and runs post-apply drift. |
| SC-4 | Production apply requires a successful test deploy, production preview, and GitHub environment approval. | A production workflow verifies a successful `Pulumi Test Deploy` run for the same SHA, generates a production preview artifact, then gates `prod` apply behind protected `prod` approval and commit SHA verification. |
| SC-5 | Nightly drift validates both target accounts. | Nightly guardrails run separate test and production preview account jobs with account-specific roles and stack lists. |
| SC-6 | Stack configs are committed without secrets or legacy passphrase metadata. | `pulumi/Pulumi.test.yaml` and `pulumi/Pulumi.prod.yaml` contain only non-secret config and KMS initialization comments. |

## Product Scope

MVP scope:
- Committed non-secret `test` and `prod` Pulumi stack config.
- Account-scoped CI variables for account, region, role, backend, stack, and KMS provider values.
- Explicit PR preview, test deploy, production preview/apply, and nightly drift workflows.
- Docs and structural tests for the environment model.

Growth scope:
- Tighter generated least-privilege AWS role policies from Pulumi outputs.
- Automated privileged CI configuration drift reports.

Out of scope:
- Adding static AWS access keys.
- Decrypting or exporting Pulumi stack state.
- Creating long-lived secrets or introducing passphrase-backed Pulumi stacks.

## User Journeys

| Journey | User | Outcome | Requirements |
| --- | --- | --- | --- |
| Trusted PR preview | Maintainer opens a same-repo PR. | CI previews the `test` stack with OIDC and validates destructive/IAM guardrails from the same artifact. | FR-1, FR-2, FR-7 |
| Fork PR validation | Contributor opens a fork PR. | CI runs static and unprivileged guardrail checks without AWS credentials. | FR-3, FR-7 |
| Main test deployment | Maintainer merges to `main`. | CI validates and applies the `test` stack, then runs drift. | FR-4, FR-7 |
| Production release | Maintainer dispatches production workflow for a reviewed SHA. | CI previews with `prod-preview`, then applies with `prod` approval and SHA verification. | FR-5, FR-6, FR-7 |
| Nightly drift | SRE reviews scheduled checks. | CI reports drift separately for `test` and `prod`. | FR-8 |

## Domain Requirements

Infrastructure automation changes must use least privilege, short-lived credentials, explicit AWS account checks, immutable audit artifacts, and secret-safe logs. GitHub environment protection must separate preview-only production access from mutation access.

## Innovation Analysis

The original design used GitHub environments as the configuration and approval boundary instead of repository-wide variables. Issue 20 supersedes that model by keeping account, role, backend, and stack selection in AWS Secrets Manager JSON values that fixed Pulumi ESC environments project at runtime, while preserving protected GitHub `prod` approval controls.

## Project-Type Requirements

This is developer infrastructure automation. Workflows must be scriptable, non-interactive, and reproducible locally through Make targets where possible. Artifacts must remain useful for review while avoiding raw state exports or secret-bearing command output.

## Functional Requirements

| ID | Requirement | Test Criteria |
| --- | --- | --- |
| FR-1 | Trusted PRs can run a real Pulumi preview against the `test` stack. | Workflow uses fixed test PR account configuration with `AWS_PREVIEW_ROLE_ARN`, `PULUMI_BACKEND_URL`, `PULUMI_SECRETS_PROVIDER`, and `PULUMI_PREVIEW_STACKS`. |
| FR-2 | IAM validation uses AWS credentials only for trusted privileged jobs. | Workflow configures OIDC after trust/missing-config checks and runs `make test-iam-validation` only in privileged mode. |
| FR-3 | Fork PRs run without AWS credentials. | Workflow checks fork source in a credential-free job and runs unprivileged preview/IAM paths without a GitHub environment or OIDC token permission. |
| FR-4 | Merges to `main` can apply only the `test` stack. | Test deploy workflow uses fixed test account configuration, test apply role, test stack variables, and post-apply drift. |
| FR-5 | Production preview uses read-only production access. | Production workflow preview job uses fixed production preview account configuration and `AWS_PREVIEW_ROLE_ARN`. |
| FR-6 | Production apply requires a successful test deployment, protected `prod` approval, and reviewed commit SHA. | Production preview verifies a successful `Pulumi Test Deploy` run for the SHA; production apply uses protected GitHub `prod`, validates SHA equality, and applies the saved plan. |
| FR-7 | Privileged logs show account, stack, environment, role, and guardrail mode without secrets. | Workflows emit sanitized evidence lines and do not call secret-revealing Pulumi or AWS commands. |
| FR-8 | Nightly drift checks run for `test` and `prod`. | Nightly guardrail workflow contains separate jobs bound to fixed test and production preview account configuration. |
| FR-9 | Stack discovery excludes example stacks unless explicitly configured. | Helper discovery ignores the exact template file `Pulumi.example.yaml`. |

## Non-Functional Requirements

- The system shall use OIDC-only AWS credentials for privileged GitHub jobs as measured by absence of static AWS key secrets in workflows.
- The system shall use AWS KMS Pulumi secrets providers for stack initialization as measured by workflow/script calls containing `--secrets-provider "$PULUMI_SECRETS_PROVIDER"`.
- The system shall fail privileged same-repo guardrails when required account-scoped variables are missing as measured by workflow prerequisite checks.
- The system shall retain preview evidence for no more than 14 days as measured by upload-artifact retention settings.
- The system shall avoid secret-revealing commands as measured by workflow and script tests checking for forbidden flags.
