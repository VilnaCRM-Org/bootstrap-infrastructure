# PRD: Issue 20 AWS Secrets Manager CI Configuration

> **Historical design, amended for the PR57 successor (2026-09-06).**
> The September [successor verification](pr57-successor-verification.md) is the
> current implementation contract. Earlier references to a sole `prod`
> deployment environment, workflow-path-only trust, or optional role fallbacks
> are superseded. Retain all installed protected command environments, exact
> workflow/ref and immutable repository identity conditions, independent account
> pins, operator ownership, and fail-closed purpose-specific roles. This document
> is requirements lineage, not current live or BMAD acceptance.

## Problem

Privileged CI workflows previously read AWS account IDs, role ARNs, Pulumi
backend URLs, secrets-provider URIs, and stack lists from GitHub Environment
variables. That made non-approval environments (`test`, `prod-preview`) double
as both account configuration and trust boundaries, and it left manual
configuration drift outside GitOps review.

## Goals

- Move privileged CI account configuration into fixed AWS Secrets Manager JSON
  secrets.
- Manage the AWS Secrets Manager secret containers and `GitHubCiConfigRead-*`
  roles through Pulumi while leaving secret JSON values human-populated in AWS
  Secrets Manager.
- Keep the protected GitHub `prod` Environment only as a production approval
  boundary.
- Authenticate to AWS with GitHub OIDC; do not introduce long-lived AWS keys or
  Pulumi access tokens.
- Validate AWS Secrets Manager-loaded configuration before deployment
  credentials are requested.
- Bind AWS OIDC trust to each role's fixed repository identity, intended
  workflow/ref and protected environment subjects. Retain `test`, `test-preview`,
  `prod-preview` and `prod`; non-production roles reject `environment:prod`.
- Deduplicate operations alert issues created from repeated AWS Backup failure
  notifications.
- Document every manual setup step that cannot be performed safely from GitOps.

## Non-Goals

- Adding production apply paths that bypass the trusted comment controller and
  protected approval boundary.
- Migrating Pulumi state secrets away from the existing AWS KMS provider.
- Replacing GitHub branch protection or production reviewer controls.

## Required AWS CI Config Secrets

| CI suffix | AWS Secrets Manager secret ID | Purpose |
| --- | --- |
| `test-pr` | `/bootstrap-infrastructure/ci/test-pr` | Trusted PR preview, IAM validation, and PR evidence collection |
| `test` | `/bootstrap-infrastructure/ci/test` | Test apply, drift, operations triage, and evidence |
| `prod-preview` | `/bootstrap-infrastructure/ci/prod-preview` | Production preview, IAM validation, and drift |
| `prod` | `/bootstrap-infrastructure/ci/prod` | Production apply after protected GitHub approval |

Workflow call sites pass only fixed suffixes such as `test-pr` or `prod`.
Account-local values remain AWS Secrets Manager-owned and are loaded by the
local AWS CI action through GitHub OIDC.

## Acceptance Criteria

- Privileged workflows load one fixed AWS Secrets Manager CI secret through a
  trusted pinned composite action and never derive the suffix from PR/comment payloads.
- Workflows keep only the minimal repository variables needed to locate the
  account-local config-read roles and regions; account-local AWS values move to
  AWS Secrets Manager. Protected `test`, `test-preview`, `prod-preview` and
  `prod` deployment environments remain in use; CI configuration does not use
  `secrets.PULUMI_ACCESS_TOKEN`.
- Production mutation jobs require the protected GitHub `prod` environment;
  preview jobs retain their separate protected preview environments.
- Pulumi component tests prove non-production automation roles do not trust
  `environment:prod`; test roles retain their intended `test`/`test-preview`
  subjects, and production apply roles retain `environment:prod`.
- Operations alert triage comments on an existing open canonical issue when a
  stable alert fingerprint already exists.
- Operator documentation describes AWS Secrets Manager-backed CI keys, OIDC
  trust, stack migration, and manual secure setup steps.
- Pulumi outputs expose the AWS Secrets Manager container IDs and
  `GitHubCiConfigRead-*` role ARNs needed to configure GitHub repository
  variables.

## BMAD/BMALPH Notes

`bmalph doctor` and `bmalph status` were run before implementation and reported
that this repository is not initialized for BMad/BMALPH. `bmalph init --dry-run`
was used to inspect generated state paths. Per repository guidance, this PR
commits the planning artifacts under `specs/` and does not commit `_bmad/`,
`.ralph/`, or generated framework state.
