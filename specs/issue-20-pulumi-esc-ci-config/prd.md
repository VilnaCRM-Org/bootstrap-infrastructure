# PRD: Issue 20 Pulumi ESC CI Configuration

## Problem

Privileged CI workflows previously read AWS account IDs, role ARNs, Pulumi
backend URLs, secrets-provider URIs, and stack lists from GitHub Environment
variables. That made non-approval environments (`test`, `prod-preview`) double
as both account configuration and trust boundaries, and it left manual
configuration drift outside GitOps review.

## Goals

- Move privileged CI account configuration into AWS Secrets Manager JSON secrets
  that are projected through fixed Pulumi ESC environments.
- Manage the AWS Secrets Manager secret containers and ESC read roles through
  Pulumi while leaving secret JSON values human-populated in AWS Secrets
  Manager.
- Keep the protected GitHub `prod` Environment only as a production approval
  boundary.
- Authenticate to ESC and AWS with OIDC; do not introduce long-lived AWS keys
  or Pulumi access tokens.
- Validate ESC-loaded configuration before AWS credentials are requested.
- Update AWS OIDC trust to fixed repository subjects and workflow refs, with a
  GitHub environment subject only for production apply.
- Deduplicate operations alert issues created from repeated AWS Backup failure
  notifications.
- Document every manual setup step that cannot be performed safely from GitOps.

## Non-Goals

- Applying production infrastructure changes from this feature branch.
- Migrating Pulumi state secrets away from the existing AWS KMS provider.
- Replacing GitHub branch protection or production reviewer controls.

## Required ESC Environments

| ESC environment | Purpose |
| --- | --- |
| `vilnacrm-org/bootstrap-infrastructure/test-pr` | Trusted PR preview and IAM validation |
| `vilnacrm-org/bootstrap-infrastructure/test` | Test apply, drift, operations triage, and evidence |
| `vilnacrm-org/bootstrap-infrastructure/prod-preview` | Production preview, IAM validation, and drift |
| `vilnacrm-org/bootstrap-infrastructure/prod` | Production apply after protected GitHub approval |

The Pulumi organization and project prefix is committed in
`.github/ci/pulumi-esc.json`, while workflow call sites pass only fixed suffixes
such as `test-pr` or `prod`. Account-local values remain AWS Secrets
Manager-owned and are imported by ESC with the `aws-secrets` provider.

## Acceptance Criteria

- Privileged workflows load one fixed ESC environment through a local composite
  action and never derive the environment name from PR/comment payloads.
- Workflows have no references to `vars.AWS_*`, GitHub `test` or
  `prod-preview` deployment environments, or `secrets.PULUMI_ACCESS_TOKEN`.
- Production apply jobs are the only privileged jobs bound to GitHub
  `environment: prod`.
- Pulumi component tests prove non-production automation roles do not trust
  `environment:test` and production roles still trust `environment:prod`.
- Operations alert triage comments on an existing open canonical issue when a
  stable alert fingerprint already exists.
- Operator documentation describes AWS Secrets Manager-backed ESC keys, OIDC
  trust, stack migration, and manual secure setup steps.
- Pulumi outputs expose the AWS Secrets Manager container IDs and ESC read role
  ARN needed to configure the hosted ESC environments.

## BMAD/BMALPH Notes

`bmalph doctor` and `bmalph status` were run before implementation and reported
that this repository is not initialized for BMad/BMALPH. `bmalph init --dry-run`
was used to inspect generated state paths. Per repository guidance, this PR
commits the planning artifacts under `specs/` and does not commit `_bmad/`,
`.ralph/`, or generated framework state.
