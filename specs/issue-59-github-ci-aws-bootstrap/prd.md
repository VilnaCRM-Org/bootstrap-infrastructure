# PRD: Issue 59 GitHub CI AWS Bootstrap

## PR60 successor amendment — 2026-09-06

The sections below retain historical requirements, stories and evidence. Their
active interpretation is defined by [the scoped successor verification](pr60-successor-verification.md)
and the installed [trusted-controller contract](../trusted-controller-installation/prd.md)
and [architecture](../trusted-controller-installation/architecture.md).
Historical readiness scores, approvals and runs do not establish current-head
acceptance. Ordinary workflows use the `workflow` claim; `job_workflow_ref` is
reserved for reusable workflow trust. Current protected environments, immutable
repository IDs, saved-plan replay and operator-only ownership supersede the
older examples below. In particular, an unsaved `pulumi up` command below is
historical and is not an executable recovery procedure.

The successor ships the independent operator program, governor runner roles and
immutable boundary prerequisites. Delegated governance resource construction,
service scaffolding and onboarding remain deferred to #78. Current source checks,
hosted review, BMAD and live acceptance are recorded separately in the amendment.

## Problem

GitHub Actions cannot complete privileged Pulumi preview and evidence jobs until
the AWS accounts contain the repository-scoped GitHub OIDC roles and AWS Secrets
Manager CI configuration payloads introduced by the AWS-only CI migration. The
deployment path must not depend on Pulumi Cloud or Pulumi ESC, and it must avoid
fallbacks that hide missing account setup.

## Goals

- Add a separate one-time Pulumi bootstrap stack for GitHub CI AWS access.
- Use only AWS services for CI configuration, Pulumi state, and Pulumi state
  secret encryption.
- Provision GitHub OIDC trust, CI config-read roles, and purpose-specific
  deployment roles for the test and production AWS accounts.
- Store CI configuration payloads in AWS Secrets Manager without committing or
  printing secret values.
- Document the minimum manual human step: local one-time stack apply with an
  administrator AWS identity in each account.
- Leave the normal CI roles least-privilege and without AdministratorAccess.

## Non-Goals

- Using Pulumi Cloud, Pulumi ESC, or Pulumi access tokens.
- Giving GitHub Actions broad AdministratorAccess for routine CI.
- Applying the bootstrap stack from GitHub before the GitHub OIDC trust exists.
- Removing the production GitHub Environment approval boundary.
- Reading or exposing raw CI secret values in local logs, PR output, or docs.

## Functional Requirements

- The bootstrap stack must run from `pulumi/github-ci-bootstrap` and stay
  isolated from the normal infrastructure stack discovery path.
- The stack must create or adopt the GitHub OIDC provider for
  `token.actions.githubusercontent.com`.
- The stack must create AWS Secrets Manager containers and config-read roles for
  `test-pr`, `test`, `prod-preview`, and `prod`.
- The stack must create preview, apply, drift, and test operations-alert triage
  roles with workflow-specific OIDC trust.
- The specs and runbook must map every AWS-using GitHub CI job to its
  config-read suffix and second-stage AWS role.
- The stack must emit GitHub repository variable values needed to point
  workflows at the account-local config-read roles.
- The documentation must explain how to run `pulumi preview` and `pulumi up`
  locally for test and prod with AWS admin profiles.

## Non-Functional Requirements

- Pulumi backend storage must be AWS S3.
- Pulumi state secrets must use AWS KMS secrets-provider URIs.
- GitHub Actions must authenticate to AWS with OIDC only; long-lived AWS keys
  are not acceptable.
- Production apply trust must require the trusted repository, approved workflow
  refs, and the GitHub `environment:prod` subject.
- Test PR trust must not be able to assume apply roles.
- Secret handling must preserve the repository rule that agents never read,
  print, summarize, or commit raw secret material.
- The PR must keep local unit, policy, structural, quality, and coverage checks
  green.

## Scope

This issue covers the one-time AWS bootstrap stack and its operator runbook. It
does not complete the later fallback-removal work; that work can continue after
the bootstrap stack is manually applied and the privileged GitHub checks can
assume their AWS roles.

## Required AWS CI Bootstrap Outputs

| Output | Purpose |
| --- | --- |
| `githubVariables` | Repository variables for GitHub Actions OIDC role discovery |
| `ciConfigurationSecretIds` | AWS Secrets Manager secret IDs for CI config payloads |
| `githubCiConfigReadRoleArns` | Roles that read one fixed CI config secret |
| `githubCiDeploymentRoleArns` | Preview, apply, and drift role ARNs used by CI payloads |
| `operationsAlertTriageRoleArn` | Test account SQS triage role for operations alerts |

## Acceptance Criteria

- No Pulumi Cloud, Pulumi ESC, or Pulumi access token is required.
- The bootstrap stack uses AWS S3 as the Pulumi backend and AWS KMS as the
  Pulumi secrets provider.
- CI config values live in AWS Secrets Manager.
- GitHub Actions uses AWS OIDC only and does not require long-lived AWS keys.
- Routine GitHub CI roles are least-privilege and do not receive
  AdministratorAccess.
- Production apply access is constrained to trusted repository workflow refs and
  the protected GitHub `prod` environment subject.
- Test PR access cannot assume apply roles.
- The AWS-using CI inventory covers preview, apply, drift, IAM validation,
  Well-Architected evidence, and operations-alert triage jobs.
- Tests verify stack shape, role trust scope, output contracts, and operator
  documentation.
- Privileged PR checks remain an expected manual-apply blocker until the stack
  has been applied in AWS.

## BMAD/BMALPH Notes

For this PR, `bmalph init --platform codex`, `bmalph status --verbose`,
`bmalph doctor --verbose`, `bmalph implement`, and
`bmalph run --no-dashboard --no-review --driver codex` were run locally against
ignored generated state. The run completed with `plan_complete`.

Sanitized local evidence:

- Run date: `2026-05-25`
- Workspace head at BMALPH run time: `ceac5f852117`
- Planning artifact copy used by BMALPH: `_bmad-output/planning-artifacts/`
- `bmalph doctor --verbose`: passed `19/19`
- `bmalph status --verbose` after run: Phase 4 implementation, Ralph loop
  completed, `Tasks: 0/0`

The repository policy keeps canonical planning artifacts under `specs/`;
generated BMAD/BMALPH/Ralph framework and state paths such as `_bmad/`,
`_bmad-output/`, `bmalph/`, `.ralph/`, and `.agents/skills/bmad-*` must not be
committed.
