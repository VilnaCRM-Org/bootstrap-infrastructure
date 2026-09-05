# PRD: Issue 59 GitHub CI AWS Bootstrap

## Security completion amendment — 2026-09-05

This document preserves the original planning decisions and historical evidence.
Where its requirements, design, acceptance criteria, or completion statements
conflict with the security completion amendment, use the amended
[PRD](../security-completion/prd.md),
[architecture](../security-completion/architecture.md), and
[verification ledger](../security-completion/verification.md) as the current
contract. Historical scores and successful runs do not prove current closure.

The amended contract requires current-head `Governance Promotion` evidence for
governance changes, issued by the dedicated environment-protected GitHub App,
with test apply, test drift, production apply, and production drift evidence tied to the same
revision. The earlier informational-only `Governance Apply` interpretation is
superseded. Dedicated governance roles and immutable per-repository permission
boundaries are provisioned through the operator-owned bootstrap stack before
onboarding. Governance consumes the existing account OIDC provider and platform
state key; it cannot widen its own permissions or those boundaries. New service
catalog entries therefore first require the real repository to exist so its
immutable GitHub identity can be pinned, followed by reviewed bootstrap boundary
inventory, complete scaffold, explicit account and backend configuration, and
subsequent workload capability review. Preview and drift can write only Pulumi
locks; initializing new backend state is a separate trusted operation. Apply
must retain its own backend access while explicit secret-read denial targets the
intended CI secret resources. Platform and service trust rules must follow their
amended workflow/environment contracts rather than be copied interchangeably.

Reconcile each original FR, NFR, story, risk acceptance, and readiness assertion
against the amendment and current evidence. Outstanding validation, operational
requirements, and unexecuted checks remain open in the verification ledger;
this notice does not mark them complete.

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
