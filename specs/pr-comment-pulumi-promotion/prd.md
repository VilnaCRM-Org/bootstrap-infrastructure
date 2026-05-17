# PR Comment Pulumi Promotion PRD

## Problem

Maintainers need a GitHub-native way to run Pulumi `plan` and `up` for pull
request infrastructure changes without manually copying SHAs into separate
workflows. Production promotion must prove the same PR head SHA was applied and
drift-checked in the test account first.

## Goals

- Accept explicit PR comments for test and production Pulumi operations.
- Reject fork pull requests before any AWS credentials are requested.
- Re-check the queued PR head SHA immediately before checkout.
- Run production commands only after the test account plan, guardrails, apply,
  and post-apply drift checks succeed for the same SHA.
- Keep production apply saved-plan-only and protected by the `prod` GitHub
  environment.

## Non-Goals

- Do not make fork pull requests privileged.
- Do not bypass existing destructive diff, IAM validation, saved-plan, or drift
  guardrails.
- Do not commit generated BMALPH or BMAD framework state.

## Acceptance Criteria

- `/pulumi test plan`, `/pulumi test up`, `/pulumi prod plan`, and
  `/pulumi prod up` are parsed deterministically.
- `/pulumi plan` and `/pulumi up` continue to mean the test environment.
- The comment workflow dispatches only exact PR head SHAs.
- Production plan/apply jobs depend on successful test apply and test
  post-apply drift jobs.
- Tests cover the parser, workflow trigger, SHA revalidation, same-repository
  guard, environment-scoped OIDC jobs, and production saved-plan-only apply.
