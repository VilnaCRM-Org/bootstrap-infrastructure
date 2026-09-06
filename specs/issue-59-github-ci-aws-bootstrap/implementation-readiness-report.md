# Implementation Readiness Report: Issue 59 GitHub CI AWS Bootstrap

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

## Status

Conditionally ready for merge after the one-time AWS bootstrap stack has been
manually applied in the test and production accounts and privileged GitHub
checks have been rerun.

## Completed Design Decisions

- Pulumi Cloud and Pulumi ESC are excluded from the CI bootstrap design.
- AWS S3 is the Pulumi backend for the bootstrap project.
- AWS KMS is the Pulumi secrets provider for stack state secrets.
- AWS Secrets Manager owns the CI configuration payloads.
- GitHub Actions uses OIDC and short-lived AWS STS credentials only.
- Config-read, preview, apply, drift, and operations alert triage roles are
  separated by purpose.
- Production apply trust keeps the protected GitHub `prod` environment subject.
- Test pull request trust cannot reach apply roles.
- Generated BMAD/BMALPH/Ralph framework files remain local and ignored; the
  committed planning source is this `specs/` directory.

## Validation Plan

- Completed: `bmalph init --platform codex`
- Completed: `bmalph status --verbose`
- Completed: `bmalph doctor --verbose`
- Completed: `bmalph implement`
- Completed: `bmalph run --no-dashboard --no-review --driver codex`, which
  exited with `plan_complete`
- BMALPH run date: `2026-05-25`
- BMALPH run head: `ceac5f852117`
- BMALPH evidence summary: `bmalph doctor --verbose` passed `19/19`;
  `bmalph status --verbose` later reported Phase 4 implementation with the
  Ralph loop completed and `Tasks: 0/0`
- Generated BMALPH/Ralph state was left in ignored paths only; committed
  evidence lives in `specs/issue-59-github-ci-aws-bootstrap/`
- `make test-unit`
- `make test-maintainability`
- `make test-ty`
- `make test-ruff`
- `make test-integration-unprivileged`
- `make test-policy`
- `make test-coverage`
- `git diff --check`
- `gh pr checks 60`
- Current-head review inspection for CodeRabbit, cubic, and qlty findings.

## Known External Dependencies

- A human must run the `pulumi/github-ci-bootstrap` stack locally with an
  administrator AWS identity in the test account.
- A human must run the same stack locally with an administrator AWS identity in
  the production account.
- The GitHub repository variables emitted by the stack must be set after apply.
- Privileged GitHub checks must be rerun after those AWS roles exist.

## Manual Apply Blocker

PR #60 cannot have all privileged GitHub checks green until the manual bootstrap
apply is complete. The expected current blockers are `Preview` and
`Test Account Evidence`; both fail because GitHub cannot yet assume the test
account config-read role
`arn:aws:iam::891377212104:role/GitHubCiConfigRead-bootstrap-infrastructure-test-pr`.

This is not a code fallback to preserve. It is the external setup dependency
that this bootstrap stack intentionally creates.

## AI Review And CI Readiness

- qlty check and qlty fmt must report no blocking issues.
- CodeRabbit comments and current-head review summaries must have no unresolved
  actionable findings.
- cubic findings must be verified and fixed or explicitly rejected with evidence.
- Code review bots that skip review because of repository or base-branch
  configuration should be recorded as skipped, not treated as approval.
- After manual AWS apply, all required non-skipped checks must be green.

## Residual Risks

- Inline IAM policies may need later tightening as the production stack surface
  changes.
- Manual use of an administrator AWS profile is powerful by design; the runbook
  limits it to one-time bootstrap preview and apply.
- Existing fallback-removal work should wait until the bootstrap roles are live
  and the privileged CI jobs prove the new path works.
