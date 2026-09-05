# Implementation Readiness Report: Issue 59 GitHub CI AWS Bootstrap

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
