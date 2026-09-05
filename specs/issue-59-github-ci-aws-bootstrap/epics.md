# Epics: Issue 59 GitHub CI AWS Bootstrap

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

## Epic 1: Bootstrap Stack

### Story 1.1: Add an isolated GitHub CI bootstrap Pulumi project

Create a separate Pulumi project for one-time GitHub CI AWS setup, isolated from
the normal infrastructure stacks and safe to run locally with an administrator
AWS profile.

**Acceptance Criteria:**

- Given a maintainer opens `pulumi/github-ci-bootstrap`, When they inspect the
  project manifest, Then it uses the Python Pulumi runtime and does not reuse the
  normal root Pulumi entrypoint.
- Given committed stack files are reviewed, When they are scanned for secret
  metadata, Then no `secure:`, `encryptedkey`, passphrase, Pulumi Cloud, or
  Pulumi ESC dependency appears.
- Given the stack is run manually, When the operator sets an AWS S3 backend and
  AWS KMS secrets provider, Then no Pulumi Cloud account is required.

## Epic 2: IAM Trust And Least Privilege

### Story 2.1: Create scoped OIDC roles for CI purposes

Create GitHub OIDC trust policies and role policies for config read, preview,
apply, drift, and operations alert triage workflows.

**Acceptance Criteria:**

- Given a GitHub token comes from an untrusted subject, When it tries to assume a
  bootstrap-created role, Then the trust policy denies it.
- Given a test pull request job runs, When it loads CI config, Then it can assume
  only the test PR config-read and preview path and cannot assume apply roles.
- Given production apply runs, When GitHub requests AWS credentials, Then trust
  requires the protected `environment:prod` subject and expected workflow refs.
- Given any AWS-using GitHub Actions job is reviewed, When it maps to AWS
  permissions, Then the spec identifies its config suffix and second-stage role.
- Given IAM validation runs, When it needs AWS permissions, Then it uses the
  preview role and does not receive apply permissions.
- Given routine CI roles are inspected, When their policies are reviewed, Then
  they do not attach AdministratorAccess.

## Epic 3: AWS Secrets Manager CI Payloads

### Story 3.1: Manage CI config containers and generated payload versions

Create fixed AWS Secrets Manager CI config containers and generated JSON payloads
for the test and production account workflows.

**Acceptance Criteria:**

- Given the bootstrap stack is applied in test, When outputs are inspected, Then
  `test-pr` and `test` secret IDs and config-read role ARNs are present.
- Given the bootstrap stack is applied in production, When outputs are
  inspected, Then `prod-preview` and `prod` secret IDs and config-read role ARNs
  are present.
- Given `writeSecretValues` is disabled, When the stack is previewed, Then the
  secret containers still exist and payload versions are omitted.
- Given `writeSecretValues` is enabled, When the stack is applied, Then generated
  payload versions are written by Pulumi and no manual JSON copy/paste is
  required.
- Given `writeSecretValues` is disabled for repair, When an operator writes
  payload values manually, Then the documented command uses `file://` input and
  does not print the JSON payload.
- Given docs or logs are reviewed, When secret handling is checked, Then raw
  secret values are not printed or committed.

## Epic 4: Documentation And Manual Apply

### Story 4.1: Document the one-time secure apply runbook

Document the local administrator apply flow and the post-apply GitHub variable
setup needed to unblock privileged CI.

**Acceptance Criteria:**

- Given an operator has test and production AWS admin profiles, When they follow
  the runbook, Then they can run preview and apply commands for both stacks.
- Given the docs show `pulumi login`, When commands are copied into a shell,
  Then backend URLs are passed as literal arguments and do not depend on inline
  environment variable expansion timing.
- Given the stack is applied, When the operator captures outputs, Then the docs
  show exactly which GitHub repository variables to set.
- Given the operator disables generated secret versions, When they continue the
  manual repair path, Then the docs explain that they must write payloads from
  local files without exposing secret JSON.

## Epic 5: Validation And PR Readiness

### Story 5.1: Prove the bootstrap contract locally and on GitHub

Keep code, tests, docs, and review state aligned so the PR is ready once the
external AWS bootstrap dependency is satisfied.

**Acceptance Criteria:**

- Given local validation is run, When unit, structural, policy, quality, and
  coverage checks complete, Then they pass without live AWS credentials.
- Given AI review comments identify valid issues, When fixes are pushed, Then the
  current head has no unresolved actionable CodeRabbit, cubic, or qlty findings.
- Given privileged GitHub checks still fail before manual apply, When logs are
  inspected, Then the failure is limited to missing AWS OIDC/config-read roles.
- Given manual apply is complete, When privileged checks are rerun, Then all
  required non-skipped PR checks are green.
