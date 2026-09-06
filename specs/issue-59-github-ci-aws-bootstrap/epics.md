# Epics: Issue 59 GitHub CI AWS Bootstrap

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
