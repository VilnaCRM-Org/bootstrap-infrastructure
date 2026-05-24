# Epics and Stories: Multi-Account Pulumi Environments

> Superseded by issue 20 for privileged CI configuration. Fixed Pulumi ESC
> environments now carry account configuration; protected GitHub `prod` remains
> the approval boundary.

## Epic 1: Stack And Discovery Contracts

### Story 1.1: Add non-secret test and prod stack configs
As an infrastructure maintainer, I want committed `test` and `prod` stack files so CI targets are explicit.

**Acceptance Criteria:**
- Given the repository stack files are inspected, Then `pulumi/Pulumi.test.yaml` exists.
- Given the repository stack files are inspected, Then `pulumi/Pulumi.prod.yaml` exists.
- Given either stack file is read, Then it includes a KMS secrets-provider initialization comment.
- Given either stack file is read, Then it does not include secret payloads or legacy passphrase metadata.

### Story 1.2: Exclude example stacks from default shared-backend discovery
As an SRE, I want CI stack discovery to avoid example files so shared backend jobs cannot select placeholder stacks by accident.

**Acceptance Criteria:**
- Given stack discovery runs without an explicit stack list, Then it ignores the exact template file `Pulumi.example.yaml`.
- When an explicit stack list includes `example`, Then discovery returns `example`.
- When tests run, Then default discovery and explicit override behavior are covered.

## Epic 2: GitHub Actions Deployment Paths

### Story 2.1: Refactor PR guardrails for the test environment
As a maintainer, I want trusted PR guardrails to use fixed test PR account configuration and fork PRs to stay unprivileged.

**Acceptance Criteria:**
- Given a trusted same-repo PR runs guardrails, Then privileged jobs use fixed test PR account configuration.
- Given a privileged PR guardrail job runs, Then it reads account-scoped variables.
- Given OIDC credentials are configured, Then the workflow uses `AWS_PREVIEW_ROLE_ARN` and `allowed-account-ids`.
- Given a fork PR runs guardrails, Then it runs unprivileged preview and IAM input extraction.
- Given privileged config is missing for a same-repo run, Then the workflow fails before preview.

### Story 2.2: Add merge-to-test deployment workflow
As an SRE, I want `main` merges to deploy to the test account only after preview and guardrails pass.

**Acceptance Criteria:**
- Given code is pushed to `main`, Then the test deploy workflow runs.
- Given a maintainer manually dispatches the workflow, Then the test deploy workflow runs.
- Given the workflow runs, Then it uses fixed test account configuration.
- Given preview completes, Then the same preview artifact feeds destructive-diff and IAM validation.
- Given apply runs, Then it uses `AWS_APPLY_ROLE_ARN`.
- Given post-apply drift runs, Then it uses `AWS_DRIFT_ROLE_ARN`.

### Story 2.3: Add production preview and apply workflow
As a release approver, I want production apply to require a reviewed preview and protected environment approval.

**Acceptance Criteria:**
- Given a maintainer dispatches production, Then the workflow accepts a commit SHA.
- Given production preview runs, Then the preview job uses fixed production preview account configuration.
- Given production apply runs, Then the apply job uses `environment: prod`.
- Given apply starts, Then it verifies the approved SHA matches the preview SHA.
- Given a Pulumi plan artifact exists, Then apply uses that saved plan.

### Story 2.4: Run nightly drift per target account
As an SRE, I want drift detection to run separately for test and prod with explicit roles and accounts.

**Acceptance Criteria:**
- Given nightly guardrails run, Then the workflow has a `test` drift job.
- Given nightly guardrails run, Then the workflow has a `prod-preview` drift job.
- Given either drift job runs, Then it uses account-scoped variables.
- Given required variables are missing, Then the drift job fails.

## Epic 3: Documentation And Auditability

### Story 3.1: Document privileged CI variables and production protection
As a repository administrator, I want setup docs for the test, production preview, and protected production paths.

**Acceptance Criteria:**
- Given setup docs are read, Then `docs/github-actions-secrets.md` documents environment variables and optional secrets.
- Given guardrail docs are read, Then `docs/ci-guardrails.md` documents privileged and unprivileged modes.
- Given CI architecture docs are read, Then `docs/ci-architecture.md` documents workflow topology.
- Given operations docs are read, Then `docs/sre-operations.md` documents release and drift operations.

### Story 3.2: Preserve sanitized evidence for privileged runs
As an auditor, I want privileged workflows to show target account, stack, role purpose, and guardrail mode without leaking secrets.

**Acceptance Criteria:**
- Given a privileged workflow runs, Then it emits a sanitized environment summary.
- Given preview or plan artifacts are uploaded, Then they use short retention.
- Given docs are read, Then they describe evidence fields and forbidden commands.

## Epic 4: Validation

### Story 4.1: Add structural tests for multi-account workflow contracts
As a maintainer, I want tests to prevent regression to repo-wide account variables.

**Acceptance Criteria:**
- Given structural tests run, Then they assert workflow environment bindings.
- Given structural tests run, Then they assert `allowed-account-ids` is used.
- Given structural tests run, Then they assert privileged workflows use purpose-specific role variables.
- Given structural tests run, Then they assert docs reference the multi-account environment model.

### Story 4.2: Validate test-account metadata safely
As an operator, I want AWS CLI validation that confirms the active test account and bootstrap dependencies without exposing secrets.

**Acceptance Criteria:**
- Given test-account validation runs, Then it uses `aws sts get-caller-identity`.
- Given test-account validation runs, Then it uses metadata-only S3, KMS, or IAM checks.
- Given validation commands are reviewed, Then no command reads secret payloads, stack exports, or decrypted values.
