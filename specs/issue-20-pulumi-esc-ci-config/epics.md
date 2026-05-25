# Epics: Issue 20 AWS Secrets Manager CI Configuration

## Epic 1: AWS CI Config Loading and Validation

- Add a local composite action that authenticates to AWS through GitHub OIDC,
  reads a fixed AWS Secrets Manager CI secret, exports environment variables,
  and exposes safe outputs for workflow `with:` blocks.
- Add a Python validator for required keys, account ID shape, AWS region shape,
  role ARN shape, S3 backend URLs, AWS KMS secrets-provider URLs, stack-list
  shape, SNS topic ARNs, and resource names.
- Cover validator behavior with focused unit tests.

## Epic 2: Workflow Migration

- Update PR guardrails, test deploy, production deploy, PR command runner,
  nightly guardrails, operations alert triage, and Well-Architected evidence to
  load AWS Secrets Manager CI config instead of GitHub Environment variables.
- Keep GitHub `environment: prod` only on production apply jobs.
- Remove privileged workflow dependencies on account-local GitHub variables
  such as `vars.PULUMI_BACKEND_URL`, `vars.PULUMI_SECRETS_PROVIDER`, and
  role/account variables loaded from AWS Secrets Manager. Keep only the minimal
  repository variables that identify the config-read role ARNs and regions, and
  remove `secrets.PULUMI_ACCESS_TOKEN`.

## Epic 3: AWS Trust Policy

- Update Pulumi-generated IAM trust policies to use fixed branch and pull
  request subjects for non-approval jobs.
- Keep the GitHub environment subject only for `prod`.
- Bind workflow refs to the expected workflow files.
- Scope operations alert triage to its dedicated workflow and protected branch.

## Epic 4: Operations Alert Hygiene

- Render sanitized issue bodies from SNS/SQS-wrapped EventBridge messages.
- Generate stable alert fingerprints that ignore occurrence IDs.
- Search for an existing open issue by fingerprint before creating a new issue.
- Delete SQS messages only after the GitHub issue create/comment operation
  succeeds.

## Epic 5: Documentation and Evidence

- Update CI, SRE, security, and alert-routing docs to describe the AWS Secrets
  Manager-backed CI config contract.
- Record BMAD/BMALPH planning artifacts under `specs/`.
- Call out manual setup and validation steps in the PR and final report.
