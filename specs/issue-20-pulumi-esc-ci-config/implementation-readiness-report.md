# Implementation Readiness Report: Issue 20 Pulumi ESC CI Configuration

## Status

Ready for targeted validation after local lint, workflow lint, unit tests, and
cloud metadata checks pass.

## Completed Design Decisions

- Fixed ESC environment names are committed in workflows; user-controlled event
  payloads cannot select an ESC environment.
- AWS Secrets Manager is the source of truth for account-local CI values; ESC
  imports those JSON secrets with `aws-secrets` and projects workflow
  `environmentVariables`.
- Pulumi manages the AWS Secrets Manager secret containers and the ESC read
  roles, but not the JSON secret values.
- GitHub `prod` remains the only deployment environment because it provides
  human production approval.
- AWS role trust uses repository ref, pull request, protected production
  environment, and workflow-ref conditions.
- ESC validation happens before AWS credentials are requested.
- Operations alert dedupe uses a stable issue fingerprint and preserves the SQS
  message until GitHub write success.

## Validation Plan

- `uv run ruff check` over changed scripts and tests.
- `uv run pytest` over ESC validator, operations alert triage, component trust,
  and Pulumi workflow-contract tests.
- `make test-actionlint` and `make test-yaml`.
- Test account metadata-only AWS CLI checks for caller identity, EventBridge,
  SNS, SQS, and AWS Backup alert context.
- Production account metadata-only AWS MCP checks for caller identity and
  Pulumi bootstrap role metadata.

## Known External Dependencies

- AWS Secrets Manager JSON values must be populated outside this PR after the
  Pulumi-managed secret containers exist.
- ESC environments must be created with `aws-secrets` imports and OIDC access
  to the relevant AWS Secrets Manager read roles.
- ESC AWS OIDC and GitHub-to-ESC OIDC trust must be enabled without moving
  account-local values out of AWS Secrets Manager.
- GitHub `prod` Environment reviewer and branch restrictions require repository
  admin rights.
- AWS account trust-policy changes require applying the Pulumi stack through the
  existing GitOps process.

## Residual Risks

- Existing open PRs may need to be rebased or rerun after this trust-model
  change lands.
- Historical operations alert duplicate issues must be closed manually or by a
  maintainer after the canonical fingerprint behavior is merged.
- If local test-account AWS credentials are expired, metadata verification is
  blocked until the maintainer refreshes them.
