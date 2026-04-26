# Implementation Readiness: Multi-Account Pulumi Environments

## Readiness Summary
The issue is ready for implementation. The repository already has Docker-backed CI entrypoints, Pulumi preview artifacts, destructive-diff checks, IAM Access Analyzer validation, and KMS-backed stack initialization patterns. The implementation should keep these local contracts and move account-specific configuration from repository variables to GitHub environment variables.

## Alignment Checks

| Area | Status | Notes |
| --- | --- | --- |
| Requirements | Ready | Issue 18 provides explicit workflow, stack, environment, security, and documentation requirements. |
| Architecture | Ready | GitHub environments provide the account and approval boundary. |
| Security | Ready | OIDC and AWS KMS are mandatory; passphrase and raw secret reads are excluded. |
| Tests | Ready | Existing Pulumi structural and delivery-contract tests can be extended. |
| Operations | Ready with external setup | GitHub environment variables and AWS roles must exist before privileged CI can pass. |

## Implementation Order
1. Add stack config and discovery tests.
2. Refactor PR guardrails to use `test` environment variables.
3. Add merge-to-test and prod preview/apply workflows.
4. Refactor nightly drift into per-account jobs.
5. Update docs and structural tests.
6. Run narrow local validation.
7. Configure GitHub environments with metadata-safe values when available.
8. Validate test-account metadata with AWS CLI.

## Risk Controls
- Keep existing Make targets as workflow entrypoints.
- Avoid direct stack export or secret-revealing CLI flags.
- Fail privileged same-repo jobs when environment variables are missing.
- Keep fork PRs credential-free.
- Use `allowed-account-ids` on every AWS credential step.
- Use short artifact retention for preview and plan artifacts.

## Open External Dependencies
- Actual AWS account IDs, role ARNs, state bucket URLs, and KMS provider URIs must be configured in GitHub environments.
- The `prod` environment must have required reviewers and deployment branch restrictions in GitHub.
- Production apply should be approved only after reviewing the production preview summary for the same commit SHA.
