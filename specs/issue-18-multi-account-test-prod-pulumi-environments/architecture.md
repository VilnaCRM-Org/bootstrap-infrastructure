# Architecture: Multi-Account Pulumi Environments

## Context
The repository currently runs guardrails from repository-wide variables. Issue 18 requires account-scoped configuration and deployment paths for `test`, `prod-preview`, and `prod` GitHub environments.

## Decisions
- Use GitHub environments, not repository-wide variables, as the account trust
  boundary for privileged Pulumi jobs.
- Keep fork pull requests credential-free and run only local, unprivileged
  guardrails for those events.
- Use account-local S3 backends with AWS KMS Pulumi secrets providers for
  committed `test` and `prod` stacks.
- Save reviewed Pulumi update plans before apply jobs and apply those saved
  plans for mutation workflows.
- Keep shared backend stack creation explicit; automation may initialize only
  local file-backed scratch stacks with an AWS KMS secrets provider.

## Tech Stack
- Pulumi Python project under `pulumi/`.
- Pulumi CLI commands run with `pulumi -C pulumi ...`.
- AWS provider with S3 state backends and AWS KMS secrets providers.
- GitHub Actions with OIDC federation through `aws-actions/configure-aws-credentials`.
- Docker Compose and Make targets for local/CI parity.
- Python validation through `uv`, `pytest`, `ruff`, `ty`, and repository structural tests.

### GitHub Environments
Use GitHub environments as the trust boundary:
- `test`: preview, apply, drift, and smoke validation against the AWS test account.
- `prod-preview`: read-only production preview and drift validation.
- `prod`: production apply, protected by required reviewers and branch restrictions.

Each environment owns account-specific variables:
- `AWS_ACCOUNT_ID`
- `AWS_REGION`
- `AWS_PREVIEW_ROLE_ARN`
- `AWS_APPLY_ROLE_ARN` where mutation is allowed
- `AWS_DRIFT_ROLE_ARN`
- `PULUMI_BACKEND_URL`
- `PULUMI_SECRETS_PROVIDER`
- `PULUMI_PREVIEW_STACKS`
- `PULUMI_DRIFT_STACKS`
- `PULUMI_ENABLE_AUTOMATION_STACK_TESTS` when enabled

### AWS Credential Flow
Every privileged job uses `aws-actions/configure-aws-credentials` with:
- `role-to-assume` from the active GitHub environment.
- `allowed-account-ids` from `AWS_ACCOUNT_ID`.
- A role-session-name containing workflow purpose and run ID.

Fork pull requests run only credential-free jobs: they do not bind a GitHub
environment, request `id-token: write`, or receive AWS credentials.

### Pulumi State and Secrets
Stacks use account-specific S3 backends and AWS KMS secrets providers:
- `test` stack: test AWS account state bucket and test KMS provider.
- `prod` stack: production AWS account state bucket and production KMS provider.

Stack initialization uses:
```bash
pulumi -C pulumi stack init <stack> --secrets-provider "$PULUMI_SECRETS_PROVIDER"
```

Stack config files contain only non-secret values. Secrets remain in Pulumi config set with `pulumi config set --secret` or in cloud secret stores.

### Workflow Topology

| Workflow | Trigger | Environment | Mutation |
| --- | --- | --- | --- |
| `pulumi-pr-guardrails.yml` | pull request, push to main | `test` for trusted privileged jobs | No |
| `pulumi-test-deploy.yml` | push to main, workflow dispatch | `test` | Yes, test only |
| `pulumi-prod.yml` | workflow dispatch | `prod-preview`, then `prod` | Yes, prod only after approval |
| `nightly-guardrails.yml` | schedule, workflow dispatch | `test`, `prod-preview` | No |

### Evidence
Privileged jobs emit sanitized evidence:
- GitHub environment name.
- Commit SHA.
- Expected AWS account ID.
- Assumed role ARN variable name/purpose.
- Pulumi stack list.
- Preview summary.
- Destructive-diff result.
- IAM Access Analyzer result.
- Drift result.
- Apply stage result for mutation workflows.

Raw preview artifacts use short retention and do not include stack exports or secrets.

## Security Constraints
- No long-lived AWS access keys in GitHub.
- No `pulumi stack export`.
- No `--show-secrets`.
- No AWS Secrets Manager, SSM SecureString, or KMS decrypt reads.
- `iam:PassRole` in managed AWS roles should be constrained by `iam:PassedToService` and explicit role patterns when role policy code is changed.

## Local Validation
Narrow validation for this change:
- `uv run pytest tests/pulumi tests/unit/test_ci_guardrails.py`
- `uv run pytest tests/unit/test_config.py tests/unit/test_pulumi_state_helpers.py`
- `make test-actionlint`
- `make test-yaml`

AWS metadata validation:
- `aws sts get-caller-identity`
- `aws s3api head-bucket --bucket <test-state-bucket>`
- `aws kms describe-key --key-id alias/<test-kms-alias>`

These commands avoid reading secret payloads.
