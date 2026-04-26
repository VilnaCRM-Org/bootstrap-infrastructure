# SRE Operations Guide

This guide covers the day-2 operating model for the template: validating local
prerequisites, previewing changes safely, and handling common infrastructure
maintenance flows.

## Preflight

Run the basic workstation check before blaming Docker, Pulumi, or CI:

```bash
make doctor
```

The command verifies that Docker and Docker Compose are available, reports the
effective env file, and prints the service and Pulumi directory that the
Makefile will target. It does not print secrets.

## Daily Workflow

For the normal edit-test loop:

```bash
make test
```

Before pushing a branch that changes infrastructure logic, Docker wiring, or CI
contracts, use the same non-mutation battery that GitHub runs in
`pulumi-local.yml`:

```bash
make ci-pr
```

When you also want the dedicated mutation suite locally:

```bash
make ci
```

Use `make ci-pr` to catch the same structural, policy, quality, unit,
integration, CLI, security-scan, and preview guardrails that GitHub runs before
merge. Use `make ci` when you also want the mutation suite before the branch
reaches GitHub Actions.

## Preview and Apply

Use previews as the default gate for real infrastructure changes:

```bash
make pulumi-preview
```

The preview target syncs the shared `uv` environment if necessary and enables
the repository policy pack automatically, so guardrail drift is caught before
the Pulumi plan is shown.

When you want to reproduce the credential-free PR preview flow locally, use:

```bash
make test-guardrails
```

That target generates the preview artifact and blocks destructive changes to
critical resources without requiring live AWS credentials. Keep
`make test-iam-validation` for the separate Access Analyzer check when you
intentionally have AWS credentials configured.

Apply only after the preview is understood and reviewed:

```bash
make pulumi-up
pulumi -C pulumi stack output
```

`make pulumi-up` uses the same policy-pack enforcement path as preview.

For drift reconciliation without applying a fresh plan:

```bash
make pulumi-refresh
```

For teardown:

```bash
make pulumi-destroy
```

Treat destroy as irreversible unless you have a tested restore path.

## Stack Strategy

Recommended stack patterns:

- `test` for the shared test AWS account
- `prod` for the protected production AWS account
- `dev` for local or shared baseline development when the repository still uses it
- `pr-<number>` for short-lived validation environments
- `smoke` for manual release verification

Avoid mixing unrelated validation work into one long-lived shared stack. It
makes previews noisy and rollback decisions ambiguous.

Shared `test` and `prod` stacks are not scratch space. Use ephemeral stacks for
experiments and destroy them after validation. Automation does not implicitly
create missing stacks in shared backends; initialize or migrate shared stacks
explicitly with the configured AWS KMS Pulumi secrets provider:

```bash
pulumi -C pulumi stack init <stack> --secrets-provider "$PULUMI_SECRETS_PROVIDER"
```

Use the stack-targeted migration command for legacy stacks that need to move to
AWS KMS-backed secrets:

```bash
pulumi -C pulumi stack change-secrets-provider \
  "awskms://alias/ALIAS_NAME?region=REGION" \
  --stack <stack>
```

Replace `ALIAS_NAME` and `REGION` with the target AWS KMS key alias or key ID
and AWS Region.

## Replica Region Migration

Committed `test` and `prod` stack files pin
`bootstrap-infrastructure:replicationRegion: eu-west-1` so future code defaults
cannot silently relocate replica buckets. That setting drives both the Pulumi
state replica buckets in `pulumi/infra/pulumi_state.py` and the central logging
replica bucket in `pulumi/infra/logging_bucket.py`.

Existing stacks that relied on the old implicit default need an explicit
migration choice before their next `pulumi up`:

1. Preserve the existing replica region by setting
   `bootstrap-infrastructure:replicationRegion: us-east-1` in that stack's
   `pulumi/Pulumi.<stack>.yaml`, then run a normal preview. If the policy
   allow-list blocks that legacy region, carry a reviewed migration exception
   with the same change instead of bypassing CrossGuard.
2. Move to `eu-west-1` by performing a manual replica drain first. Confirm S3
   replication is caught up, retain or copy any required objects from the old
   state and logging replicas, then update the stack config and review the
   preview during a maintenance window.

Do not run targeted or partial updates that include `pulumi-state` while
omitting `central-logging` during this migration. State bucket logging depends
on the concrete central logging bucket resources, so a full-stack preview/apply
keeps the logging and state replica changes ordered together.

## GitHub Environment Operations

The deployment boundary is the GitHub environment:

- `test` handles trusted PR previews, main-branch test applies, and test drift
- `prod-preview` handles production preview and drift without production apply
  permissions
- `prod` handles production apply and must require reviewers plus deployment
  branch restrictions

Before approving `prod`, compare the reviewed commit SHA with the apply SHA and
review the preview summary, destructive diff result, IAM validation result, AWS
account evidence, stack name, and role purpose. Do not approve a production
apply from a different SHA than the preview you reviewed.

Privileged runs should preserve evidence that is useful but not sensitive:
GitHub environment, account ID, region, OIDC role purpose, backend type, stack
names, guardrail mode, commit SHA, and artifact names. Evidence must not include
stack exports, decrypted secret values, access keys, tokens, or private keys.

## Safe AWS Validation

Use metadata-only checks when validating account setup:

```bash
aws sts get-caller-identity
aws s3api head-bucket --bucket <state-bucket>
aws kms describe-key --key-id alias/<pulumi-secrets-key-alias>
aws iam get-role --role-name <github-oidc-role-name>
```

These commands confirm identity and bootstrap dependencies without reading
secret payloads. Keep Pulumi validation non-secret as well:

```bash
pulumi -C pulumi stack ls
pulumi -C pulumi config
```

Do not use secret-revealing flags or raw stack export commands for routine
evidence collection.

## Operations Alerting

The bootstrap stack provisions an encrypted SNS topic named
`bootstrap-<environment>-operations`, a customer-managed KMS key aliased as
`alias/bootstrap-<environment>-operations-alerting`, and EventBridge rules for
high-severity control-plane signals:

| Signal | Source | Immediate owner action |
| --- | --- | --- |
| AWS Backup failed, aborted, or expired job | `aws.backup` job state events | Confirm the affected vault, plan, and protected bucket, then schedule a fresh backup or restore drill |
| KMS key deletion, disablement, rotation disablement, or policy change | `aws.kms` CloudTrail events | Verify the key and actor, cancel unintended deletion, and review deploy role access |
| IAM OIDC provider or role policy changes | `aws.iam` CloudTrail events | Confirm the GitHub OIDC trust still matches approved branches or environments |
| S3 bucket encryption, logging, policy, or replication changes | `aws.s3` CloudTrail events | Confirm state and log buckets still enforce encryption, TLS, logging, and replication |

SNS subscriptions and escalation routes are account-local operations controls.
Do not treat the alerting foundation as complete until the target account has a
confirmed subscription, owner, and incident route.

## Backup and Restore Evidence

Monthly backup review should record the stack, account, vault name, plan name,
last successful backup job timestamp, and any failed job IDs. Quarterly restore
drills should restore into an isolated location and verify object metadata only;
do not inspect Pulumi state contents, decrypted stack values, or secret payloads
as part of routine evidence collection.

Target recovery posture for bootstrap state is:

- RPO: one daily AWS Backup recovery point plus S3 versioning
- RTO: restore procedure reviewed and executable within one business day
- DR boundary: primary-region state and log buckets have cross-region replicas

## Incident and Drift Triage

When something looks wrong:

1. run `make doctor`
2. run `make test` to separate local code issues from cloud drift
3. run `make pulumi-refresh` if the concern is live-state drift
4. inspect `pulumi -C pulumi stack output` for the non-secret state you expect
5. use an ephemeral stack for risky experiments instead of debugging directly in
   a shared environment
6. if a change is intentionally destructive, document the reason and add the
   `allow-destructive-infra-change` label instead of bypassing the workflow

## CI Troubleshooting

Map failures back to their local commands:

- `Structural` -> `make test-pulumi && make test-repository-catalogs && make test-repository-fanout`
- `Policy` -> `make test-policy`
- `Ruff` -> `make test-ruff`
- `Ty` -> `make test-ty`
- `Maintainability` -> `make test-maintainability`
- `Architecture` -> `make test-architecture`
- `Dependency Hygiene` -> `make test-dependency-hygiene`
- `Coverage` -> `make test-unit && make test-integration-unprivileged && make test-policy && make test-coverage` when AWS-backed automation tests are disabled; use `make test-unit && make test-integration && make test-policy && make test-coverage` when they are enabled
- `Unit` -> `make test-unit`
- `Integration` -> `make test-integration-unprivileged` by default, or `make test-integration` when AWS-backed automation tests are enabled
- `Mutation` -> `make test-mutation`
- `Run Bats Tests` -> `make test-cli`
- `Local Battery` -> `make ci-pr-unprivileged` by default, or `make ci-pr` when AWS-backed automation tests are enabled
- `Preview` -> `make test-preview-unprivileged` by default, or `make test-preview` when AWS-backed preview variables are configured
- `Destructive Diff Gate` -> `make test-destructive-diff`
- `Cost Proxy` -> `make test-cost-proxy`
- `IAM Validation` -> `make test-iam-validation-unprivileged` by default, or `make test-iam-validation` when AWS credentials are configured
- `Secrets Scan` -> `make test-secrets`
- `Dependency Audit` -> `make test-deps-security`
- `Bandit` -> `make test-bandit`
- `Actionlint` -> `make test-actionlint`
- `Yamllint` -> `make test-yaml`
- `Hadolint` -> `make test-dockerfile`
- `CodeQL`, `Dependency Review`, `Infracost`, and `CodeRabbit` -> GitHub-native only

That mapping is intentional. If a failure cannot be reproduced locally with the
matching target, the problem is probably workflow-specific and should be treated
as a CI contract issue.

## Release Hygiene

Release automation should stay boring:

- keep changelog generation deterministic
- use the documented token fallback contract
- avoid mixing release logic with deployment logic
- prefer one-purpose workflows over single giant pipelines

## Cleanup

When local state gets messy:

```bash
make clean
```

This removes Compose state and Python build artifacts without touching cloud
resources.
