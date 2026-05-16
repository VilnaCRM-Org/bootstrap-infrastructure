# Security Baseline

This template is designed to give DevOps and SRE teams a safe default starting
point rather than a bare Pulumi skeleton. The controls in this guide describe
what is already enforced in the repository and what should remain true as the
template evolves.
For the current Well-Architected identity, permissions, wildcard, boundary, and
exception ledger, see [Security Operating Evidence](security-operating-evidence.md).
For repository data classes, retention, storage, and secret-safety rules, see
[Data Classification And Retention](data-classification-retention.md).

## Threat Model

The main risks for this repository are:

- accidental secret disclosure through local tooling, CI logs, or checked-in files
- supply-chain drift in the Docker workspace and GitHub Actions automation
- over-privileged automation tokens in release or deployment workflows
- non-reproducible infrastructure changes that bypass preview and review
- unsafe infrastructure defaults that slip past code review without enforceable guardrails

The template does not try to eliminate all operational risk. It does aim to make
the safe path the easy path for normal day-to-day infrastructure work.

## Current Built-In Controls

### Container and Supply Chain

- The Docker base image is pinned by digest, not just by tag.
- Pulumi, AWS CLI, `uv`, and Bats downloads are verified with SHA-256 checksums.
- The runtime image carries only the tooling required for development and CI; it
  does not keep the transient download helpers from the build stage.
- Unused Pulumi language hosts are removed to reduce image size and attack
  surface.
- The container defaults disable noisy update checks and the AWS CLI pager so
  automation behaves predictably.

### GitHub Actions

- Actions are pinned to immutable commit SHAs.
- CI workflows use least-privilege `permissions` blocks.
- PR validation workflows use concurrency groups with
  `cancel-in-progress: true` so stale runs do not compete for runners.
- Preview, IAM validation, and drift detection use GitHub OIDC and short-lived
  AWS credentials rather than static access keys.
- Every infrastructure PR now produces a Pulumi preview artifact before merge.
- Critical deletes and replacements are blocked unless the pull request carries
  the explicit `allow-destructive-infra-change` label.
- Gitleaks, `pip-audit`, `actionlint`, and CodeQL are part of the review gate.
- Release workflows serialize runs with `cancel-in-progress: false` so tag and
  changelog publication cannot be interrupted mid-run.
- CI jobs define timeouts so hung runs fail fast instead of silently burning
  minutes.
- `actions/checkout` runs with `persist-credentials: false` to avoid leaving a
  writable Git credential behind in the workspace.

### Pulumi Guardrails

- Runtime guardrails validate `environment` and `serviceName` before the Pulumi
  program exports stack metadata.
- A Pulumi policy pack under `policy/` enforces mandatory default tags, region
  allowlists, S3 privacy, encryption, logging, wildcard IAM restrictions, and
  production-database safety for supported AWS resources.
- Mandatory tags include `DataClassification`, `Criticality`, and
  `RetentionClass` so reviewers can separate ownership, protection, and
  retention decisions from resource names.
- The same preview artifact is reused for destructive-change gating and AWS IAM
  Access Analyzer validation.
- The preview artifact is also used for a static cost and quota proxy that
  highlights durable resource fanout before apply.
- Policy validation has a dedicated CI workflow and a focused local command:
  `make test-policy`.

### Secrets and Identity

- Local developer overrides belong in `.env`, which stays git-ignored.
- Shared Pulumi backends for CI and maintainer workflows should use an AWS
  KMS-backed secrets-provider by default (for example, `awskms://...`), not a
  passphrase-backed shared backend.
- `.env.empty` is the committed fallback used to keep the Docker and Make flows
  runnable without real credentials.
- The shared Docker bootstrap script materializes `.env` with owner-only
  permissions to avoid leaving fallback configuration world-readable.
- The CI battery is intentionally local-backend-friendly and does not require
  live AWS credentials by default.
- Release automation falls back to `GITHUB_TOKEN` when
  `REPO_GITHUB_TOKEN` is not configured.
- Bootstrap automation is a management role. It can manage tagged Pulumi
  secrets and operations-alerting KMS keys, but it does not receive KMS
  data-plane actions for repository secrets keys.

### Detection and Response

- The stack creates EventBridge rules for AWS Backup failures, KMS key risk
  events, IAM/OIDC policy changes, and S3 state/log control-plane changes.
- These rules publish to the environment operations SNS topic. The topic uses a
  dedicated customer-managed KMS key so the key policy can grant EventBridge
  the permissions required to publish to an encrypted topic. Account owners
  must attach the approved subscription and escalation route before treating the
  alerts as live operational coverage.
- Incident responders must use metadata-only commands unless a
  secret-management task explicitly requires handling secret material.

## Recommended Practices for Downstream Repositories

### Prefer Federated Identity

Use GitHub OIDC with short-lived cloud credentials whenever the target platform
supports it. Static access keys should be treated as an exception for legacy
systems, not the first choice.

### Keep Permissions Narrow

When you add new workflows:

1. start with `contents: read`
2. add only the extra scopes the workflow actually needs
3. document the permission contract in `docs/`

### Review Before Apply

Use `make pulumi-preview` before `make pulumi-up`, and keep reviewable PRs as
the normal path for infrastructure changes. A preview that is not tied to the
code under review is much harder to trust later.

### Prefer Ephemeral Validation Stacks

For manual checks, use short-lived stacks such as `pr-17` or `smoke`, then tear
them down after the test. Shared long-lived development stacks hide drift and
make failure analysis harder.

## Safe Extension Checklist

When you extend this template, verify all of the following:

- new external downloads are pinned and verified
- new workflows define `permissions`, `concurrency`, and `timeout-minutes`
- new Make targets do not print secrets or require live credentials unless that
  behavior is explicitly documented
- new AWS resource types are checked against the Pulumi policy pack when they
  should inherit the repository guardrails
- new secrets are added to [GitHub Actions Secrets](./github-actions-secrets.md)
  and referenced from the relevant operator guide
- structural tests are updated so the security contract stays enforced

## What This Template Intentionally Does Not Do

- Pull requests do not auto-deploy infrastructure.
- Long-lived credentials are never embedded in the Docker image.
- CI green status is not treated as a replacement for human review of a
  production-impacting infrastructure diff.
