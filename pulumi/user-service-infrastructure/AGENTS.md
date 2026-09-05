# AGENTS.md — user-service-infrastructure (managed service repo)

These are the repo-local agent rules for `user-service-infrastructure`. They mirror
the governance gating and secret-handling posture enforced centrally by the
`bootstrap-infrastructure` governance stack. An agent (or human) working in this
repo MUST follow them.

## What this repo is

`user-service-infrastructure` is a **managed `*-infrastructure` service repo**. Its
AWS deploy infrastructure — the Pulumi state bucket, the KMS secrets key/alias, and
the GitHub OIDC deploy/config-read roles — is **provisioned and owned by the central
governance stack**, not by this repo. This repo only:

- holds the service's own Pulumi program (`pulumi/__main__.py` + stacks), and
- self-deploys through governance-provided OIDC roles via `.github/workflows/self-deploy.yml`.

This repo **consumes, never creates** that infrastructure.

## Hard rules

### 1. Never create IAM roles or OIDC trust for yourself
- Do NOT add `aws.iam.Role`, `aws.iam.Policy`, `aws.iam.RolePolicy`,
  `aws.iam.OpenIdConnectProvider`, or any `assume_role_policy` /
  `sts:AssumeRoleWithWebIdentity` trust to this repo's Pulumi program.
- The deploy roles already exist and are governance-owned:
  - `GitHubCiPreview-user-service-infrastructure-{env}`
  - `GitHubCiApply-user-service-infrastructure-{env}`
  - `GitHubCiDrift-user-service-infrastructure-{env}`
  - `GitHubCiConfigRead-user-service-infrastructure-{suffix}`
  Reference them by name/ARN; do not redefine them.

### 2. Consume the governance-provided backend + secrets key
- Pulumi backend: `s3://pulumi-user-service-infrastructure-{env}-state` (set as
  `pulumiBackendUrl` in the stack config).
- Pulumi secrets provider: `awskms://alias/pulumi-user-service-infrastructure-{env}-secrets?region=eu-central-1`
  (the stack `secretsprovider`). Never point at `alias/pulumi-platform-bootstrap-*` —
  that platform key is reserved for the governance stack and is not granted to this repo.

### 3. Two accounts, one region
- `test` stack -> AWS account `891377212104`; `prod` stack -> AWS account `933245420672`;
  region `eu-central-1`. Each stack pins ONLY its own account (no cross-account literal
  in the other stack). Account literals live ONLY in the stack config, never in Python.

### 4. OIDC-only credentials — no static keys, no AdministratorAccess
- All AWS credentials come from **GitHub OIDC role assumption** through
  `./.github/actions/load-aws-ci-env` + `aws-actions/configure-aws-credentials`.
- NEVER commit a static AWS access key id / secret access key (the long-lived
  IAM key pair), Pulumi access token, or passphrase. The committed stack files carry
  non-secret config only (`awskms://` secrets provider, no `secure:`/`encryptionsalt`).
- NEVER request or attach `AdministratorAccess`. The service apply role is
  backend-only and scoped to this repository. Workloads need a separate
  reviewed capability and boundary change.

### 5. IaC-only apply (saved-plan path)
- Applies go through the saved-plan path only: `make pulumi-up-plan`. Never
  `make pulumi-up` (direct apply is rejected under `GITHUB_ACTIONS=true`).
- The deploy flow is PR-comment driven: `/pulumi test up` then `/pulumi prod up`,
  test before prod, with prod gated on test success.

### 6. Kravalg-gated, preview-blocked until operator apply
- Changes that touch IAM/governance/trust are reviewed under the central CODEOWNERS
  `@Kravalg` gate (in `bootstrap-infrastructure`). This repo does not weaken that gate.
- `pulumi preview` cannot run here until the operator has applied governance for this
  repo and set the GitHub repo-variables; until then the assets are validated by
  structure only (no live preview).

## Secret handling

- Source of truth for CI config is **AWS Secrets Manager** (`/user-service-infrastructure/ci/{suffix}`),
  read at runtime via the governance config-read role. Do not duplicate secret values
  into this repo, into stack config, or into workflow files.
- Treat every value loaded from the CI-config secret as sensitive: never echo it,
  never write it to logs or PR comments.

## Executable scaffold contract

Generate this repository with scripts/scaffold_infrastructure_repository.py in the
bootstrap source; never copy only the template directory. Initial permissions are
backend-only. Real workloads require separately reviewed capability grants.
Service apply environments are test/prod, distinct from test-preview/prod-preview.
Initialize missing shared stacks only through trusted main Initialize Service Stack,
never through a preview fallback or an unguarded local resource update.

Apply comments and Initialize Service Stack dispatches must be requested by a
maintainer other than sole environment reviewer Kravalg. Kravalg approves the
protected environment; the original apply commenter cannot also be the approver.
