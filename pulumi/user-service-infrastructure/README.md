# user-service-infrastructure (scaffold template)

Template assets for the managed `user-service-infrastructure` service repo. The
operator copies/pushes these into the real `user-service-infrastructure` GitHub
repository; they live here in `bootstrap-infrastructure` so they are versioned and
reviewed alongside the governance stack that backs them.

## What's here

```
pulumi/user-service-infrastructure/
  pulumi/
    Pulumi.yaml            # project name: user-service-infrastructure
    Pulumi.test.yaml       # test stack  -> account 891377212104, eu-central-1
    Pulumi.prod.yaml       # prod stack  -> account 933245420672, eu-central-1
    Pulumi.example.yaml    # non-discovered example (structural parity)
    __main__.py            # thin baseline; consumes governance resources, creates no IAM
  AGENTS.md                # repo-local agent rules (gating + secret posture)
  README.md                # this file
```

The self-deploy workflow (`.github/workflows/self-deploy.yml`) is added by Story 5.2.

## Consumes, never creates

This repo runs Pulumi against **governance-provided** infrastructure that the central
`bootstrap-infrastructure` governance stack creates for this repo:

| Resource | Name | Owner |
|---|---|---|
| Pulumi state bucket | `s3://pulumi-user-service-infrastructure-{env}-state` | governance stack |
| Pulumi secrets key | `alias/pulumi-user-service-infrastructure-{env}-secrets` | governance stack |
| Deploy roles | `GitHubCiPreview/Apply/Drift-user-service-infrastructure-{env}` | governance stack |
| Config-read roles | `GitHubCiConfigRead-user-service-infrastructure-{suffix}` | governance stack |
| CI-config secret | `/user-service-infrastructure/ci/{suffix}` (AWS Secrets Manager) | governance stack |

The scaffold creates **no IAM roles, no OIDC trust, no state bucket, and no KMS key**
of its own. See `AGENTS.md` for the full rule set.

## Accounts and region

- `test` -> AWS account `891377212104`
- `prod` -> AWS account `933245420672`
- region `eu-central-1`

Each stack pins only its own account (account literals live in the stack config,
never in Python).

## Credentials and apply path

- AWS credentials come **only** from GitHub OIDC role assumption (no static AWS keys,
  no `AdministratorAccess`).
- Applies use the saved-plan IaC-only path (`make pulumi-up-plan`), PR-comment driven,
  test then prod.

## Preview is blocked until the operator applies governance

The consumed backend bucket, KMS key, deploy roles, and the GitHub repo-variables the
workflow reads only exist after the operator runs the one-time governance apply for
this repo and sets the variables. Until then `pulumi preview` cannot resolve its
backend/secrets provider, so this template is validated by **structure only** (asset
presence, referenced names, no secrets) — never by running `pulumi preview`/`up`.
