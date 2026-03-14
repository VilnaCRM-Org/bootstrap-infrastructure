# Pulumi Bootstrap KMS Architecture

This repository is the stage-1 bootstrap layer for downstream Pulumi stacks.

## Stage-0 vs Stage-1

Stage-0:
- pre-existing account or platform bootstrap resources
- owns the KMS key used by `bootstrap-infrastructure` itself
- example alias: `alias/pulumi-platform-bootstrap-test`

Stage-1:
- this repository
- creates per-repository Pulumi state buckets
- creates per-repository Pulumi secrets KMS keys
- creates per-repository GitHub OIDC deploy roles
- exports `pulumiSecretsProviderUrls`

The important constraint is that `bootstrap-infrastructure` cannot use a KMS key that it creates during its own very first deployment. That is why the repository itself must start with a pre-existing stage-0 bootstrap key.

## Downstream Repository Flow

For a repository such as `user-service-infrastructure`, the bootstrap stack should be the source of truth for both:
- the Pulumi state bucket
- the Pulumi secrets KMS key

Recommended shape:
- one state bucket per repository per environment
- one KMS key per repository per environment
- one GitHub deploy role per repository

This repository now exports:
- `pulumiStateBuckets`
- `pulumiBackendUrls`
- `pulumiSecretsKeyArns`
- `pulumiSecretsAliases`
- `pulumiSecretsProviderUrls`
- `deployRoleArns`

The downstream repository should set:
- `PULUMI_BACKEND_URL` from `pulumiBackendUrls[repo]`
- `PULUMI_SECRETS_PROVIDER` from `pulumiSecretsProviderUrls[repo]`
- its GitHub OIDC deploy role from `deployRoleArns[repo]`

## Why Per-Repository Keys

Per-repository KMS keys are the safer default because they:
- reduce blast radius
- simplify access reviews
- keep IAM policies least-privilege
- align with the existing per-repository state-bucket model

A single shared application key is only worth considering if operational simplicity is more important than isolation.
