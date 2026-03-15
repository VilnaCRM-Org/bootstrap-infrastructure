# Pulumi CrossGuard Policy Pack

This repository ships a Pulumi CrossGuard Policy Pack in `policy_pack/` and applies it through the shared `scripts/run_pulumi_command.sh` entrypoint.

## What it enforces

- `approved-bootstrap-resource-types`: blocks high-cost resource families such as EC2, ECS, EKS, NAT, RDS, and Redshift.
- `taggable-bootstrap-resources-have-finops-tags`: requires `App`, `Environment`, `Owner`, `CostCenter`, and `Purpose` tags on taggable bootstrap resources.
- `bootstrap-resources-stay-in-approved-regions`: blocks AWS resources outside the approved region allowlist.
- `pulumi-state-buckets-use-inline-guardrails`: requires inline versioning and AES256 encryption on Pulumi state buckets.
- `s3-public-access-blocks-are-locked-down`: requires all S3 public-access-block flags to be `true`.
- `s3-buckets-must-not-use-public-acls`: blocks public bucket ACLs unless `AllowPublicAccess=true` explicitly records the exception.
- `s3-versioning-resources-are-enabled`: requires bucket versioning resources to use `Enabled`.
- `s3-encryption-resources-default-to-aes256`: requires AES256 default encryption for companion S3 encryption resources.
- `s3-bucket-policies-enforce-tls`: requires bucket policies to deny non-TLS access.
- `kms-keys-enable-rotation`: requires automatic KMS rotation and a deletion window of at least 30 days.
- `ecr-repositories-are-hardened`: requires immutable tags and `scanOnPush` on ECR repositories.
- `backup-plans-expire-recovery-points`: requires AWS Backup plans to expire recovery points within 90 days.
- `iam-policies-avoid-wildcard-iam-permissions`: blocks wildcard IAM permissions unless a reviewed `Sid` is explicitly allowlisted.
- `production-buckets-avoid-risky-defaults`: blocks `forceDestroy` on production-like S3 buckets.

## Where it runs

- Local CI wrapper: `make pulumi-plan-ci`, `make pulumi-up-ci`, `make pulumi-drift-ci`
- GitHub deploy workflows: `pulumi.yml`, `pulumi-prod.yml`
- PR comment automation: `pulumi-pr-commands.yml` dispatches `pulumi-pr-command-runner.yml`
- Drift detection: `pulumi-drift.yml`
- Dedicated policy tests: `make test-policy`
- CrossGuard alias: `make test-crossguard`
- PR preview guardrail: `pulumi-preview.yml`

## Coverage

The policy helper code is part of the repository-wide Python coverage gate.

Local commands:
```bash
make test-policy
make test-crossguard
make check-coverage
```

The dedicated coverage workflow combines the structural, cost, policy, unit, integration, and e2e Python suites and fails if Pulumi code plus policy code drops below 100%.

## Notes

- The approved region allowlist defaults to `eu-central-1`, `us-east-1`, and `us-west-2`.
- Maintainers can override the region allowlist with `VILNACRM_ALLOWED_AWS_REGIONS`.
- Wildcard IAM exceptions are intentionally hard to use. If one is unavoidable, the reviewed statement `Sid` must be provided through `VILNACRM_IAM_WILDCARD_ALLOWLIST_SIDS` and justified in the PR.
- This repository keeps the policy pack local so it can run the same way in local CI, GitHub Actions, and PR automation. Pulumi Cloud-hosted best-practice packs can be layered later, but they are not the source of truth here.
