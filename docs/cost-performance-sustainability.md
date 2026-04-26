# Cost, Performance, and Sustainability Guardrails

This repository uses static controls first and cloud spend controls second.
Bootstrap infrastructure creates durable AWS resources, so the review process
must show the projected fanout before resources are applied.

## Repository Fanout

`make test-repository-fanout` validates committed repository catalogs and prints
a non-secret estimate of resources implied by the catalog. The estimate uses
`expectedEnvironments` on each repository entry, defaulting to two environments
when the field is omitted.

Tracked categories include S3 buckets, KMS keys, IAM roles, AWS Backup
selections, the shared backup vault and plan, the shared GitHub OIDC provider,
the runner ECR repository, the operations SNS topic, the operations alert KMS
key, and EventBridge alert rules. Thresholds are static and deliberately
conservative; raise them only with a capacity review and an owner recorded in
the pull request.

## Preview Cost Proxy

`make test-cost-proxy` reads Pulumi preview JSON and counts create or replace
operations for cost and quota-driving resource families. The check writes
Markdown and JSON evidence under `.artifacts/pulumi-preview/` in CI.

The proxy does not calculate spend. It is a guardrail for unusual fanout,
resource replacement, and quota pressure. Use AWS Budgets, Cost Anomaly
Detection, and Service Quotas for account-level controls once the payer account,
alert destination, and owner are confirmed.

## Catalog Metadata

Repository catalog entries can include:

- `owner`: team or service owner for review and cleanup
- `lifecycleState`: `active`, `planned`, `deprecated`, or `archived`
- `lastReviewed`: ISO date of the last ownership and demand review
- `expectedEnvironments`: projected environment count for capacity estimates

These values are non-secret and may be exported or tagged for review evidence.
They should not contain tokens, account credentials, customer data, or private
incident details.

## Review Expectations

For every catalog expansion, reviewers should check:

- whether the new repository has an accountable owner
- whether the projected environment count matches the rollout plan
- whether S3, KMS, IAM, backup, and alerting fanout stays below thresholds
- whether deprecated or archived repositories should be removed before adding
  more durable resources
- whether live AWS quota or budget checks are needed before apply
