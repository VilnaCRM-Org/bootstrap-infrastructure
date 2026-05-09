# Cost, Performance, and Sustainability Guardrails

This repository uses static controls first and cloud spend controls second.
Bootstrap infrastructure creates durable AWS resources, so the review process
must show the projected fanout before resources are applied and must preserve
evidence that account-level cost controls are routed to an owner.

## Repository Fanout

`make test-repository-fanout` validates committed repository catalogs and prints
a non-secret estimate of resources implied by the catalog. The estimate uses
`expectedEnvironments` on each repository entry, defaulting to two environments
when the field is omitted.

Tracked categories include S3 buckets, KMS keys, IAM roles, AWS Backup
selections, the shared backup vault and plan, the shared GitHub OIDC provider,
the runner ECR repository, the operations SNS topic, the operations alert KMS
key, CloudTrail management-event trail, and EventBridge alert rules. Thresholds are static and deliberately
conservative; raise them only with a capacity review and an owner recorded in
the pull request.

## Performance Operating Evidence

Use `docs/performance-operating-evidence.md` for repository-owned performance
ADRs. That file records resource-selection alternatives, fanout constraints,
storage access patterns, storage-class rationale, region and network decisions,
owners, cadence, validation sources, and fallback rules. It must be updated
before adding new AWS service families, storage paths, regions, VPC resources,
or public endpoints.

Use `docs/workload-applicability-evidence.md` for the current no-VPC,
no-public-endpoint, and no-idle-compute applicability record. That file is the
service-selection gate for future runtime compute or public ingress.

Use `docs/operating-review-2026-05-09.md` for the current repository-owned
demand review, stale asset review, service review, cost-of-effort notes,
performance observations, CI efficiency review, and sustainability governance
record.

Use `docs/region-sustainability-evidence.md` for the primary/replica region
decision matrix and the exception gate before region or replicated-data changes.

## Preview Cost Proxy

`make test-cost-proxy` reads Pulumi preview JSON and counts create or replace
operations for cost and quota-driving resource families. The check writes
Markdown and JSON evidence under `.artifacts/pulumi-preview/` in CI.

The proxy does not calculate spend. It is a guardrail for unusual fanout,
resource replacement, and quota pressure. It complements the AWS Budget, Cost
Anomaly Detection, and Service Quotas controls used for account-level review.
The current weighted threshold is `66`, matching the full first-time bootstrap
baseline that includes automation, CloudTrail, backup, cost controls, security
detection, configuration inventory, and operations monitoring.

## AWS Budget And Cost Anomaly Controls

The bootstrap stack provisions repo-owned cost alerts through the same
operations SNS topic used for control-plane events:

- A monthly AWS Budget named `bootstrap-<environment>-monthly-cost`.
- Actual spend notification at 80% of the configured budget.
- Forecasted spend notification at 100% of the configured budget.
- A service-dimensional Cost Anomaly Detection monitor named
  `bootstrap-<environment>-service-cost` when
  `bootstrap-infrastructure:costAnomalyMonitorArn` is unset, or reuse of that
  configured existing monitor ARN when the account already has a
  service-dimensional monitor.
- An immediate anomaly subscription named
  `bootstrap-<environment>-cost-alerts` that publishes to the operations SNS
  topic when absolute impact meets the configured threshold.
- Optional activation of the repository cost allocation tag keys when
  `bootstrap-infrastructure:manageCostAllocationTags` is enabled.

Cost Explorer must already be enabled in the target account before Pulumi can
create Cost Anomaly Detection resources. AWS does not provide an API to enable
Cost Explorer, so this remains an account-owner prerequisite for test and
shared environments.

Configuration values are non-secret:

| Config key | Default | Purpose |
| --- | ---: | --- |
| `bootstrap-infrastructure:monthlyBudgetLimitUsd` | `100` | Monthly budget limit in USD. |
| `bootstrap-infrastructure:costAnomalyThresholdUsd` | `10` | Absolute anomaly impact threshold in USD. |
| `bootstrap-infrastructure:costAnomalyMonitorArn` | unset | Existing Cost Anomaly monitor ARN to reuse when the account already has a service-dimensional monitor. |
| `bootstrap-infrastructure:manageCostAllocationTags` | `false` | Activates the repo-managed cost allocation tags in Cost Explorer when the account owner approves the account-global change. |

Pulumi exports provide non-secret evidence handles for reviews:

- `monthlyBudgetName`
- `costAnomalyMonitorArn`
- `costAnomalySubscriptionArn`
- `operationsAlertTopicArn`
- `operationsAlertQueueArn`
- `operationsAlertQueueSubscriptionArn`

Do not inspect invoices or billing exports in routine repository evidence. For
Well-Architected review, metadata such as the budget name, anomaly monitor ARN,
threshold configuration, SNS route, owner, last reviewed date, and summarized
Cost Explorer cost or transfer lines is sufficient.

The current review record is
`docs/finops-review-2026-05-09.md`. It records the active cost allocation tag
set, budget and anomaly thresholds, SNS route, month-to-date service cost
snapshot, data-transfer review, action thresholds, and next review date for the
test workload.

## Catalog Metadata

Repository catalog entries can include:

- `owner`: team or service owner for review and cleanup
- `lifecycleState`: `active`, `planned`, `deprecated`, or `archived`
- `lastReviewed`: ISO date of the last ownership and demand review
- `expectedEnvironments`: projected environment count for capacity estimates

These values are non-secret and may be exported or tagged for review evidence.
They should not contain tokens, account credentials, customer data, or private
incident details.

## Current 5/5 Cost Evidence

The 2026-05-09 FinOps review closes the current repository-owned cost evidence
for the test workload:

- `platform-maintainers` is recorded as the accountable FinOps owner for this
  review.
- Budget, actual threshold, forecast threshold, anomaly threshold, and SNS route
  are recorded from AWS metadata.
- Cost allocation tags for owner, cost center, app, project, repository,
  environment, criticality, classification, and retention are active.
- Month-to-date service cost and data-transfer snapshots are retained as
  summarized Cost Explorer evidence.
- Budget, anomaly, transfer, fanout, and catalog expansion action thresholds
  are documented with fallback behavior.

Future production approval, catalog growth, additional replicated data classes,
or new service families must refresh this evidence before changing cost claims.

## Review Expectations

For every catalog expansion, reviewers should check:

- whether the new repository has an accountable owner
- whether the projected environment count matches the rollout plan
- whether S3, KMS, IAM, backup, and alerting fanout stays below thresholds
- whether deprecated or archived repositories should be removed before adding
  more durable resources
- whether the monthly budget and anomaly threshold still match the expected
  spend profile
- whether the operations alert queue has a confirmed owner and downstream route
- whether live AWS quota or payer-account evidence is needed before apply

`make report-well-architected-evidence` records the current static fanout
report together with metadata-only AWS Budget and Cost Anomaly Detection checks.
It does not query invoices or detailed billing exports. A future cost or
sustainability claim must keep owner-approved thresholds, recurring review
evidence, and live account headroom current where catalog growth can affect
quotas.

The current Well-Architected quota headroom record is retained at
`specs/issue-17-well-architected-5-of-5/quota-headroom-evidence-2026-05-09.json`.
It uses count-only AWS metadata plus Service Quotas/default quota values and
must be refreshed before catalog expansion.
