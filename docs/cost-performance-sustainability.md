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

## Preview Cost Proxy

`make test-cost-proxy` reads Pulumi preview JSON and counts create or replace
operations for cost and quota-driving resource families. The check writes
Markdown and JSON evidence under `.artifacts/pulumi-preview/` in CI.

The proxy does not calculate spend. It is a guardrail for unusual fanout,
resource replacement, and quota pressure. It complements the AWS Budget, Cost
Anomaly Detection, and Service Quotas controls used for account-level review.
The current weighted threshold is `64`, matching the full first-time bootstrap
baseline that includes automation, CloudTrail, backup, cost controls, and
operations monitoring.

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

Do not inspect invoices, Cost Explorer report contents, or billing exports in
routine repository evidence. For Well-Architected review, metadata such as the
budget name, anomaly monitor ARN, threshold configuration, SNS route, owner, and
last reviewed date is sufficient.

## Catalog Metadata

Repository catalog entries can include:

- `owner`: team or service owner for review and cleanup
- `lifecycleState`: `active`, `planned`, `deprecated`, or `archived`
- `lastReviewed`: ISO date of the last ownership and demand review
- `expectedEnvironments`: projected environment count for capacity estimates

These values are non-secret and may be exported or tagged for review evidence.
They should not contain tokens, account credentials, customer data, or private
incident details.

## Remaining 5/5 Cost Evidence

The repository now owns the Budget and Cost Anomaly Detection resources, but an
honest 5/5 still needs account-owner evidence outside the codebase:

- FinOps owner approval for the monthly budget limit and anomaly threshold.
- Cost Explorer enabled in the target account before Pulumi apply.
- Confirmed downstream incident route for the durable operations alert queue or
  the operations SNS topic.
- Activated cost allocation tag evidence when the payer account supports it.
- Monthly cost report or dashboard location with reviewer and date.
- Spend approval thresholds by account and environment.
- Cross-region replication transfer estimate and action threshold.
- Live AWS Service Quotas or account headroom evidence before large catalog
  expansion.

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
It does not query invoices or spend details. A 5/5 cost or sustainability claim
still needs owner-approved thresholds, recurring review evidence, and live
account headroom where catalog growth can affect quotas.
