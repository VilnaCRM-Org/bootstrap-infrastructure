# FinOps Review 2026-05-09

This record captures metadata-only cost evidence for the
`bootstrap-infrastructure` test workload. It excludes invoices, private billing
exports, and personal subscriber details.

## Metadata

| Field | Value |
| --- | --- |
| Workload | `bootstrap-infrastructure` |
| Account | `891377212104` |
| Environment | `test` |
| Review date | 2026-05-09 |
| Accountable owner | `platform-maintainers` acting as FinOps owner for this review |
| Review cadence | Monthly and before catalog, retention, replica, or service-family expansion |
| Next review | 2026-06-09 |

## Active Cost Allocation Tags

Cost Explorer activation was updated on 2026-05-09 and returned no errors.
`list-cost-allocation-tags --status Active` then showed these workload tag keys
as active:

| Tag key | Status |
| --- | --- |
| `App` | Active |
| `CostCenter` | Active |
| `Criticality` | Active |
| `DataClassification` | Active |
| `Environment` | Active |
| `Owner` | Active |
| `Project` | Active |
| `Repository` | Active |
| `RepositoryProject` | Active |
| `RetentionClass` | Active |

## Budget And Anomaly Controls

| Control | Current evidence | Review decision |
| --- | --- | --- |
| Monthly budget | `bootstrap-test-monthly-cost`, limit `100.0 USD`, monthly cost budget. | Approved for the test bootstrap workload. Revisit before production approval or catalog expansion. |
| Actual budget alert | `GREATER_THAN` `80.0` with SNS subscriber `arn:aws:sns:eu-central-1:891377212104:bootstrap-test-operations`. | Approved. Treat as SEV2 when triggered. |
| Forecast budget alert | `GREATER_THAN` `100.0` with the same operations topic route. | Approved. Treat as no-go for expansion until reviewed. |
| Cost anomaly subscription | `bootstrap-test-cost-alerts`, immediate frequency, absolute impact threshold `10 USD`, service-dimensional monitor `e5509927-1fcc-400c-9536-0fdd01314bc9`, SNS subscriber confirmed. | Approved. Keep routed to the operations topic. |

## Month-To-Date Cost Snapshot

Cost Explorer `get-cost-and-usage` for 2026-05-01 through 2026-05-10 returned
these nonzero service costs:

| Service | Unblended cost |
| --- | ---: |
| AWS Backup | `0.0061807992 USD` |
| AWS Key Management Service | `0.526881712 USD` |
| AWS Secrets Manager | `0.3251119304 USD` |
| Amazon EC2 Container Registry | `0.0067186653 USD` |
| Amazon Route 53 | `0.50123 USD` |
| Amazon Simple Storage Service | `0.0282029506 USD` |
| AmazonCloudWatch | `0.00108 USD` |
| Tax | `0.32 USD` |

The observed month-to-date total from these lines is below the `100 USD`
monthly budget and does not require a cost-reduction action for the current
single-repository test workload.

## Data Transfer Review

Cost Explorer usage-type review for 2026-05-01 through 2026-05-10 showed data
transfer lines with zero cost except `USE1-EUC1-AWS-Out-Bytes`, which reported
`0.0000003508 USD` on `0.0000175368` usage units. Current cross-region transfer
does not require a reduction action.

Action thresholds for the current workload:

- Review replication design before adding a new replicated data class or
  changing either region.
- Open a FinOps review when account-level data transfer exceeds `1 USD` in a
  month or when S3 transfer usage exceeds `1 GB` in a month.
- Block catalog expansion when static fanout, quota headroom, budget, anomaly,
  or transfer thresholds are exceeded without owner approval.

## Outcome

Cost Optimization evidence is current for the test workload on 2026-05-09.
Future production approval, catalog growth, additional replicated data classes,
or new service families must refresh this record and retain the AWS metadata
used for the review.
