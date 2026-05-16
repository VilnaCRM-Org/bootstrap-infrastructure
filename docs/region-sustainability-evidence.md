# Region Sustainability Evidence

This file records the repository-owned region decision matrix for the bootstrap
infrastructure workload. It is a public artifact and contains only non-secret
region, service, owner, and decision evidence.

## Evidence Metadata

| Field | Value |
| --- | --- |
| Workload | `bootstrap-infrastructure` |
| Review date | 2026-05-09 |
| Evidence owner | SRE plus platform owner |
| Freshness | Quarterly and before region, replica, residency, or replicated-data changes |
| Validation sources | `pulumi/Pulumi.test.yaml`, `pulumi/Pulumi.prod.yaml`, policy region allowlist, `docs/performance-operating-evidence.md`, `docs/operating-review-2026-05-09.md`, quota headroom evidence |
| Fallback | Keep SUS1 below 5/5 and block region changes when residency, service availability, transfer impact, recovery objective, or sustainability evidence is missing. |

## Region Decision Matrix

| Criterion | Primary `eu-central-1` | Replica `eu-west-1` | Decision |
| --- | --- | --- | --- |
| Residency and compliance | Existing stack configs and test-account evidence use an EU region. | Replica stays in an EU region. | Keep primary and replica in the EU for current bootstrap data classes. |
| Service availability | Required primary controls are available: S3, KMS, IAM/OIDC integration, AWS Backup, CloudTrail, EventBridge, SNS, SQS, Budgets, Cost Anomaly Detection, GuardDuty, Security Hub, and AWS Config. | Replica path requires S3 and supporting replication controls. | No service gap requires another region for the current workload. |
| Latency | No user-facing request path exists; control-plane latency is dominated by GitHub runner startup and AWS API behavior. | Replica is recovery-only and not on the normal preview/apply path. | Region choice is acceptable for the current control-plane workload. |
| Recovery | Primary holds active state and logs. | Replica provides regional separation for state and log recovery. | Keep cross-region replication for recovery; do not add active-active runtime complexity. |
| Transfer impact | Replicated data is limited to current state/log classes and bounded by lifecycle, retention, and catalog fanout controls. | Transfer increases cost and resource use but supports recovery objectives. | Future data classes or material growth require a GB/month estimate and owner approval before replication expands. |
| Sustainability posture | Managed services, no always-on compute, lifecycle controls, backup retention, and data classification reduce idle resource use. | Recovery-only replica avoids active duplicate compute. | Prefer managed/serverless and lifecycle controls over custom always-on recovery infrastructure. |
| Exception path | New primary regions require compliance, service, latency, transfer, cost, and sustainability review. | New replica regions require the same review plus restore objective comparison. | Region exceptions require SRE and platform-owner approval before merge. |

## Current Decision

Keep `eu-central-1` as the primary region and `eu-west-1` as the replica region
for the current bootstrap workload. This decision is valid for the current
S3/KMS/IAM/Backup/logging/security/cost-control footprint and the single active
repository catalog. It must be refreshed before adding a user-facing endpoint,
always-on compute, another replicated data class, or another managed
repository.
