# Incident And DR Drill Evidence 2026-05-09

This record captures a metadata-only tabletop and live-metadata drill for the
`bootstrap-infrastructure` test workload. It does not include object contents,
decrypted Pulumi state, credentials, private incident notes, or stack exports.

## Metadata

| Field | Value |
| --- | --- |
| Workload | `bootstrap-infrastructure` |
| Environment | `test` |
| Account | `891377212104` |
| Primary region | `eu-central-1` |
| Replica region | `eu-west-1` |
| Drill date | 2026-05-09 |
| Drill type | Tabletop plus live AWS metadata validation |
| Evidence owner | SRE, with security reviewer for IAM/KMS/OIDC scenarios |
| Freshness | Quarterly; stale after 2026-08-07 |

## Live Metadata Checks

| Check | Evidence | Result |
| --- | --- | --- |
| Backup health | `aws backup list-backup-jobs --by-created-after 2026-05-01T00:00:00Z` returned completed jobs for `pulumi-bootstrap-infrastructure-test-state`, `pulumi-api-gateway-infrastructure-test-state`, and `company-central-logs-eu-central-1-test`, including 2026-05-09 jobs. | Passed |
| State replication rule | `get-bucket-replication` on `pulumi-bootstrap-infrastructure-test-state` returned enabled rule `bootstrap-infrastructure-to-euwest1` with destination `pulumi-bootstrap-infrastructure--c1194dce-eu-west-1-replication`. | Passed |
| Log replication rule | `get-bucket-replication` on `company-central-logs-eu-central-1-test` returned enabled rule `central-logs-to-euwest1` with destination `company-central-logs-eu-central-1-test-eu-west-1-replication`. | Passed |
| State replica parity sample | `head-object` for `state/pr-preview/.pulumi/backups/bootstrap-infrastructure/test/test.1778342040395443439.json` reported source `ReplicationStatus=COMPLETED`, replica `ReplicationStatus=REPLICA`, matching `ContentLength=754623`, and matching version ID `9hDdC5XqjJS7uNyTiGtHCx9kalZBnd8Z`. | Passed |
| Second replica parity sample | `head-object` for `state/pr-preview/.pulumi/backups/bootstrap-infrastructure/test/test.1778341781214722904.json` reported source `ReplicationStatus=COMPLETED`, replica `ReplicationStatus=REPLICA`, matching `ContentLength=580777`, and matching version ID `YcswrhRSp8.eSiNIyxqdYNinIAWKIgGc`. | Passed |
| Replication metrics | `cloudwatch list-metrics` for `ReplicationLatency` and `OperationsPendingReplication` returned no metrics for the state bucket. | Accepted for current workload because sampled object replication status proves completion; future replica-lag SLOs must enable S3 replication metrics or S3 RTC. |
| Alert rules | `events list-rules --name-prefix bootstrap-test` returned four enabled rules: backup failure, KMS risk, IAM/OIDC risk, and S3 control-plane risk. | Passed |
| Alert route | `docs/alert-routing-evidence.md` records SNS target metadata and a successful SNS-to-SQS probe. | Passed for durable queue route; downstream human route remains tracked under OPS8. |

## Scenario Drill Record

| Scenario | Detection path | First checks exercised | Recovery or fail-forward decision | Evidence retained |
| --- | --- | --- | --- | --- |
| Primary state bucket unavailable | S3 CloudTrail event, failed preview/apply, or S3 control-plane EventBridge rule. | Confirm AWS identity, bucket existence, versioning, encryption, replication rule, latest completed backup, and sampled replica object status. | Keep primary read-only until root cause is known; restore policy/access if safe, otherwise restore latest AWS Backup recovery point into an isolated bucket before promotion. | Bucket names, backup job IDs, sampled object keys, replication status, owner decision. |
| Replica lag or replica unavailable | Replication status check, future S3 replication metric, or restore drill observation. | Check replication configuration, sampled source/replica object metadata, and latest backup job for the source bucket. | Primary remains source of truth; use AWS Backup restore if primary and replica are both unsafe. | Replication rule IDs, sampled object metadata, latest backup job, follow-up decision. |
| KMS key disabled, pending deletion, or policy changed | `bootstrap-test-kms-risk` EventBridge rule from CloudTrail KMS events. | Describe key and alias, inspect CloudTrail actor/action, verify affected SNS or CloudTrail encryption path. | Cancel unintended deletion or re-enable key under security-review direction; pause affected apply paths until encryption evidence is restored. | Key alias or ARN, CloudTrail event, containment owner, follow-up issue. |
| GitHub OIDC trust or deploy role changed | `bootstrap-test-iam-oidc-risk` EventBridge rule, IAM validation, or failed privileged workflow. | Inspect role trust policy, GitHub ref/environment conditions, recent IAM CloudTrail events, and local IAM validation output. | Disable or narrow affected role, rerun IAM validation, and require security reviewer approval before privileged jobs resume. | Role name, trust-policy diff, workflow URL, CloudTrail event, reviewer. |
| Log delivery failure | CloudTrail status, S3 policy change event, or missing log delivery observation. | Check CloudTrail status, log bucket policy, access-log bucket policy, EventBridge rule inventory, and latest backup. | Restore delivery policy or fail forward to compliant trail/log bucket; keep investigation evidence metadata-only. | Trail name, bucket name, failure time, policy diff, recovery action. |
| Backup failure | `bootstrap-test-backup-failed` EventBridge rule and AWS Backup job metadata. | Check job state, protected resource ARN, vault, plan, and SNS/SQS route. | Fix root cause, schedule a fresh backup, and run a restore drill when recoverability is uncertain. | Job ID, vault, plan, remediation owner, next drill date. |
| Hosted workflow failure | GitHub check context, workflow logs, local focused check, and branch-protection evidence. | Reproduce locally when possible, inspect required check names, validate saved-plan manifests for apply paths. | Fix workflow/code, rerun checks, and block merge until hosted checks pass or an approved admin exception is recorded. | Workflow URL, check name, head SHA, local command output summary. |

## Outcome

The drill satisfies current repository-owned incident and DR exercise evidence
for backup health, state/log replication posture, degraded-mode decision paths,
KMS/IAM/OIDC/logging incident response, and hosted workflow failure response.
It does not close branch protection, production approval, downstream human alert
route, human MFA/SSO, permissions-boundary attestation, or external
security-owner approval.
