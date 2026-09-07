# Data Protection And Recovery Evidence

This file records repository-owned at-rest protection, backup, and restore
evidence for the bootstrap infrastructure workload. It is safe to publish
because it contains decisions, owners, control paths, and metadata references,
not object contents, decrypted Pulumi state, credentials, or private incident
details.

## Evidence Metadata

| Field | Value |
| --- | --- |
| Workload | `bootstrap-infrastructure` |
| Review date | 2026-05-09 |
| Evidence owner | Security reviewer for at-rest decisions; SRE for backup, restore, and Vault Lock/Object Lock posture |
| Freshness | Per storage, backup, KMS, retention, or replica change; monthly backup review; quarterly restore drill |
| Validation sources | `pulumi/infra/pulumi_state.py`, `pulumi/infra/logging_bucket.py`, `pulumi/infra/backup.py`, `pulumi/infra/operations_monitoring.py`, `pulumi/infra/security_account_controls.py`, restore drill evidence, policy-pack tests, and collector AWS metadata checks |
| Fallback | Keep SEC8 and REL9 below 5/5 when encryption, retention, restore, or exemption evidence is missing or stale. |

## At-Rest Protection Matrix

| Data path | Current protection | Decision | Validation | Fallback |
| --- | --- | --- | --- | --- |
| Pulumi state buckets | S3 versioning, default SSE-S3, SSE-C blocked, TLS-only bucket policy, public-access block, ownership controls, access logging, replication, and AWS Backup. | Keep active state in S3 Standard with SSE-S3; Pulumi secret values remain encrypted by the AWS KMS-backed Pulumi secrets provider rather than relying on bucket KMS for secret confidentiality. | `pulumi/infra/pulumi_state.py`, policy-pack encryption checks, restore drill evidence. | Block apply and restore from backup if state policy, versioning, encryption, or backup evidence is missing. |
| Pulumi state replicas | S3 versioning, default SSE-S3, SSE-C blocked, TLS-only bucket policy, public-access block, ownership controls, and replication role scoping. | Keep replicas as recovery copies in the allowlisted paired region; do not add lower-tier storage for active replica objects until RTO/RPO and transfer-cost evidence changes. | `pulumi/infra/pulumi_state.py`, quota and fanout evidence. | Keep primary read-only during replica-lag investigation and restore from primary or backup when the replica is unusable. |
| Central log buckets | S3 versioning, default SSE-S3, SSE-C blocked, public-access block, bucket policies, lifecycle transition, and replication. | SSE-S3 is sufficient for access logs because access is controlled by bucket/IAM policy, retained log objects are confidential metadata, and CloudTrail management-event logs have separate KMS evidence. | `pulumi/infra/logging_bucket.py`, collector CloudTrail evidence. | Treat log delivery failure or policy removal as SEV1/SEV2 depending on environment and restore logging controls before score claims. |
| CloudTrail management events | Existing or repo-created trail must be multi-region, logging, log-file validated, and KMS encrypted. | Reuse an existing compliant trail when supplied; otherwise repo-created trail uses a dedicated KMS key and scoped bucket policy. | Collector `aws_cloudtrail_management_events` check. | Keep SEC4/SEC8 evidence below 5/5 for CloudTrail paths when KMS encryption or validation is absent. |
| AWS Config snapshots | Dedicated S3 bucket with default SSE-S3, SSE-C blocked, TLS-only bucket policy, versioning, lifecycle expiration, and public-access block. | Config snapshots are configuration metadata; SSE-S3 plus scoped delivery and retention controls are sufficient for this workload. | `pulumi/infra/security_account_controls.py`, `docs/security-operating-evidence.md`. | Refresh recorder, delivery channel, and bucket posture after Config scope, delivery, retention, or region changes. |
| Pulumi secrets keys | Customer-managed KMS keys and aliases per managed repository with rotation enabled. | Use KMS-backed Pulumi secrets providers for secret values; do not print decrypted config or secret stack outputs in evidence. | `pulumi/infra/pulumi_secrets.py`, `docs/github-actions-secrets.md`. | Stop shared-stack operations until the intended KMS provider is available and verified. |
| Operations alerts | Operations SNS topic uses a customer-managed KMS key; SQS subscription is durable. | Encrypt alert transport at SNS because EventBridge, Budgets, and Cost Anomaly events route through the operations topic. | Collector `aws_sns_alert_route` check. | Keep alert-route claims blocked when topic encryption or subscription evidence is absent. |
| AWS Backup recovery points | AWS Backup vault and daily plan protect central logs and state buckets with 90-day retention. | Use AWS Backup for scheduled recovery points and isolated restore drills; vault encryption follows AWS Backup vault encryption behavior and source resource protection. | `pulumi/infra/backup.py`, collector restore-job check, restore drill evidence. | Open SEV2 follow-up for failed jobs and run a fresh restore drill after remediation. |
| CI artifacts and saved plans | GitHub artifact retention plus saved-plan manifest hash, backend, stack, commit, preview hash, and age checks. | Treat artifacts as review evidence only; reject stale or tampered plans before apply. | `scripts/run_pulumi_command.py`, saved-plan tests. | Regenerate preview and plan from the intended commit when manifest validation fails. |

## Daily Backup Schedule

The canonical TEST plan runs at 10:00 UTC; PROD remains at 05:00 UTC.
Both retain a 60-minute start window, a 120-minute completion window and
90-day retention. TEST has two existing 05:00 UTC plans selecting the same
central log bucket. Their configured latest completion bounds are 08:00 and
09:00 UTC (the latter has a 180-minute completion window), leaving one hour
before the canonical TEST slot. Preserve those plans, vaults and recovery
points; consolidation requires a separate ownership review. One plan has
verified retained checkpoint ownership; the other plan's current checkpoint
owner remains unresolved.

AWS applies [plan updates to future backups](https://docs.aws.amazon.com/aws-backup/latest/devguide/updating-a-backup-plan.html).
For a same-day transition, verify the updated rule before 10:00 UTC and observe
the existing 05:00 job and new scheduled job independently. Do not infer job
creation or successful backup from rule readback alone. If the deployment misses
that slot, reassess the transition against the daily-backup RPO before applying.
The [start and completion windows](https://docs.aws.amazon.com/aws-backup/latest/APIReference/API_BackupRuleInput.html)
bound configured scheduling; delayed service cancellation or other concurrent
jobs still require live job verification. This schedule-only change preserves
S3 versioning and the existing TEST/PROD restore evidence; it requires no new
restore drill.

## Vault Lock And Object Lock Decision

Current design: retain mutable active S3 state with versioning, encrypted Pulumi
secrets, replication and a separately protected AWS Backup copy. S3 objects are
not claimed to be locked. The 2026-08-07 Object Lock and Vault Lock exemptions
expired and are not renewed by this change.

| Control | Decision | Validation and limits |
| --- | --- | --- |
| S3 Object Lock | Do not introduce retention locks on the active state, log, replica or Config buckets. Recovery retention is enforced on the AWS Backup copy. | Versioning, lifecycle, encryption and replication remain unchanged. Object Lock can be enabled on eligible existing buckets; the previous creation-only statement was incorrect. This design does not claim immutable live objects or compliance-mode retention. |
| AWS Backup Vault Lock | `S3BackupPlan` declares a protected governance-mode lock with a 90-day minimum, matching the existing daily plan. `ChangeableForDays` and maximum retention are omitted. | Require reviewed TEST and PROD apply, no-drift and `DescribeBackupVault` evidence (`Locked=true`, `MinRetentionDays=90`, no `LockDate`). Governance mode remains removable by independently authorized administrators. Existing recovery-point lifecycle values are unchanged. |
| S3 SSE-KMS for state and log buckets | Keep default SSE-S3 and KMS-encrypted Pulumi secret values. CloudTrail and operations SNS retain their dedicated KMS controls. | No change to encryption or recovery access. Reassess if these buckets receive new secret-bearing data classes. |

The operator setting `platformBackupVaultArn` binds the additional permission to
one exact account-local, environment-tagged `s3-backup` vault. Configure it from
reviewed platform output/metadata before the operator permission apply. No value
means no new grant. The grant permits only `PutBackupVaultLockConfiguration` with
minimum 90 days and absent compliance/max parameters; it grants neither lock
removal nor recovery-point deletion. `DescribeBackupVault` is already permitted.
Pulumi protection rejects ordinary removal/replacement of the lock resource.

Existing bindings to verify before installation:

- TEST: `arn:aws:backup:eu-central-1:891377212104:backup-vault:s3-backup-vault-3b9f5bf`.
- PROD: `arn:aws:backup:eu-central-1:933245420672:backup-vault:s3-backup-vault-3dab3a7`.

Installation order is operator permission preview/apply, then platform lock
preview/apply, followed by vault metadata and drift checks. A source declaration
alone does not close SEC8/REL9: retain their unresolved live-control status until
both installations are verified. No new restore drill is required by this
retention-only change; preserve the actual TEST R6 and PROD R1 drill records.

AWS documents the [reversible governance-mode and existing recovery-point
semantics](https://docs.aws.amazon.com/aws-backup/latest/devguide/vault-lock.html),
[exact vault permission and retention condition keys](https://docs.aws.amazon.com/service-authorization/latest/reference/list_backup.html),
and [enabling Object Lock on existing buckets](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock-configure.html).

## Restore Runbook

Use this runbook for non-production restore drills and recovery evidence.

1. Confirm AWS identity, account, region, target stack, backup vault, backup
   plan, and candidate recovery point using metadata-only commands.
2. Restore to an isolated bucket matching
   `awsbackup-restore-<environment>-bootstrap-<account>-*`; never overwrite the
   active Pulumi backend as the first restore step.
3. Validate restore job status, created resource ARN, versioning metadata, and
   object count or metadata only. Do not read Pulumi state contents or decrypted
   stack values.
4. Record workload, environment, source recovery point ARN, restore job ID,
   target restore location, validation result, operator or automation context,
   and timestamps.
5. Remove the isolated restore bucket after validation and record cleanup
   confirmation.
6. If cleanup or validation fails, keep REL9 below 5/5, open a SEV2 follow-up,
   and run a fresh drill after remediation.

Latest accepted drill:
`specs/issue-17-well-architected-5-of-5/restore-drill-evidence-2026-04-27.json`
records restore job `d7f25510-1dfd-4f11-8953-72ed1c971c2c`, completed on
2026-04-27, validation `passed`, and cleanup confirmed on 2026-05-09.

Latest incident and DR scenario drill:
`docs/incident-drill-evidence-2026-05-09.md` records completed backup metadata,
state and log replication rules, replica object parity samples, KMS/IAM/OIDC,
logging, backup, and hosted workflow scenarios, and degraded-mode decisions for
the current test workload.

## Backup Review Cadence

Monthly backup review must retain:

- Stack, environment, account, vault name, plan name, and protected resource
  families.
- Last successful backup-job timestamp and any failed, aborted, or expired job
  IDs.
- Last restore drill date and whether it is inside the 90-day freshness window.
- Vault Lock/Object Lock exemption status or implementation status.
- Owner decision and follow-up issue when evidence is stale or contradictory.

Quarterly restore drills must use an isolated target and metadata-only
validation. A restore drill becomes stale after 90 days.

## Production DR Owner Evidence

`RESTORE_DRILL_EVIDENCE` proves the workload-scoped restore drill. Production
DR claims also need a production-owner record before `REL13` can move to 5/5.
Generate that non-secret record from the latest collector output after the
owner has approved production RTO/RPO targets, recovery ownership, escalation,
recovery order, communications expectations, latest accepted drill evidence,
next review or drill date, and evidence retention location:

```bash
PRODUCTION_DR_OWNER_OUTPUT=docs/production-dr-owner-YYYY-MM-DD.md \
PRODUCTION_DR_OWNER_JSON_OUTPUT=docs/production-dr-owner-YYYY-MM-DD.json \
PRODUCTION_DR_REVIEWER='<reviewer or team>' \
PRODUCTION_DR_OWNER='<production recovery owner or team>' \
PRODUCTION_DR_ESCALATION_PATH='<escalation path>' \
PRODUCTION_DR_RTO_TARGET='<production RTO target or accepted exemption>' \
PRODUCTION_DR_RPO_TARGET='<production RPO target or accepted exemption>' \
PRODUCTION_DR_RECOVERY_ORDER='<ordered recovery expectations>' \
PRODUCTION_DR_COMMUNICATIONS_PLAN='<communications expectations>' \
PRODUCTION_DR_LATEST_ACCEPTED_DRILL='<accepted drill or tabletop evidence>' \
PRODUCTION_DR_NEXT_REVIEW_DATE='YYYY-MM-DD' \
PRODUCTION_DR_EVIDENCE_RETENTION_LOCATION='<evidence location>' \
PRODUCTION_DR_APPROVAL='approved' \
PRODUCTION_DR_ACTION='<non-secret owner evidence and follow-up note>' \
PRODUCTION_DR_EXPIRY_DATE='YYYY-MM-DDTHH:MM:SSZ' \
make report-production-dr-owner-evidence
```

Then include the JSON in a collector run:

```bash
PRODUCTION_DR_OWNER_EVIDENCE=docs/production-dr-owner-YYYY-MM-DD.json \
make report-well-architected-evidence
```

## Degraded Mode Playbooks

| Scenario | First checks | Recovery path | Evidence |
| --- | --- | --- | --- |
| Primary state bucket unavailable | Confirm identity, bucket existence, policy, versioning, encryption, and recent CloudTrail S3 events. | Restore policy/access if safe, otherwise restore latest recovery point to an isolated bucket and promote only after SRE approval. | Bucket name, CloudTrail event IDs, recovery point ARN, owner decision. |
| Replica lag or replica unavailable | Check replication configuration, latest object versions, and replication metrics when available. | Keep primary as source of truth until lag is understood; use backup restore if both primary and replica are unsafe. | Bucket pair, replication rule ID, lag observation, owner decision. |
| KMS key disabled or pending deletion | Describe key and alias, inspect CloudTrail KMS events, and identify actor. | Cancel unintended deletion or re-enable key under security-review direction; regenerate secrets provider evidence if needed. | Key alias, CloudTrail event, containment owner, follow-up issue. |
| Log delivery failure | Check S3 bucket policy, CloudTrail status, access log delivery, and EventBridge alerts. | Restore delivery policy or fail forward to a compliant trail/log bucket; record any evidence gap. | Trail name, bucket name, failure time, recovery action. |
| Backup failure | Check backup job state, protected resource ARN, vault, plan, and EventBridge alert. | Fix root cause, schedule a fresh backup, and run a restore drill if recoverability is in doubt. | Job ID, vault, plan, remediation owner, next drill date. |
