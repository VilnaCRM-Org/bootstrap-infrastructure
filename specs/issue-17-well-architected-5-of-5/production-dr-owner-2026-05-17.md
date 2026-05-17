# Production DR Owner Evidence 2026-05-17

This production DR owner record is generated from metadata-only Well-Architected collector output and completed with production-owner review fields. Do not add credentials, secret values, private incident notes, customer data, screenshots containing private identities, or raw account exports.

## Review Metadata

| Field | Value |
| --- | --- |
| Workload | bootstrap-infrastructure |
| Environment | prod |
| Review date | 2026-05-17 |
| Reviewer | Kravalg |
| Production recovery owner | Kravalg |
| Escalation path | Kravalg / platform-maintainers via GitHub issue and maintained incident channel |
| RTO target | One business day for bootstrap infrastructure recovery under current accepted-risk production posture. |
| RPO target | One daily AWS Backup recovery point plus S3 versioning for state and log data. |
| Recovery order | Restore Pulumi state and read access first, validate KMS/secrets provider and GitHub OIDC roles, run preview/drift, then resume applies only after prod environment approval. |
| Communications expectations | Post status and recovery decisions in the maintained incident channel and linked GitHub issue; do not expose secrets, raw stack exports, or private incident notes. |
| Latest accepted drill | restore-drill-evidence-2026-04-27 |
| Next review or drill date | 2026-06-17 |
| Evidence retention location | specs/issue-17-well-architected-5-of-5/production-dr-owner-2026-05-17.md |
| Approval decision | accepted_risk |
| Evidence expiry | 2026-06-17 |
| Evidence source generated at | 2026-05-17T14:01:36.982564+00:00 |

## Collector Restore Evidence

| Field | Value |
| --- | --- |
| Restore workload | bootstrap-infrastructure |
| Restore environment | test |
| Completed at | 2026-04-27T05:05:41.655000Z |
| Target restore location | s3://awsbackup-restore-pr22w5-bootstrap-891377212104-drill |
| Validation result | passed |
| Cleanup confirmed | True |

## Follow-Up Actions

- Time-limited production-owner acceptance based on the successful test restore drill; run and record a production-specific tabletop or restore drill before expiry.
