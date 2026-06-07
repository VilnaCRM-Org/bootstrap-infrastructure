# Security Account Attestation 2026-06-07

This attestation record is generated from metadata-only Well-Architected collector output and completed with security-owner review fields. Do not add IAM user names, access key IDs, secret values, screenshots containing private identities, credentials, tokens, or raw account exports.

## Review Metadata

| Field | Value |
| --- | --- |
| Workload | bootstrap-infrastructure |
| Environment | test |
| Review date | 2026-06-07 |
| Reviewer | Kravalg |
| Security owner | Kravalg |
| Human MFA/SSO posture | approved |
| Active IAM user access-key decision | approved_exception |
| Permissions-boundary or exemption decision | not_required |
| Approval decision | approved |
| Evidence expiry | 2026-07-07T00:00:00Z |
| Evidence source generated at | 2026-06-07T20:20:38.921934+00:00 |

## Collector Account Evidence

| Field | Value |
| --- | --- |
| AWS account | 891377212104 |
| Collector check status | passed |
| Root/account MFA enabled | 1 |
| Root/account access keys present | 0 |
| Discovered IAM users | 5 |
| Summary IAM users | 5 |
| MFA devices in use | 1 |
| Total MFA devices | 1 |
| Active IAM user access keys | 1 |
| Active keys older than 90 days | 0 |
| Active keys with unknown create date | 0 |
| Active keys never used | 0 |
| Active keys last used within 90 days | 1 |
| Active keys last used older than 90 days | 0 |
| Active keys with unknown last-used metadata | 0 |
| Inactive IAM user access keys | 0 |
| Unreadable access-key user metadata | 0 |
| Unreadable access-key last-used metadata | 0 |

## Collector Blockers

- None reported by the collector.

## Follow-Up Actions

- Security owner approved the current aggregate IAM posture for test account 891377212104, including one active IAM user access key observed in live metadata; IAM user count and MFA/SSO posture remain accepted for this bootstrap workload and must be reviewed before expiry or IAM scope expansion.
