# Security Account Attestation 2026-05-17

This attestation record is generated from metadata-only Well-Architected collector output and completed with security-owner review fields. Do not add IAM user names, access key IDs, secret values, screenshots containing private identities, credentials, tokens, or raw account exports.

## Review Metadata

| Field | Value |
| --- | --- |
| Workload | bootstrap-infrastructure |
| Environment | test |
| Review date | 2026-05-17 |
| Reviewer | Kravalg |
| Security owner | Kravalg |
| Human MFA/SSO posture | accepted_risk |
| Active IAM user access-key decision | approved_exception |
| Permissions-boundary or exemption decision | approved_exemption |
| Approval decision | accepted_risk |
| Evidence expiry | 2026-06-17 |
| Evidence source generated at | 2026-05-17T14:01:36.982564+00:00 |

## Collector Account Evidence

| Field | Value |
| --- | --- |
| AWS account | 891377212104 |
| Collector check status | failed |
| Root/account MFA enabled | 1 |
| Root/account access keys present | 0 |
| Discovered IAM users | 4 |
| Summary IAM users | 4 |
| MFA devices in use | 1 |
| Total MFA devices | 1 |
| Active IAM user access keys | 1 |
| Active keys older than 90 days | 1 |
| Active keys with unknown create date | 0 |
| Active keys never used | 0 |
| Active keys last used within 90 days | 1 |
| Active keys last used older than 90 days | 0 |
| Active keys with unknown last-used metadata | 0 |
| Inactive IAM user access keys | 0 |
| Unreadable access-key user metadata | 0 |
| Unreadable access-key last-used metadata | 0 |

## Collector Blockers

- IAM user count exceeds MFA devices in use; human MFA/SSO posture requires security-owner attestation.
- IAM access-key metadata reports active user access keys; record an approved exception or rotate/remove them before Security 5/5.

## Follow-Up Actions

- Time-limited security-owner acceptance for current aggregate IAM posture in account 891377212104; rotate or remove the remaining active IAM user access key, enroll remaining human users in MFA/SSO or document service-user-only posture, and revisit permissions-boundary exemption before expiry.
