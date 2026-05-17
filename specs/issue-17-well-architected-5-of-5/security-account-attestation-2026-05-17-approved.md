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
| Human MFA/SSO posture | approved |
| Active IAM user access-key decision | no_active_keys |
| Permissions-boundary or exemption decision | not_required |
| Approval decision | approved |
| Evidence expiry | 2026-08-17T00:00:00Z |
| Evidence source generated at | 2026-05-17T15:18:25.238127+00:00 |

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
| Active IAM user access keys | 0 |
| Active keys older than 90 days | 0 |
| Active keys with unknown create date | 0 |
| Active keys never used | 0 |
| Active keys last used within 90 days | 0 |
| Active keys last used older than 90 days | 0 |
| Active keys with unknown last-used metadata | 0 |
| Inactive IAM user access keys | 0 |
| Unreadable access-key user metadata | 0 |
| Unreadable access-key last-used metadata | 0 |

## Collector Blockers

- IAM user count exceeds MFA devices in use; human MFA/SSO posture requires security-owner attestation.

## Follow-Up Actions

- IAM user access keys were removed from the test account; IAM users have no console login profiles, GitHub Actions uses environment-scoped OIDC roles, and scoped automation policies plus policy-pack/IAM validation replace the prior permissions-boundary exemption for this no-runtime bootstrap workload.
