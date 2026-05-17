# Alert Route Observation 2026-05-17

This monthly observation record is generated from the metadata-only Well-Architected collector output and completed with human review fields. Do not add alert payloads, stack exports, credentials, tokens, private incident notes, or access-key material.

## Review Metadata

| Field | Value |
| --- | --- |
| Workload | bootstrap-infrastructure |
| Environment | test |
| Review date | 2026-05-17 |
| Reviewer | Kravalg |
| Route owner | SRE |
| Downstream route | Scheduled GitHub Actions workflow .github/workflows/operations-alert-triage.yml assumes the dedicated test OIDC operations-alert triage role, creates GitHub issues from sanitized SQS/SNS/EventBridge alert metadata, and deletes messages only after issue creation; smoke test routed messages to issues #39, #40, #41, and #42. |
| Severity expectations | SEV1/SEV2 control-plane, backup, KMS, IAM/OIDC, S3, budget, and anomaly events are routed to GitHub issues for maintainer review, with the durable SQS queue retained as the fallback buffer. |
| Fallback behavior | If scheduled issue triage fails or GitHub issue creation is unavailable, inspect bootstrap-test-operations-alerts manually, create a metadata-only GitHub issue, and keep OPS8 blocked until the workflow route is restored. |
| Review decision | approved |
| Evidence source generated at | 2026-05-17T15:18:25.238127+00:00 |

## Collector Route Evidence

| Field | Value |
| --- | --- |
| SNS topic ARN | arn:aws:sns:eu-central-1:891377212104:bootstrap-test-operations |
| Encrypted | True |
| Subscription count | 1 |
| Subscription protocols | sqs |

## Queue Observation

| Field | Value |
| --- | --- |
| Queue name | bootstrap-test-operations-alerts |
| Queue ARN | arn:aws:sqs:eu-central-1:891377212104:bootstrap-test-operations-alerts |
| Visible messages | 0 |
| Not visible messages | 0 |
| Delayed messages | 0 |
| Retention seconds | 345600 |
| Visibility timeout seconds | 30 |

## Follow-Up Actions

- Implemented scheduled GitHub issue triage for the operations alert queue, granted scoped SQS consume permissions to a dedicated test OIDC operations-alert triage role, explicitly denied alert-queue consumption from the shared automation role, and performed a metadata-only smoke test that created and closed handled test-alert issues #39-#42.
