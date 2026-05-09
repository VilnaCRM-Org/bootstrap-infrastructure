# Alert Routing Evidence

This record captures the repository-owned observability and alert-routing
evidence for the bootstrap workload as of 2026-05-09. It contains only
non-secret AWS metadata, route-test identifiers, owners, and fallback rules.

## Metadata

| Field | Value |
| --- | --- |
| Workload | `bootstrap-infrastructure` |
| Environment | `test` |
| Region | `eu-central-1` |
| Evidence owner | SRE |
| Review cadence | Monthly and per alert-source change |
| Secret safety | Do not add payloads with stack exports, credentials, object contents, or private incident notes. |

## Alert Inventory

The current workload has no application runtime, load balancer, queue worker,
or customer request path. Monitoring is therefore focused on bootstrap
control-plane risk events, recovery events, CI/drift status, and cost alerts.

| Signal | Live source | Rule or route | Target | Owner | Runbook |
| --- | --- | --- | --- | --- | --- |
| Backup, copy, or restore job failed, aborted, or expired | AWS Backup EventBridge events | `bootstrap-test-backup-failed` | `arn:aws:sns:eu-central-1:891377212104:bootstrap-test-operations` | SRE | `docs/data-protection-recovery-evidence.md` |
| KMS key disabled, deletion scheduled, rotation disabled, or key policy changed | CloudTrail API events from `kms.amazonaws.com` | `bootstrap-test-kms-risk` | Operations SNS topic | Security reviewer plus SRE | `docs/security-operating-evidence.md` |
| GitHub OIDC provider or deploy-role trust changed | CloudTrail API events from `iam.amazonaws.com` | `bootstrap-test-iam-oidc-risk` | Operations SNS topic | Security reviewer plus SRE | `docs/security-operating-evidence.md` |
| State/log bucket encryption, policy, logging, or replication changed | CloudTrail API events from `s3.amazonaws.com` | `bootstrap-test-s3-control-plane-risk` | Operations SNS topic | SRE | `docs/data-protection-recovery-evidence.md` |
| Budget threshold or cost anomaly | AWS Budgets and Cost Anomaly Detection | Operations topic policy permits the account-local publishers | Operations SNS topic | FinOps owner plus SRE | `docs/cost-performance-sustainability.md` |
| Drift, preview, destructive diff, IAM validation, and policy failures | GitHub Actions and local make targets | Required-check contract plus workflow summaries | PR checks and workflow logs | Maintainer | `docs/ci-guardrails.md` |

Live AWS metadata checked on 2026-05-09:

- `aws events list-rules --name-prefix bootstrap-test --region eu-central-1`
  returned four enabled rules: `bootstrap-test-backup-failed`,
  `bootstrap-test-iam-oidc-risk`, `bootstrap-test-kms-risk`, and
  `bootstrap-test-s3-control-plane-risk`.
- `aws events list-targets-by-rule` returned one SNS target for each rule:
  `arn:aws:sns:eu-central-1:891377212104:bootstrap-test-operations`.
- `aws cloudwatch describe-alarms --alarm-name-prefix bootstrap-test` returned
  no metric or composite alarms. This is expected for the current no-runtime
  workload; future runtime compute, public endpoints, or replica-lag SLOs must
  add metric alarms before those claims can pass.
- `aws cloudwatch list-dashboards --dashboard-name-prefix bootstrap-test`
  returned no dashboards. The current observability inventory is docs-based
  because the workload has no runtime telemetry dashboard; future runtime or
  monthly operations dashboards must be linked here.

## Route Test

The collector already verifies that the operations SNS topic is KMS-encrypted
and has an SQS subscription. A direct SNS-to-SQS probe also passed on
2026-05-09:

| Step | Result |
| --- | --- |
| Publish probe | `aws sns publish` to `bootstrap-test-operations` returned message ID `901ab1e8-a146-55ef-a995-d391dd612a29`. |
| Receive probe | `aws sqs receive-message` on `bootstrap-test-operations-alerts` returned message ID `06e63d7f-bd7e-448f-a91c-46850ce69104` containing test ID `wa-alert-route-test-2026-05-09T173000Z`. |
| Cleanup | The probe message was deleted from the queue after validation. |

A synthetic EventBridge event with AWS service source `aws.backup` was rejected
with `NotAuthorizedForSourceException`, so EventBridge-to-SNS coverage remains
validated by live rule/target metadata and Pulumi component tests rather than
service-event injection.

## Fallbacks

- Keep OPS8, OPS10, and human-escalation claims below 5/5 until the downstream
  human alert route or incident tool is recorded with owner, target, and test
  evidence.
- Keep REL6 below 5/5 when resource-specific metric coverage is stale or
  incomplete, including future replica-lag, runtime, or public-endpoint
  metrics.
- Add a new row before merging any new alert source, metric alarm, dashboard,
  downstream subscriber, runtime compute, or public endpoint.
