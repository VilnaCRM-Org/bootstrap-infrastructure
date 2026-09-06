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

The collector verifies that the operations SNS topic is KMS-encrypted, has an
SQS subscription, and can read non-secret queue metadata such as queue name,
visible and not-visible message counts, retention, and visibility timeout. A
direct SNS-to-SQS probe also passed on 2026-05-09:

| Step | Result |
| --- | --- |
| Publish probe | `aws sns publish` to `bootstrap-test-operations` returned message ID `901ab1e8-a146-55ef-a995-d391dd612a29`. |
| Receive probe | `aws sqs receive-message` on `bootstrap-test-operations-alerts` returned message ID `06e63d7f-bd7e-448f-a91c-46850ce69104` containing test ID `wa-alert-route-test-2026-05-09T173000Z`. |
| Cleanup | The probe message was deleted from the queue after validation. |

A synthetic EventBridge event with AWS service source `aws.backup` was rejected
with `NotAuthorizedForSourceException`, so EventBridge-to-SNS coverage remains
validated by live rule/target metadata and Pulumi component tests rather than
service-event injection.

## Human Consumption Route

Operations alerts are consumed by the scheduled
`.github/workflows/operations-alert-triage.yml` workflow. The workflow loads the
fixed `vilnacrm-org/bootstrap-infrastructure/test` AWS Secrets Manager CI secret, assumes the
dedicated test account operations alert triage role through GitHub OIDC, reads
metadata-only messages from `bootstrap-test-operations-alerts`, and writes
sanitized GitHub issue records in `VilnaCRM-Org/bootstrap-infrastructure`.

The issue body includes an `operations-alert:fingerprint=<hash>` marker built
from stable event fields such as source, detail type, state, backup vault,
backup plan, backup rule, and resource ARN. Repeated notifications for the same
underlying route update the open canonical issue with a comment instead of
creating duplicate issues. The workflow deletes SQS messages only after the
GitHub issue create or comment operation succeeds. It must not write raw alert
payloads, stack exports, credentials, tokens, or private incident notes to
GitHub.

Legacy operations-alert issues that predate the fingerprint marker are not
automatically absorbed by the search query. Treat the first post-merge
fingerprinted issue as the canonical record for that alert stream, then link
and close older duplicate issues only after an SRE confirms the sanitized
events share the same underlying AWS Backup state, vault, plan or rule, and
protected resource. A comment on a legacy issue is not enough for future
workflow dedupe because the workflow searches issue bodies for the marker.
If the original SQS messages were already drained and no new matching alert
arrives, use the manual **Operations Alert Canonical Backfill** workflow to
create or update the canonical fingerprinted issue from SRE-confirmed stable
fields before running legacy reconciliation. The backfill workflow runs behind
the same `operations-alert-reconcile` GitHub Environment, requires an HTTPS
`sre_confirmation_reference`, accepts one `stable_event_json` object containing
the confirmed EventBridge `source`, `detailType`, `state`, `resourceArn`,
optional AWS Backup stable fields, optional `detail`, and optional `resources`,
and requires this exact confirmation sentence:

```text
I confirm these stable fields represent the canonical operations alert stream
```

After SRE confirmation, use the manual **Operations Alert Legacy Reconcile**
workflow to close legacy duplicates. The workflow requires a canonical issue
whose body already contains `operations-alert:fingerprint=`, accepts only
unmarked open `Operations alerts queued:` issues as legacy duplicates, requires
an HTTPS SRE confirmation reference, and uses GitHub duplicate closure
semantics. It runs behind the
`operations-alert-reconcile` GitHub Environment so repository administrators can
require SRE or reviewer approval before any duplicate closure. It does not
request AWS or GitHub OIDC credentials; it only writes issue comments and
duplicate closures.

The workflow confirmation input must exactly match this sentence, and the
`sre_confirmation_reference` input must point to the sanitized SRE confirmation
comment or ticket. Do not put raw alert payloads, credentials, stack exports,
tokens, or private incident notes in that referenced record.

```text
I confirm these legacy issues match the canonical operations alert stream
```

The shared Pulumi automation role carries an explicit deny for alert-queue
`sqs:ReceiveMessage` and `sqs:DeleteMessage`; only the dedicated triage role
may drain alert messages.

The durable SQS queue remains the delivery buffer and fallback path; GitHub
issues are the human review route for maintainers.

## Queue Consumption Metadata

A non-secret route metadata refresh on 2026-05-10 UTC confirmed that the
repository-owned durable queue exists. The scheduled GitHub issue triage
workflow provides the human consumption route, while queue depth remains
volatile observation metadata:

| Check | Result |
| --- | --- |
| SNS topic | `arn:aws:sns:eu-central-1:891377212104:bootstrap-test-operations` reports one confirmed subscription and a KMS key. |
| Subscription | The confirmed subscriber protocol is `sqs`, endpoint `arn:aws:sqs:eu-central-1:891377212104:bootstrap-test-operations-alerts`. |
| Queue | `bootstrap-test-operations-alerts` resolved to an SQS queue URL in `eu-central-1`. |
| Queue depth | Current visible, not-visible, and delayed counts are captured by the collector and generated observation records as observation-only metadata. Read the latest counts from `.artifacts/well-architected/evidence.json` instead of hard-coding them in retained review docs. |
| Queue retention | `MessageRetentionPeriod=345600` and `VisibilityTimeout=30`. |

The visible queue depth is useful operating evidence when it shows why a
maintainer issue route is required, but it is volatile. It is not sufficient
OPS8 evidence by itself: SRE still needs to retain the scheduled workflow
history, generated GitHub issues, or a current fallback observation record.

## Monthly Observation Record

The `Well-Architected Evidence` workflow now runs on pull requests, pushes to
`main`, manual dispatch, and a monthly schedule on the ninth day of the month.
Scheduled runs remain advisory even if evidence enforcement is enabled, upload
the metadata-only evidence bundle, and retain the artifact for 90 days. The
separate operations alert triage workflow creates GitHub issues from queued
alert metadata every 30 minutes. Mixed SQS batches are split by stable alert
stream before GitHub issue search/create/comment operations, so unrelated
streams do not collapse into one duplicate marker. Legacy issues without the
`operations-alert:fingerprint=` marker still require SRE confirmation and an
HTTPS `sre_confirmation_reference` before backfill or closure.

After a scheduled or manual collector run, SRE can render a dated observation
record from `.artifacts/well-architected/evidence.json`:

```bash
ALERT_ROUTE_OBSERVATION_OUTPUT=docs/alert-route-observation-YYYY-MM-DD.md \
ALERT_ROUTE_OBSERVATION_JSON_OUTPUT=docs/alert-route-observation-YYYY-MM-DD.json \
ALERT_ROUTE_REVIEWER='<reviewer or team>' \
ALERT_ROUTE_OWNER='SRE' \
ALERT_ROUTE_DOWNSTREAM='<ChatOps, ticketing, paging, or approved queue-owner process>' \
ALERT_ROUTE_SEVERITY='<severity and response expectation>' \
ALERT_ROUTE_FALLBACK='<fallback when the downstream route is unavailable>' \
ALERT_ROUTE_DECISION='accepted' \
ALERT_ROUTE_EXPIRY_DATE='YYYY-MM-DDTHH:MM:SSZ' \
ALERT_ROUTE_ACTION='<non-secret evidence and remediation note>' \
make report-alert-route-observation

ALERT_ROUTE_OBSERVATION_EVIDENCE=docs/alert-route-observation-YYYY-MM-DD.json \
make report-well-architected-evidence
```

The generated record includes SNS/SQS route metadata, queue depth, retention,
visibility timeout, downstream route, severity expectations, fallback behavior,
review decision, and follow-up actions. JSON output can be supplied back to the
collector through `ALERT_ROUTE_OBSERVATION_EVIDENCE`; the collector validates
approval, freshness, expiry, evidence/remediation notes, and exact stable
SNS/SQS route metadata while treating queue depth as observation-only data. It
intentionally omits message
payloads, private incident notes, stack exports, credentials, tokens, and
access-key material. OPS8 should stay below 5/5 until a real observation file
exists with an approved downstream route or accepted queue-owner process and
the monthly history is current.
When JSON output is requested, the generator also fails before writing if
`ALERT_ROUTE_EXPIRY_DATE` is missing, invalid, or expired, if the review date is
stale or future-dated, or if the decision value is outside the collector's
accepted values.

## Fallbacks

- Keep OPS8 and human-escalation claims below 5/5 until the downstream human
  alert route or incident tool is recorded with owner, target, and test
  evidence.
- Use `docs/incident-drill-evidence-2026-05-09.md` for the current OPS10 and
  REL6 drill evidence. Keep REL6 below 5/5 when future resource-specific metric
  coverage is stale or incomplete, including future replica-lag, runtime, or
  public-endpoint metrics.
- Add a new row before merging any new alert source, metric alarm, dashboard,
  downstream subscriber, runtime compute, or public endpoint.


### Fingerprint version 2 cutover (2026-09-06 source correction)

The reviewed renderer now hashes versioned, canonical JSON of the **complete**
stable event fields. Display sanitization (backticks/newlines and the 200-character
field limit) no longer changes hash input. Volatile occurrence identifiers stay
excluded. The grouped metadata reports `fingerprintVersion: 2`; the issue marker
remains `operations-alert:fingerprint=<24-hex-digest>` for workflow compatibility.
All earlier version-1 stream hashes change, including short events. This source
change does not claim that existing issues were migrated or redelivery QA passed.

Before enabling the corrected triage workflow, the SRE must reconcile each existing
canonical issue using independently verified full stable event metadata, record
its v1-to-v2 mapping and evidence, and update/backfill the intended canonical record
through the protected procedure. A v1 hash alone cannot identify the right stream:
the old truncation could merge distinct events. Do not automatically fall back to
v1 markers or close duplicates solely by matching old hashes. If the full stream
identity is unavailable, retain that uncertainty and create a distinct v2 record
rather than falsely claiming continuity. After the reviewed cutover, verify a real
allowed alert and its redelivery update the intended v2 issue, while a different
stable field after character200 produces a different stream. No live migration
or notification is performed by the local tests.

Large batches show the first10 sanitized occurrences, total message count and
explicit omitted count, keeping even four-byte Unicode metadata below the body
size budget. Omitted IDs are not claimed to appear in an uploaded artifact. The
workflow must still create/update the issue successfully before deleting the full
processed SQS group. Counted omission is display policy, not proof that an incident
was resolved or that all occurrences were individually investigated.

### Typed backup classification before acknowledgment

The EventBridge backup rule is a conservative first filter. AWS's
`TestEventPattern` API confirms that `anything-but: ""` also matches null; nested
conditions on the same field do not provide a reliable string-type conjunction.
The triage consumer therefore validates Backup, Copy, and Restore job events
before deciding whether they need an issue or can be acknowledged as benign.
This is a staged filter contract, not a claim that the EventBridge pattern alone
excludes every malformed event.

The trusted CI configuration supplies `OPERATIONS_TOPIC_ARN`. For known backup
job events, the consumer requires that exact SNS Notification topic, the expected
account and region, event and job identifiers, message IDs, a valid receipt,
and scalar `state`/`status` fields that agree when both are present. A completed
job with absent, null, or empty-string `statusMessage` is benign. A nonempty
string (including whitespace) is actionable, as are FAILED, ABORTED, and EXPIRED
states. Nonstring messages, malformed metadata, conflicting states, unexpected
job states, and duplicate receipt handles are quarantined. Here quarantine means
retaining the existing SQS message for investigation; no new queue or automatic
redrive is implied. Unknown and nonbackup alerts retain their existing issue and
fingerprint behavior when their receipt is valid.

The workflow first creates or updates every actionable issue. It then publishes
a sanitized classification artifact containing only message hashes, dispositions,
and fixed reason codes. Receipt handles and event payloads stay in private runner
files. Only successful issue handling **and** successful audit upload permit the
later deletion step to use the explicit acknowledgment allowlist. No quarantined
receipt appears in that allowlist. Any quarantine leaves the workflow failed and
visible after the safe receipts are acknowledged. Failure to publish the audit
or create an issue prevents all acknowledgment in that run.

The seven-day artifact is a classification record, not evidence of successful
backup, restore, rule deployment, or SNS/SQS delivery. The local integration test
executes the actual acknowledgment shell against a local AWS stub and proves that
only actionable and validated-benign receipts are selected; it performs no live
queue or issue operations. Actual end-to-end acceptance still requires the
reviewed consumer to be deployed and observed through the authorized workflow.
