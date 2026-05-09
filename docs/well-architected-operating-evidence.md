# Well-Architected Operating Evidence

This register is the repository-owned evidence bundle for the bootstrap
infrastructure Well-Architected review on 2026-05-09. It records current
owners, review cadence, fallback actions, and non-secret evidence locations for
controls that can be owned in this repository.

This file does not override administrator-owned GitHub settings, payer-account
billing settings, security account services, or production environment
approval. Those remain external controls and must be proven by metadata or
owner attestations before any final 5/5 claim.

## Evidence Metadata

| Field | Value |
| --- | --- |
| Workload | `bootstrap-infrastructure` |
| Review date | 2026-05-09 |
| Repository owner | `platform-maintainers` |
| Primary environment | `test` |
| Production state | No production approval evidence is accepted until the `prod` GitHub environment exists and requires reviewers. |
| Secret safety | Public repository artifact; do not add stack exports, decrypted Pulumi config, tokens, keys, or private incident details. |

## Owner Registry

| Control area | Accountable | Responsible | Evidence cadence | Fallback when stale or missing |
| --- | --- | --- | --- | --- |
| Priority, risk, and tradeoff register | `platform-maintainers` | Maintainer | Quarterly and before major infrastructure changes | Keep affected question below 5/5 and require maintainer review before merge. |
| CI guardrails and branch protection | `platform-maintainers` | Platform owner | Per workflow or ruleset change | Treat PR as not merge-ready until required checks and reviewer rules are proven by GitHub metadata. |
| Operations alerts, runbooks, KPI review, and ORR | SRE | SRE | Monthly, plus before 5/5 reviews | Use `docs/alert-routing-evidence.md`; keep affected claims capped until inventory, route, owner, runbook, and test evidence are current. |
| Security controls, threat model, and incident response | Security reviewer | SRE | Quarterly and per IAM or detection change | Use `docs/security-operating-evidence.md`; keep Security claims capped when external security exceptions are open. |
| Backup, restore, drift, and DR | SRE | SRE | Monthly backup review; quarterly restore or DR drill | Treat restore or DR readiness as stale after 90 days without a successful drill. |
| Cost controls and transfer review | FinOps owner | Maintainer | Monthly and per catalog expansion | Block Cost Optimization 5/5 claims until thresholds, reports, and payer-account tag evidence are current. |
| Performance and capacity review | Platform owner | Maintainer | Monthly and per catalog expansion | Require remediation issue for missed SLOs before adding durable fanout. |
| Workload applicability and dependency inventory | Maintainer | SRE and security reviewer | Quarterly and per new runtime, network, or dependency path | Use `docs/workload-applicability-evidence.md`; block affected 5/5 claims until scope, owners, and future gates are refreshed. |
| Sustainability governance | `platform-maintainers` | Platform owner | Quarterly and per region or retention change | Block sustainability score increases until owner, KPI, and exception records are refreshed. |

## Priority And Risk Register

| Priority | Business outcome | Risk controlled | SLO or SLA impact | Tradeoff | Owner | Review cadence |
| --- | --- | --- | --- | --- | --- | --- |
| P0 | Preserve infrastructure state and logs. | State loss, log loss, unrecoverable deployment drift. | RPO is one daily AWS Backup recovery point plus S3 versioning; RTO target is one business day for non-production bootstrap state. | Cross-region replication and backups add cost and operational evidence requirements. | SRE | Quarterly and after restore drills. |
| P0 | Keep infrastructure changes reviewable and reversible. | Accidental destructive apply or IAM blast-radius expansion. | Same-repo PRs must have preview, destructive diff, IAM validation, policy, and security gates before merge. | Slower merge path for infrastructure changes. | Maintainer | Per workflow or ruleset change. |
| P1 | Detect control-plane risk events. | Missed backup, KMS, IAM/OIDC, or S3 control-plane changes. | SEV1/SEV2 events route to the operations topic and durable SQS queue. | Human escalation remains external until downstream route is confirmed. | SRE | Monthly alert-route review. |
| P1 | Bound account spend and durable resource fanout. | Budget surprise, quota pressure, stale repositories. | PRs must pass static fanout and preview cost-proxy thresholds. | Static proxy is conservative and does not replace FinOps review. | FinOps owner | Monthly and per catalog expansion. |
| P2 | Prefer managed and serverless control-plane services. | Idle compute, patch toil, avoidable emissions. | No always-on runtime compute is provisioned by this repository. | Managed services can limit low-level tuning options. | Platform owner | Quarterly. |

## Operational Readiness Record

| Readiness item | Current evidence | Status | Fallback |
| --- | --- | --- | --- |
| Repository owner and RACI | This file and `docs/sre-operations.md`. | Current for repository-owned controls. | If owners are disputed, keep affected scores below 5/5. |
| Local validation | `make ci-pr-unprivileged` passed on 2026-05-09 after the account security-control changes. | Current local signal. | Hosted GitHub checks are still required before merge readiness. |
| AWS identity and metadata collector | `make report-well-architected-evidence` collector output passed identity, alert topic, CloudTrail, restore, and fanout checks on 2026-05-09. | Current metadata signal. | Re-run after every new push or account change. |
| Branch protection | Collector reports zero required status checks. | Blocked. | Repository admin must update the active ruleset. |
| Production approval | `gh api repos/.../environments/prod` returns 404; `prod-preview` has no protection rules. | Blocked. | Create protected `prod` environment with required reviewers before production claims. |
| Security account services | Repository code now provisions GuardDuty, Security Hub, AWS Config recorder, and the Config delivery bucket; `docs/security-operating-evidence.md` records identity, permission, wildcard, boundary, and exception evidence; live account evidence remains pending until apply. | Blocked. | Security owner must enable or formally exempt these account controls and retain post-apply evidence. |
| Data protection and recovery | `docs/data-protection-recovery-evidence.md` records at-rest protection, Vault Lock/Object Lock posture, restore runbook, backup review cadence, and degraded-mode playbooks. | Current for repository-owned SEC8 and REL9 evidence. | Refresh before storage, backup, KMS, retention, or replica changes. |
| Alert and monitoring inventory | `docs/alert-routing-evidence.md` records live EventBridge rules, SNS targets, absence of runtime alarms/dashboards, SNS-to-SQS probe evidence, owners, runbooks, and fallback rules. | Current for repository-owned observability inventory. | Refresh monthly and before adding alert sources, dashboards, runtime compute, or public endpoints. |
| Current operating review | `docs/operating-review-2026-05-09.md` records KPI observations, demand/stale asset review, service review, cost-of-effort notes, improvement actions, and sustainability governance. | Current for repository-owned review-loop evidence. | Refresh monthly for KPIs and quarterly for sustainability/service review. |
| Region sustainability | `docs/region-sustainability-evidence.md` records the primary/replica region decision matrix, service availability, residency, latency, transfer impact, recovery rationale, sustainability posture, and exception path. | Current for repository-owned SUS1 evidence. | Refresh before region, replica, residency, or replicated-data changes. |
| Fault isolation | `docs/fault-isolation-evidence.md` records per-repository state, KMS, OIDC, environment, automation, and replication boundaries with test evidence. | Current for repository-owned REL10 evidence. | Refresh before IAM, state, KMS, catalog, or environment changes. |

## KPI And Review Register

| KPI | Target | Current observation | Owner | Cadence | Fallback |
| --- | --- | --- | --- | --- | --- |
| Backup health | No unresolved failed, aborted, or expired protected-resource jobs. | Collector found one completed restore job in the last 90 days. | SRE | Monthly | Open SEV2 follow-up for failed jobs. |
| Restore drill freshness | Latest non-production drill no older than 90 days. | Restore job `d7f25510-1dfd-4f11-8953-72ed1c971c2c` completed on 2026-04-27 and cleanup is confirmed. | SRE | Quarterly | Reliability score stays below 5/5 after 90 days without a fresh drill. |
| Drift freshness | Shared-stack drift evidence no older than 24 hours. | Local `make test-drift` previously passed with `86 unchanged`; hosted run is queued. | SRE | Daily for shared stacks | Treat merge readiness as blocked when hosted drift evidence is absent for apply paths. |
| Guardrail health | Same-repo required checks pass and are not skipped. | Local unprivileged battery, real test preview, destructive gate, cost proxy, and IAM validation passed; hosted checks remain queued. | Maintainer | Per PR | Do not merge until hosted checks pass or admin records a temporary exception. |
| Saved-plan integrity | Apply jobs use the exact reviewed Pulumi plan. | `make pulumi-plan` writes a manifest with stack, backend, commit SHA, preview hash, and plan hash; `make pulumi-up-plan` rejects missing, stale, mismatched, or tampered manifests. | Maintainer | Per deploy workflow change | Do not apply from a saved plan when manifest validation fails; regenerate preview and plan from the intended commit. |
| Alert route freshness | Operations SNS route has a subscription, inventory, and route test. | `docs/alert-routing-evidence.md` records four enabled EventBridge rules, SNS targets, no runtime alarms/dashboards, and a successful SNS-to-SQS probe; downstream human route remains external. | SRE | Monthly | Keep organizational consumption and escalation claims below 5/5 until downstream route is confirmed. |
| Cost alert readiness | Budget and anomaly thresholds reviewed in the last 30 days. | Budget and anomaly resources exist; FinOps approval and monthly report are missing. | FinOps owner | Monthly | Keep cost questions below 5/5. |
| Catalog demand | Active repositories have owner, lifecycle state, last-reviewed date, and expected environments. | `pulumi/repositories.bootstrap.json` passes catalog and fanout validation. | Maintainer | Monthly | Block catalog expansion when metadata is stale or thresholds are exceeded. |
| Quota headroom | Projected bootstrap fanout stays within live or default service quotas. | `quota-headroom-evidence-2026-05-09.json` records count-only AWS usage, Service Quotas values, projected count, and remaining headroom. | SRE | Per catalog change | Block merge when projected usage exceeds quota, leaves no CloudTrail slot, or lacks an owner-approved reduction or quota plan. |
| Sustainability posture | Region, retention, idle-compute, and CI efficiency choices have a current review. | Region rules are documented here; data classes and retention are documented in `docs/data-classification-retention.md`; no always-on runtime compute exists. | `platform-maintainers` | Quarterly | Keep sustainability score below 5/5 if this register is older than one quarter. |

## Runbooks And Playbooks

| Scenario | First checks | Recovery or fail-forward path | Evidence to retain |
| --- | --- | --- | --- |
| Failed preview or destructive diff | Inspect the matching GitHub job, run `make test-guardrails-unprivileged`, then run privileged preview only with approved OIDC metadata. | Fix code, remove destructive action, or add `allow-destructive-infra-change` only after review. | Workflow URL, head SHA, preview summary, label state, reviewer. |
| Failed IAM validation | Run `make test-iam-validation-unprivileged`; when AWS credentials are approved, run `make test-iam-validation`. | Narrow policy statements or document unavoidable wildcard/list actions with owner approval. | IAM input artifact, Access Analyzer finding summary, policy diff. |
| Saved plan rejected before apply | Inspect `.artifacts/pulumi-plan/manifest.json`, the selected stack, backend URL, expected commit SHA, manifest age, and plan hash. | Regenerate `make pulumi-plan` from the intended commit and rerun destructive diff and IAM validation before applying. | Manifest path, rejected field, workflow URL, commit SHA, regenerated preview summary. |
| State bucket unavailable | Verify AWS identity, S3 bucket metadata, KMS key state, and CloudTrail events without reading object contents. | Fail forward by restoring access policy or restoring state into an isolated location from backup. | Bucket name, KMS alias, CloudTrail event IDs, restore evidence path. |
| Replica lag or replica unavailable | Check S3 replication configuration and replication metrics when available. | Keep primary state read-only until lag is understood; restore from primary or backup if replica is unusable. | Bucket names, replication rule IDs, last successful backup, owner decision. |
| KMS key disabled or pending deletion | Describe the key and alias; inspect CloudTrail for actor and action. | Cancel unintended deletion, re-enable the key, or restore from backup under security owner direction. | Key ARN or alias, CloudTrail event, containment owner, follow-up issue. |
| Backup failure | Check AWS Backup job state, vault, plan, and EventBridge alert metadata. | Schedule a fresh backup or restore drill after root cause is fixed. | Job ID, vault name, plan name, remediation owner. |
| Compromised OIDC trust or deploy role | Inspect IAM role trust policy, GitHub workflow ref/environment, and recent CloudTrail IAM events. | Disable or narrow the affected role, rotate any exposed credentials if static keys were involved, and require security review before re-enable. | Role name, trust-policy diff, CloudTrail event, reviewer. |
| Production apply request | Verify the reviewed commit SHA, successful test deploy on `main`, production preview, saved-plan manifest, destructive diff, IAM validation, and protected environment approval. | Do not apply until `prod` environment approval, reviewed SHA, and saved-plan manifest all match. | Environment approval metadata, workflow URL, commit SHA, approver, plan manifest hash evidence. |

## Decision Matrices

### Network Applicability

This repository currently provisions no VPC, load balancer, WAF, listener,
public endpoint, or runtime network plane. Network questions are therefore
handled as conditional controls. Any future VPC or public endpoint change must
add subnet, route, flow-log, TLS, ingress, WAF, and private-access evidence in
the same PR.
The current applicability statement and dependency inventory are retained in
`docs/workload-applicability-evidence.md`.

### Compute Applicability

This repository provisions no always-on runtime compute. Compute-adjacent
surfaces are GitHub Actions runners and the optional ECR runner repository,
which currently has no image inventory. Future always-on compute must include a
utilization target, image vulnerability SLA, patch cadence, autoscaling or
shutdown behavior, and owner-approved exception.
The no-idle-compute rule for future service selection is retained in
`docs/workload-applicability-evidence.md`.

### Region And Sustainability

| Region role | Current value | Rationale | Open evidence |
| --- | --- | --- | --- |
| Primary | `eu-central-1` | Existing test-account region and committed stack config. | Owner-approved compliance and latency rationale. |
| Replica | `eu-west-1` | Allowlisted paired region for state and logging replicas. | Transfer-cost and sustainability comparison. |

Region changes must compare compliance, service availability, latency, data
transfer cost, sustainability inputs, and recovery objectives before merge.
The current region decision matrix is retained in
`docs/region-sustainability-evidence.md`.

### Storage, Retention, And Transit

| Data class | Current controls | Retention or lifecycle | Open evidence |
| --- | --- | --- | --- |
| Pulumi state | S3 versioning, encryption, TLS-only bucket policy, backup, replica bucket. | Noncurrent expiration is configured by stack code. | Vault Lock or exemption and restored-state runbook. |
| Central logs | S3 encryption, logging controls, lifecycle transition, replica bucket. | Primary logs transition to lower-cost storage. | Replica lifecycle rationale and monthly growth trend. |
| Backups | AWS Backup vault, plan, and restore drill evidence. | Backup retention is managed by the stack. | Recurring audit cadence and Vault Lock decision. |
| ECR images | Immutable tags, scan-on-push, lifecycle cap. | Old images are cleaned by lifecycle policy. | Scan result review and remediation SLA. |
| Optional runner image | `docs/compute-runner-evidence.md` records live ECR metadata, stale vulnerable image deletion, and empty current inventory. | Scan-on-push is enabled, tags are immutable, and no deployable image remains. | Fresh scan with no unaccepted critical/high findings or a security-owner exception before any future image is used. |
| CI artifacts | GitHub artifact retention and sanitized summaries. | Workflow-defined retention. | Production preview artifact retention review. |

All current repository data paths are S3 or GitHub artifact paths and must
enforce TLS in transit. Future public endpoints must document TLS listener
policy, certificate ownership, WAF or ingress posture, and monitoring.
At-rest protection and recovery decisions are retained in
`docs/data-protection-recovery-evidence.md`.

### Cost And Demand

| Control | Current repository evidence | Action threshold |
| --- | --- | --- |
| Monthly budget | `monthlyBudgetName` and collector `aws_cost_controls` pass. | FinOps owner reviews at least monthly and after threshold changes. |
| Cost anomaly detection | Existing monitor ARN and subscription evidence exist. | Immediate anomaly alerts above configured threshold require SEV2 triage. |
| Static fanout | Repository fanout thresholds pass. | Catalog expansion that exceeds thresholds requires owner approval. |
| Data transfer | Cross-region replication exists. | Add GB/month estimate before increasing replicated data classes or regions. |
| Stale assets | Catalog has owner, lifecycle state, and last-reviewed metadata. | Deprecated or archived entries require cleanup issue before adding more durable fanout. |

### Performance Efficiency

| Metric | Target | Evidence source | Fallback |
| --- | --- | --- | --- |
| PR local battery | Completes without manual intervention. | `make ci-pr-unprivileged` output. | Split slow suites or reduce redundant jobs. |
| Preview duration | Fast enough for PR review without bypass pressure. | GitHub Actions run duration when runners are available. | Investigate plugin cache, stack fanout, and workflow parallelism. |
| Drift duration | Completes within scheduled window. | Drift workflow or `make test-drift`. | Reduce stack scope or split drift checks. |
| Storage growth | Growth reviewed before thresholds or cost alerts fire. | Monthly KPI review and catalog report. | Add cleanup issue or retention change proposal. |
| Data retention posture | Every current artifact class has classification, owner, retention, storage, and deletion rationale. | `docs/data-classification-retention.md`. | Block merge for new data classes until classification and retention evidence exists. |
| Resource and region ADRs | Current resource, storage, region, network, fanout, owner, cadence, validation, and fallback evidence exists. | `docs/performance-operating-evidence.md`. | Block new service families, storage paths, regions, VPCs, or public endpoints until the ADR is updated. |

## Continuous Improvement Loop

Every monthly review should record:

1. KPI observations and missed-threshold actions.
2. Incidents, near misses, and post-incident follow-up owners.
3. Cost, quota, and fanout trend decisions.
4. Security control posture changes or exceptions.
5. Sustainability and retention decisions.
6. Updated Well-Architected evidence paths and expiry dates.

Quarterly reviews must re-check the AWS Well-Architected question set, refresh
question scores, and confirm that external controls are either proven or still
block final 5/5 claims.
The current dated review record is `docs/operating-review-2026-05-09.md`.
