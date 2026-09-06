# Operating Review 2026-05-09

This is the current repository-owned operating review record for the bootstrap
infrastructure Well-Architected evidence refresh. It is a public artifact and
contains only non-secret status, owner roles, review decisions, and follow-up
actions.

## Review Metadata

| Field | Value |
| --- | --- |
| Workload | `bootstrap-infrastructure` |
| Review date | 2026-05-09 |
| Review owner | `platform-maintainers` |
| Participants by role | Maintainer, SRE, security reviewer, platform owner, FinOps owner placeholder |
| Evidence scope | Repository docs, question matrix, local checks, AWS metadata collector, repository catalog, quota headroom, restore drill, and external-control records |
| Fallback | Do not claim final 5/5 while external controls or unresolved question rows remain open. |

## Current No-Go Items

| Item | Owner | Current state | Required action |
| --- | --- | --- | --- |
| GitHub required checks | Repository admin | Active ruleset reports zero required status checks. | Apply documented branch ruleset with exact required check names. |
| Production approval | Repository admin plus SRE | `prod` environment evidence is missing. | Create protected `prod` environment with required reviewers and branch restrictions. |
| Security external attestations | Repository admin plus security reviewer | GuardDuty, Security Hub, and AWS Config are live in the test account after guarded apply and hosted post-apply drift validation. A current IAM metadata refresh still shows IAM users and one active access-key status row, so human MFA/SSO, static-key exception/remediation evidence, permissions-boundary or exemption attestation, and external security-owner approval remain required. Current `main` provides `make report-security-account-attestation` to record that owner decision without exposing private IAM user names or access key IDs. | Record the external security attestations without exposing private user data or keep SEC1/SEC2/SEC3 capped. |
| Default-branch Dependabot alerts | Security reviewer plus maintainer | Current Dependabot metadata reports zero open high or critical default-branch alerts for `uv.lock`; the latest collector passes `github_dependabot_alerts`. | Keep hosted Dependabot evidence current and require closure or exact-alert owner exceptions for any future high or critical alerts. |

## KPI Observations

| KPI | Observation | Decision | Follow-up |
| --- | --- | --- | --- |
| Local static validation | Focused tests, `make verify-well-architected-questions`, and full local `make ci-pr-unprivileged` passed on 2026-05-11 after the latest implementation changes. | Current local evidence is acceptable for the repository-owned code and evidence slice. | Re-run full local CI before merging any further code changes. |
| PR and review state | Collector reports local and PR head match, and hosted checks completed successfully on the current implementation line. Live PR state remains open, unapproved, and `mergeStateStatus=BLOCKED` with reviewer requests outstanding. | Hosted checks are acceptable, but the PR control-plane state is not acceptable for final 5/5 until reviewers approve and admin controls are repaired. | Re-run collector after review approval and admin settings change. |
| Backup and restore | Restore job `d7f25510-1dfd-4f11-8953-72ed1c971c2c` completed on 2026-04-27; cleanup was confirmed on 2026-05-09. | Restore evidence is current until the 90-day freshness window expires. | Schedule next restore drill before 2026-07-26. |
| Alert route | `docs/alert-routing-evidence.md` records four enabled EventBridge rules, SNS targets, no runtime alarms/dashboards, a successful SNS-to-SQS probe, and collector-verified stable SNS/SQS route metadata. Queue-depth counts are retained only as observation metadata in generated collector/observation artifacts. | Repository-owned observability inventory and durable queue route are current; downstream human route or approved queue-owner consumption process remains external. | SRE records downstream route and monthly consumption evidence before OPS8 escalation claims can pass. |
| Runner image vulnerability posture | `docs/compute-runner-evidence.md` records immutable ECR repository metadata, scan-on-push, the vulnerable stale-image scan, and 2026-05-09 deletion of the unused image inventory. | SEC6 is clear for the current no-runtime workload because ECR now has no deployable runner image. | Platform owner must require a clean scan or security-owner exception before any future runner image is used. |
| FinOps readiness | `docs/finops-review-2026-05-09.md` records active cost allocation tags, `100 USD` monthly budget, 80% actual and 100% forecast alerts, `10 USD` anomaly threshold, SNS route, month-to-date service cost, and transfer thresholds. | Cost Optimization evidence is current for the single-repository test workload. | Refresh by 2026-06-09 or before production approval, catalog growth, region, retention, or replicated-data changes. |
| Incident and DR drill | `docs/incident-drill-evidence-2026-05-09.md` records completed backup jobs, enabled state/log replication rules, replica parity samples, KMS/IAM/OIDC/logging/backup/workflow scenarios, and degraded-mode decisions. | Repository-owned incident and DR exercise evidence is current until the quarterly freshness window expires. | Schedule next incident/DR drill before 2026-08-07. |
| Catalog demand | `pulumi/repositories.bootstrap.json` has one active repository, owner `platform`, last reviewed 2026-04-27, and two expected environments. | No stale or deprecated catalog entries require cleanup in this review. | Refresh catalog ownership by 2026-05-27 or before expansion. |
| Quota headroom | Quota evidence records projected bootstrap fanout within quota or repo thresholds, with CloudTrail and AWS Config no-go notes. | Catalog expansion is allowed only while projected counts remain within no-go rules. | Refresh quota evidence before adding repositories or account-level resources. |
| Performance | No always-on runtime compute exists; current hosted check evidence covers Preview, IAM Validation, Destructive Diff Gate, Local Battery, security scans, and quality gates. | Performance model and resource ADRs are current. | Refresh queue/run-time observations monthly and per workflow change. |
| Sustainability | Current workload uses managed services, lifecycle controls, data retention, no idle compute, and catalog demand metadata. | Sustainability posture is current for repository-owned controls. | Refresh quarterly or before region, retention, or compute changes. |

## Priority And Tradeoff Decisions

| Priority | Decision | Rationale | Owner | Next review |
| --- | --- | --- | --- | --- |
| P0: safe changes | Keep saved-plan manifest enforcement, destructive diff, IAM validation, and branch-protection proof as merge gates. | Prevents unreviewed apply, stale plan, and destructive-change risk. | Maintainer | Per workflow change |
| P0: recover state and logs | Keep AWS Backup, S3 versioning, replication, restore drills, and metadata-only validation. | State/log recovery is the primary availability objective for this control-plane workload. | SRE | Monthly backup review |
| P1: account detection | Keep CloudTrail, EventBridge, SNS/SQS, GuardDuty, Security Hub, and AWS Config evidence requirements. | Detection coverage is now proven for the test account and must stay fresh before final security claims. | Security reviewer plus SRE | Monthly after apply |
| P1: bound growth | Keep catalog metadata, fanout checks, cost proxy, and quota evidence as expansion gates. | New repositories multiply durable resources and quota pressure. | Maintainer plus FinOps owner | Per catalog change |
| P2: reduce idle work | Keep managed/serverless-first and no-idle-compute rule. | The workload has no user traffic path and should not add patching or idle capacity. | Platform owner | Quarterly |

## Learning And Improvement Record

| Observation | Action taken | Outcome | Next action |
| --- | --- | --- | --- |
| Saved plans needed stronger apply integrity. | Added plan manifest hash, commit, stack, backend, preview hash, and stale-plan validation. | REL4 passed. | Preserve tests for future workflow changes. |
| Account security services needed concrete implementation evidence. | Added GuardDuty, Security Hub, AWS Config recorder/delivery, guarded local apply evidence, live metadata checks, and no-drift validation. | SEC4 is supported for the test account; default-branch Dependabot alert closure is now verified; remaining Security blockers are human/admin attestations. | Refresh live posture monthly and close the remaining external security attestations. |
| Quota and catalog growth needed current headroom evidence. | Added metadata-only quota headroom report and no-go rules. | REL1 passed. | Refresh before catalog expansion. |
| Data classes and retention were implicit. | Added data classification and retention matrix. | SUS4 passed and SEC7 improved. | Update before new data classes. |
| Performance, applicability, and data-protection decisions were scattered. | Added performance, workload applicability, and data-protection evidence. | PERF1, PERF3, PERF4, SEC5, SEC8, SEC9, REL2, REL3, REL9, and SUS5 passed. | Keep these docs current per service change. |
| Incident and DR scenarios needed current exercise records. | Added metadata-only scenario drill evidence for state, replica, KMS, IAM/OIDC, logging, backup, and workflow failures. | OPS10, SEC10, REL5, REL6, REL11, and REL12 passed for repository-owned scope. | Repeat quarterly and before production approval. |

## Demand, Decommission, And Stale Asset Review

| Asset | State | Demand signal | Cleanup decision | Evidence |
| --- | --- | --- | --- | --- |
| `bootstrap-infrastructure` managed repository | Active | Two expected environments are recorded for bootstrap test/prod paths. | Retain. | `pulumi/repositories.bootstrap.json` |
| Deprecated repositories | None in current catalog. | No stale entries found. | No cleanup issue required. | `make test-repository-fanout` |
| Ephemeral local artifacts | `.artifacts/` ignored and regenerated by checks. | Local evidence only. | Do not commit generated artifacts. | `.gitignore`, collector output |
| AWS durable resources | State, logs, backup, alerts, cost, security controls. | Required for bootstrap control plane. | Destroy only through reviewed Pulumi workflow with backup/restore evidence. | `docs/sre-operations.md` |

Decommission rule: any future repository with `deprecated` or `archived`
lifecycle state must have an owner decision, backup/restore impact review,
destroy safety check, and follow-up date before new durable fanout is added.

## Cost And Service Review

| Service family | Current decision | Cost and effort note | Follow-up |
| --- | --- | --- | --- |
| S3 state/log/config buckets | Use managed object storage with lifecycle, replication, versioning, and backup. | Low operational effort and no server maintenance; cross-region replication adds transfer/storage cost accepted for recovery. | Add monthly GB trend before increasing replicated data classes. |
| KMS | Use per-repo secrets keys and dedicated keys for alerting/CloudTrail paths. | Adds key inventory but keeps secret and audit encryption ownership explicit. | Revisit if key count approaches quota or ownership changes. |
| AWS Backup | Use managed daily backups and quarterly restore drills. | Avoids custom backup workers; restore drill effort is planned quarterly. | Review Vault Lock exemption before production approval. |
| EventBridge/SNS/SQS | Use managed event routing and durable queue subscription. | Avoids polling compute; live inventory and SNS-to-SQS test are current; downstream human route still external. | SRE records downstream route owner. |
| Budgets and Cost Anomaly Detection | Use account-level budget/anomaly metadata through operations topic. | Provides spend guardrails; current thresholds, active tags, monthly cost, and transfer evidence are recorded in the FinOps review. | Refresh by 2026-06-09 or before production approval and catalog expansion. |
| GuardDuty/Security Hub/AWS Config | Use managed account security services. | Adds account-level resources but avoids custom security inventory workers; guarded local apply and no-drift validation proved current test posture. | Refresh metadata monthly and after detector, hub, recorder, delivery, or region changes. |
| GitHub Actions | Use hosted runners and Dockerized toolchain. | Avoids idle self-hosted compute; the hosted check suite has completed for the current implementation line without requiring idle self-hosted capacity. | Review queue/run time monthly and per workflow change. |

Cost-of-effort decision: this PR favors managed services and repository
evidence over custom workers. The implementation adds durable account controls
but reduces manual audit, restore, security, and cost-review effort. No
additional always-on compute is accepted in this review.

## Performance And CI Efficiency Review

| Area | Observation | Target | Follow-up |
| --- | --- | --- | --- |
| Local docs/evidence validation | Ruff, JSON consistency, and repository fanout passed for docs-only evidence updates. | Keep docs-only checks fast enough to avoid bypass pressure. | Use full local CI before code changes. |
| Hosted checks | The latest collector and hosted-check refresh confirm the PR head completed same-repo Preview, IAM Validation, Destructive Diff Gate, Local Battery, mutation, quality, security, and dependency checks. | Hosted compute evidence is acceptable for PERF2 in this review. | Platform owner watches hosted queue and evaluates workflow split if queue delay becomes persistent. |
| Workflow redundancy | No new CI jobs were added by the docs/evidence slices. | Avoid duplicate scans or previews. | Review CI matrix before adding future checks. |
| Artifact retention | Saved plans and preview artifacts are short-lived and hash-verified. | Keep enough evidence for review without retaining secret-bearing artifacts. | Preserve manifest checks for apply workflows. |

## Sustainability Governance Review

| Control | Current decision | Exception process |
| --- | --- | --- |
| Region selection | Primary `eu-central-1`, replica `eu-west-1`, with future changes requiring compliance, latency, transfer-cost, and sustainability review. | Region exceptions require SRE and sustainability owner approval. |
| Data retention | Data classification and retention matrix is current for state, logs, Config snapshots, backups, replicas, ECR, CI artifacts, saved plans, cost metadata, evidence, and local config. | New data classes must update retention before merge. |
| Compute | No always-on runtime compute is provisioned. | Always-on compute requires utilization, scaling/shutdown, owner, patch, cost, and sustainability evidence. |
| CI efficiency | No redundant jobs added in this evidence pass; hosted queue/run time is retained as an external capacity signal. | CI expansion requires target runtime and duplication review. |
| Demand | Catalog has one active repository with owner and expected environments. | Expansion requires owner, lifecycle state, expected environments, fanout, quota, and stale-asset review. |

Next quarterly sustainability review is due by 2026-08-07 or before any region,
retention, compute, or catalog expansion change.

## Alert Cutover Source Amendment (2026-09-06)

This May observation remains historical. The successor source groups alerts by
complete stable fingerprint-v2 metadata and displays the first 10 occurrences
with an omitted count. See [alert routing evidence](alert-routing-evidence.md)
for the v1-to-v2 mapping and protected `Operations Alert Canonical Backfill` /
`Operations Alert Legacy Reconcile` procedures. Record stable SNS/SQS route metadata;
queue depth remains observation-only metadata, never a durable readiness gate.
This amendment does not refresh any dated external-control result.
