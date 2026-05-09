# Performance Operating Evidence

This file records repository-owned performance evidence for the bootstrap
infrastructure workload. The workload is a control-plane repository: it does
not serve user traffic, run an application fleet, or own a VPC. Performance
evidence therefore focuses on resource selection, storage access patterns,
region/network choices, CI control-plane latency, and scaling limits for
repository fanout.

## Evidence Metadata

| Field | Value |
| --- | --- |
| Workload | `bootstrap-infrastructure` |
| Review date | 2026-05-09 |
| Evidence owner | Platform owner for resource selection; SRE for storage, region, and network decisions |
| Freshness | Per AWS service-family change, per catalog expansion, and quarterly for storage or region assumptions |
| Validation sources | `make test-repository-fanout`, `make test-cost-proxy`, `make report-well-architected-evidence`, `quota-headroom-evidence-2026-05-09.json`, and Pulumi component tests |
| Fallback | Keep the affected PERF question below 5/5, block catalog expansion when fanout or quota evidence fails, and require an ADR update before introducing new compute, storage, network, or public endpoint resources. |
| Secret safety | Public repository artifact; includes only resource counts, service choices, owners, and non-secret thresholds. |

## Resource Selection ADR

| Decision | Selected option | Alternatives considered | Performance rationale | Tradeoff | Owner | Review cadence |
| --- | --- | --- | --- | --- | --- | --- |
| Infrastructure state | S3 backend with versioning, replication, lifecycle, and AWS Backup | Pulumi Service, local file backend, single-region S3 only | S3 provides durable object access, direct AWS IAM integration, and predictable control-plane latency without running servers. | Requires bucket/KMS policy care and restore evidence. | SRE | Per backend or region change |
| Secrets provider | AWS KMS-backed Pulumi secrets provider | Passphrase provider, plaintext config, external vault | KMS removes local passphrase coordination and gives low-latency envelope operations in the target account. | KMS key availability becomes part of recovery planning. | Security reviewer | Per secrets-provider change |
| Deployment execution | GitHub Actions plus Dockerized Pulumi toolchain | Maintainer laptops only, self-hosted runners by default | Hosted runners provide parallel PR checks and reproducible tool versions without idle compute. | Runner queue health is external, so queue and runtime observations must be retained monthly and per workflow change. | Platform owner | Monthly and per workflow change |
| Backup and restore | AWS Backup for protected S3 resources plus restore drills | Manual object copy, S3 versioning only | Managed backup gives scheduled recovery points and metadata evidence without custom workers. | Restore freshness must be retained. | SRE | Quarterly drill |
| Control-plane detection | EventBridge, SNS, SQS, CloudTrail, GuardDuty, Security Hub, AWS Config | Polling jobs or custom daemons | Native event routing avoids always-on compute and scales with AWS control-plane events. | Live service posture still requires post-apply metadata evidence. | SRE plus security reviewer | Monthly after apply |
| Repository fanout | Catalog-driven resources with static fanout and quota checks | Ad hoc per-repo stacks | Catalog estimates make resource growth visible before apply and avoid hidden per-repo expansion. | Conservative static thresholds can require manual review before actual quota exhaustion. | Maintainer | Per catalog change |

## Fanout And Constraint Table

| Resource family | Bootstrap projected count | Constraint | No-go or review threshold | Evidence |
| --- | ---: | --- | --- | --- |
| S3 buckets | 8 | Object storage operations are control-plane and low volume; bucket count is the primary scaling concern. | Block when catalog fanout or live quota headroom fails. | `pulumi/repositories.bootstrap.json`, `quota-headroom-evidence-2026-05-09.json` |
| KMS keys | 3 | Key creation and policy updates are low frequency; cryptographic request-rate quotas are not expected to bind this workload. | Block when projected key count exceeds recorded quota rules or key policy evidence is missing. | `quota-headroom-evidence-2026-05-09.json` |
| IAM roles | 7 | Role count and policy document size are more relevant than runtime latency. | Block when role fanout, trust-policy scope, or IAM validation fails. | repository fanout, policy tests, IAM validation |
| EventBridge rules | 4 | Event volume is limited to control-plane changes and backup job events. | Require SRE review before adding new high-volume event sources. | operations monitoring component tests |
| Backup selections | 2 | Backup scheduling is managed service work; restore drills validate recovery behavior. | Block 5/5 recovery claims when restore evidence is stale. | restore drill evidence |
| CloudTrail trails | 1 projected by this repo | The account quota is tight; the latest headroom evidence leaves one remaining trail slot. | Do not add another trail without SRE approval and a quota plan. | `quota-headroom-evidence-2026-05-09.json` |
| AWS Config recorders | 1 | Regional recorder quota is one; this repository must create or reuse the recorder rather than fan out. | Future Config changes must reuse or update the recorder. | `quota-headroom-evidence-2026-05-09.json` |
| GuardDuty and Security Hub | 1 detector and 1 account subscription in the target region | Account-level services are not per-repository hot paths; posture evidence is the binding factor. | Keep security posture below 5/5 until post-apply metadata evidence exists. | Pulumi component tests and external-control evidence |

## Storage Performance Model

| Data path | Access pattern | Size or growth assumption | Latency/RPO expectation | Storage behavior | Review trigger |
| --- | --- | --- | --- | --- | --- |
| Pulumi state | Read/write during preview, plan, apply, refresh, and drift. | Small JSON checkpoints; growth follows stack and resource count. | Interactive CI operations read current state from the primary region; recovery RPO is one daily backup plus S3 versioning. | Keep active state in standard S3 storage with versioning and noncurrent expiration. | Stack fanout, state size, or backend change. |
| State replica | Recovery-only read path. | Mirrors primary state object growth. | Replica is not on the normal preview/apply hot path; it supports regional recovery and eventual replication. | Use the allowlisted paired region; no lower-tier storage class is selected for active replica objects because recovery simplicity is preferred over marginal savings. | Region, RPO, or transfer-cost change. |
| Central logs | Write-heavy AWS delivery, read during investigation. | Growth follows CloudTrail, S3 access logging, AWS Config, and control-plane activity. | Investigation reads tolerate higher latency after the active investigation window. | Lifecycle transition is acceptable after active investigation needs decline; current classification and retention are in `docs/data-classification-retention.md`. | New log source or monthly growth threshold breach. |
| AWS Config snapshots | AWS Config delivery and security review. | Growth follows recorded resource changes. | Not on deployment hot path. | Dedicated bucket with lifecycle expiration. | New recorder scope or delivery bucket change. |
| Backup recovery points | Restore-only access path. | Growth follows protected bucket object count and retention. | Restore drill freshness, not read latency, is the key performance signal. | Managed by AWS Backup retention. | Restore drill, retention, or vault change. |
| ECR runner images | Pull during runner image use and scan during push. | Bounded by lifecycle cap. | Optional runner image should avoid bypass pressure from slow pulls. | Immutable tags, scan-on-push, and lifecycle cleanup. | Image base, size, or lifecycle change. |
| CI artifacts and saved plans | Read during the same workflow or PR review. | Short-lived summaries, JSON previews, and binary plans. | Must be available before apply; stale artifacts are rejected by manifest checks. | Short retention and hash verification. | Workflow artifact or saved-plan contract change. |

## Network And Region ADR

| Area | Current decision | Performance rationale | Validation and fallback | Future trigger |
| --- | --- | --- | --- | --- |
| Primary region | `eu-central-1` | Matches committed stack defaults and current account evidence region; keeps control-plane operations close to the existing workload account. | Region policy and stack config must agree; block region changes without compliance, latency, service availability, transfer-cost, and sustainability review. | Primary-account move or workload residency change. |
| Replica region | `eu-west-1` | Regional separation for recovery without adding an active runtime path. | Replica is not part of the interactive preview/apply path; revisit if restore objectives, residency, or transfer cost changes. | RTO/RPO, residency, or cost threshold change. |
| VPC topology | Not applicable | This repository creates no VPC, load balancer, NAT gateway, endpoint, or user traffic path. | Keep future VPC work blocked until subnet, route, endpoint, flow-log, TLS, WAF, latency, and private-access evidence exists. | Any VPC, subnet, route table, endpoint, or NAT gateway resource. |
| Public endpoints | None | No request/response workload exists in this repository. | Public endpoints must define TLS policy, monitoring, capacity, abuse controls, and owner before merge. | Any load balancer, API, CDN, listener, or public DNS record. |
| CI network path | GitHub-hosted runner to AWS APIs | Network performance is dominated by hosted runner queue/start time and AWS control-plane API latency. | Current PR checks completed on 2026-05-09, including Preview, IAM Validation, Destructive Diff Gate, Local Battery, security scans, and quality gates; workflow design changes must preserve cache and parallelism evidence. | Persistent queue delay or workflow runtime threshold breach. |

## Review Rules

- New AWS service families must update the resource-selection ADR and fanout
  table before merge.
- New storage paths must update the storage performance model with access
  pattern, growth expectation, latency or RPO expectation, and lifecycle
  behavior.
- New network paths must add topology, latency, private/public access, TLS,
  monitoring, and failure-mode evidence.
- Hosted runner queue time remains external evidence; retain the current PR
  check completion record monthly and per workflow change, and treat persistent
  queue delay as a provider or workflow-design review trigger.
