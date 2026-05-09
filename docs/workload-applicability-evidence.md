# Workload Applicability Evidence

This file records applicability evidence for Well-Architected questions where
the bootstrap workload has no application runtime, VPC, public endpoint, or
request path. It is a public repository artifact and must not include secrets,
stack outputs with sensitive values, private incident notes, or screenshots.

## Evidence Metadata

| Field | Value |
| --- | --- |
| Workload | `bootstrap-infrastructure` |
| Review date | 2026-05-09 |
| Evidence owner | Maintainer plus SRE for topology; security reviewer for network and transit controls; platform owner for service-selection exceptions |
| Freshness | Per new AWS service family, VPC, endpoint, runtime compute, or dependency change; otherwise quarterly |
| Validation sources | `pulumi/infra/bootstrap_infrastructure.py`, `policy/pack.py`, `policy/guardrails.py`, `docs/performance-operating-evidence.md`, `docs/security-operating-evidence.md`, and repository fanout evidence |
| Fallback | Keep the affected Well-Architected question below 5/5 and block merge until this evidence is updated for the new resource path. |

## Applicability Statement

The current repository provisions bootstrap control-plane resources only. It
does not provision:

- VPCs, subnets, route tables, NAT gateways, VPC endpoints, load balancers, or
  WAF resources.
- Public application endpoints, listeners, APIs, CDN distributions, public DNS
  records, or user traffic paths.
- Always-on runtime compute such as EC2, ECS services, EKS node groups, Lambda
  functions, batch workers, or self-hosted runners.

The primary runtime surfaces are GitHub Actions jobs and AWS managed
control-plane services. Any future resource that changes this scope must update
this file, `docs/performance-operating-evidence.md`, and the question matrix in
the same pull request.

## Dependency Inventory

| Dependency | Role | Inputs | Outputs | Failure mode | Owner | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| GitHub repository and Actions | Reviews, previews, plans, applies, security checks, and drift jobs. | Workflow YAML, repository variables, OIDC environment, PR branch. | Check contexts, artifacts, saved plans, review metadata. | Queued runners or missing required checks block merge/apply. | Maintainer plus platform owner | `.github/workflows/`, `docs/ci-guardrails.md` |
| GitHub branch ruleset and environments | External governance for required checks and production approval. | Admin-managed ruleset and environment protection. | Required-check and approval metadata. | Missing admin metadata keeps branch protection and production approval unresolved. | Repository admin | `scripts/configure_github_repository_controls.py` |
| Pulumi state S3 buckets | Durable state backend per managed repository. | Catalog entries, stack config, AWS account and region. | Backend URLs, versioned state objects, replication objects. | State unavailable or stale blocks preview/apply until restored. | SRE | `pulumi/infra/pulumi_state.py` |
| Pulumi secrets KMS keys | Envelope protection for stack secrets providers. | Repository catalog and region. | KMS aliases and provider URLs. | Disabled or pending-deletion key blocks secret operations and triggers incident handling. | Security reviewer plus SRE | `pulumi/infra/secrets.py` |
| Central log buckets and CloudTrail | Access logs and management-event audit trail. | Account events, bucket delivery, trail configuration. | Log objects and CloudTrail metadata. | Delivery failure reduces investigation evidence and blocks detection claims. | SRE plus security reviewer | `pulumi/infra/logging_bucket.py`, collector CloudTrail evidence |
| AWS Backup | Recovery points and restore drill source for state/log buckets. | Protected S3 ARNs, backup vault, plan, role. | Recovery points and restore jobs. | Failed backup or stale restore drill blocks recovery claims. | SRE | `pulumi/infra/backup.py`, restore drill evidence |
| EventBridge, SNS, and SQS | Control-plane and cost alert routing. | AWS Backup, KMS, IAM/OIDC, S3, budget, and anomaly events. | Encrypted operations topic and durable queue subscription. | Missing subscription or downstream route blocks alert-route claims. | SRE | `pulumi/infra/operations_monitoring.py`, collector SNS evidence |
| IAM and GitHub OIDC | Least-privilege AWS access for workflows and automation. | Repository, branch, environment, and AWS account metadata. | Preview/apply roles, automation policy, trust policies. | Trust or permission drift blocks privileged workflow use. | Maintainer plus security reviewer | `pulumi/infra/iam/`, IAM validation |
| Cost controls | Budget, anomaly monitor, and optional cost allocation tag activation. | Budget threshold, anomaly threshold, operations topic. | Budget and anomaly alert metadata. | Missing FinOps approval blocks final cost claims. | FinOps owner plus maintainer | `pulumi/infra/cost_controls.py`, external-control evidence |
| Security account controls | GuardDuty, Security Hub, AWS Config recorder, and Config delivery. | Account/region, delivery bucket, recorder role. | Security posture and configuration inventory metadata. | Stale or missing live posture evidence caps SEC4 until refreshed. | Security reviewer plus SRE | `pulumi/infra/security_account_controls.py`, `docs/security-operating-evidence.md` |

## Network And Transit Applicability

| Path | Current state | Protection | Future trigger |
| --- | --- | --- | --- |
| S3 state and log paths | Current data path. | Bucket policies deny non-TLS access, public access is blocked, ownership is enforced, and policy pack rejects public S3 exposure. | New bucket classes must keep TLS, public-access, encryption, logging, and lifecycle controls. |
| GitHub Actions to AWS APIs | Control-plane API path. | GitHub OIDC federation and AWS APIs use TLS; jobs must pass account preflight before privileged operations. | Self-hosted runners or private networking require endpoint, egress, and hardening evidence. |
| EventBridge, SNS, SQS, Backup, KMS, CloudTrail, AWS Config | AWS managed service paths. | Managed service transport is TLS; data payloads are metadata-only for routine evidence. | Custom event processors, webhooks, or integrations require TLS, auth, monitoring, and data-handling evidence. |
| Public application ingress | Not applicable. | No load balancer, API, CDN, listener, public DNS, or application endpoint exists. | Any public endpoint must include TLS policy, certificate ownership, WAF or ingress posture, abuse controls, monitoring, and rollback plan. |
| VPC topology | Not applicable. | No VPC route, subnet, endpoint, NAT, security group, or network ACL is created. | Any VPC work must add subnet and route design, endpoint strategy, flow logs, ingress rules, egress controls, and failure-mode evidence. |

The policy pack provides preventive controls for future network mistakes:
`aws-region-allowlist`, `s3-no-public-exposure`, and
`security-group-no-open-admin-ports` are mandatory policies. Future public
ingress must add policy coverage before it can keep SEC5, SEC9, REL2, and
PERF4 at 5/5.

## Service Selection And No-Idle-Compute Rule

Managed and serverless AWS services are the default for this repository. The
current implementation uses S3, KMS, IAM, AWS Backup, CloudTrail, EventBridge,
SNS, SQS, Budgets, Cost Anomaly Detection, GuardDuty, Security Hub, AWS Config,
ECR, and GitHub-hosted Actions instead of always-on runtime compute.

Future always-on compute is prohibited unless the pull request includes:

- A workload reason that cannot be met by managed services, scheduled jobs, or
  GitHub-hosted Actions.
- Expected utilization, shutdown or scaling behavior, owner, patch cadence, and
  vulnerability response SLA.
- Cost, sustainability, security, reliability, and performance impact notes.
- Alerting, logging, backup, recovery, and incident runbook evidence.
- An exception expiry date and review owner.

Without that evidence, the change is a no-go and SUS5 must remain below 5/5.
