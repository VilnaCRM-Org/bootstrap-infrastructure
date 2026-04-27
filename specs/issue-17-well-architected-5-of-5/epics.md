# Epics and Stories: Well-Architected 5/5 Remediation Roadmap

## Traceability Matrix

| Issue #17 roadmap item | Epic |
| --- | --- |
| Make current guardrails mandatory | Epic 1 |
| Fix region and replication controls | Epic 2 |
| Reduce automation IAM blast radius | Epic 3 |
| Add operational monitoring and alerting | Epic 4 |
| Prove backup and recovery | Epic 5 |
| Add cost controls | Epic 6 |
| Add catalog and quota guardrails | Epic 7 |
| Improve data lifecycle and sustainability | Epic 8 |
| Extend policy pack coverage | Epic 8 |
| Improve operational process documentation | Epic 4 |
| Analyze all AWS Well-Architected questions | Epic 0 |
| Analyze repository functional and non-functional requirements | Epic 0 |
| Prove future score changes with evidence | Epic 0 |

## Global Completion Gates

No future implementation story may claim a Well-Architected score increase until:

- The matching row in `question-matrix.md` is updated with implemented evidence and a comparison against `main`.
- Evidence is non-secret or explicitly classified as a secret-managed artifact that must not be printed.
- Owner, evidence location, freshness SLA, cadence, and fallback action are recorded.
- The narrowest useful local tests and applicable GitHub checks pass.
- Real AWS validation is captured through metadata-only commands, an ephemeral stack, or the OIDC-backed `Pulumi Test Deploy` workflow without exposing secrets.

## Epic 0: Evidence Governance And Full Question Coverage
As an architect, I want every AWS Well-Architected question and every current repository FR/NFR represented in an evidence ledger so the 5/5 target is auditable instead of aspirational.

### Story 0.1: Maintain the 57-question matrix
**Acceptance Criteria:**
- Given the Well-Architected scorecard is reviewed, Then OPS1-11, SEC1-11, REL1-13, PERF1-5, COST1-11, and SUS1-6 all have rows in `question-matrix.md`.
- Given a future implementation changes a control, Then the affected row records current evidence, target evidence, owner, cadence, fallback, and validation source.
- Given a question is not currently applicable, Then the row explains why and states the future resource type that would make it applicable.

### Story 0.2: Maintain FR/NFR coverage
**Acceptance Criteria:**
- Given a future story changes state, secrets, OIDC, automation IAM, logging, backup, catalog, or CI behavior, Then the PR maps the change to repository functional duties and non-functional safety requirements.
- Given a future score increase is proposed, Then the PR proves that secret safety, KMS-backed Pulumi, least privilege, auditability, main comparison, and test-account proof still hold.

### Story 0.3: Capture external-control evidence
**Acceptance Criteria:**
- Given a control is enforced outside this repository, Then the story records owner, system of record, evidence link or artifact location, freshness SLA, review cadence, fallback, and secret-safety classification.
- Given external evidence is missing or stale, Then the story cannot close as 5/5 and must either implement an in-repo control or document the no-go condition.

## Epic 1: Mandatory CI And Deployment Guardrails
As a maintainer, I want same-repo infrastructure PRs to run real AWS-backed safety checks so merge decisions do not rely on skipped privileged guardrails.

### Story 1.1: Define required privileged check contract
**Acceptance Criteria:**
- Given a same-repo infrastructure PR, Then the required preview, destructive diff, and IAM validation checks are identified by exact workflow and check names.
- Given a fork PR, Then the unprivileged fallback remains credential-free and is not treated as equivalent to same-repo AWS validation.
- Given a required privileged check is skipped, Then docs define whether the skip is acceptable and who may approve it.

### Story 1.2: Document required metadata variables without values
**Acceptance Criteria:**
- Given setup docs are reviewed, Then required variable names include AWS account, role, backend, and KMS provider metadata without secret values.
- Given Pulumi stack guidance is reviewed, Then AWS KMS remains the only shared secrets-provider path.
- Given future implementation runs, Then missing privileged configuration fails before AWS credentials are assumed.

### Story 1.3: Define branch protection evidence
**Acceptance Criteria:**
- Given branch protection is reviewed, Then required status checks match the non-skipped AWS-backed job names.
- Given branch protection is externally managed, Then the owner, evidence URL or screenshot location, and review cadence are documented.
- Given a Well-Architected score depends on branch protection, Then the evidence includes the PR number, branch, head SHA, check names, skipped-check policy, and reviewer rule state.

## Epic 2: Region, Replication, And Data Residency Controls
As an SRE, I want replication regions to be explicit, allowlisted, and documented so durability does not create unmanaged residency, cost, or sustainability risk.

### Story 2.1: Replace unsafe replica-region fallback
**Acceptance Criteria:**
- Given replication configuration is absent, Then future implementation either fails fast or uses a documented allowlisted paired region.
- Given `replicationRegion` is set, Then it is validated against the policy allowlist before preview/apply.
- Given tests run, Then non-allowlisted regions are rejected.

### Story 2.2: Document RTO, RPO, and residency assumptions
**Acceptance Criteria:**
- Given state and log replication docs are reviewed, Then test and prod RTO/RPO targets are stated.
- Given a replica region is selected, Then the data residency and transfer-cost rationale is documented.
- Given external residency controls exist, Then evidence owner and cadence are recorded.
- Given current branch evidence is reviewed, Then the plan acknowledges the current `eu-west-1` replica default and focuses implementation on explicit policy, evidence, and rationale gaps.

## Epic 3: Automation IAM Blast Radius Reduction
As a security reviewer, I want bootstrap automation permissions narrowed so the automation role can mutate only intended bootstrap-managed resources.

### Story 3.1: Inventory broad permission areas
**Acceptance Criteria:**
- Given current automation IAM is reviewed, Then broad S3, KMS, ECR, Backup, and IAM permissions are listed at a high level without exposing secrets.
- Given an action cannot be ARN-scoped by AWS, Then the wildcard is documented with a service limitation and compensating control.
- Given current branch evidence is reviewed, Then the plan distinguishes already-scoped automation permissions from residual wildcard or external-boundary gaps.

### Story 3.2: Scope resources with prefixes, tags, and regions
**Acceptance Criteria:**
- Given future policy code is implemented, Then supported actions use known bucket, key, alias, repository, backup, and role naming patterns.
- Given AWS supports conditions, Then tag, region, or service conditions are applied where practical.
- Given validation runs, Then policy-pack tests or IAM Access Analyzer evidence covers the narrowed policy.

### Story 3.3: Decide on permissions boundary usage
**Acceptance Criteria:**
- Given bootstrap automation role design is reviewed, Then the plan either adds a permissions boundary or documents why the boundary is externally managed.
- Given an external boundary is claimed, Then owner, policy ARN, review cadence, and fallback are documented.

## Epic 4: Monitoring, Alerting, And Operational Process
As an operator, I want failures to route to accountable owners with severity and response expectations.

### Story 4.1: Define operational alert inventory
**Acceptance Criteria:**
- Given the alert inventory is reviewed, Then it covers AWS Backup failures, S3 replication failures or latency, KMS deletion and key policy changes, nightly drift failures, and guardrail failures.
- Given each alert is listed, Then signal source, route, severity, owner, and expected response are defined.
- Given an alert is externally managed, Then evidence and escalation owner are documented.
- Given a future alert implementation is reviewed, Then the PR includes test evidence or a documented external alarm proof without printing secret values.

### Story 4.2: Define dashboard and health KPIs
**Acceptance Criteria:**
- Given operational health docs are reviewed, Then backup, replication, drift, and CI guardrail status appear as dashboard requirements.
- Given KPIs are defined, Then they have measurement source and review cadence.
- Given KPI evidence is used for OPS9 or PERF5, Then it records target, threshold, last observation, owner, and action if the threshold is missed.

### Story 4.3: Add incident process requirements
**Acceptance Criteria:**
- Given incident docs are reviewed, Then severity definitions, escalation path, communication expectations, and post-incident review requirements are present.
- Given ownership docs are reviewed, Then RACI or equivalent accountability is defined for bootstrap infrastructure.
- Given security incidents are reviewed, Then playbooks cover compromised OIDC, unexpected KMS changes, state bucket access anomaly, log delivery failure, and guardrail bypass.

### Story 4.4: Define operational readiness review
**Acceptance Criteria:**
- Given 5/5 readiness is reviewed, Then the ORR checklist covers owners, runbooks, alert routes, restore evidence, cost/quota readiness, branch protection, and test-account deployment evidence.
- Given a no-go item is open, Then the review records owner, target date, risk, and whether the score remains unchanged.

## Epic 5: Backup, Restore, And Disaster Recovery Proof
As an SRE, I want backup controls proven by restore evidence so recovery claims are operationally defensible.

### Story 5.1: Decide Backup Vault Lock
**Acceptance Criteria:**
- Given backup architecture is reviewed, Then Backup Vault Lock is either implemented or documented as externally enforced with evidence.
- Given an exemption is used, Then the risk, owner, review cadence, and fallback are documented.

### Story 5.2: Define restore drills for Pulumi state and logs
**Acceptance Criteria:**
- Given restore runbooks are reviewed, Then they cover Pulumi state buckets and central log buckets.
- Given a restore drill runs, Then it uses non-production validation and avoids secret-revealing commands.
- Given scheduled reporting is reviewed, Then restore evidence and last successful drill date are included.
- Given restore evidence is used for REL9, REL11, REL12, or REL13, Then it includes stack/environment, date, operator, source backup, validation result, and cleanup confirmation without including secret material.

### Story 5.3: Define DR targets
**Acceptance Criteria:**
- Given environment docs are reviewed, Then RTO and RPO are defined for test and prod.
- Given failover assumptions are reviewed, Then replication, backup, and manual recovery steps are aligned with the target.

## Epic 6: Cost Management And Cost Guardrails
As a FinOps owner, I want cost controls and cost evidence so multi-repository bootstrap expansion does not create unmanaged spend.

### Story 6.1: Add budget and anomaly-control requirements
**Acceptance Criteria:**
- Given cost control docs are reviewed, Then the repo-owned `CostControls` component is represented as the source for the monthly AWS Budget, Budget notifications, Cost Anomaly Detection monitor creation or configured monitor reuse, immediate anomaly subscription, and optional cost allocation tag activation.
- Given cost allocation tag activation is reviewed, Then `CostCenter`, `App`, `RepositoryProject`, and the other managed tag keys have payer-account activation evidence or a documented owner-controlled blocker.
- Given budget or anomaly evidence is reviewed, Then it records configured thresholds, SNS route, downstream subscription or incident route, owner, last reviewed date, and fallback action.

### Story 6.2: Define PR cost signal
**Acceptance Criteria:**
- Given a future infrastructure PR adds resources, Then it produces a cost estimate or resource-count cost proxy before merge.
- Given cost estimation uses an external tool, Then setup, ownership, and failure behavior are documented.
- Given cost estimation is unavailable, Then the PR records a resource-count cost proxy for S3 buckets, KMS keys, IAM roles, Backup selections, ECR repositories, storage lifecycle, and cross-region transfer.

### Story 6.3: Review cross-region transfer cost
**Acceptance Criteria:**
- Given replication is configured, Then transfer-cost impact is reviewed and linked to RTO/RPO and residency decisions.
- Given replica defaults change, Then the cost rationale is updated.
- Given monthly cost evidence is reviewed, Then the transfer model records estimated GB/month, cost threshold, alert owner, and action if threshold is exceeded.

## Epic 7: Catalog, Fanout, Quota, And Cleanup Controls
As a maintainer, I want repository catalog expansion bounded by quotas and cleanup rules so bootstrap resources scale predictably.

### Story 7.1: Define fanout preflight
**Acceptance Criteria:**
- Given the repository catalog changes, Then a preflight estimates S3 buckets, KMS keys, IAM roles, Backup selections, and other managed resources per repository.
- Given projected counts exceed configured thresholds, Then the PR fails or requires documented approval.
- Given the preflight runs, Then it records current counts, projected counts, quota headroom, and comparison with `main`.

### Story 7.2: Validate AWS service quotas
**Acceptance Criteria:**
- Given validation runs with AWS metadata access, Then quota checks use safe metadata calls and do not read secrets.
- Given a quota is externally managed, Then owner, evidence, cadence, and fallback are documented.

### Story 7.3: Define stale repository cleanup
**Acceptance Criteria:**
- Given catalog entries are reviewed, Then each entry has owner and last-reviewed metadata or an explicit equivalent.
- Given a repository is stale, Then cleanup cadence, approval, and destroy safety checks are documented.
- Given stale cleanup runs, Then evidence includes approval, protected-resource checks, destroy or retain decision, and follow-up date.

## Epic 8: Lifecycle, Sustainability, And Policy Coverage
As an infrastructure owner, I want lifecycle and policy controls to reduce waste and prevent future resource classes from bypassing guardrails.

### Story 8.1: Add lifecycle and storage-class requirements
**Acceptance Criteria:**
- Given primary and replica log buckets are reviewed, Then retention and storage-class transitions are configurable or explicitly justified.
- Given state and log replicas use `STANDARD`, Then the durability, access, and sustainability rationale is documented.
- Given lifecycle evidence is reviewed, Then it maps each data class to sensitivity, retention, storage class, access frequency, cost impact, and sustainability rationale.

### Story 8.2: Define sustainability goals and reporting
**Acceptance Criteria:**
- Given sustainability docs are reviewed, Then goals cover region selection, data retention, backup justification, and ephemeral validation cleanup.
- Given scheduled reporting is reviewed, Then bucket growth, backup volume, ECR image age, and tag-based cost or carbon indicators are included where available.
- Given sustainability goals are updated, Then the region decision matrix records compliance, latency, service availability, cost/transfer, sustainability considerations, exception owner, and review date.

### Story 8.3: Extend policy pack coverage conditionally
**Acceptance Criteria:**
- Given networking resources are introduced, Then VPC Flow Logs, public ingress, WAF, load balancer, and TLS listener guardrails are required where applicable.
- Given data classification is required, Then tag policy and tests enforce the classification taxonomy.
- Given Backup Vault Lock is required, Then policy or docs enforce the control or documented exemption.
- Given new compute, network, or public endpoint resources are introduced, Then the PR updates SEC5, SEC6, SEC9, REL2, and PERF4 rows in the question matrix before merge.
