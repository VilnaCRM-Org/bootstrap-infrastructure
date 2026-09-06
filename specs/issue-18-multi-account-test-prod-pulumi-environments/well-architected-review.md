# AWS Well-Architected Review

> **Configuration source superseded by issue 20.** Account configuration now uses
> fixed AWS Secrets Manager suffixes with independent repository account pins.
> Protected `test`, `test-preview`, `prod-preview`, `prod` and the installed
> governance/reconciliation environments remain required. See the
> [PR57 successor contract](../issue-20-pulumi-esc-ci-config/pr57-successor-verification.md).
> Historical removal or environment-variable setup instructions below are not
> the current execution contract.

Scope: issue #18 multi-account test/prod Pulumi environment support.

This is an engineering review against the AWS Well-Architected Framework's six
pillars, not an AWS Well-Architected Tool workload review. Source references:

- https://aws.amazon.com/architecture/well-architected/
- https://docs.aws.amazon.com/wellarchitected/latest/framework/welcome.html
- https://docs.aws.amazon.com/wellarchitected/latest/framework/sec-design.html
- https://docs.aws.amazon.com/wellarchitected/2022-03-31/framework/oe-design-principles.html

## Score Summary

| Pillar | `main` | PR before latest review fixes | PR after latest review fixes | Change |
| --- | ---: | ---: | ---: | --- |
| Operational Excellence | 4.5 | 4.0 | 4.1 | Multi-account workflows add more moving parts, but explicit preflight and state-level concurrency improve operability. |
| Security | 4.0 | 4.0 | 4.2 | PR keeps OIDC/KMS guardrails, fails earlier on invalid workflow inputs, and now scopes the bootstrap automation policy away from account-wide S3/KMS/ECR/Backup/IAM access where AWS supports resource scoping. |
| Reliability | 4.0 | 4.0 | 4.1 | Saved plans, drift checks, and destructive diff gates remain; test/prod state operations are now serialized by stable concurrency groups. |
| Performance Efficiency | 2.5 | 3.0 | 3.0 | Bounded CI and explicit stack lists improve control-plane efficiency; no runtime performance model is expected for this bootstrap repo. |
| Cost Optimization | 3.0 | 3.5 | 3.5 | Lifecycle, retention, and tagging improve; budgets and cost anomaly detection remain future work. |
| Sustainability | 2.5 | 2.5 | 2.5 | Cleanup/retention help indirectly, but sustainability is not yet a first-class requirement. |

Overall score:

- `main`: 3.4 / 5
- PR before latest review fixes: 3.5 / 5
- PR after latest review fixes: 3.6 / 5

## Highest-Priority Findings Addressed

1. Production and test state operations could overlap across workflows.
   - Fixed by using stable state-level concurrency groups for test and prod
     deployment/drift paths.
2. OIDC actions read role/account inputs directly from `vars.*`, bypassing the
   job-level environment values that preflight validates.
   - Fixed by using `env.*` for OIDC role ARN, region, and allowed account ID.
3. Privileged Pulumi commands could defer missing `PULUMI_SECRETS_PROVIDER`
   failures until later Pulumi execution.
   - Fixed by failing fast unless the provider is set and starts with
     `awskms://`.
4. Workflow preflight only checked for non-empty backend/account values.
   - Fixed by validating 12-digit account IDs, `s3://` backends, and
     `awskms://` secrets providers before assuming AWS credentials.
5. The bootstrap automation role had account-wide resource permissions for
   several mutable AWS services.
   - Fixed by deriving S3, ECR, KMS alias/key, IAM role, and AWS Backup
     resource scopes from the bootstrap naming contract, leaving wildcard
     resources only for AWS actions that cannot be ARN-scoped.

## Remaining Improvements

1. Move CI configuration to Pulumi ESC and minimize GitHub Environment
   variables. Tracked in issue #20.
2. Add a saved-plan manifest that records stack name, backend URL, commit SHA,
   and SHA-256 for each plan, then verify it before `pulumi up --plan`.
3. Validate restore procedures for Pulumi state backups and define RTO/RPO targets.
4. Implement budget/anomaly detection or an Infracost-style cost signal for bootstrap
   resources.
5. Define explicit sustainability goals for retention, artifact churn, and
   ephemeral validation stack cleanup.
