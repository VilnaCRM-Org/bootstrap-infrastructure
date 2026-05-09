# Fault Isolation Evidence

This file records repository-owned fault-isolation evidence for the bootstrap
infrastructure workload. It is a public artifact and includes only non-secret
resource patterns, tests, and owner expectations.

## Evidence Metadata

| Field | Value |
| --- | --- |
| Workload | `bootstrap-infrastructure` |
| Review date | 2026-05-09 |
| Evidence owner | SRE plus security reviewer |
| Freshness | Per IAM, state bucket, KMS, repository catalog, or environment change |
| Validation sources | `pulumi/infra/pulumi_state.py`, `pulumi/infra/pulumi_secrets.py`, `pulumi/infra/iam/github_oidc.py`, `tests/unit/test_components.py`, policy-pack tests, IAM validation |
| Fallback | Keep REL10 below 5/5 when per-repository or per-environment state, role, or KMS boundaries are not covered by tests. |

## Isolation Matrix

| Boundary | Current control | Test evidence | Fallback |
| --- | --- | --- | --- |
| Repository state buckets | State bucket names include repository and environment; deploy policies grant access only to `state/*` in the matching repository bucket. | `test_github_oidc_roles_scope_state_and_kms_per_repository` asserts separate S3 bucket/object ARNs for two repositories. | Block new repository catalog patterns until state ARN tests are updated. |
| Repository secrets keys | Pulumi secrets KMS keys and aliases are created per repository and environment; deploy policies receive only the matching key ARN. | `test_github_oidc_roles_scope_state_and_kms_per_repository` asserts each deploy role references only its own KMS key ARN. | Keep REL10/SEC3 below 5/5 if deploy policy can reference another repository key. |
| OIDC deploy roles | Each deploy role trust policy scopes GitHub subject to the repository and branch. | `test_github_oidc_roles_scope_state_and_kms_per_repository` asserts `repo:<org>/<repo>:ref:refs/heads/<branch>` for two repositories. | Block deploy-role changes until trust-policy tests prove repository and branch scoping. |
| Environment naming | State buckets, KMS aliases, automation roles, and alert resources include the sanitized environment segment. | Existing component and config tests cover environment normalization and name limits. | Block environment naming changes that break deterministic resource boundaries. |
| Automation role | Bootstrap automation policy uses deterministic name prefixes, tags, service constraints, and scoped resource ARNs for bootstrap-managed resources. | `test_github_automation_emits_runner_repository_and_role`, policy-pack wildcard checks, and IAM validation. | Require security reviewer approval before adding wildcard or account-level actions. |
| Replication roles | State and log replication roles are created per bucket pair and scoped to source/destination bucket ARNs. | Component tests cover replication region separation and resource creation; future policy changes must add explicit ARN assertions. | Keep REL10 below 5/5 if replication policies expand beyond the bucket pair. |

## Review Rules

- New repository catalog fields that affect names, branches, projects, or
  environments must update fault-isolation tests before merge.
- New deploy-role permissions must prove repository bucket, object prefix, KMS
  key, and OIDC subject scoping.
- New cross-repository or cross-environment access must be treated as an
  exception with owner, expiry, blast-radius rationale, and security review.
