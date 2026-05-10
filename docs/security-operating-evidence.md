# Security Operating Evidence

This register records repository-owned security evidence for the bootstrap
infrastructure Well-Architected review on 2026-05-09. It is intentionally
non-secret: do not add IAM access keys, Pulumi stack exports, decrypted config,
private incident details, or screenshots containing account-sensitive data.

This file does not prove human MFA/SSO posture, organization permissions
boundaries, static-key exception evidence, or external security-owner approval.
Those remain external controls.
Current vulnerability-review evidence is retained in
`docs/vulnerability-review-2026-05-09.md`.

## Authentication Matrix

| Principal | Current control | Evidence source | Owner | Cadence | Fallback |
| --- | --- | --- | --- | --- | --- |
| GitHub Actions preview and IAM validation | Environment-scoped OIDC trust using `repo:VilnaCRM-Org/bootstrap-infrastructure:environment:test` or `prod-preview`; no static AWS keys. | `.github/workflows/pulumi-pr-guardrails.yml`, `docs/github-actions-secrets.md`, `pulumi/infra/iam/github_oidc.py`. | Maintainer plus security reviewer | Per workflow or trust-policy change | Fail privileged jobs when OIDC variables are missing or account ID does not match. |
| GitHub Actions apply | Separate apply role, protected `prod` environment for production, saved-plan manifest, and commit SHA checks. | `.github/workflows/pulumi-test-deploy.yml`, `.github/workflows/pulumi-prod.yml`, `scripts/run_pulumi_command.py`. | Maintainer plus SRE | Per deploy workflow change | Do not apply until the environment, SHA, manifest, destructive diff, and IAM validation evidence match. |
| Local maintainer AWS access | Local credentials are outside the repository and are passed only through explicit Docker environment flags. | `.env` is ignored; `.env.empty` is committed; `docs/security-baseline.md`. | Maintainer | Quarterly | Treat local static keys as an exception requiring external owner approval and rotation evidence. |
| Human GitHub administration | Branch rulesets and environments require repository admin rights. | `scripts/configure_github_repository_controls.py` documents the desired state. | Repository admin | Per ruleset or environment change | Keep branch protection and production approval unresolved until GitHub metadata proves the controls. |

## Permission Matrix

| Role or policy surface | Scope | Boundary | Validation |
| --- | --- | --- | --- |
| Preview role | Reads stack state, generates Pulumi previews, runs destructive diff and IAM Access Analyzer validation. | GitHub environment OIDC subject and account allow-listing. | Same-repo PR guardrail workflow and `make test-guardrails`. |
| Apply role | Applies saved plans only in `test` or protected `prod`. | GitHub environment approval, commit SHA checks, saved-plan manifest, backend match, and plan hash verification. | `make pulumi-plan`, `make pulumi-up-plan`, workflow tests, and unit coverage. |
| Bootstrap automation policy | Manages repository-prefixed S3, KMS, IAM, Backup, ECR, EventBridge, CloudTrail, SNS/SQS, Budgets, Cost Anomaly, GuardDuty, Security Hub, and AWS Config resources. | Resource ARNs, deterministic name prefixes, request/resource tags, service constraints, and policy-pack wildcard checks. | `tests/unit/test_components.py`, `tests/policies/test_policy_pack.py`, `make test-iam-validation` when AWS credentials are available. |
| AWS Config recorder role | Allows AWS Config to describe supported resources and write delivery objects to the dedicated Config bucket. | Service principal trust for `config.amazonaws.com` and bucket-prefix policy. | Pulumi unit tests and real preview policy-pack validation. |
| Backup role | Allows AWS Backup to protect repository state/log buckets and restore to isolated drill locations. | `iam:PassedToService` condition for AWS Backup plus scoped backup resources. | Restore evidence and backup component tests. |

## Wildcard Permission Justification

Wildcard resources are allowed only where AWS does not expose a stable resource
ARN before creation, where the API is account-level, or where an AWS list action
is not resource-scopable. Compensating controls must use request tags, resource
tags, deterministic names, service conditions, and tests.

| Statement or action family | Why `Resource: "*"` remains | Compensating control |
| --- | --- | --- |
| `sts:GetCallerIdentity` | AWS identity lookup is account metadata and has no resource ARN. | Read-only; used for account evidence and preflight checks. |
| `kms:CreateKey` | KMS keys have no ARN before creation. | Requires bootstrap `Environment` and `Purpose` request tags. |
| `kms:ListAliases` | KMS alias listing is not resource-scopable. | Follow-up alias changes are scoped to bootstrap aliases and tagged keys. |
| `iam:CreateOpenIDConnectProvider` and `iam:ListOpenIDConnectProviders` | OIDC provider creation/list APIs are account-level. | Trust policy is environment-scoped; provider ARN is deterministic after creation. |
| `ce:*CostAnomaly*` create actions | Cost Explorer anomaly resources require account-level creation APIs. | Requires request tags and later resource-tag conditions where AWS supports them. |
| `guardduty:ListDetectors` and `guardduty:CreateDetector` | Detector discovery and creation are account-level. | Detector creation requires bootstrap request tags; management is scoped to account detector ARNs. |
| AWS Config delivery channel actions | AWS Config delivery-channel APIs are account/region-level and do not support the same recorder ARN scoping. | Recorder role, delivery bucket, and recorder management are scoped to bootstrap names. |
| Cost allocation tag activation | Cost allocation tag activation is payer/account-level. | `docs/finops-review-2026-05-09.md` records the current active tag evidence; future tag taxonomy changes must refresh FinOps approval. |

## Permissions Boundary Decision

This repository does not create or attach an organization-wide permissions
boundary. A boundary is an administrator-owned guardrail and should not be
self-managed by the same bootstrap automation role it is meant to constrain.

Current compensating controls are:

- environment-scoped GitHub OIDC trust
- account allow-listing in privileged jobs
- deterministic AWS resource names and ARN scopes
- request and resource tag conditions where AWS supports them
- policy-pack rejection of wildcard IAM in repository code unless allowlisted
- AWS IAM Access Analyzer validation over rendered preview policies
- branch protection and production environment approval once repository admins
  apply the documented GitHub settings

Final 5/5 security evidence still requires either an administrator-owned
permissions-boundary ARN and review cadence or a named security-owner exemption
that explains why the scoped repository controls are sufficient.

## Threat Model And Secure SDLC

| Risk | Repository control | Review cadence | Fallback |
| --- | --- | --- | --- |
| Static credential exposure | OIDC-first workflows, `.env` ignored, Gitleaks in CI. | Per workflow change and monthly vulnerability review | Revoke exposed key, rotate affected credentials, and block merge until scan passes. |
| Over-privileged automation | Scoped IAM resources, tag conditions, wildcard justification, Access Analyzer. | Per IAM change | Keep Security score below 5/5 and require security-owner exception. |
| Tampered or stale deployment plan | Saved-plan manifest with commit, backend, stack, preview hash, plan hash, and age checks. | Per deploy workflow change | Regenerate preview and plan from the intended commit. |
| Missed control-plane detection | CloudTrail evidence, EventBridge rules, live GuardDuty/Security Hub/AWS Config posture, and drift checks. | Monthly after apply | Re-run metadata checks after detection, logging, recorder, or alert-route changes; keep human escalation tracked under OPS8. |

## Live Security Account Posture

The test account posture was proven with metadata-only checks after a guarded
local Pulumi apply using the AWS KMS secrets provider on 2026-05-09 UTC. The
apply ran from PR head `b05d233` and completed with 30 resources created, 1
updated, and 86 unchanged. A follow-up drift check from PR head `b84bb4f` passed
with `Resources: 117 unchanged`.

| Service | Live evidence | Follow-up |
| --- | --- | --- |
| GuardDuty | Detector `502efed8294c4b95a7f0778aaa4b8d62` in `eu-central-1` returned `Status=ENABLED` and bootstrap `security-detection` tags. | Refresh monthly and after detector-feature or region changes. |
| Security Hub | `describe-hub` returned `arn:aws:securityhub:eu-central-1:891377212104:hub/default` with `AutoEnableControls=true`. | Refresh monthly and after standards/control changes. |
| AWS Config | Recorder `bootstrap-test-configuration-recorder`, delivery channel `bootstrap-test-configuration-delivery`, bucket `bootstrap-891377212104-eu-central-1-test-aws-config`, `recording=true`, and `lastStatus=SUCCESS`. | Refresh monthly and after recorder scope, bucket, or delivery changes. |
| Vulnerable dependencies or workflow code | `pip-audit`, Bandit, CodeQL, actionlint, dependency hygiene checks, and `docs/vulnerability-review-2026-05-09.md`. | Per PR and monthly review | Patch, pin, or record a time-bound exception with owner approval. |

## Human And Static-Credential Metadata

A non-secret IAM metadata refresh on 2026-05-10 UTC confirmed that the
security-account external control is still open:

| Check | Result | Follow-up |
| --- | --- | --- |
| Caller identity | `arn:aws:iam::891377212104:user/codex_cli`. | Treat local static credentials as an owner-approved exception until remediated. |
| IAM account summary | `Users=4`, `MFADevices=1`, `MFADevicesInUse=1`, `AccountMFAEnabled=1`, `AccountPasswordPresent=1`, and `AccountAccessKeysPresent=0`. | Security owner must attest human MFA/SSO posture without exposing private user data. |
| IAM user inventory | Four IAM users exist in the account; password last-used values were not present in the metadata returned. | Security owner decides which users are required, retired, or covered by an exception. |
| Access-key status by user | One IAM user has an active access key; the other three users returned no access-key status rows. Access key IDs were not printed or retained. | Record static-key exception, rotation plan, or remediation before SEC2 can pass at 5/5. |

This metadata does not prove human MFA/SSO coverage, does not replace an
administrator-owned permissions boundary, and does not constitute external
security-owner approval. Keep SEC1, SEC2, and SEC3 capped until those
attestations or remediations are recorded.

## Network And Transit Applicability

The current workload has no VPC, public endpoint, listener, API, CDN, public
DNS record, or application request path. `docs/workload-applicability-evidence.md`
records the network applicability statement, current TLS paths, future VPC and
public-ingress triggers, owners, validation sources, and fallback behavior.
Policy-pack coverage blocks public S3 exposure and public SSH/RDP exposure for
future resources.

## At-Rest Protection

`docs/data-protection-recovery-evidence.md` records the at-rest protection
matrix for state, logs, replicas, CloudTrail, AWS Config, Pulumi secrets,
operations alerts, AWS Backup recovery points, and saved plans. It also records
the current S3 Object Lock, AWS Backup Vault Lock, and S3 SSE-KMS exemptions
with owners, expiry, rationale, and fallback behavior.

## Exception Register

Use `make report-security-account-attestation` to render a non-secret
security-owner review record from `.artifacts/well-architected/evidence.json`.
The command requires explicit human MFA/SSO, active IAM user access-key,
permissions-boundary or exemption, and approval decisions. The generated record
includes aggregate active-key age and last-used counts from the collector, but
must not include IAM user names, access key IDs, screenshots with private
identities, credentials, tokens, or raw account exports. This record path helps
close issue #28, but SEC1, SEC2, and SEC3 stay below 5/5 until a real security
owner approves current evidence or records remediation.
Set `SECURITY_ACCOUNT_ATTESTATION_JSON_OUTPUT` when rendering the owner record
to also produce the machine-readable JSON form. A later collector run can take
that file through `SECURITY_ACCOUNT_ATTESTATION_EVIDENCE`; the collector only
accepts it when the attested aggregate counts match the live IAM evidence and
the owner decisions are current, unexpired, and approved.

| Exception | Status | Owner | Expiry | Required follow-up |
| --- | --- | --- | --- | --- |
| Human MFA/SSO evidence | Open external control | Repository admin plus security reviewer | Before final 5/5 claim | Prove organization or repository human-access policy without exposing private user data. |
| Live GuardDuty/Security Hub/AWS Config posture | Closed for current test stack | Security reviewer plus SRE | Monthly after apply | Metadata-only checks on 2026-05-09 UTC proved detector, hub, recorder, and delivery channel posture; refresh after security-account changes. |
| Test stack secrets-provider migration | Closed for current local evidence | Maintainer plus security reviewer | Per stack backend or secrets-provider change | Guarded local plan/apply and drift used the configured AWS KMS provider; managed workflow run `25606158994` remains historical evidence of why KMS-provider validation is required. |
| Permissions boundary or exemption attestation | Open external control | Security reviewer | Before final 5/5 claim | Record administrator-owned boundary ARN or approved exemption. |
