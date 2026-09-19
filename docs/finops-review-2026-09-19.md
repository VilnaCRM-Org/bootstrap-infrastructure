# Account cost review — 19 September 2026

## Target and status

The target is **less than USD 100 per month combined, including tax**, for test
(`891377212104`) and production (`933245420672`). It is not USD 100 per account.
The target is **not yet achieved or forecast to be achieved by this PR**.

This patch disables Security Hub CSPM and stops the customer-managed AWS Config
recorder **only when both the environment is `test` and the AWS account is
`891377212104`**, as explicitly approved by the owner on 19 September 2026.
Production and other account/environment combinations retain both services.
The Config recorder, delivery channel, bucket and existing retention remain;
GuardDuty, CloudTrail, encryption and backups are unchanged.

It also allocates default account budgets of USD 30 for test and USD 65
for production, explicitly includes tax, and preserves explicit configuration
overrides. Budgets are alerts, not spending caps, and save no money by themselves.
Existing configured limits must be reviewed through the saved-plan deployment
workflow; changing defaults does not override a configured USD 100 limit.

No AWS resource was changed manually during this audit. No production apply was
performed. These are proposed changes awaiting reviewed IaC deployment, not
realized savings.

## Billing evidence

Read-only Cost Explorer queries used `UnblendedCost`, monthly granularity and
service/usage-type grouping. Service amounts exclude tax; account totals include
the separate Tax service. September figures are partial, with the exclusive
query end date `2026-09-19`. They are not a full-month bill.

| Account | August total | September console month-end forecast |
| --- | ---: | ---: |
| Production | $89.35 | $112.71 |
| Test | $32.03 | $42.37 |
| Combined | $121.38 | $155.08 |

Forecasts are estimates, not budgets or guarantees. August is the completed
baseline; the September forecast makes the required saving materially larger.

| Service | Production, September 1–18 | Test, September 1–18 |
| --- | ---: | ---: |
| Security Hub | $13.711 | $7.613 |
| AWS Config | $6.570 | $5.787 |
| KMS | $3.131 | $3.750 |
| GuardDuty | $1.071 | $2.278 |
| CodeBuild | $13.790 | not in the top ten |
| CodePipeline | $3.292 | not in the top ten |
| WAF | $10.798 | not in the top ten |
| CloudWatch | $3.876 | not in the top ten |
| Secrets Manager | $1.613 | $1.546 |
| S3 | $0.566 | $1.173 |
| Tax | $12.280 | $5.320 |

These are account service totals, not exact repository allocations. KMS and
security services support multiple workloads. Do not attribute every build to
bootstrap or every KMS key exclusively to platform overhead.

Production Security Hub charges inspected for September were 13,711 paid
compliance checks at $0.001 each. Free findings ingestion cost $0. Production
has CIS AWS Foundations v1.2.0 and AWS Foundational Security Best Practices v1.0.0
enabled in Frankfurt. A request to aggregate active findings was throttled, so
there is no verified per-control cost ranking.

Config usage was:

| Account | Continuous configuration items | Daily configuration items |
| --- | ---: | ---: |
| Production | 614 / $1.842 | 394 / $4.728 |
| Test | 405 / $1.215 | 381 / $4.572 |

The live production recorder matches the code: all supported resource types,
global resources included, default DAILY recording. Daily items cost four times
as much per item as continuous items in this observed bill, but switching modes
can increase the number of items and security checks. Do not assume that changing
to continuous recording guarantees a 75% saving.

Test's Config inventory includes 923 `AWS::Config::ResourceCompliance` records,
461 backup recovery points, 205 IAM policies and 105 IAM roles. Inventory counts
are not monthly billed item counts. They do not establish savings from exclusions.

Test recorder inspection found the customer-managed
`bootstrap-test-configuration-recorder` in DAILY mode, and recorder listing
returned one PAID recorder without a service principal. All 355 Config rules
returned were created by `securityhub.amazonaws.com` (335 AWS-owned and 20
CUSTOM_LAMBDA source rules). No separately created rule was observed. The test
account is not a Security Hub organization administrator; the administrator
lookup returned no administrator. Recheck these conditions at deployment time.

## Savings already proposed in application repositories

- [Website PR #123](https://github.com/VilnaCRM-Org/website-infrastructure/pull/123)
- [CRM PR #54](https://github.com/VilnaCRM-Org/crm-infrastructure/pull/54)

The estimated recurring opportunity is $4.60/month in ineffective alarms plus
$9/month from an **opt-in, separately staged** shared-WAF migration. Defaults
retain the dedicated CRM WAF. These are prospective, before-tax estimates, not
realized savings. Build/path filtering and artifact-log fixes have additional
usage-dependent savings that have not been priced.

At unchanged August usage, the approved test exception plus both application
opportunities total about $30.22/month before tax. Subtracting only those amounts
from August's $121.38 tax-inclusive bill yields $91.16, before any corresponding
tax reduction. This is a historical scenario, not a September forecast. The WAF
saving requires the staged migration; merging its defaults does not realize it.

September production CodeBuild already exceeds August's $7.40. A sample of the
100 most recent production builds included website regression batches and CRM
sandbox builds. The sample is not a complete September usage allocation; summed
phase time is not invoice-equivalent billed time. Removing tests, changing their
cadence or retiring sandboxes requires a workflow decision and consumer checks.

## Approved test exception and remaining decisions

1. **Test Security Hub and Config:** disabling these would remove automated test
   posture/compliance checks and new configuration history. Retain production
   controls, GuardDuty, CloudTrail, encryption and backups. August test service
   charges were $11.915 + $4.704 = $16.619. September's $13.40 over 18 days implies
   about $22.33 for 30 days if usage stays constant, not a verified forecast.
   The owner **approved this test-only exception**, and it is implemented in
   this PR. It does not by itself guarantee the combined account target.
   Security Hub disables findings ingestion too; GuardDuty remains available
   directly and its existing EventBridge alert rules remain unchanged.
   AWS permanently deletes archived Security Hub findings after 30 days and
   active findings/configuration after 90 days of disablement. Existing Config
   bucket history remains under its existing lifecycle, not indefinite retention.
2. **Narrower Config recording:** excluding compliance-history records or unused
   resource types may save money while retaining selected security checks, but
   removes parts of configuration/compliance history and requires dependency
   analysis. No exclusion is enabled by this PR.
3. **Build cadence:** running expensive application regression suites less often
   can reduce build charges but delays feedback. Keep per-release checks unless
   the owner approves a different cadence.
4. **Historical logs/replicas:** noncurrent versions and replicas need a separate
   retention decision. Do not delete historical evidence to meet a cost target.
5. **KMS:** do not delete or consolidate keys without encrypted-state, secret,
   backup and recovery dependency analysis. Keeping an old key for decryption
   means its fixed charge remains.

## Rollout and proof

Use existing IaC ownership: platform Pulumi owns these account controls; do not
create competing Terraform resources. Follow the repository's protected,
saved-plan test-then-prod workflow. Review budget configuration overrides and
confirm tax-inclusive limits in each plan. No automatic resource shutdown is
introduced.

The TEST plan must show deletion of only the Security Hub account resource
`security-account-controls-security-hub` for the security exception, plus
`isEnabled: true -> false` on the existing Config recorder status. No Config
recorder, delivery channel, bucket, KMS key, GuardDuty detector or backup may be
deleted. Use the existing `allow-destructive-infra-change` review mechanism for
the deliberate Security Hub removal; do not weaken the deletion guardrail.
The PROD plan must retain Security Hub and enabled Config recording, with only
the intended budget changes. Abort if these boundaries do not match the plan.

Before the TEST apply, verify that no organization policy will re-enable CSPM,
and inspect all customer/service-linked Config recorders and standalone rules.
Stopping a customer-managed recorder does not stop a service-linked recorder or
necessarily stop standalone periodic rule evaluations. Include any further
changes through their actual IaC owner, never manual cleanup. If findings must
be preserved beyond AWS's disablement retention, arrange a reviewed export
before applying; this PR does not export sensitive findings.

After apply, check `securityPostureEnabled=false`, Config recorder status stopped,
Security Hub disabled in Frankfurt, and continuing GuardDuty/CloudTrail coverage.
`securityHubAccountArn` resolves to `None` in the disabled test account and is
omitted from serialized Pulumi stack outputs; use `securityPostureEnabled` as the
explicit status instead of expecting a JSON `null` ARN. Production retains its ARN.
AWS may take time to remove service-linked rules; investigate residual charges
before claiming zero Config/Security Hub cost. To roll back, revert the explicit
test account exception and use a newly reviewed saved plan to re-enable CSPM and
Config. Deleted Security Hub findings cannot be recovered by a code rollback.

After approved changes deploy, compare full-month or normalized daily costs at
similar workload levels, separately report tax/credits, and inspect month-end
forecast again. A PR, a green test suite or a budget alert does not prove the
bill is below USD 100. Already incurred charges cannot be undone by this change.

## References

- [Security Hub CSPM pricing](https://aws.amazon.com/security-hub/cspm/pricing/):
  identical controls shared by standards are charged once; disabling a duplicate
  standard does not remove those shared-check charges.
- [Config recording-frequency analysis](https://aws.amazon.com/blogs/mt/best-practices-for-analyzing-aws-config-recording-frequencies/)
- [Config scope and compliance-history tradeoffs](https://aws.amazon.com/blogs/security/optimize-aws-config-for-aws-security-hub-to-effectively-manage-your-cloud-security-posture/)
- [AWS Budgets cost types](https://docs.aws.amazon.com/aws-cost-management/latest/APIReference/API_budgets_CostTypes.html)
- [Security Hub CSPM disablement and data retention](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-disable.html)
- [Config customer-managed versus service-linked recorders](https://docs.aws.amazon.com/config/latest/developerguide/stop-start-recorder.html)
