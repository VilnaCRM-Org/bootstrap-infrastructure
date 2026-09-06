# Architecture: Issue 59 GitHub CI AWS Bootstrap

## PR60 successor amendment — 2026-09-06

The sections below retain historical requirements, stories and evidence. Their
active interpretation is defined by [the scoped successor verification](pr60-successor-verification.md)
and the installed [trusted-controller contract](../trusted-controller-installation/prd.md)
and [architecture](../trusted-controller-installation/architecture.md).
Historical readiness scores, approvals and runs do not establish current-head
acceptance. Current purpose-specific CI/governor ordinary-workflow trusts use
the `workflow` claim; `job_workflow_ref` is reserved for reusable workflow trust.
Current protected environments, immutable repository IDs, saved-plan replay and
operator-only ownership supersede the
historical design. The operational procedure below uses reviewed saved-plan
creation and exact replay; unsaved apply is not a recovery procedure.

The successor ships the independent operator program, governor runner roles and
immutable boundary prerequisites. Delegated governance resource construction,
service scaffolding and onboarding remain deferred to #78. Current source checks,
hosted review, BMAD and live acceptance are recorded separately in the amendment.

## Control Boundaries

AWS is the control plane for CI configuration and Pulumi secret encryption.
The privileged operator needs a separately authorized short-lived identity in
its exact account. Existing ordinary GitHub workflows receive short-lived AWS
credentials through OIDC and scoped roles; they cannot modify the operator's
own authority. This PR installs the operator program, not a privileged GitHub
operator executor. Such an executor requires separately reviewed OIDC seeding
and protected workflow installation; local root applies are not final GitHub
deployment acceptance.

```text
Privileged operator execution
  -> separately authorized short-lived identity for test or prod
  -> reviewed saved plan with the exact S3 backend and KMS secrets provider
  -> pulumi/github-ci-bootstrap stack
  -> AWS IAM OIDC provider, roles, policies, and Secrets Manager payloads

GitHub Actions
  -> repository variables select config-read role and AWS region
  -> GitHub OIDC assumes one config-read role
  -> AWS Secrets Manager returns the fixed CI JSON payload
  -> workflow assumes preview, apply, drift, or operations role
```

Pulumi Cloud and Pulumi ESC are not in the control path.

## Tech Stack

- Pulumi Python for infrastructure definitions.
- AWS IAM for OIDC trust, role boundaries, and inline role policies.
- AWS Secrets Manager for CI configuration JSON payload storage.
- AWS S3 for Pulumi backend state.
- AWS KMS for Pulumi secrets-provider encryption.
- GitHub Actions OIDC for short-lived CI credentials.
- GitHub repository variables for non-secret role discovery values.

## Bootstrap Stack Contract

The isolated project at `pulumi/github-ci-bootstrap` composes the shared
`PlatformIamBoundaries`, `GitHubCiBootstrap`, `PlatformControlIam` and
`GovernanceAutomation` components. It owns bootstrap CI resources, platform
control IAM, immutable platform/service/replication boundaries and governor
runner prerequisites. It is excluded from ordinary platform stack discovery.
The delegated governance program, service construction and onboarding belong
to PR78; platform and governor roles cannot provision their own operator roots
of trust.

| Stack | AWS account | CI suffixes | Special role |
| --- | --- | --- | --- |
| `test` | `891377212104` | `test-pr`, `test` | Operations alert triage |
| `prod` | `933245420672` | `prod-preview`, `prod` | None |

The stack writes protected IAM and Secrets Manager resources, emits role and
secret identifiers as stack outputs, and defaults to writing the generated CI
payload versions. Operators can disable payload writes with
`github-ci-bootstrap:writeSecretValues=false` when they need a container-only
repair.

## AWS Trust Model

Current purpose-specific CI, configuration-reader and governor roles bind the
audience, immutable repository/owner identity and allowed purpose context;
ordinary-workflow trusts use the allowed `workflow` claim, while reusable-workflow
trusts require the allowed `job_workflow_ref`. Legacy `PulumiAutomation` and
`PulumiDeploy` trusts bind their protected environment, main ref and immutable
repository/owner identity without a `workflow` claim; this legacy contract is
not proof of a workflow-pinned operator executor and must not be broadened.
A workflow name alone is not an attestation of source code. The simplified
subjects below are
historical categories; current generated policies also pin immutable repository
and owner IDs and the applicable exact protected context.

| Role type | Trusted subject |
| --- | --- |
| Test PR preview/config | `repo:VilnaCRM-Org/bootstrap-infrastructure:pull_request` |
| Test branch apply/drift/config | `repo:VilnaCRM-Org/bootstrap-infrastructure:ref:refs/heads/main` |
| Prod preview/drift/config | `repo:VilnaCRM-Org/bootstrap-infrastructure:ref:refs/heads/main` |
| Prod apply | `repo:VilnaCRM-Org/bootstrap-infrastructure:environment:prod` |

Preview and drift roles can read stack metadata and Pulumi backend state, but
they explicitly cannot read arbitrary Secrets Manager secret values. Apply roles
receive only the account-local mutation permissions needed by the Pulumi stack.

## AWS-Using CI Permission Inventory

Each platform workflow in the inventory below first assumes a config-read role
that can read exactly
one Secrets Manager CI payload. The workflow then assumes the second-stage role
from that payload for the actual AWS operation.

| Workflow job | Config suffix | Second-stage role | AWS purpose |
| --- | --- | --- | --- |
| `pulumi-pr-guardrails.yml` `Preview` on pull requests | `test-pr` | Test preview | PR Pulumi preview against shared test backend |
| `pulumi-pr-guardrails.yml` `IAM Validation` on pull requests | `test-pr` | Test preview | Access Analyzer validation for IAM policies from the preview artifact |
| `well-architected-evidence.yml` `Test Account Evidence` on pull requests | `test-pr` | Test preview | Read-only evidence collection for Well-Architected checks |
| `pulumi-test-deploy.yml` `Test Preview` | `test` | Test preview | Main-branch test plan creation |
| `pulumi-test-deploy.yml` `Test IAM Validation` | `test` | Test preview | Access Analyzer validation for test plan IAM policies |
| `pulumi-test-deploy.yml` `Test Apply` | `test` | Test apply | Apply the saved test plan |
| `pulumi-test-deploy.yml` `Test Post-Apply Drift` | `test` | Test drift | Verify no test drift after apply |
| `nightly-guardrails.yml` `Test Drift Detection` | `test` | Test drift | Scheduled test drift detection |
| `operations-alert-triage.yml` `Triage Operations Alerts` | `test` | Operations alert triage | Read/delete test operations SQS messages and create GitHub issues |
| `well-architected-evidence.yml` `Test Account Evidence` on `main` or schedule | `test` | Test preview | Read-only evidence collection from the protected branch |
| `pulumi-pr-command-runner.yml` test preview/IAM/apply/drift jobs | `test` | Test preview, apply, or drift | Maintainer-triggered test operations from trusted branch workflow refs |
| `pulumi-prod.yml` `Prod Preview` | `prod-preview` | Prod preview | Production plan creation |
| `pulumi-prod.yml` `Prod IAM Validation` | `prod-preview` | Prod preview | Access Analyzer validation for prod plan IAM policies |
| `pulumi-prod.yml` `Prod Apply` | `prod` | Prod apply | Apply saved production plan after GitHub `prod` environment approval |
| `pulumi-prod.yml` `Prod Post-Apply Drift` | `prod-preview` | Prod drift | Verify no production drift after apply |
| `nightly-guardrails.yml` `Prod Drift Detection` | `prod-preview` | Prod drift | Scheduled production drift detection |
| `pulumi-pr-command-runner.yml` prod preview/IAM/apply/drift jobs | `prod-preview` or `prod` | Prod preview, apply, or drift | Maintainer-triggered production operations with protected apply trust |

IAM validation intentionally uses the preview role because the helper can call
AWS Access Analyzer and, when artifacts are absent, may need the same read-only
Pulumi preview surface. It does not receive a separate apply-capable role.

## Secrets Manager Payload Contract

The bootstrap stack creates these fixed secrets:

| Suffix | Secret ID |
| --- | --- |
| `test-pr` | `/bootstrap-infrastructure/ci/test-pr` |
| `test` | `/bootstrap-infrastructure/ci/test` |
| `prod-preview` | `/bootstrap-infrastructure/ci/prod-preview` |
| `prod` | `/bootstrap-infrastructure/ci/prod` |

Payloads include account ID, region, Pulumi backend URL, AWS KMS
secrets-provider URL, stack lists, and purpose-specific role ARNs. The workflows
load one fixed suffix per job and validate the payload before assuming the
deployment role.

By default the bootstrap stack writes the generated Secrets Manager secret
versions. This replaces the earlier manual payload-entry step and reduces human
copy/paste of secret JSON. Operators can set
`github-ci-bootstrap:writeSecretValues=false` for a container-only repair; in
that mode they must write payloads later with `aws secretsmanager
put-secret-value --secret-string file://payload.json` from local files and must
not print the payloads in terminal output, PR comments, or documentation.

## GitHub Repository Variables

The stack output `githubVariables` provides the values operators set in the
repository:

- `AWS_TEST_REGION`
- `AWS_TEST_PR_CI_CONFIG_ROLE_ARN`
- `AWS_TEST_CI_CONFIG_ROLE_ARN`
- `AWS_PROD_REGION`
- `AWS_PROD_PREVIEW_CI_CONFIG_ROLE_ARN`
- `AWS_PROD_CI_CONFIG_ROLE_ARN`

These variables are not secret material; they only let GitHub locate the
account-local config-read roles.

## Privileged operator saved-plan procedure

Follow the complete account, state, provider and replay bindings in the
[operator guide](../../docs/github-ci-bootstrap-stack.md#reviewed-local-operator-procedure).
The guide's historical local operator identity is distinct from the separately
reviewed GitHub OIDC executor needed for final automation acceptance.

1. Verify the authorized short-lived identity, expected account, source revision
   and exact operator backend/project/stack. Preserve reviewed ownership and
   encrypted backups of existing checkpoints before any mutation.
2. Require the existing versioned operator checkpoint and KMS provider identity.
   First-stack initialization is separate explicit setup; missing state never
   triggers initialization, import, lock removal or direct-apply recovery.
3. Use `make pulumi-plan` with `PULUMI_DIR=pulumi/github-ci-bootstrap` and the
   explicit TEST stack, plus every account/backend/source binding from the guide.
   Review the saved plan, full IAM policy/trust union, resource ownership and
   deletion/replacement scope independently.
4. Replay only that reviewed plan with `make pulumi-up-plan`, retaining its
   exact source, checkpoint, provider, account and artifact bindings. Recheck
   refreshed drift and actual resource metadata afterward. Never use an unsaved
   apply or retry a failed plan against changed state.
5. Repeat for PROD only after the required TEST and production review gates.
   Final acceptance must include real GitHub/OIDC execution receipts; a local
   root apply does not substitute for them.
6. Verify and publish the nonsecret role/region variables from actual outputs.
   If payload writing was intentionally disabled, reconcile the exact fixed
   SecretVersions through a separate reviewed secret-management operation.
   Never print payloads or provider key material.
7. Rerun privileged CI and verify evidence enforcement, real comment-driven
   TEST/PROD saved-plan apply/drift and post-deployment QA. Source installation
   alone does not satisfy those acceptance gates.
