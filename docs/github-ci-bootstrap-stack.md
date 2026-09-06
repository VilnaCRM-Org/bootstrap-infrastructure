# GitHub CI AWS Bootstrap Stack

The isolated `pulumi/github-ci-bootstrap` project owns privileged platform
control IAM and CI configuration in each AWS account. Pulumi Cloud and Pulumi
ESC are not used. A reviewed local operator identity performs any authorized
bootstrap update; ordinary GitHub CI roles never receive `AdministratorAccess`.
Adding this source does not authorize an apply or a state migration.

## Resource ownership

Per account, the operator creates or adopts:

- the GitHub Actions OIDC provider, fixed CI secret containers and encrypted
  `SecretVersion` values under `/bootstrap-infrastructure/ci/`;
- purpose-specific `GitHubCiConfigRead-*`, `GitHubCiPreview-*`,
  `GitHubCiApply-*` and `GitHubCiDrift-*` roles;
- `OperationsAlertTriage-*` in TEST;
- platform immutable permission boundaries, legacy `PulumiAutomation` and
  `PulumiDeploy` control IAM, Config recorder IAM, and fixed platform state/log
  replication IAM;
- three dedicated governor runner roles and per-catalog immutable service and
  replication boundaries, exported through `governanceGithubVariables`.

The normal platform entrypoint uses `manage_control_resources=False` and reads
these identities. Preserve resource names, parents, provider references, adoption
overrides and explicit boundary dependencies. Removing governor prerequisites
would drop resources the existing operator checkpoint may already own.
`repositories.governance.json` contains actual repository and owner IDs; this
inventory does not create governed service buckets, keys, CI roles or secrets.
The delegated `pulumi/governance` program and service onboarding remain #78 work.

## CI Role Mapping

| Workflow job | CI suffix | Runtime role | Permission set |
| --- | --- | --- | --- |
| PR guardrails preview | `test-pr` | `AWS_PREVIEW_ROLE_ARN` | preview |
| PR guardrails IAM validation | `test-pr` | `AWS_PREVIEW_ROLE_ARN` | preview plus IAM validation |
| Test deploy preview | `test` | `AWS_PREVIEW_ROLE_ARN` | preview |
| Test deploy apply | `test` | `AWS_APPLY_ROLE_ARN` | apply |
| Test deploy drift | `test` | `AWS_DRIFT_ROLE_ARN` | drift |
| Prod preview | `prod-preview` | `AWS_PREVIEW_ROLE_ARN` | preview |
| Prod apply | `prod` | `AWS_APPLY_ROLE_ARN` | apply through GitHub `prod` environment |
| Prod drift | `prod-preview` | `AWS_DRIFT_ROLE_ARN` | drift |
| Nightly drift | `test`, `prod-preview` | `AWS_DRIFT_ROLE_ARN` | drift |
| PR command runner | `test`, `prod-preview`, `prod` | preview/apply/drift role by command | matching command role |
| Well-Architected evidence | `test-pr` or `test` | `AWS_PREVIEW_ROLE_ARN` | preview plus account evidence reads |
| Operations alert triage | `test` | `AWS_OPERATIONS_ALERT_TRIAGE_ROLE_ARN` | SQS triage |

## Permission shape and trust

Evaluate the complete identity-policy union together with immutable permission
boundaries and explicit denies. The platform apply role cannot mutate operator
control roles, OIDC, CI secrets or their boundaries. Its workload grants remain
account/repository-bound. Config-read roles can describe/read exactly their fixed
CI secret; preview/drift may use their backend and KMS provider but deny CI
payload reads. Preview/drift backend writes are limited to lock objects.
Governor apply can update its dedicated backend checkpoint and only the exact
catalog resource inventory; it cannot widen its own roles or service boundaries.

Trust pins audience, immutable repository/owner IDs, exact repository subject,
branch and purpose. Ordinary workflows bind the `workflow` claim;
`job_workflow_ref` is for reusable workflows. Workflow names alone do not attest
code. Command preview/drift use protected `test-preview`/`prod-preview`, apply
uses `test`/`prod`, and governor preview/drift and apply use
`governance-preview` and `governance`. The `test-pr` suffix does not authorize
apply. Preserve the installed main-branch and environment trust contracts.

Wildcard actions/resources are not a general exception: inspect effective
permissions and quotas against the actual rendered documents. Existing platform
full-document policy pins do not exempt governor policies from NFR5. Review all
trust, managed and inline policy sizes, aggregate role limits and retained
policies before changing permissions.

## Reviewed local operator procedure

Use an approved short-lived local AWS profile. Verify `aws sts
get-caller-identity` returns the independently expected account and approved
operator role: TEST `891377212104`, PROD `933245420672`, region `eu-central-1`.
If assuming a role, verify the caller first and use the approved role mapping.
Never rely on a role name or stack selection as proof of account identity.

Before preview, bind the exact source commit, immutable GitHub repository/owner
IDs and catalogs to the canonical operator project `github-ci-bootstrap`, stack,
backend, checkpoint VersionId/ETag, KMS provider/key and retained-policy inventory.
Confirm single state ownership and encrypted backups of affected checkpoints.
Existing deployments require the separately reviewed ownership migration to be
complete; a code-mode switch cannot repair duplicate owners. Reject unintended
deletion, replacement, import or provider/role ownership drift.

The operator's own backend is distinct from `github-ci-bootstrap:pulumiBackendUrl`.
That configuration field is emitted into platform CI payloads, typically with
`state/test` or `state/prod`. It must not redirect the operator project to the
platform checkpoint. Preserve the existing operator backend root, project/stack
identity and existing secrets-provider encrypted data key. Committed YAML holds
public configuration only. The installed helper reconstructs private provider
metadata from the exact checkpoint and refuses a missing or changed binding.
Initial state-only initialization is a separately approved trusted prerequisite,
never a repair fallback after a failed select, preview or apply.

After these prerequisites, use the repository helpers with literal backend
arguments matching the verified operator checkpoint. The following TEST example
is a template; replace the commit and profile only after independent review.
PROD requires its own account/backend/provider binding and review. Use the
corresponding stack and verified operator backend in both commands:

| Stack | Expected account | Operator backend root | AWS KMS provider |
| --- | --- | --- | --- |
| `test` | `891377212104` | `s3://pulumi-bootstrap-infrastructure-test-state` | `awskms://alias/pulumi-platform-bootstrap-test?region=eu-central-1` |
| `prod` | `933245420672` | `s3://pulumi-bootstrap-infrastructure-prod-state` | `awskms://alias/pulumi-platform-bootstrap-prod?region=eu-central-1` |

Verify these roots against the existing canonical checkpoint before use; this
table does not authorize relocating a stack. For PROD, change `AWS_ACCOUNT_ID`,
profile, backend, provider and `PULUMI_STACK` together, retain the same explicit
source/plan bindings, and independently review the PROD plan before replay.

```bash
AWS_PROFILE=<approved-test-operator-profile> \
AWS_ACCOUNT_ID=891377212104 \
PULUMI_COMMIT_SHA=<reviewed-source-commit> \
PULUMI_BACKEND_URL=s3://pulumi-bootstrap-infrastructure-test-state \
PULUMI_SECRETS_PROVIDER='awskms://alias/pulumi-platform-bootstrap-test?region=eu-central-1' \
make pulumi-plan PULUMI_DIR=pulumi/github-ci-bootstrap PULUMI_STACK=test
```

`make pulumi-plan` performs a refreshed preview with the policy pack and saves
both the exact plan and its manifest. Independently review the plan, policy pack,
trust/policy/boundary/secret changes, direct dependencies, quotas and destructive
diff/IAM validation results. Keep artifacts private and bind source, account,
backend, provider, retained policies and plan hashes in the review receipt.
Do not replay until the reviewer accepts that concrete plan.

```bash
AWS_PROFILE=<approved-test-operator-profile> \
AWS_ACCOUNT_ID=891377212104 \
PULUMI_COMMIT_SHA=<reviewed-source-commit> \
PULUMI_EXPECTED_SHA=<reviewed-source-commit> \
PULUMI_BACKEND_URL=s3://pulumi-bootstrap-infrastructure-test-state \
PULUMI_SECRETS_PROVIDER='awskms://alias/pulumi-platform-bootstrap-test?region=eu-central-1' \
make pulumi-up-plan PULUMI_DIR=pulumi/github-ci-bootstrap PULUMI_STACK=test
```

Replay only that saved plan. A failed apply does not authorize unsaved apply,
policy bypass, lock cancellation, secret-provider replacement or state repair.
Investigate the cause and obtain a fresh reviewed plan when a binding changes.
After replay, perform metadata-only readback and a refreshed zero-drift check
against the same operator checkpoint; retain its commit/account/plan receipt.
Operator receipts are not GitHub OIDC, protected-environment approval or actual
comment-deployment evidence. TEST and PROD evidence remain separate.

## Outputs To Capture

```bash
pulumi -C pulumi/github-ci-bootstrap stack output githubVariables --stack test
pulumi -C pulumi/github-ci-bootstrap stack output governanceGithubVariables --stack test
pulumi -C pulumi/github-ci-bootstrap stack output ciConfigurationSecretIds --stack test
pulumi -C pulumi/github-ci-bootstrap stack output githubCiConfigReadRoleArns --stack test
pulumi -C pulumi/github-ci-bootstrap stack output githubCiDeploymentRoleArns --stack test
pulumi -C pulumi/github-ci-bootstrap stack output operationsAlertTriageRoleArn --stack test

pulumi -C pulumi/github-ci-bootstrap stack output githubVariables --stack prod
pulumi -C pulumi/github-ci-bootstrap stack output governanceGithubVariables --stack prod
pulumi -C pulumi/github-ci-bootstrap stack output ciConfigurationSecretIds --stack prod
pulumi -C pulumi/github-ci-bootstrap stack output githubCiConfigReadRoleArns --stack prod
pulumi -C pulumi/github-ci-bootstrap stack output githubCiDeploymentRoleArns --stack prod
```

Capture `governanceGithubVariables` separately as operator prerequisite metadata;
it is not completed service onboarding. Set the GitHub repository variables from
`githubVariables`, plus independently verified account pins:

```bash
gh variable set AWS_TEST_ACCOUNT_ID --body '891377212104'
gh variable set AWS_TEST_REGION --body '<region>'
gh variable set AWS_TEST_PR_CI_CONFIG_ROLE_ARN --body '<test-pr-config-read-role-arn>'
gh variable set AWS_TEST_CI_CONFIG_ROLE_ARN --body '<test-config-read-role-arn>'
gh variable set AWS_PROD_ACCOUNT_ID --body '933245420672'
gh variable set AWS_PROD_REGION --body '<region>'
gh variable set AWS_PROD_PREVIEW_CI_CONFIG_ROLE_ARN --body '<prod-preview-config-read-role-arn>'
gh variable set AWS_PROD_CI_CONFIG_ROLE_ARN --body '<prod-config-read-role-arn>'
```

## Secret Payloads

By default, the stack writes the required AWS Secrets Manager JSON values with
Pulumi secret encryption. The payloads contain no static credentials.

The operator normally owns these values. A separately reviewed secret-management
operation may use `put-secret-value` with a private local JSON file when
`writeSecretValues` is disabled; reconcile its state ownership before a later
operator replay. These examples are not an automatic payload repair procedure:

```bash
AWS_PROFILE=<test-admin-profile> aws secretsmanager put-secret-value \
  --secret-id /bootstrap-infrastructure/ci/test-pr \
  --secret-string file://<test-pr-payload>.json

AWS_PROFILE=<test-admin-profile> aws secretsmanager put-secret-value \
  --secret-id /bootstrap-infrastructure/ci/test \
  --secret-string file://<test-payload>.json

AWS_PROFILE=<prod-admin-profile> aws secretsmanager put-secret-value \
  --secret-id /bootstrap-infrastructure/ci/prod-preview \
  --secret-string file://<prod-preview-payload>.json

AWS_PROFILE=<prod-admin-profile> aws secretsmanager put-secret-value \
  --secret-id /bootstrap-infrastructure/ci/prod \
  --secret-string file://<prod-payload>.json
```

Verify with `describe-secret`. Do not use `get-secret-value` for verification.
