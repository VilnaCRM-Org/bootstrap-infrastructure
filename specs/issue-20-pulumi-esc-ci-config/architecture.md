# Architecture: Issue 20 AWS Secrets Manager CI Configuration

> **Historical design, amended for the PR57 successor (2026-09-06).**
> The September [successor verification](pr57-successor-verification.md) is the
> current implementation contract. Earlier references to a sole `prod`
> deployment environment, workflow-path-only trust, or optional role fallbacks
> are superseded. Retain all installed protected command environments, exact
> workflow/ref and immutable repository identity conditions, independent account
> pins, operator ownership, and fail-closed purpose-specific roles. This document
> is requirements lineage, not current live or BMAD acceptance.

## Control Boundaries

AWS Secrets Manager owns the privileged account-local configuration. GitHub
Actions uses GitHub OIDC to assume one `GitHubCiConfigRead-*` role per fixed CI
suffix, reads one AWS Secrets Manager JSON secret, and exports selected keys as
workflow environment variables. Pulumi Cloud and Pulumi ESC are not used. GitHub
`prod` protects platform production apply with human approval and branch
restrictions. Protected `test`, `test-preview`, and `prod-preview` environments
remain in use for their respective test and preview jobs.

```text
GitHub workflow
  -> GitHub repository variables select the config-read role ARN and region
  -> GitHub OIDC assumes the fixed GitHubCiConfigRead-* role
  -> AWS Secrets Manager loader reads the fixed CI secret suffix
  -> scripts/validate_ci_environment.py validates exported variables
  -> aws-actions/configure-aws-credentials assumes purpose-specific role
  -> Make/Pulumi command runs with sanitized evidence
```

Fork pull requests stay on the existing unprivileged artifact path and do not
request OIDC.

## AWS CI Config Contract

Each fixed suffix maps to one AWS Secrets Manager JSON secret:

| AWS Secrets Manager CI secret suffix | AWS Secrets Manager secret ID |
| --- | --- |
| `test-pr` | `/bootstrap-infrastructure/ci/test-pr` |
| `test` | `/bootstrap-infrastructure/ci/test` |
| `prod-preview` | `/bootstrap-infrastructure/ci/prod-preview` |
| `prod` | `/bootstrap-infrastructure/ci/prod` |

The Pulumi `test` stack creates the `test-pr` and `test` AWS Secrets Manager
secret containers plus matching `GitHubCiConfigRead-*` roles. The Pulumi `prod`
stack creates the `prod-preview` and `prod` containers plus matching production
read roles. The platform `CiConfiguration` component owns containers and read
roles, not values. The separate operator `GitHubCiBootstrap` component defaults
to `write_secret_values=True` and manages encrypted `SecretVersion` resources
from its generated CI payloads; setting that option false leaves version
management external. Check the owning component before rotating values, because
an operator apply can replace a manually changed managed payload. The
`githubCiConfigReadRoleArns` stack output gives operators
the role ARNs to store as GitHub repository variables.

Common AWS CI config variables:

- `AWS_ACCOUNT_ID`
- `AWS_REGION`
- `PULUMI_BACKEND_URL`
- `PULUMI_SECRETS_PROVIDER`

Purpose-specific AWS CI variables:

- `AWS_PREVIEW_ROLE_ARN`
- `AWS_APPLY_ROLE_ARN`
- `AWS_DRIFT_ROLE_ARN`
- `AWS_OPERATIONS_ALERT_TRIAGE_ROLE_ARN`
- `OPERATIONS_ALERT_QUEUE_NAME`
- `OPERATIONS_TOPIC_ARN`
- `OPERATIONS_CLOUDTRAIL_NAME`
- `PULUMI_PREVIEW_STACKS`
- `PULUMI_DRIFT_STACKS`

Pulumi stack config may include only non-account-local static configuration.
Do not use Pulumi config to store AWS account IDs, role ARNs, backend URLs,
stack lists, or secrets-provider URIs. Shared CI stacks still initialize or
migrate with `--secrets-provider "$PULUMI_SECRETS_PROVIDER"`, and the provider
must be `awskms://`.

## AWS Trust Model

Purpose-specific non-production roles accept only their intended repository
subjects, selected from:

- `repo:VilnaCRM-Org/bootstrap-infrastructure:ref:refs/heads/main`
- `repo:VilnaCRM-Org/bootstrap-infrastructure:pull_request`
- `repo:VilnaCRM-Org/bootstrap-infrastructure:environment:test`
- `repo:VilnaCRM-Org/bootstrap-infrastructure:environment:test-preview`
- `repo:VilnaCRM-Org/bootstrap-infrastructure:environment:prod-preview`

This is not a shared allowlist for every role. Test and preview roles must not
accept production apply subjects. Platform production apply roles trust only:

- `repo:VilnaCRM-Org/bootstrap-infrastructure:environment:prod`

The ordinary alert workflow does not use a reusable-workflow
`job_workflow_ref` claim. The alert policy helper in `automation.py` binds the
ordinary `workflow` claim to `Operations Alert Issue Triage`, together with
`refs/heads/main`, repository and immutable repository/owner identity. The
operator-owned triage role in `ci_bootstrap.py` requires the same exact workflow
name, alongside audience, repository, main ref and immutable identity. Other
operator roles retain their purpose-specific conditions. AWS supports this
ordinary workflow-name condition in its [GitHub OIDC claim mapping](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_iam-condition-keys.html#condition-keys-wif).
Verify the actual consumed role policy before activating v2; a workflow-name
condition does not restrict the workflow file path.

## Operations Alert Dedupe

`scripts/operations_alert_triage.py` renders sanitized issue bodies and a stable
fingerprint marker:

```text
<!-- operations-alert:fingerprint=<hash> -->
```

The fingerprint uses durable alert identity fields such as source, detail type,
state, backup vault, backup plan, backup rule, resource ARN, stable
EventBridge detail, and resources. Generic nested `id` fields remain part of the
stable identity. It deliberately ignores the top-level event ID and explicitly
named occurrence IDs such
as SQS message ID, SNS message ID, backup job ID, request ID, and event time.
The workflow splits mixed SQS batches into one GitHub issue update per stable
alert stream, then deletes queue messages only after every issue creation or
comment creation succeeds.

Legacy alert issues created before this marker was introduced will not be
auto-deduped. V2 remains staged until the reviewed SRE mapping is complete.
Maintainers use the protected backfill and reconciliation procedures with
confirmed sanitized stable fields; v1 hashes alone do not establish v2 identity.

The manual Operations Alert Legacy Reconcile workflow gives SREs a GitOps-owned
cleanup path after confirmation. It requires a canonical fingerprinted issue,
requires an HTTPS SRE confirmation reference, rejects already-fingerprinted
legacy issues, and closes confirmed legacy issues with
`gh issue close --duplicate-of`.

## Manual Secure Steps

- Apply the Pulumi `test` and `prod` stacks so AWS contains the four Secrets
  Manager containers and AWS CI config read roles.
- Populate the four AWS Secrets Manager JSON values in the owning AWS accounts.
- Configure the repository role-locator variables after verifying the secret
  containers and their populated account-local values; the pinned loader reads
  them without publishing their values.
- Configure GitHub-to-AWS OIDC for this repository and GitHub OIDC for each
  AWS Secrets Manager read role.
- Apply the Pulumi trust-policy update in each AWS account through the normal
  stack process.
- Keep the installed protected test, preview and production environments,
  reviewers and deployment branch restrictions in place.
- Verify test-account AWS metadata with local AWS CLI credentials and
  production metadata with AWS MCP/read-only access before enabling apply.
