# Architecture: Issue 20 AWS Secrets Manager CI Configuration

## Control Boundaries

AWS Secrets Manager owns the privileged account-local configuration. GitHub
Actions uses GitHub OIDC to assume one `GitHubCiConfigRead-*` role per fixed CI
suffix, reads one AWS Secrets Manager JSON secret, and exports selected keys as
workflow environment variables. Pulumi Cloud and Pulumi ESC are not used. GitHub
`prod` remains the only deployment environment because it adds human approval
and branch restrictions for production apply.

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
read roles. Pulumi does not own secret versions or secret values; operators
populate and rotate the JSON payloads directly in AWS Secrets Manager after the
containers exist. The `githubCiConfigReadRoleArns` stack output gives operators
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

Non-production automation roles trust:

- `repo:VilnaCRM-Org/bootstrap-infrastructure:ref:refs/heads/main`
- `repo:VilnaCRM-Org/bootstrap-infrastructure:pull_request`

Production apply roles trust only:

- `repo:VilnaCRM-Org/bootstrap-infrastructure:environment:prod`

Trust conditions also bind
`token.actions.githubusercontent.com:job_workflow_ref` to the workflow files
that need the role. The operations alert triage role trusts only
`operations-alert-triage.yml@refs/heads/main`.

## Operations Alert Dedupe

`scripts/operations_alert_triage.py` renders sanitized issue bodies and a stable
fingerprint marker:

```text
<!-- operations-alert:fingerprint=<hash> -->
```

The fingerprint uses durable alert identity fields such as source, detail type,
state, backup vault, backup plan, backup rule, resource ARN, stable
EventBridge detail, and resources. It deliberately ignores occurrence IDs such
as SQS message ID, SNS message ID, backup job ID, request ID, and event time.
The workflow splits mixed SQS batches into one GitHub issue update per stable
alert stream, then deletes queue messages only after every issue creation or
comment creation succeeds.

Legacy alert issues created before this marker was introduced will not be
auto-deduped. The first post-merge run creates or updates a canonical
fingerprinted issue. Maintainers can then link and close older duplicates after
confirming the sanitized AWS Backup events share the same underlying stream, or
they can edit one chosen issue body to include the computed marker from retained
raw payloads.

The manual Operations Alert Legacy Reconcile workflow gives SREs a GitOps-owned
cleanup path after confirmation. It requires a canonical fingerprinted issue,
requires an HTTPS SRE confirmation reference, rejects already-fingerprinted
legacy issues, and closes confirmed legacy issues with
`gh issue close --duplicate-of`.

## Manual Secure Steps

- Apply the Pulumi `test` and `prod` stacks so AWS contains the four Secrets
  Manager containers and AWS CI config read roles.
- Populate the four AWS Secrets Manager JSON values in the owning AWS accounts.
- Create the four AWS Secrets Manager CI secrets and configure each one to import its JSON
  secret with `aws secretsmanager get-secret-value`.
- Configure GitHub-to-AWS OIDC for this repository and GitHub OIDC for each
  AWS Secrets Manager read role.
- Apply the Pulumi trust-policy update in each AWS account through the normal
  stack process.
- Keep protected GitHub `prod` reviewers and deployment branch restrictions in
  place.
- Verify test-account AWS metadata with local AWS CLI credentials and
  production metadata with AWS MCP/read-only access before enabling apply.
