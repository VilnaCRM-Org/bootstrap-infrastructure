# Current Closeout Evidence: Issue 20 AWS Secrets Manager CI Configuration

Recorded on 2026-05-25 in the `Europe/Sofia` timezone for branch
`codex/issue20-pulumi-esc`.

## Audited PR Head

| Field | Value |
| --- | --- |
| PR | `https://github.com/VilnaCRM-Org/bootstrap-infrastructure/pull/57` |
| Latest implementation head SHA | `e0242f029d3e34217af13ec01328dd49778f1089` |
| Latest implementation short SHA | `e0242f0` |
| Source of truth | AWS Secrets Manager remains the source of truth for account-local CI values; Pulumi Cloud and Pulumi ESC are not used for CI configuration. |
| Secret handling | No secret values, `GetSecretValue` responses, decrypted stack outputs, access keys, or tokens were read or recorded. |

## GitHub State

Open repository issues at the time of this audit:

| Issue | State | Current disposition |
| --- | --- | --- |
| `#20` | Open | GitOps implementation is present in PR `#57`; live closeout still needs external AWS CI config/AWS setup and successful privileged checks. |
| `#49` | Open | Legacy unmarked operations-alert issue; do not close until a canonical fingerprinted issue exists and SRE confirms it is the same alert stream with a sanitized HTTPS confirmation reference. |
| `#50` | Open | Legacy unmarked operations-alert issue; do not close until a canonical fingerprinted issue exists and SRE confirms it is the same alert stream with a sanitized HTTPS confirmation reference. |
| `#52` | Open | Legacy unmarked operations-alert issue; do not close until a canonical fingerprinted issue exists and SRE confirms it is the same alert stream with a sanitized HTTPS confirmation reference. |
| `#53` | Open | Legacy unmarked operations-alert issue; do not close until a canonical fingerprinted issue exists and SRE confirms it is the same alert stream with a sanitized HTTPS confirmation reference. |
| `#54` | Open | Legacy unmarked operations-alert issue; do not close until a canonical fingerprinted issue exists and SRE confirms it is the same alert stream with a sanitized HTTPS confirmation reference. |
| `#55` | Open | Legacy unmarked operations-alert issue; do not close until a canonical fingerprinted issue exists and SRE confirms it is the same alert stream with a sanitized HTTPS confirmation reference. |
| `#56` | Open | Legacy unmarked operations-alert issue; do not close until a canonical fingerprinted issue exists and SRE confirms it is the same alert stream with a sanitized HTTPS confirmation reference. |

Current PR `#57` review state is approved, but merge state is still blocked
until the current local commits are pushed, hosted checks rerun, and external
AWS setup is completed. The latest audited remote checks before this refresh
had all repo-owned jobs green except a CodeQL check for clear-text logging of a
CI secret identifier and two expected privileged setup checks. The CodeQL issue
is fixed on implementation head `e0242f0` by removing the secret ID from the
validator summary.

The prior Pulumi Cloud-era privileged checks failed before AWS-only loading was
implemented:

```text
Invalid response from token exchange 400: Bad Request (invalid_request: invalid organization vilnacrm-org)
```

The AWS-only setup removes that Pulumi Cloud token exchange path. Remaining live
setup work is limited to valid AWS credentials, AWS Secrets Manager payloads,
and GitHub repository variables. Current AWS-only remote failures stop before
AWS credentials are requested because the repository variables are still empty:

```text
config-role-arn must be an AWS IAM role ARN.
```

Local validation on this implementation head passed:

- `uv run pytest tests/pulumi/test_ci_guardrails.py::test_well_architected_evidence_workflow_uploads_enforced_reports tests/pulumi/test_delivery_contracts.py::test_multi_account_workflows_use_fixed_aws_ci_config_contracts tests/unit/test_components.py::test_ci_configuration_manages_aws_secret_containers_and_github_read_roles tests/unit/test_mutation_targets.py::test_mutation_target_ci_config_validation_and_lookup_helpers -q`
- `uv run pytest tests/unit/test_validate_ci_environment.py -q`
- `uv run ruff check pulumi/infra/ci_config.py tests/pulumi/test_ci_guardrails.py tests/pulumi/test_delivery_contracts.py tests/unit/test_components.py tests/unit/test_mutation_targets.py scripts/validate_ci_environment.py tests/unit/test_validate_ci_environment.py`
- `make test-actionlint`
- `make test-yaml`
- `git diff --check`

## AWS Metadata Checks

### Test Account

Local AWS CLI checks for the test account could not prove live state because
the current Codex process still inherits stale `AWS_ACCESS_KEY_ID` and
`AWS_SECRET_ACCESS_KEY` values from its parent environment. `aws configure list`
therefore reports credentials from `env` and region `eu-central-1` from
`~/.aws/config` in this running session:

```text
aws sts get-caller-identity --output json
An error occurred (InvalidClientTokenId) when calling the GetCallerIdentity operation: The security token included in the request is invalid.
```

The stale shell startup exports were removed from `~/.bashrc`; backup:
`/home/kravtsov/.bashrc.codex-backup-20260525171555`. When those inherited
environment variables are explicitly unset for a command, AWS CLI uses the
shared credentials file and authenticates to production account `933245420672`,
not the test account `891377212104`:

```text
env -u AWS_ACCESS_KEY_ID -u AWS_SECRET_ACCESS_KEY -u AWS_SESSION_TOKEN aws sts get-caller-identity --output json
Account: 933245420672
Arn: arn:aws:iam::933245420672:user/codex
```

No test-account profile is configured locally yet. No test-account issue should
be closed from this workstation until a maintainer configures a dedicated test
profile and reruns metadata-only verification against account `891377212104`.

### Production Account

AWS MCP metadata checks succeeded for account `933245420672` with caller
`arn:aws:iam::933245420672:user/codex`.

The production operations queue exists:

| Field | Value |
| --- | --- |
| Queue name | `bootstrap-prod-operations-alerts` |
| Queue ARN | `arn:aws:sqs:eu-central-1:933245420672:bootstrap-prod-operations-alerts` |
| Region | `eu-central-1` |
| Visible messages | `1` |
| Not-visible messages | `0` |
| Delayed messages | `0` |
| SSE | `SqsManagedSseEnabled=true` |

The production AWS CI config AWS backing resources for this PR are not present yet:

| Resource | Metadata-only result |
| --- | --- |
| `/bootstrap-infrastructure/ci/prod-preview` | `ResourceNotFoundException` from `secretsmanager:DescribeSecret` |
| `/bootstrap-infrastructure/ci/prod` | `ResourceNotFoundException` from `secretsmanager:DescribeSecret` |
| `GitHubCiConfigRead-bootstrap-infrastructure-prod-preview` | `NoSuchEntityException` from `iam:GetRole` |
| `GitHubCiConfigRead-bootstrap-infrastructure-prod` | `NoSuchEntityException` from `iam:GetRole` |

That absence is expected before the reviewed Pulumi `prod` stack has been
applied. It also proves production privileged checks cannot be treated as
complete yet.

## Issue 20 Acceptance Status

| Requirement | Current evidence | Status |
| --- | --- | --- |
| Fixed privileged AWS Secrets Manager CI secrets | Workflows call `.github/actions/load-aws-ci-env` with fixed suffixes such as `test-pr`, `test`, `prod-preview`, and `prod`; same-repo PR Well-Architected evidence now uses `test-pr` instead of the main-branch `test` trust path. | GitOps implemented |
| AWS Secrets Manager source of truth | Pulumi creates secret containers and GitHub OIDC read roles; docs/tests state values stay in AWS Secrets Manager and must not be copied into Pulumi config, GitHub variables, workflow logs, or docs. | GitOps implemented |
| No GitHub `test` or `prod-preview` deployment environments for non-approval jobs | Workflow contracts and tests enforce only protected production apply uses `environment: prod`. | GitOps implemented |
| Production approval preserved | Protected GitHub `prod` Environment remains the production apply approval boundary. | GitOps implemented; repository-admin verification still required |
| Protected manual reconcile gate | The repository controls helper now prints, applies, and verifies both `prod` and `operations-alert-reconcile`; the manual reconcile workflow requires `operations-alert-reconcile` and has no AWS/OIDC permission. | GitOps implemented; repository-admin verification still required |
| Fork PR isolation | Fork paths stay unprivileged and do not open AWS CI config or request AWS credentials. | GitOps implemented |
| KMS-backed Pulumi secrets provider | Validators require `awskms://` for shared CI stack configuration. | GitOps implemented |
| Live AWS secret load and AWS role assumption | Privileged checks require the AWS-only GitHub variables, read roles, and Secrets Manager payloads. | Manual secure setup required |
| AWS Secrets Manager payloads populated | Pulumi intentionally does not manage `SecretVersion` resources or JSON values. | Manual secure setup required |
| Legacy GitHub Environment variable cleanup | Cleanup workflow is present and confirmation-gated. | Run manually only after AWS Secrets Manager-backed privileged CI is green |

## Legacy Operations Alert Issues

Issues `#49`, `#50`, and `#52` through `#56` all reference
`bootstrap-test-operations-alerts` in account `891377212104`,
region `eu-central-1`, and AWS Backup `Backup Job State Change` events. None
of those issue bodies contains an `operations-alert:fingerprint=` marker.

Live `main` does not yet contain the fingerprint-aware triage workflow or the
manual reconcile workflow from PR `#57`, and the live repository does not yet
have an `operations-alert-reconcile` protected Environment. Do not close those
issues automatically. The safe GitOps path is:

1. Merge and run the fingerprint-aware operations alert triage workflow, or
   recover a computed fingerprint from retained raw payloads without exposing
   payload contents.
2. Establish one canonical issue whose body contains
   `operations-alert:fingerprint=`.
3. Have SRE confirm the legacy issues match the same underlying alert stream,
   including state, vault, plan or rule, and protected resource. Retain a
   sanitized HTTPS confirmation reference without raw alert payloads,
   credentials, stack exports, tokens, or private incident notes.
4. Run **Operations Alert Legacy Reconcile** with the canonical issue and the
   confirmed legacy issue list plus the SRE confirmation reference.

Closure is safe only after SRE confirms the legacy issue list against the
canonical fingerprinted issue and records the sanitized confirmation reference.

## Manual Secure Steps Still Required

1. Apply the reviewed Pulumi `test` and `prod` stacks so AWS creates the four
   Secrets Manager containers and `GitHubCiConfigRead-*` roles.
2. Populate the four AWS Secrets Manager JSON values in the owning AWS accounts.
3. Configure GitHub repository variables with the `GitHubCiConfigRead-*` role
   ARNs and account regions.
4. Refresh local test-account AWS CLI credentials and rerun metadata-only
   verification.
5. Have a repository administrator run
   `GITHUB_REPOSITORY_CONTROLS_MODE=--apply make configure-github-repository-controls`
   and then `GITHUB_REPOSITORY_CONTROLS_MODE=--verify-only make configure-github-repository-controls`
   so GitHub has both protected `prod` and `operations-alert-reconcile`
   Environments.
6. Rerun privileged PR checks and confirm `Preview` and `Test Account Evidence`
   pass on the current head.
7. Run GitHub Environment legacy variable cleanup only after AWS Secrets Manager-backed
   privileged CI is green, then delete the temporary cleanup token.
8. Close `#20` only after the successful run and reviewer acceptance of the AWS
   Secrets Manager source-of-truth refinement.
9. Close `#49`, `#50`, and `#52` through `#56` only through the manual legacy
   reconcile workflow after SRE confirmation, including the required
   `sre_confirmation_reference`.

## BMAD/BMALPH Notes

Canonical planning artifacts remain under `specs/issue-20-pulumi-esc-ci-config/`.
Generated BMAD/BMALPH/Ralph framework state remains intentionally uncommitted
per `AGENTS.md`.
