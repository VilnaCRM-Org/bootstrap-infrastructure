# Current Closeout Evidence: Issue 20 Pulumi ESC CI Configuration

Recorded on 2026-05-25 in the `Europe/Sofia` timezone for branch
`codex/issue20-pulumi-esc`.

## Audited PR Head

| Field | Value |
| --- | --- |
| PR | `https://github.com/VilnaCRM-Org/bootstrap-infrastructure/pull/57` |
| Audited head SHA | `fd313a41695319c8beb1bbce75ec4c5860affe9d` |
| Audited short SHA | `fd313a4` |
| Source of truth | AWS Secrets Manager remains the source of truth for account-local CI values; Pulumi Cloud/ESC is not the vault and is only the fixed projection and OIDC layer. |
| Secret handling | No secret values, `GetSecretValue` responses, decrypted stack outputs, access keys, or tokens were read or recorded. |

## GitHub State

Open repository issues at the time of this audit:

| Issue | State | Current disposition |
| --- | --- | --- |
| `#20` | Open | GitOps implementation is present in PR `#57`; live closeout still needs external ESC/AWS setup and successful privileged checks. |
| `#49` | Open | Legacy unmarked operations-alert issue; do not close until a canonical fingerprinted issue exists and SRE confirms it is the same alert stream. |
| `#50` | Open | Legacy unmarked operations-alert issue; do not close until a canonical fingerprinted issue exists and SRE confirms it is the same alert stream. |
| `#52` | Open | Legacy unmarked operations-alert issue; do not close until a canonical fingerprinted issue exists and SRE confirms it is the same alert stream. |
| `#53` | Open | Legacy unmarked operations-alert issue; do not close until a canonical fingerprinted issue exists and SRE confirms it is the same alert stream. |
| `#54` | Open | Legacy unmarked operations-alert issue; do not close until a canonical fingerprinted issue exists and SRE confirms it is the same alert stream. |
| `#55` | Open | Legacy unmarked operations-alert issue; do not close until a canonical fingerprinted issue exists and SRE confirms it is the same alert stream. |
| `#56` | Open | Legacy unmarked operations-alert issue; do not close until a canonical fingerprinted issue exists and SRE confirms it is the same alert stream. |

Current PR `#57` review state is approved, but merge state is still blocked.
Current checks on head `fd313a4` are `28` passing, `5` skipped, and `2`
failing privileged setup checks. All repo-side checks are green, including
`Local Battery`, `Mutation`, `CodeRabbit`, `qlty check`, `qlty fmt`, `CodeQL`,
`Bandit`, and `Actionlint`.

The current privileged `Preview` and `Test Account Evidence` checks fail before
ESC values or AWS credentials are loaded:

```text
Invalid response from token exchange 400: Bad Request (invalid_request: invalid organization vilnacrm-org)
```

This failure is outside the repository runtime path unless the committed ESC
organization slug is wrong. If `vilnacrm-org` is the real ESC organization, a
human maintainer must configure GitHub-to-ESC OIDC for that organization. If it
is not the real organization, update `.github/ci/pulumi-esc.json` through
review.

## AWS Metadata Checks

### Test Account

Local AWS CLI checks for the test account could not prove live state because
the configured local token is invalid. `aws configure list` shows credentials
coming from local environment variables and region `eu-central-1` from
`~/.aws/config`; no other AWS CLI profile is configured locally.

```text
aws sts get-caller-identity --output json
An error occurred (InvalidClientTokenId) when calling the GetCallerIdentity operation: The security token included in the request is invalid.

aws sqs get-queue-url --queue-name bootstrap-test-operations-alerts --region eu-central-1 --output json
An error occurred (InvalidClientTokenId) when calling the GetQueueUrl operation: The security token included in the request is invalid.
```

No test-account issue should be closed from this workstation until a maintainer
refreshes the local AWS CLI session and reruns metadata-only verification.

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

The production ESC AWS backing resources for this PR are not present yet:

| Resource | Metadata-only result |
| --- | --- |
| `/bootstrap-infrastructure/ci/prod-preview` | `ResourceNotFoundException` from `secretsmanager:DescribeSecret` |
| `/bootstrap-infrastructure/ci/prod` | `ResourceNotFoundException` from `secretsmanager:DescribeSecret` |
| `PulumiEscCiSecretsRead-bootstrap-infrastructure-prod` | `NoSuchEntityException` from `iam:GetRole` |

That absence is expected before the reviewed Pulumi `prod` stack has been
applied. It also proves production privileged checks cannot be treated as
complete yet.

## Issue 20 Acceptance Status

| Requirement | Current evidence | Status |
| --- | --- | --- |
| Fixed privileged ESC environments | Workflows call `.github/actions/load-esc-ci-env` with fixed suffixes such as `test-pr`, `test`, `prod-preview`, and `prod`. | GitOps implemented |
| AWS Secrets Manager source of truth | Pulumi creates secret containers and ESC read roles; docs/tests state values stay in AWS Secrets Manager and must not be copied into ESC encrypted literals, Pulumi Cloud secrets, or any other ESC-managed secret value. | GitOps implemented |
| No GitHub `test` or `prod-preview` deployment environments for non-approval jobs | Workflow contracts and tests enforce only protected production apply uses `environment: prod`. | GitOps implemented |
| Production approval preserved | Protected GitHub `prod` Environment remains the production apply approval boundary. | GitOps implemented; repository-admin verification still required |
| Protected manual reconcile gate | The repository controls helper now prints, applies, and verifies both `prod` and `operations-alert-reconcile`; the manual reconcile workflow requires `operations-alert-reconcile` and has no AWS/OIDC permission. | GitOps implemented; repository-admin verification still required |
| Fork PR isolation | Fork paths stay unprivileged and do not open ESC or request AWS credentials. | GitOps implemented |
| KMS-backed Pulumi secrets provider | Validators require `awskms://` for shared CI stack configuration. | GitOps implemented |
| Live ESC open and AWS role assumption | Current privileged checks fail at GitHub-to-ESC token exchange for `vilnacrm-org`. | Manual secure setup required |
| AWS Secrets Manager payloads populated | Pulumi intentionally does not manage `SecretVersion` resources or JSON values. | Manual secure setup required |
| Legacy GitHub Environment variable cleanup | Cleanup workflow is present and confirmation-gated. | Run manually only after ESC-backed privileged CI is green |

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
   including state, vault, plan or rule, and protected resource.
4. Run **Operations Alert Legacy Reconcile** with the canonical issue and the
   confirmed legacy issue list.

Closure is safe only after SRE confirms the legacy issue list against the
canonical fingerprinted issue.

## Manual Secure Steps Still Required

1. Apply the reviewed Pulumi `test` and `prod` stacks so AWS creates the four
   Secrets Manager containers and `PulumiEscCiSecretsRead-*` roles.
2. Populate the four AWS Secrets Manager JSON values in the owning AWS accounts.
3. Create the four ESC environments and configure each one to import its AWS
   Secrets Manager JSON secret with `fn::open::aws-secrets`.
4. Configure GitHub-to-ESC OIDC for the real ESC organization and ESC AWS OIDC
   for each Secrets Manager read role.
5. Refresh local test-account AWS CLI credentials and rerun metadata-only
   verification.
6. Have a repository administrator run
   `GITHUB_REPOSITORY_CONTROLS_MODE=--apply make configure-github-repository-controls`
   and then `GITHUB_REPOSITORY_CONTROLS_MODE=--verify-only make configure-github-repository-controls`
   so GitHub has both protected `prod` and `operations-alert-reconcile`
   Environments.
7. Rerun privileged PR checks and confirm `Preview` and `Test Account Evidence`
   pass on the current head.
8. Run GitHub Environment legacy variable cleanup only after ESC-backed
   privileged CI is green, then delete the temporary cleanup token.
9. Close `#20` only after the successful run and reviewer acceptance of the AWS
   Secrets Manager source-of-truth refinement.
10. Close `#49`, `#50`, and `#52` through `#56` only through the manual legacy
   reconcile workflow after SRE confirmation.

## BMAD/BMALPH Notes

Canonical planning artifacts remain under `specs/issue-20-pulumi-esc-ci-config/`.
Generated BMAD/BMALPH/Ralph framework state remains intentionally uncommitted
per `AGENTS.md`.
