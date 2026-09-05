# Multi-Repo IAM/OIDC Governance Stack

The governance stack is a separate Pulumi project at `pulumi/governance` that
provisions the per-repo CI credentials (state buckets, KMS keys, and the
`GitHubCiPreview/Apply/Drift` + `GitHubCiConfigRead` roles) for every
`*-infrastructure` service repo listed in `pulumi/repositories.governance.json`.
It is the bootstrap component (`pulumi/github-ci-bootstrap`) lifted into a
per-repo loop, sharing the generalized code under `pulumi/infra/`.

Pulumi Cloud and Pulumi ESC are not used. State lives in S3 and secrets are
encrypted with AWS KMS, exactly like the bootstrap stack.

## Design Overview

### Two accounts, separate-account isolation

The stack runs as two Pulumi stacks in **two separate AWS accounts**, both in
`eu-central-1`:

| Stack  | AWS account     | Secrets provider                                            |
| ------ | --------------- | ---------------------------------------------------------- |
| `test` | `891377212104`  | `awskms://alias/pulumi-platform-bootstrap-test?region=eu-central-1`  |
| `prod` | `933245420672`  | `awskms://alias/pulumi-platform-bootstrap-prod?region=eu-central-1`  |

Putting `test` and `prod` in different accounts isolates the blast radius: a
compromised `test`-stack apply role in `891377212104` cannot touch the `prod`
account `933245420672` at all. The account number is **per-stack config**
(`governance:awsAccountId`) and the literal lives only in the stack files
(`pulumi/governance/Pulumi.test.yaml` pins `891377212104`,
`pulumi/governance/Pulumi.prod.yaml` pins `933245420672`); the component code in
`pulumi/infra/*.py` carries **no account-number literal**. At apply time each
stack asserts `aws.get_caller_identity().account_id` equals its configured
`governance:awsAccountId` and raises otherwise, so a stack cannot apply into the
wrong account even if the operator's shell points elsewhere.

### Per-account OIDC provider, consumed never created

Each account owns exactly one GitHub Actions OIDC provider for
`token.actions.githubusercontent.com`. The `github-ci-bootstrap` project is the
sole owner of each account's provider. The governance stack **consumes** its
account's provider by a pinned ARN (`governance:githubOidcProviderArn`) via
`.get()` — it never creates or adopts the provider. The `test` stack consumes
`arn:aws:iam::891377212104:oidc-provider/token.actions.githubusercontent.com`;
the `prod` stack consumes the `933245420672` provider. If
`governance:githubOidcProviderArn` is unset the stack raises before any apply
(it must never fall back to creating the provider), so the ARN must be pinned in
each stack's config before the first governance apply.

### Sole approver and IaC-only applies

`@Kravalg` is the sole approver: CODEOWNERS scopes all governance/IAM/policy
paths to `@Kravalg`, and the protected `governance` GitHub Environment requires
`@Kravalg` as the only reviewer with `prevent_self_review: true`. `@dmytrocraft`
opens PRs and requests `plan` or `up`. An apply requester must hold current
write permission and differ from the sole approver `@Kravalg`; trusted preflight
checks the original comment author, independently of the Actions actor.
`@Kravalg` approves the protected environment and cannot request their own apply.

Steady-state applies are **IaC-only**: there is no human `pulumi up` in CI. The
governance runner (`pulumi-governance.yml`) only replays a `make pulumi-up-plan`
saved plan against the protected `governance` environment after `@Kravalg`'s
approval. The required `Governance Promotion` status is issued by the dedicated environment-protected GitHub App for the
exact PR head after successful test apply, test drift, prod apply and prod drift, with an
immutable proof artifact. Governance-touching heads remain blocked until this
proof exists; unrelated changes receive a scope-based success. CODEOWNERS
review and protected environment approvals remain additional controls. A
plan or test-only result cannot satisfy production promotion. The only permitted direct `pulumi up` is the operator's
one-time local bootstrap of the governance stack (no `GITHUB_ACTIONS`),
documented in the runbook below.

The legacy `Governance Apply` status does not satisfy the required promotion
proof.

### Onboarding is catalog-driven

After the operator provisions its reviewed boundary inventory, onboarding a new
`X-infrastructure` service is catalog-driven on the governance
side: add the repo to `pulumi/repositories.governance.json` (a `project` set to
the full repo slug) and run the multi-PR flow documented in `AGENTS.md`. Never
add `bootstrap-infrastructure` to the governance catalog — it self-manages via
`github-ci-bootstrap`, and listing it would double-manage the same IAM roles and
CI secret.

## Operator Runbook

The following steps require live AWS-admin or GitHub-org-admin credentials.
Every step below is marked **OPERATOR** because none of them is a committable
change a non-privileged agent makes; they are performed by the operator with
real credentials. Pure code/IaC/docs changes are delivered through the gated
PR-comment flow and are out of this runbook.

Before each AWS apply, remove inherited shell credentials and verify the exact
account. Do not set empty AWS variables.

```bash
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_PROFILE
aws sso login --profile <test-admin-profile>
AWS_PROFILE=<test-admin-profile> aws sts get-caller-identity --output json   # must be 891377212104
aws sso login --profile <prod-admin-profile>
AWS_PROFILE=<prod-admin-profile> aws sts get-caller-identity --output json   # must be 933245420672
```

### Prerequisite — Resolve immutable GitHub repository identity [OPERATOR]

Inspect the actual service repository before granting its catalog entry. If it
is absent, create the empty repository first; if it exists, preserve its content
and settings. Record the immutable repository/owner identifiers and verify the
current GitHub OIDC subject format for that repository. Trust provisioning must
use this real metadata before bootstrap boundary inventory or governance grants
are applied. Publish the reviewed scaffold only after its prerequisites are
ready; do not infer immutable IDs from a name or overwrite an existing service.

### Prerequisite — Provision governance automation and immutable boundaries [OPERATOR]

Update the operator-owned `pulumi/github-ci-bootstrap` stack before the first
governance apply. Its `GovernanceAutomation` component creates three dedicated
roles per account: `GitHubGovernancePreview-{env}`,
`GitHubGovernanceDrift-{env}`, and `GitHubGovernanceApply-{env}`. It consumes the
bootstrap provider and creates no additional OIDC provider. Do not create these
roles manually with ad-hoc policy JSON.

The bootstrap entrypoint requires `github-ci-bootstrap:awsAccountId` and checks
the live caller account before allocating any infrastructure resource. The
committed non-secret test configuration pins `891377212104`; prod pins
`933245420672`. Missing, malformed or mismatched account IDs fail closed.
Keep those assertions in any external local config used for an operator apply.

The operator stack is also the sole owner of the platform control identities:
CI configuration secrets/read roles, CI deployment roles, the OIDC provider,
legacy `PulumiAutomation` and `PulumiDeploy` roles and their policies, Config
recorder IAM, and fixed platform state/log replication IAM. `PlatformControlIam`
consumes the existing repository KMS aliases through metadata lookup and creates
no workload resources. `PlatformIamBoundaries` owns the immutable control and
workload ceilings. The control boundary attaches to platform apply and legacy
automation/deploy roles; Config and replication roles remain service-specific.
Test triage remains owned by `GitHubCiBootstrap`; prod triage is owned by
`PlatformControlIam`. The real platform entrypoint explicitly sets
`manage_control_resources=False`, preserving ECR, recorder, buckets and other
workloads while using read-only references for these identities.

Before applying this ownership conversion to an existing deployment, prepare a
reviewed resource-by-resource source/target URN map and encrypted state backups.
Resolve all duplicate owners and preserve historical unique resources explicitly;
rehearse the proposed state migration and require previews with no unintended
deletes or replacements. Do not apply the operator graph while another stack
still owns the same physical identity. Existing names are adopted from read-only
IAM metadata, including legacy inline policy suffixes and exact attachments.
The AWS CLI and Pulumi provider account must match; unexpected lookup failures or
ambiguous policy names stop adoption. When historical stacks left multiple
matching inline policies, the operator config `platformInlinePolicyNames` maps
an exact role name to its expected logical policy prefix and authoritative live
policy name. Only the reviewed Automation/Deploy inventory is accepted; every
preferred name must match that prefix and exist in live metadata. The tracked
test/prod pins come from the reviewed authoritative state and metadata. Do not
choose the first match or retire an older policy implicitly; retain and review
legacy grants separately until their authorized retirement. This source change does not itself migrate
state or establish live ownership. Preserve pinned legacy log/backup role names
in stack configuration rather than generating replacement names.

Operator-owned `PlatformControlStateGuard` inline policies protect legacy
Automation/Deploy roles; equivalent guards protect the three CI purposes. They
explicitly deny object access outside the canonical platform `state/{env}`
prefix, including operator/governance checkpoints, and deny foreign-repository
KMS operations. Preview/drift retain lock-only object mutation and no version
deletion. These explicit guards remain effective when a bucket policy adds a
session grant; the platform cannot replace or remove the guards. Verify the
final boundary plus all identity/resource policies, including retained legacy
grants, before claiming effective isolation.

Preview and drift trust the protected `governance-preview` environment; apply
trusts the protected `governance` environment. Trust also pins the repository,
main branch, workflow name `Pulumi Governance Runner`, and STS audience.
Both environments must be configured with the documented reviewer controls
before running their workflows.

The bootstrap stack also owns `GovernanceBoundary-{project}-{env}` and
`GovernanceReplicationBoundary-{project}-{env}` policies for every entry in
`pulumi/repositories.governance.json`. Service deploy/config roles and S3
replication roles must carry their matching boundary. Governance cannot modify
boundary policies, remove boundaries, change its own automation roles, modify
platform roles or mutate the OIDC provider. Its role-policy permissions target
only the catalogued roles and require the immutable boundary. Replication
PassRole permission is limited to S3 and the exact replication role.

The service boundary initially permits only each repository's own state,
secrets-provider key and CI configuration. It does not grant deployment of an
existing service's workload resources. Extend those capabilities through an
explicit reviewed bootstrap boundary change. Adding a repository also requires
this bootstrap stack's reviewed boundary/inventory update before governance can
manage it; the governor cannot widen its own delegation. The current policy
layout rejects more than four managed repositories instead of silently
exceeding the default ten managed-policy attachment quota per runner role.

Run the existing one-time bootstrap runbook in
[GitHub CI AWS bootstrap](github-ci-bootstrap-stack.md) for test, then prod.
Use a hardware-MFA administrator identity, inspect the preview, and record the
reviewed commit and role/policy changes. The new component exports only
non-secret setup metadata in `governanceGithubVariables`:

```bash
AWS_PROFILE=<test-admin-profile> pulumi -C pulumi/github-ci-bootstrap stack output governanceGithubVariables --stack test --json
AWS_PROFILE=<prod-admin-profile> pulumi -C pulumi/github-ci-bootstrap stack output governanceGithubVariables --stack prod --json
```

The defaults use the account's bootstrap state bucket with an isolated
`/governance` prefix and `alias/pulumi-platform-bootstrap-{env}` KMS key.
Optional bootstrap config keys `governanceBackendUrl`,
`governanceSecretsProvider`, and `governanceRepositoryCatalogPath` are explicit
inputs. Backend URLs must be `s3://<bucket>/governance`; secrets providers must
match the environment's platform alias and configured region.

Before continuing, verify the account-specific provider ARN described in Step 2
and provision the GitHub environments and variables described in Steps 4–5.
The state bucket, platform KMS key, provider and central access-log buckets are
existing bootstrap prerequisites, not resources created by the governance
runner. Capture metadata-only evidence of their existence.

### Step 1 — One-time governance bootstrap apply [OPERATOR]

This one-time local apply uses an AdministratorAccess, hardware-MFA admin
session. Log the operation and diff the resulting roles against the committed
Pulumi program. Direct `pulumi up` is allowed locally for this bootstrap step;
steady-state CI must use `make pulumi-up-plan`.

Use explicit S3 login and account credentials for every command. Perform the
provider verification in Step 2 before these commands. For an existing stack,
replace its `stack init` command with `stack select`; do not initialize it twice.

```bash
# Test: verify identity is account 891377212104.
AWS_PROFILE=<test-admin-profile> aws sts get-caller-identity
AWS_PROFILE=<test-admin-profile> pulumi -C pulumi/governance login s3://pulumi-bootstrap-infrastructure-test-state/governance
AWS_PROFILE=<test-admin-profile> pulumi -C pulumi/governance stack init test --secrets-provider 'awskms://alias/pulumi-platform-bootstrap-test?region=eu-central-1'
AWS_PROFILE=<test-admin-profile> pulumi -C pulumi/governance preview --stack test
AWS_PROFILE=<test-admin-profile> pulumi -C pulumi/governance up --stack test --yes

# Prod: verify identity is account 933245420672. Continue only after test succeeds.
AWS_PROFILE=<prod-admin-profile> aws sts get-caller-identity
AWS_PROFILE=<prod-admin-profile> pulumi -C pulumi/governance login s3://pulumi-bootstrap-infrastructure-prod-state/governance
AWS_PROFILE=<prod-admin-profile> pulumi -C pulumi/governance stack init prod --secrets-provider 'awskms://alias/pulumi-platform-bootstrap-prod?region=eu-central-1'
AWS_PROFILE=<prod-admin-profile> pulumi -C pulumi/governance preview --stack prod
AWS_PROFILE=<prod-admin-profile> pulumi -C pulumi/governance up --stack prod --yes
```

`stack init --secrets-provider` persists the provider in local stack metadata.
The subsequent preview/apply uses it; no transient secrets-provider environment
variable is needed. If an operator chose a different approved backend bucket,
substitute the exact exported `AWS_GOVERNANCE_*_BACKEND_URL` consistently in
both the local login and GitHub configuration.

### Step 2 — Pin the per-account OIDC provider ARN before first apply [OPERATOR]

The governance stack **consumes** its account's OIDC provider by ARN and
**raises if the ARN is unset** — it never creates the provider. Before the first
apply in Step 1, read `oidcProviderArn` from **each account's** `github-ci-bootstrap`
stack output and pin it into the matching governance stack config:

```bash
# test account 891377212104 -> Pulumi.test.yaml
pulumi -C pulumi/github-ci-bootstrap stack output oidcProviderArn --stack test
# expect arn:aws:iam::891377212104:oidc-provider/token.actions.githubusercontent.com

# prod account 933245420672 -> Pulumi.prod.yaml
pulumi -C pulumi/github-ci-bootstrap stack output oidcProviderArn --stack prod
# expect arn:aws:iam::933245420672:oidc-provider/token.actions.githubusercontent.com
```

The committed stack files already pin these:
`pulumi/governance/Pulumi.test.yaml` sets
`governance:githubOidcProviderArn: arn:aws:iam::891377212104:oidc-provider/...`
and `pulumi/governance/Pulumi.prod.yaml` sets the `933245420672` provider ARN.
Confirm each stack points at **its own account's** provider — the `test` stack
must reference the `891377212104` provider and the `prod` stack the
`933245420672` provider. Never point the `prod` stack at the test provider or
vice versa.

### Step 3 — Verify each stack's cost-anomaly monitor matches its account [OPERATOR]

There is **no single-account reconciliation** and no stripping of
`933245420672`: the live two-account config is already correct. Both anomaly
monitors already exist — the `test` stack's monitor in `891377212104` and the
`prod` stack's monitor in `933245420672`. Verify that each stack's
`costAnomalyMonitorArn`, **if present**, has an account matching that stack's
account, and **do NOT repoint prod away from `933245420672`**:

```bash
# test stack: costAnomalyMonitorArn account must be 891377212104
# prod stack: costAnomalyMonitorArn account must be 933245420672
```

Absence is permitted — the code path tolerates a null/unset value. This is an
apply-time verification, not a code change. The `test`-stack monitor ARN must
embed `891377212104` and the `prod`-stack monitor ARN must embed `933245420672`;
swapping them would point a stack's anomaly monitoring at the wrong account.

### Step 4 — Configure the protected governance environment + branch protection [OPERATOR]

Apply the protected `governance` GitHub Environment (sole reviewer `@Kravalg`,
`prevent_self_review: true`, administrator bypass disabled, and exactly one
custom deployment rule for the `main` branch) and the hardened branch
ruleset (`dismiss_stale_reviews_on_push` + `require_last_push_approval`) with a
repo-admin token. Review the dry-run payload first, then apply:

```bash
python scripts/configure_github_repository_controls.py \
  --repo VilnaCRM-Org/bootstrap-infrastructure --dry-run   # review the governanceEnvironment payload
python scripts/configure_github_repository_controls.py \
  --repo VilnaCRM-Org/bootstrap-infrastructure --apply
```

The `--apply` branch `PUT`s `repos/{repo}/environments/governance` (requiring
`@Kravalg`) and re-verifies the controls. Any push after `@Kravalg`'s approval
dismisses the stale code-owner review and requires fresh approval of the new
head before `/pulumi prod up` is accepted.

### Step 5 — Set GitHub repo variables from the governance githubVariables output [OPERATOR]

The bootstrap stack's `governanceGithubVariables` output supplies every dedicated
runner variable: `AWS_GOVERNANCE_{TEST,PROD}_{PREVIEW,DRIFT,APPLY}_ROLE_ARN`,
`ACCOUNT_ID`, `REGION`, `BACKEND_URL`, and `SECRETS_PROVIDER`. Set those values
on `VilnaCRM-Org/bootstrap-infrastructure` without inventing role ARNs.
The output contains metadata only, not CI secret values.

```bash
AWS_PROFILE=<test-admin-profile> pulumi -C pulumi/github-ci-bootstrap stack output governanceGithubVariables --stack test --json
AWS_PROFILE=<prod-admin-profile> pulumi -C pulumi/github-ci-bootstrap stack output governanceGithubVariables --stack prod --json
gh variable set AWS_GOVERNANCE_TEST_APPLY_ROLE_ARN --repo VilnaCRM-Org/bootstrap-infrastructure --body '<exact exported value>'
# Repeat for every key exported by test and prod; verify the values match the output.
```

For each managed service repository, use the governance stack's `perRepo`
output and its nested `githubVariables` map to configure that service's own
`AWS_TEST_REGION`, `AWS_TEST_PR_CI_CONFIG_ROLE_ARN`, `AWS_TEST_CI_CONFIG_ROLE_ARN`,
`AWS_PROD_REGION`, `AWS_PROD_PREVIEW_CI_CONFIG_ROLE_ARN`, and
`AWS_PROD_CI_CONFIG_ROLE_ARN`. These service variables differ from the dedicated
bootstrap governance runner variables. Never fetch raw CI payload values for
this setup or evidence capture.

### Step 6 — Publish the scaffold to the identified repository [OPERATOR]

Use the real `user-service-infrastructure` repository resolved before the catalog
and boundary grants. Generate the complete scaffold dependency closure with
`scripts/scaffold_infrastructure_repository.py` into a new local destination,
review the generated files, and publish them through the existing repository's
review flow. Preserve its current application and infrastructure content. The
`pulumi/user-service-infrastructure/` template folder alone does not contain every
Make/action/helper dependency.

The scaffold consumes the governance-provided state bucket, KMS key and roles.
Its first preview requires the governance resources, service variables, protected
environments, and trusted state initialization to have completed. Validate all
referenced local actions, scripts, dependencies and policy files in a clean
checkout before triggering self-deployment.

### Step 7 — Maintainer request and separate @Kravalg approval [OPERATOR]

Run the real AWS applies (test then prod) through the gated PR-comment flow.
A current write-permission maintainer such as `@dmytrocraft` comments
`/pulumi test up` then `/pulumi prod up` on the governance PR. `@Kravalg` approves
the protected `environment: governance`; the apply jobs replay the
saved plan with `make pulumi-up-plan`, and the runner publishes `Governance Promotion`
proof for the exact head SHA only after test apply, test drift, prod apply and prod drift succeed. Capture the real ARNs/outputs after each apply. The
`prod` apply is gated on the `test` apply succeeding (test-then-prod ordering).

### Step 8 — Audited break-glass if @Kravalg is unavailable [OPERATOR]

`@Kravalg` is the sole reviewer with `prevent_self_review: true`; if unavailable,
no governance apply can proceed. Use one of these explicit, audited break-glass
paths, then revert immediately:

- **Temporary second reviewer:** an org-admin adds a time-boxed temporary second
  reviewer to the `governance` environment (logged), and removes it immediately
  after the apply.
- **Operator-local direct apply:** an operator runs the Step 1 local
  `pulumi -C pulumi/governance up` from a hardware-MFA admin session (logged),
  then diffs the resulting roles against the committed Pulumi program before any
  PR-comment apply is re-enabled.

Both paths must be logged. The local bootstrap apply (Step 1) is the single most
privileged action in the system and is the break-glass of last resort.

## Residual Risk

Test and prod use separate accounts. Managed service roles have no inherited
platform IAM administration grants. Bootstrap-owned boundaries cap each service
at its own state, KMS alias and CI configuration; replication has a separate
S3-only boundary. The governor can update only catalogued resource identities,
cannot remove these boundaries, and cannot update its own delegation.

The governor remains privileged over the catalogued repositories within its
account. Its protected approval, reviewed saved plan and immutable boundary
inventory are mandatory controls. KMS creation uses repository request tags
and later key administration uses repository resource tags because an uncreated
key has no stable ARN. Existing keys with conflicting ownership tags require
operator investigation rather than a permission fallback. IAM Access Analyzer
and live provider previews must validate the generated policies before apply.


The platform PR-comment runner also projects verified account deployments onto the
actual PR head through the dedicated main-only evidence App. Its final job requires
the authenticated preflight, successful test apply and drift, and successful prod
apply and drift. Both publishers download saved-plan artifacts from their own run,
verify manifest commit SHA and plan hashes, and record the original comment/source
run and immutable base/head. A moved base or head, missing artifact or skipped stage
cannot publish success. Scope and promotion reporters share a per-PR concurrency
group, preventing a pending scope update from racing a completed proof. The required
status retains the name `Governance Promotion`; non-governance scope success alone
never creates successful test/prod deployment records.
