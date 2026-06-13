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
opens PRs and may always run `plan` (read-only); only the governance `up`
trigger is gated to `@Kravalg`.

Steady-state applies are **IaC-only**: there is no human `pulumi up` in CI. The
governance runner (`pulumi-governance.yml`) only replays a `make pulumi-up-plan`
saved plan against the protected `governance` environment after `@Kravalg`'s
approval. The required `Governance Apply` status check is posted explicitly to
the PR head SHA: `success` for non-governance PRs, `pending` for
governance-touching PRs, then `success` once the gated test+prod apply
completes. The only permitted direct `pulumi up` is the operator's one-time
local bootstrap of the governance stack (no `GITHUB_ACTIONS`), documented in the
runbook below.

### Onboarding is config-only

Onboarding a new `X-infrastructure` service is config-only on the governance
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

### Step 1 — One-time governance bootstrap apply [OPERATOR]

This is the single most privileged action in the system (an AdministratorAccess
admin session creating every trust role). It **MUST** run from a hardware-MFA
admin session, be logged, and the resulting roles diffed against the committed
Pulumi program before any PR-comment apply is re-enabled. Direct `pulumi up` is
allowed only for this local bootstrap step (no `GITHUB_ACTIONS`); all
steady-state applies go through the gated PR-comment runner.

Apply the `test` stack first (account `891377212104`), then the `prod` stack
(account `933245420672`), each with its per-account secrets provider:

```bash
export AWS_REGION=eu-central-1

# --- test stack (account 891377212104) ---
pulumi -C pulumi/governance stack init test \
  --secrets-provider awskms://alias/pulumi-platform-bootstrap-test?region=eu-central-1
AWS_PROFILE=<test-admin-profile> \
PULUMI_SECRETS_PROVIDER='awskms://alias/pulumi-platform-bootstrap-test?region=eu-central-1' \
pulumi -C pulumi/governance preview --stack test
AWS_PROFILE=<test-admin-profile> \
PULUMI_SECRETS_PROVIDER='awskms://alias/pulumi-platform-bootstrap-test?region=eu-central-1' \
pulumi -C pulumi/governance up --stack test --yes

# --- prod stack (account 933245420672) ---
pulumi -C pulumi/governance stack init prod \
  --secrets-provider awskms://alias/pulumi-platform-bootstrap-prod?region=eu-central-1
AWS_PROFILE=<prod-admin-profile> \
PULUMI_SECRETS_PROVIDER='awskms://alias/pulumi-platform-bootstrap-prod?region=eu-central-1' \
pulumi -C pulumi/governance preview --stack prod
AWS_PROFILE=<prod-admin-profile> \
PULUMI_SECRETS_PROVIDER='awskms://alias/pulumi-platform-bootstrap-prod?region=eu-central-1' \
pulumi -C pulumi/governance up --stack prod --yes
```

Run `pulumi -C pulumi/governance stack init <stack> --secrets-provider
"$PULUMI_SECRETS_PROVIDER"` only once per stack; if a stack already exists, skip
`stack init` and run `stack select` instead. The governance stack stores its own
state in a dedicated S3 backend encrypted by `alias/pulumi-platform-bootstrap-{env}`;
that platform-bootstrap key is never granted to any managed service repo.

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
`prevent_self_review: true`, protected-branch-only) and the hardened branch
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

Read the governance stack's `perRepo` / `githubVariables` outputs and set the
matching GitHub repository variables so the managed repo's self-deploy workflow
can resolve its config-read role ARNs:

```bash
pulumi -C pulumi/governance stack output perRepo --stack test
pulumi -C pulumi/governance stack output perRepo --stack prod

gh variable set AWS_TEST_CI_CONFIG_ROLE_ARN \
  --body '<perRepo[...].configReadRoleArns.test>' --repo <repo>
gh variable set AWS_PROD_CI_CONFIG_ROLE_ARN \
  --body '<perRepo[...].configReadRoleArns.prod>' --repo <repo>
# ...and the rest of the per-env githubVariables (test-pr, prod-preview).
```

### Step 6 — Create user-service-infrastructure + push the scaffold [OPERATOR]

Create the `user-service-infrastructure` repo in `VilnaCRM-Org` (org-admin) and
push the in-repo scaffold under `pulumi/user-service-infrastructure/` (its
`pulumi/` project plus `.github/workflows/self-deploy.yml`). The scaffold
*consumes, never creates* the governance-provided state bucket
(`s3://pulumi-user-service-infrastructure-{env}-state`), KMS key/alias, and
deploy roles, so it cannot `pulumi preview` until the governance apply (Step 1)
and the repo variables (Step 5) exist:

```bash
gh repo create VilnaCRM-Org/user-service-infrastructure --private
# copy pulumi/user-service-infrastructure/** into the new repo, then git push
```

### Step 7 — Gated real applies via @Kravalg PR comments [OPERATOR]

Run the real AWS applies (test then prod) through the gated PR-comment flow.
`@Kravalg` comments `/pulumi test up` then `/pulumi prod up` on the governance
PR; the apply jobs run under the protected `environment: governance`, replay the
saved plan with `make pulumi-up-plan`, and the runner posts `Governance Apply`
success to the head SHA. Capture the real ARNs/outputs after each apply. The
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

Test↔prod blast radius is isolated by separate accounts — a compromised
test-stack apply role in `891377212104` cannot touch the prod account
`933245420672`. The remaining, accepted residual risk is the narrower
within-account cross-repo IAM blast radius: repos that share an account share the
apply role's account-global automation grants. Cross-repo isolation holds for
state buckets and KMS keys, not for account-global IAM within the same account.
This is documented and accepted (not a blocker), and is materially lower than a
shared-account model would be.
