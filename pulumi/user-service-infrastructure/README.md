# Service infrastructure scaffold

Generate a complete repository from the bootstrap repository root:

```sh
uv run python scripts/scaffold_infrastructure_repository.py \
  --repository user-service-infrastructure \
  --destination /tmp/new-user-service-infrastructure
```

The destination must not exist. The generator never merges into or overwrites an
existing service repository. Review the generated files before publishing them.
Copying this template directory alone is insufficient: the generator includes the
pinned Docker runtime, frozen `uv.lock`, shared Python helper closure, local CI
configuration action, policy pack, Make targets, authenticated comment intake,
and saved-plan runner. `scaffold-manifest.json` records every generated file hash,
the project name, CLI pin and initial capability limit. Keep the manifest with the
reviewed onboarding artifact; it records generation, not future repository edits.

The baseline exports configuration metadata only. Governance owns its S3 backend,
KMS key, config secrets and OIDC roles. Operator-owned `github-ci-bootstrap`
provisions the immutable permission boundary. Deploying
actual service workloads requires separately reviewed capability and boundary
changes. Catalog membership grants no general AWS infrastructure authority.

Before granting privileges, create or inspect the actual service GitHub repository
and pin its immutable repository ID and owner ID in the governance catalog. Never
replace these identities with name-only trust. Then provision the catalog entry and bootstrap
boundary inventory in both accounts. Configure the service repository variables
from governance `githubVariables`, including independent `AWS_TEST_ACCOUNT_ID`
and `AWS_PROD_ACCOUNT_ID` pins. Create protected `test`, `prod`, `test-preview`
and `prod-preview` environments with Kravalg as sole reviewer, self-review
prevention, administrator bypass disabled, and exactly one custom deployment
rule for the `main` branch. Verify the separate deployment branch-policy API;
"Protected branches only" can allow every branch. CODEOWNERS covers every file.
Service applies trust `test` or `prod`; the central governor's `governance`
environment belongs to the bootstrap repository.

Provision a dedicated evidence GitHub App installed only on this service
repository. Grant statuses/deployments write and actions/contents/pull-requests
read, with no AWS or repository-administration permission. Store its signing key
as `GOVERNANCE_PROMOTION_APP_PRIVATE_KEY` only in the `governance-evidence`
environment, restricted to exactly the `main` branch with no tags or administrator
bypass. This environment needs no reviewer gate; it only publishes results from
the protected jobs. Set `GOVERNANCE_PROMOTION_APP_ID` and
`GOVERNANCE_PROMOTION_APP_SLUG`, and bind the required `Governance Promotion`
status to that App ID. Preserve code-owner review, current-push approval, stale
review dismissal, all required CI checks, and test/prod deployment requirements.
Use a separate App key per repository to keep signing authority isolated.

Publish the reviewed scaffold to trusted `main`, then dispatch **Initialize
Service Stack** once for `test` and once for `prod`, approving the corresponding
protected environment. It verifies the pinned project, CLI, account, backend and
KMS provider. A successful project-scoped stack listing must confirm absence
before `stack init`; existing stacks are selected, and API/authorization errors
fail closed. Initialization never runs the Pulumi program or any resource update.
Its receipt records the trusted SHA and whether it created backend stack metadata.

After initialization, open a same-repository PR and comment `/pulumi test plan`,
`/pulumi test up`, `/pulumi prod plan` or `/pulumi prod up`. Maintainers can request
plans; protected environment approval remains required before credentials are
issued. Commands bind the original unedited comment, intake run, current PR SHA,
current permissions and immutable request artifact. A prod plan does not apply
test. Prod up requires the same-run successful test saved-plan apply and drift,
then a production saved-plan apply and drift. The service runtime has no IAM
Access Analyzer grant; local policy and destructive-diff gates still run.
The trusted final publisher validates both saved-plan artifacts and all apply
and drift results before recording deployments on the exact PR head. It carries
the original comment, intake run and base SHA in the evidence. Failed, skipped,
test-only and plan-only runs cannot publish promotion success.

`make start` builds the pinned local runtime. Every workflow Make target exists
in the generated checkout; OIDC session variables are forwarded only to the
container at execution time. No static credential file or value is generated.
The test account is 891377212104, production is 933245420672, in eu-central-1.

Apply comments and Initialize Service Stack dispatches must be requested by a
maintainer other than sole environment reviewer Kravalg. Kravalg approves the
protected environment; the original apply commenter cannot also be the approver.
