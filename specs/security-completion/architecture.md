# Security architecture amendment

## Trust boundaries

1. A one-time operator session uses existing short-lived AWS login credentials to
   provision the `github-ci-bootstrap` project. The project asserts `awsAccountId`,
   adopts the account's existing OIDC provider, and owns platform runners plus
   immutable service permissions boundaries. Preview before apply; preserve
   existing state ownership and protected resources.
2. Dedicated bootstrap governance runners trust the bootstrap repository, main
   ref, intended workflow and protected governance environment. Their policies
   permit only catalogued service IAM/state/CI configuration resources. They
   cannot change their own roles, the OIDC provider or bootstrap boundaries.
3. Service deployment roles trust their own repository and test/prod deployment
   environments. Preview/drift have separate environments and state lock-only
   writes. Workload permission expansion requires a reviewed boundary and
   service-policy update; catalog inclusion alone grants no administrator path.
4. The issue-comment intake runs trusted code without AWS credentials. The
   dispatch runner independently validates source run/artifact, comment,
   permissions, immutable PR comparison, request freshness and single-use claim.
   Governance scope includes all workflows, actions, scripts and execution
   configuration. PR code is checked out only after authorization succeeds.
5. Planning and apply use separate roles. The loader validates an independently
   configured AWS account before assuming the config-reader role. Trusted
   validation scripts run from the trusted checkout with system Python, before
   untrusted dependency installation can execute code.
   Each credential-bearing environment uses a custom deployment rule for exactly
   the `main` branch, with no tags or wildcards and no administrator bypass.
   Command environments require only Kravalg and prevent self-review. Verification
   reads both the environment and its separate deployment branch policies; the
   "Protected branches only" mode is insufficient without classic branch rules.
6. Saved-plan manifests bind SHA, stack, backend, project and policy pack.
   Promotion carries the same PR commit through test apply/drift and prod
   apply/drift. A failed saved plan ends the run; investigation and a new plan
   are required before retrying.

## Merge evidence

The generic `github-actions` App identity represents many workflows. Binding a
required status to that App does not identify which workflow emitted it.

Use the dedicated organization App `vilnacrm-infrastructure-evidence` (App ID
`4840884`). Its repository installation has statuses/deployments write and
actions/contents/pull-requests read access, with metadata read implicit. It has
no AWS or repository-administration rights and cannot push code or workflows.

The private signing key exists only in the `governance-evidence` environment's
secret store. That environment permits the exact main branch, no tags or branch
wildcards, and no administrator bypass. All main-executable workflows/helpers
are code-owned. Trusted `pull_request_target` scope reporting and the trusted
final promotion reporter can mint repository-scoped installation tokens.
Neither job executes PR code. Non-governance scope can pass immediately;
governance scope stays pending until verified promotion completes.

The required `Governance Promotion` status is bound to this dedicated App ID.
Actual verified applies are also projected into the existing required test/prod
deployment records with run, commit and artifact references. A projection cannot
be emitted from a plan-only, test-only, skipped or failed promotion.

## First deployment and recovery

A new S3 backend needs Pulumi metadata before a read-only preview can run. Use a
trusted state-only initializer with the intended apply role and protected
environment. It validates account/backend/project, selects an existing exact
stack, or initializes only after confirmed absence. It does not run `up`, import
arbitrary state or execute service PR code. Shared-backend errors never trigger
automatic initialization in the generic command helper.

Recovery preserves checkpoint versions and state ownership. Do not cancel a
lock based solely on a CI failure string, reuse another project's plan, import
the same cloud resource into two active stacks, or destroy protected production
resources to make a preview clean. Investigate and record the recovery decision.

## Current evidence boundaries

This document specifies intended behavior. Consult `verification.md` and the
current QA reports for implemented, deployed and verified status. The service
workload migration from static SQS keys also needs matching application SDK
credential-chain and read-only health-check behavior; removing environment
variables alone is insufficient.


## Original requester and environment approver separation

Apply requests must come from a current write-permission maintainer other than
sole approver Kravalg. Trusted preflight authenticates the original unedited
comment and rejects Kravalg self-requests before any credential job. Kravalg
approves the protected governance/test/prod environment; prevent_self_review stays
enabled. This separation does not rely on github.actor or triggering_actor:
repository_dispatch may identify the Actions bot instead of the comment author.
Direct stack-initialization workflow_dispatch must likewise be started by another
maintainer, so the sole reviewer can approve without self-review.


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

## Bounded PR192 closeout

The original one-time operator bootstrap remains a separately authorized
short-lived AWS login operation. PR213 completed its actual TEST/PROD saved-plan
apply and full drift acceptance. Routine existing platform/governance/service
workflows use their protected OIDC identities; a governance receipt proves only
its own stack. None of these receipts claims hosted operator execution.

Automatic execution of every affected bootstrap stack from an ordinary comment
is tracked separately in [issue215](https://github.com/VilnaCRM-Org/bootstrap-infrastructure/issues/215).
It remains required for the broader autonomous-bootstrap goal, but adds a new
executor/routing capability outside this PR's original one-time bootstrap
architecture. The user explicitly requested that PR192 not expand to include it.
Live deployment-comment progress is separately tracked in issue214.

For this closeout, preserve the installed 25 required checks and App issuers,
two approvals including a CODEOWNER plus an approved AI reviewer, stale-review
dismissal, last-push approval and protected TEST/PROD environments. Never
substitute a historical approval, restore result or deployment for a required
current-head check. See `verification.md` for scope and evidence boundaries.
