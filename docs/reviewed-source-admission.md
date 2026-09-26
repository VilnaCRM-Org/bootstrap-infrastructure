# Independently reviewed source admission (#185)

After activation, the central bootstrap repository runs ordinary PR guardrails
without AWS credentials. Source installation preserves the existing same-repository
PR checks until the operator completes the staged cutover below.
`Reviewed PR Preview` is an automatic `workflow_run` workflow loaded from protected
main. A completed PR check or submitted/edited/dismissed review supplies a signal;
its artifacts and output values do not authorize execution. The runner fetches the
actual source run and current PR from GitHub, then admits one exact head SHA.
An explicit admission-job repository check rejects fork signals before the
admission job starts; both credentialed jobs require that job to succeed. This
early filter supplements the trusted verifier's numeric repository identity and
exact-head review checks; repository membership alone never authorizes execution.

The trusted policy in `scripts/reviewed_source_admission.py` requires:

- An open same-repository PR targeting main, matching the immutable admitted SHA.
- A current-head approving review by someone other than the PR author. The latest
  decisive review for each numeric reviewer ID wins; ordinary comments do not
  revoke an approval. Outstanding changes requested fail closed.
- A human reviewer with current write/maintain/admin permission and matching
  numeric identity, or the explicitly authorized CodeRabbit account
  (`136622811`, `coderabbitai[bot]`, `Bot`). Bot authorization is committed main
  policy; it does not pretend the App is a collaborator with write permission.
  Automated admission also requires `.coderabbit.yaml` to match trusted main; a
  PR cannot change its own approver configuration and use that bot as its gate.
- Current main still equals the runner's trusted policy SHA. Changing the
  authorization policy on main invalidates waiting/rerun workers using old policy.
- Fresh source/review observations after permission lookup. A moved head,
  dismissed/replaced approval, or changed trusted main fails admission.

Each credentialed job starts on a fresh runner, checks out trusted main, and runs
this verifier before loading CI configuration or requesting preview credentials.
Only then does it check out the exact admitted PR SHA and execute its Make/Docker/
Pulumi program. No claim is made that a verifier remains trustworthy after
same-user PR execution. The existing central comment worker uses the same verifier
inside its precredential recheck, after environment waits; request provenance,
scope, protected environments and deployment barriers remain required.

Source admission does not grant merge approval or waive any existing destructive,
cost, IAM, promotion, or branch-protection gate. Preview and IAM jobs have no PR,
status, deployment, or repository write permission. No long-lived token is added;
TEST preview policy, separate runtime/publisher credentials, S3 backend and KMS
secrets provider remain unchanged. The trusted preview retains destructive-diff,
cost-proxy and IAM checks. The unprivileged PR results do not establish a real AWS
preview. A separate clean trusted publisher emits the distinct PR-head contexts
`Reviewed Preview`, `Reviewed Destructive Diff Gate`, and `Reviewed IAM Validation`
only after all three real jobs succeed and source admission is rechecked. The
publisher authenticates terminal signal identity separately from conclusion.
When it processes a same-repository PR/review signal, it first sets these contexts
pending. A failed, cancelled or timed-out signal then publishes failure without
admitting credentials; dismissed approval on a successful signal also publishes
failure. The final publisher replaces prior success with failure when its fresh
source/review recheck fails. Native execution job names differ from these contexts.
Legacy `Preview`, `Destructive Diff Gate`, and `IAM Validation` names remain intact
for the source-installation PR. Their skipped results cannot satisfy the distinct
reviewed-source contexts. Only the dedicated publisher App has status-write
permission; every job in `Reviewed PR Preview` keeps `GITHUB_TOKEN` read-only. Runtime jobs receive
neither the App token nor its private key. Context names alone are not an issuer
boundary: a same-repository PR workflow can request its own status-writing
`GITHUB_TOKEN`, so every reviewed-source requirement must pin the dedicated App.

## Dedicated publisher prerequisite

Provision a new organization-owned GitHub App specifically for reviewed-source
statuses and install it only on `VilnaCRM-Org/bootstrap-infrastructure`. Do not
reuse the shared GitHub Actions issuer (`15368`) or the promotion/evidence App
(`4840884`); source rejects both. Grant the App statuses write and contents,
actions, pull requests and administration read. Tokens are minted for this one
repository by the pinned App-token action and revoked by its post-job cleanup.
No App was provisioned and no key was read or installed by this source change.

Create the `reviewed-source-publisher` environment with custom branch policies
allowing only the `main` branch, no tags/wildcards, and administrator bypass
disabled. It needs no required reviewer or wait timer. Store
`REVIEWED_SOURCE_APP_PRIVATE_KEY` **only in that environment**, never at repository
or organization scope. Set that environment's non-secret variables
`REVIEWED_SOURCE_APP_ID` and `REVIEWED_SOURCE_APP_SLUG` to the actual new App, and
`REVIEWED_SOURCE_RULESET_ID` to the existing active default-branch ruleset used for
cutover. Keep `REVIEWED_SOURCE_PREVIEW_ACTIVE` a repository variable shared by the
ordinary workflow and clean publisher jobs.

Both clean jobs read back the main-only key boundary before minting an App token.
Publication resolves the App's public numeric identity and organization owner,
checks the returned status creator's numeric bot identity, and rejects another
issuer. When activated, it also reads the actual ruleset and requires strict
checks, default-branch scope, no bypass actors and exactly one entry per
`Reviewed*` context with `integration_id` equal to the dedicated App ID. Missing
App/key/environment configuration, shared issuers and bare-name requirements
fail closed. Operator enrollment must independently confirm the private key has
no repository/organization copy; a workflow cannot prove absence of another copy.

## Required activation evidence

The source can be installed in one independently reviewed PR without changing any
currently required check context. Source installation alone does **not** close
#185: it leaves the legacy credentialed PR path in place until the following
source/trust rollout and activation are complete. Merging source does not apply
the IAM trust changes or update the ruleset.

### Stage 1: install the trusted source

Keep the repository variable `REVIEWED_SOURCE_PREVIEW_ACTIVE` unset or `false`.
Provision and verify the dedicated publisher prerequisite before relying on new
statuses. Missing configuration blocks those new clean jobs and leaves existing
required checks intact; it does not authorize a shared-token fallback.
The legacy `Preview`, `Destructive Diff Gate`, and `IAM Validation` jobs retain
their existing names and behavior, allowing the installation PR to pass the
currently required checks. Independent review and every existing required check
remain mandatory. The new trusted-main workflow publishes different contexts and
cannot supply its own installation evidence from the PR branch. Record the
installed main SHA; a waiting runner using an older policy SHA fails closed.

The new main workflow may fail to load CI configuration until Stage 2 installs
its IAM trust. Those new contexts are not required during installation. Do not
add them as requirements until the trusted workflow exists on main and can issue
genuine current-head results. The central comment worker begins enforcing source
admission as soon as the source is installed, in addition to its existing protected
environments and request authentication.

### Stage 2: retire trust and enroll the reviewed-source contexts

1. Through the independently reviewed operator process, install and read back
   both bootstrap TEST config-reader and preview-role trust changes from the
   exact reviewed source. Both must reject the generic
   `repo:VilnaCRM-Org/bootstrap-infrastructure:pull_request` subject, including
   its configured immutable-ID subject form. The test-pr config-reader admits
   protected main and `Reviewed PR Preview`; preserve existing main and protected
   environment routes on the runtime role. Keep `test`/`test-preview` deployment
   branch policies restricted to main.
2. Record live negative STS tests for both retired PR subjects and a successful
   trusted preview of an independently approved exact head. A new submitted,
   edited or dismissed review provides a trusted signal even while the legacy
   PR credential attempts fail after trust retirement. Failed or skipped source
   checks cannot substitute for review approval or successful trusted jobs.
3. The branch-protection owner adds `Reviewed Preview`,
   `Reviewed Destructive Diff Gate`, and `Reviewed IAM Validation` to the active
   ruleset, with `integration_id` set to the actual dedicated App ID on each,
   preserving **every existing required context**, its issuer and every review
   rule. Bare names or shared GitHub Actions issuer bindings are rejected. Read
   back all three issuer-bound requirements and genuine current-head results from
   that App. Prove that an identically named success from `GITHUB_TOKEN` or another
   App does not satisfy them. This additive cutover is retained by the repository
   control reconciler alongside its existing baseline.
4. Only after those readbacks, set `REVIEWED_SOURCE_PREVIEW_ACTIVE=true`.
   Ordinary PR guardrails then select the credential-free path; the legacy
   privileged jobs skip while the distinct reviewed-source contexts remain
   mandatory. Verify an unreviewed head cannot merge or obtain either TEST role,
   and an independently approved head completes the real guardrails. No second
   source PR is needed to activate this installed flag.

The activation flag controls workflow availability, not credential authorization.
A PR can change its own workflow or ignore the flag; only installed IAM trust
retirement blocks that bypass. Never enable the flag before enrolling the new
required contexts: skipped legacy checks alone do not prove a real AWS preview.
The rollout can temporarily block merges between trust retirement and completed
status/flag cutover. Do not restore generic PR trust, publish synthetic success,
remove required checks, or grant a bypass to recover availability. Keep #185 open
and downstream workload activation blocked until the complete evidence exists.
Record role policy hashes, source SHA, ruleset readback and sanitized run IDs;
never record session credentials or CI configuration payloads.

Use the independently reviewed operator process to install trust; this change
performs no AWS apply. Preserve existing repository/owner IDs, audience, role
permissions boundaries, account pins and protected-environment controls. Verify
actual AWS claim handling and installed policies; rendering tests are not live
STS evidence.

After trusted workflow source and trust are installed, record these rehearsals:

1. An unreviewed same-repository PR and a fork run only unprivileged checks; a
   PR-authored workflow directly requesting either retired role is denied by STS.
2. Exact-head independent approval automatically starts the trusted preview and
   completes real preview, destructive/cost and IAM checks using TEST credentials.
3. Head movement, review dismissal/replacement, human rights revocation, and a
   trusted policy change while queued prevent the next credentialed job.
4. A comment-driven worker waiting for an environment approval rechecks the same
   source admission before preparing credentials.
5. Same-name successes from the shared Actions issuer or another App do not satisfy
   any reviewed-source requirement. Failed/cancelled/timed-out review signals,
   dismissed approval and failed final rechecks invalidate earlier success through
   the dedicated publisher without authorizing cloud credentials.

GitHub review reads and AWS STS issuance are separate services, so these checks
cannot form an atomic revocation transaction. Admission is evaluated immediately
before issuance; already issued sessions cannot be revoked by dismissing a review.
The checkout stays pinned even if the PR subsequently moves. Credentials remain
short-lived and bounded by the existing preview policy. GitHub API or protected
publisher outages can prevent invalidation delivery; a stored status is not an
atomic or continuously renewed review attestation. Record such failures and block
activation rather than claiming the live revocation rehearsal succeeded.

## Downstream boundary

IAM generator changes deliberately retire generic PR subjects only for
`VilnaCRM-Org/bootstrap-infrastructure`. Generated/installed service PR preview
paths still require equivalent trusted admission and a coordinated trust change
before issue #219 grants workload access. Do not treat central admission or green
central tests as service admission evidence. A service implementation must pin its
own repository identity and trusted policy revision, verify independent current-
head review, keep verification before PR execution, and retire both direct PR
credential subjects. It must preserve its existing deployment gates and publisher
separation.
