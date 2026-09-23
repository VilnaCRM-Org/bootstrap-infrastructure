# Independently reviewed source admission (#185)

The central bootstrap repository runs ordinary PR guardrails without AWS credentials.
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
preview. A separate clean trusted publisher emits the existing required PR-head contexts
`Preview`, `Destructive Diff Gate`, and `IAM Validation` only after all three real
jobs succeed and source admission is rechecked. Each new PR/review signal first
sets these contexts pending, so dismissal cannot leave an old success in place.
Legacy local/main check names are distinct and cannot satisfy these contexts by
being skipped. The publisher has status-write permission and no cloud credentials;
runtime jobs have no status-write permission. Existing ruleset context requirements
remain unchanged.

## Required activation evidence

The first installation needs a reviewed two-stage source/trust rollout: this
new trusted workflow must exist on main before it can publish authoritative
statuses. A PR branch cannot use its own new workflow as the trust root or
self-authorize these required checks. Use existing independently trusted evidence
for any bootstrap transition; do not bypass or remove the required checks. This
draft does not execute that transition.

A source merge alone does **not** close #185. Before credentialed PR execution is
considered safe, the operator must install and read back the bootstrap TEST
config-reader and preview-role trust changes. Both must reject the generic
`repo:VilnaCRM-Org/bootstrap-infrastructure:pull_request` subject. The test-pr
config-reader admits only protected main and `Reviewed PR Preview`; the preview
role retains its existing main and protected-environment routes. Existing
`test`/`test-preview` deployment branch policies must remain restricted to main.
This is the enforcement boundary a PR cannot remove by editing its own workflow.
Do not add the retired PR subject back to make a failing preview green.

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

GitHub review reads and AWS STS issuance are separate services, so these checks
cannot form an atomic revocation transaction. Admission is evaluated immediately
before issuance; already issued sessions cannot be revoked by dismissing a review.
The checkout stays pinned even if the PR subsequently moves. Credentials remain
short-lived and bounded by the existing preview policy.

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
