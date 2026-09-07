# Deployment smoke marker — 2026-06-07

## Historical intent

The following marker came from commit `a77e4f8c65e195c60b0cb7856885634efd1d3524` in PR #74. It records a proposed smoke test, not a successful deployment. Its historical operator-stack target is superseded by the controller contract below.

> # Deployment Smoke Test
>
> This disposable PR record is used to exercise the GitHub-driven `test` deployment
> path for the GitHub CI bootstrap stack.
>
> Expected command:
>
> ```text
> /pulumi test up
> ```
>
> Scope:
>
> - Target account: `test`
> - Target stack: `github-ci-bootstrap/test`
> - Purpose: verify that PR command intake, preview, IAM validation, apply, and
>   post-apply drift checks complete successfully through GitHub Actions.

## Controller amendment — 2026-09-06

Retarget and update this PR against the installed `main` controller before starting a new smoke run. Keep the PR open, unmerged and in the same repository, with `main` as its base. Record the current PR head SHA, base SHA and trusted controller workflow SHA; an old branch run or approval does not certify the updated head.

This document alone is outside the governance path set. A PR whose complete diff contains only this marker routes to the **platform** runner. The controller reads the account-local stack list and backend from its validated CI configuration; the expected platform targets are `test` with the canonical `state/test` backend and `prod` with `state/prod`. Confirm those values in the new run's sanitized metadata rather than inferring a target from this document's directory name. If other files change, the controller recomputes scope from the complete current diff, including renamed paths.

The command does **not** select `github-ci-bootstrap/test`. Operator-owned IAM/OIDC/secrets remain under the separately reviewed operator program and procedure. This smoke marker must not cause the platform to regain control-resource ownership or substitute PR code for the operator program.

## TEST smoke procedure

1. Confirm installed trusted intake/runner code, valid account and immutable repository identity, current CI configuration, initialized shared checkpoint and migrated control ownership. Review the exact PR head and verify the diff is still documentation-only.
2. A current repository writer submits a fresh, unedited comment:

   ```text
   /pulumi test plan
   ```

   Inspect the saved plan, destructive-diff result and IAM-validation result. A no-change platform plan is acceptable; do not add an infrastructure change merely to produce a deployment event.
3. For an authorized TEST apply, a current writer **other than Kravalg** submits a new comment:

   ```text
   /pulumi test up
   ```

   Kravalg reviews the current plan and approves the protected `test` environment. The runner creates and applies its own saved plan for that request; it does not reuse an unrelated earlier plan-only run. Preview and drift use the bounded `test-preview` environment.
4. Record the actual intake and runner IDs, original comment ID, pinned PR/base/controller SHAs, account/role/backend/stack metadata, saved-plan and manifest hashes, environment approval, and each job result. TEST success requires the TEST preview, destructive-diff, IAM-validation, saved-plan apply and post-apply drift stages to succeed for the recorded head.

The controller authenticates the original intake artifact and comment, revalidates current permission/head/base/scope, and rejects replays, edited comments, stale requests and API ambiguity. Credentialed jobs recheck the current PR head before credentials. If the PR changes or a request expires/fails, inspect the failure and submit a new reviewed comment when appropriate; never use a job rerun, lock cancellation or unsaved apply to bypass the request/plan contract.

## TEST/PROD and review boundary

`/pulumi test up` proves only the observed TEST run. Plan-only success, a queued comment, an operator CLI receipt, this document, or a successful informational status is not two-account promotion evidence.

When a separately authorized two-account acceptance run is ready, use a fresh comment for the unchanged reviewed head:

```text
/pulumi prod up
```

That request runs TEST apply and post-apply drift, then the guarded PROD stages in the same runner execution. It requires valid PROD ownership/checkpoint/configuration prerequisites and Kravalg's protected `prod` approval; PROD preview and drift use `prod-preview`. Only the protected dedicated App publisher may produce the exact-head promotion/deployment proof after every required stage succeeds and current PR/base/repository checks still agree. Do not present an earlier TEST-only receipt as this proof.

This documentation amendment does not authorize a new PROD run or declare any run successful. Record current review/CI requirements and any explicitly authorized deferral separately. The installation-only PR #193 decision is not a blanket replacement for subsequent live acceptance, and full PR #192/bootstrap acceptance retains its own recorded requirements.

## Evidence state

No historical or current smoke success is established by this marker. Until real run evidence is recorded, status is **NOT EXECUTED / NOT VERIFIED**. Keep failed, cancelled, skipped and deferred outcomes distinguishable.

A later evidence entry must include tester and date, PR/head/base/controller SHAs, original comment and intake/runner URLs, target account/environment/role/backend/stack, plan and manifest hashes, relevant job and approval results, expected versus observed outcome, and a link to the protected App proof when testing two-account promotion. Store only sanitized metadata; never attach credentials, CI secret values or Pulumi checkpoint contents.
