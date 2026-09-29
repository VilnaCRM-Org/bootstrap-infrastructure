# TEST capability activation (PR #280)

PR #280 is the reviewed source change that activates the TEST PoC prerequisite
capability after the independent seed amendment is installed. It is rebased on
main after PR #275 and the TEST preview-trust cutover in PR #276. It is not live
seed-installation evidence, and merging it deploys nothing. Merge it only inside
the freeze window below, after every [merge precondition](#merge-preconditions-nfr8)
is recorded.
The separate trust prerequisite is installed: PR #276 merged as
`bea52521c70e9842a898b6294f8cdcb5765b8217` after protected TEST run
[36450787780](https://github.com/VilnaCRM-Org/bootstrap-infrastructure/actions/runs/36450787780)
completed its saved-plan apply, post-apply drift and account receipt. Live TEST
role readback found no generic `pull_request` subject and retained main,
`test`, `test-preview`, immutable repository ID and owner ID conditions.

## Requirements

This change implements FR5, FR6, FR7 and NFR5 through NFR8 in
[requirements.md](requirements.md); they supersede FR2, FR4 and NFR1 of the
disabled PR #255 state.

| ID | Where |
| --- | --- |
| FR5 | Enabled packaged identity; [scope and offline proof](#scope-and-offline-proof-fr5-fr6-fr7-nfr5) |
| FR6 | Boundary, governor and attachment parity; [scope and offline proof](#scope-and-offline-proof-fr5-fr6-fr7-nfr5) |
| FR7 | TEST pin `ff2eaf29…`; the amendment cannot be replayed |
| NFR5 | TEST-only scope, PROD unchanged, no AWS mutation on merge |
| NFR6 | [Rollback and fail-forward](#rollback-and-fail-forward-nfr6) |
| NFR7 | [Freeze window and merge sequence](#freeze-window-and-merge-sequence-nfr7) |
| NFR8 | [Merge preconditions](#merge-preconditions-nfr8) |

## Ordered activation (FR5-FR7, NFR7)

1. Make PR #280 merge-ready before touching AWS: exact head reviewed by
   CodeRabbit and `@Kravalg`, every required check green on that head, no
   unresolved threads, branch current with main. Its TEST catalog is exactly the
   amendment result `ff2eaf296e5bd6e6bf8b02c7cdc31a2cfbcaef53fdea6173c64f77a3095effe7`;
   its provenance keeps `activation_authorized: false` because catalog metadata
   never authorizes an apply. It admits the single mutable attachment
   `arn:aws:iam::891377212104:policy/GitHubCiApply-user-service-infrastructure-test-poc-prerequisites`
   only on `GitHubCiApply-user-service-infrastructure-test`, then enables the
   packaged exact TEST repository identity.
2. Preserve the separately installed PR #276 TEST trust cutover. Recheck the
   complete preview role trust immediately before the expanded identity grant;
   no generic `pull_request` subject may return. The trust removal and permission
   widening remain separate reviewed deployments.
3. Open the freeze window, then independently install the reviewed PR #275
   four-policy TEST amendment per [the installation runbook](amendment-installation.md).
   Authenticate the complete resulting template, all four default policy
   documents, attachments, boundaries, guards and restored permanent deny-update
   stack policy. Retain the change-set ID, source SHA and readback digests. A
   successful CloudFormation status alone does not satisfy this prerequisite.
4. Record the [merge preconditions](#merge-preconditions-nfr8) on PR #280, merge
   it through normal branch protection and close the freeze window as described
   below.
5. Install any required TEST governor identity policy update through the existing
   protected operator saved-plan path. The seed amendment changes immutable
   ceilings and guards; it does not install the mutable governor identity Allow
   needed to manage the new service policy. Inspect the exact saved plan and
   stop on unreviewed scope. Do not substitute a direct local apply.
6. Use the protected governance PR-comment saved-plan path to install the service
   apply managed policy and preview/drift read grants. A current write-permission
   maintainer requests `/pulumi test up`; `@Kravalg` approves `governance`.
   Preserve the repository's test-then-prod promotion contract: TEST apply/drift
   and PROD apply/drift at the same revision remain required for promotion,
   even though this capability is TEST-only and PROD has no new capability.
   Do not publish promotion success from TEST-only or stale-head evidence.
7. Verify the exact policy/attachments and native resource metadata. Keep
   `Issue215CutoverSessions` throughout. Its separate reviewed activation is a
   prerequisite to any downstream service apply; this change cannot bypass the
   deny-all hold. Then rerun the exact-head service PR comment plan and the
   separately authorized apply/drift sequence.

## Freeze window and merge sequence (NFR7)

Operator runs execute the runtime from trusted `main`: the operator account
workflow mounts the `.trusted` checkout. At the start of every TEST preview,
drift and apply stage they call `verify_active_enrollment` against main's
`CATALOG_HASHES["test"]` pin. The live seed and main's pin must therefore change
together:

- Merge before install: main pins `ff2eaf29…` while AWS still holds the
  `ef419680…` documents. Every operator TEST run fails closed at enrollment
  until the seed is installed.
- Install before merge: AWS holds the `ff2eaf29…` documents while main still
  pins `ef419680…`. Every operator TEST run fails closed at enrollment until
  PR #280 merges.

`/pulumi prod plan` and `/pulumi prod up` run the TEST sequence first, so both
failure modes also stop PROD promotions that include the operator stack. Keep the
gap short and explicit:

1. Complete ordered step 1 first. Do not start installation while review,
   required checks or rebases are outstanding.
2. Announce the freeze: no `/pulumi` commands whose scope includes the operator
   stack, and no other merges to main, until the window closes. A new main
   commit would require a rebase and fresh checks inside the window.
3. Install the seed amendment (ordered step 3). If installation fails or leaves a
   partial result, follow [rollback and fail-forward](#rollback-and-fail-forward-nfr6)
   and do not merge.
4. Record the merge preconditions, then merge PR #280 immediately with normal
   branch protection.
5. Close the window only after the first post-merge operator TEST plan passes its
   enrollment checks against the installed seed.

An administrator bypass merge is forbidden, including to shorten the window or
to work around a failing, pending or missing required check. Fix the cause, or
leave the PR unmerged and follow the rollback decisions.

## Merge preconditions (NFR8)

Record sanitized metadata only (IDs, SHAs, digests, run links) on PR #280 before
merging. Do not record credentials, stack exports or CI configuration payloads.

- [ ] CloudFormation change-set ID executed on the TEST seed stack in account
      `891377212104`, `eu-central-1`, with the complete paginated change set
      accepted by `validate_test_poc_change_set` as exactly four non-replacing
      `PolicyDocument` modifications.
- [ ] Source SHA of the reviewed amendment packet and the exact PR #280 head SHA
      being merged.
- [ ] Canonical SHA-256 of the complete installed stack template, equal to the
      packet's proposed template and its protected S3 `TemplateURL` artifact.
- [ ] Default-version documents of the four target policies, hashed with
      `seed.policy_registry.document_hash`, equal the catalog `template_sha256`:
  - `GovernanceBoundary-user-service-infrastructure-test`:
    `805998b51f71ed626fb7e3f4b4c73e9e72a36b2da7de912679a489a86f1becfc`
  - `issue215-seed/test/ceiling/C-GitHubGovernanceDrift`:
    `02517ab54e01f164dbcd290a468b76dc8153ae7b2951fbc7f3585de9a160c07f`
  - `issue215-seed/test/ceiling/C-GitHubGovernancePreview`:
    `b97d4596cde3454a697e14453c5b7e9a904f6aef8c940d6857a275872e65e076`
  - `issue215-seed/test/guard/G-GitHubGovernanceApply`:
    `b6d1a587aba8767d40258add3f8b056711e51ffc6e18b536f115105fc7480d53`
- [ ] Attachments, permissions boundaries and guards of every catalog principal
      read back unchanged apart from the four documents.
- [ ] The permanent deny-update stack policy is restored; record its digest.
- [ ] `verify_active_enrollment` on the PR #280 TEST registry passes for an
      independently authenticated, non-root, read-only observation of the
      installed account. Record the registry SHA-256 and verified counts.
- [ ] PR #280 exact head still has current approvals, green required checks and
      no unresolved threads.

## Rollback and fail-forward (NFR6)

Default to fail-forward. The seed ceilings grant nothing without the governance
identity policy, and `Issue215CutoverSessions` still denies service sessions on
the TEST apply role. Withdraw only when the capability itself is wrong. Never run
a direct apply, cancel a Pulumi lock, retry a failed saved plan, edit the catalog
to match live state, publish synthetic success or bypass branch protection.

**Seed installation fails or is partial (before merge).** Restore the permanent
deny-update stack policy. Read back the stack status, template and four
default-version documents. If they still equal the `ef419680…` baseline, main
stays valid: leave PR #280 unmerged and close the freeze. Any mixed or
`UPDATE_ROLLBACK_FAILED` state keeps the freeze. Reconcile it through a
separately reviewed change set and never replay the executed one.

**Governance TEST apply fails (ordered step 6).** Stop before PROD. Keep the seed
and the merged source. Record the run ID, failed stage, saved-plan manifest hash
and sanitized diagnostics. Read back whether the `poc-prerequisites` policy, its
attachment and the preview/drift grants exist. Repair the backend, KMS, artifact
or source cause through reviewed changes. Then run a fresh exact-head
`/pulumi test plan`, review it, and run `/pulumi test up`. Promotion stays
blocked until TEST apply/drift and PROD apply/drift pass at the same revision.

**Drift appears.**
- Governance drift after apply: stop promotion and do not accept it with a
  refresh. Identify the out-of-band change from read-only metadata. Restore the
  reviewed state with a fresh saved plan, or fix the source through review.
- Seed drift: `verify_active_enrollment` fails, or the four default-version
  hashes, stack policy, attachments or guards differ from the catalog. Treat it
  as a security event, open the freeze and stop operator runs. Restore the
  catalog state through a reviewed CloudFormation change set under the
  deny-update policy. Never change the catalog to match live AWS.

**Capability must be withdrawn.** Setting `enabled: false` alone leaves the
installed seed ceilings wider than the source identity and fails the
boundary-parity tests against the `ff2eaf29…` pin. Complete withdrawal therefore
also reverses the seed catalog through a new CloudFormation change set under the
deny-update policy, in this order:

1. Withdraw the identity grant first, while the seed guard still admits the exact
   policy ARN. A reviewed PR sets `enabled: false` and updates the parity tests to
   the withdrawn-identity/installed-ceiling state. Apply it through the protected
   governance saved-plan path. The plan may only delete the `poc-prerequisites`
   policy, its apply-role attachment and the preview/drift read grants. If the
   runner lacks a required delete or detach action, stop for review and do not
   use break-glass implicitly. Read back the service apply role attachments
   (`pulumi-backend`, `secret-read-deny` and guards only) and the absence of the
   policy.
2. Reverse the seed. Source contains no reversal generator today:
   `build_catalog()` binds only to the pre-install baseline. A reviewed change
   must first add a reversal packet bound to `ff2eaf29…` that produces the
   `ef419680…` documents, plus a change-set validator for exactly those four
   reverse modifications. In one freeze window, create and validate that change
   set under a narrow temporary stack policy, execute only its ID, restore the
   permanent deny-update policy and read back the four documents against the
   `ef419680…` catalog. Then merge the reviewed source that restores the
   `ef419680…` pin and removes the TEST attachment allowlist entry.
3. Health checks: the post-merge operator TEST plan passes its enrollment checks,
   governance TEST drift is clean, and the service apply role still carries
   `Issue215CutoverSessions`.
4. Evidence: both PR SHAs, governance run IDs, change-set ID, template digest,
   four document hashes, stack-policy digest, enrollment result and sanitized
   readbacks.

## Scope and offline proof (FR5, FR6, FR7, NFR5)

Only the four independently owned TEST policy documents change in the catalog.
Principals, trust, attachments recorded in the immutable catalog and PROD remain
unchanged. The only new mutable attachment identity belongs to the TEST service
apply role. IAM still excludes publisher/runtime, send-mail, delete, DNS UPSERT
and lifecycle permissions. The trusted service validator must enforce exact
generated DKIM names and values; IAM's namespace cap alone cannot establish them.

The capability tests exercise the packaged enabled identity, boundary parity,
exact action/resource sets, foreign identities, DNS negative cases and the
single-role attachment allowlist. Historical amendment tests reconstruct and
hash-check the previous catalog before rendering their synthetic packet. Calling
the amendment generator against the new active catalog still fails closed,
preventing the installed result from being treated as a fresh amendment baseline.

The earlier requirements, impact and review documents describe the staged,
disabled PR #255 state. FR5-FR7 and NFR5 supersede it only after the live
installation prerequisite and separate source review; this change does not
assert that governance promotion, operator activation or service deployment has
completed.
