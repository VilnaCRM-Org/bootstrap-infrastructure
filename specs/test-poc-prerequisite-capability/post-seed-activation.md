# TEST capability activation candidate

This local candidate is rebased on main after PR #275 and the TEST preview-trust
cutover in PR #276. It is not live seed-installation evidence.
Do not publish or deploy it until the independent seed amendment completes the
exact readback required by [the installation runbook](amendment-installation.md).
The separate trust prerequisite is installed: PR #276 merged as
`bea52521c70e9842a898b6294f8cdcb5765b8217` after protected TEST run
[36450787780](https://github.com/VilnaCRM-Org/bootstrap-infrastructure/actions/runs/36450787780)
completed its saved-plan apply, post-apply drift and account receipt. Live TEST
role readback found no generic `pull_request` subject and retained main,
`test`, `test-preview`, immutable repository ID and owner ID conditions.

## Ordered activation

1. Independently install the reviewed PR #275 four-policy TEST amendment.
   Authenticate the complete resulting template, all four default policy
   documents, attachments, boundaries, guards and restored permanent deny-update
   stack policy. Retain the change-set ID, source SHA and readback digests. A
   successful CloudFormation status alone does not satisfy this prerequisite.
2. Preserve the separately installed PR #276 TEST trust cutover. Recheck the
   complete preview role trust immediately before the expanded identity grant;
   no generic `pull_request` subject may return. The trust removal and permission
   widening remain separate reviewed deployments.
3. Review this source change separately. Its TEST catalog is exactly the
   amendment result `ff2eaf296e5bd6e6bf8b02c7cdc31a2cfbcaef53fdea6173c64f77a3095effe7`;
   its provenance keeps `activation_authorized: false` because catalog metadata
   never authorizes an apply. It admits the single mutable attachment
   `arn:aws:iam::891377212104:policy/GitHubCiApply-user-service-infrastructure-test-poc-prerequisites`
   only on `GitHubCiApply-user-service-infrastructure-test`, then enables the
   packaged exact TEST repository identity. Verify active seed enrollment with
   independently authenticated AWS observations before privileged execution.
4. Install any required TEST governor identity policy update through the existing
   protected operator saved-plan path. The seed amendment changes immutable
   ceilings and guards; it does not install the mutable governor identity Allow
   needed to manage the new service policy. Inspect the exact saved plan and
   stop on unreviewed scope. Do not substitute a direct local apply.
5. Use the protected governance PR-comment saved-plan path to install the service
   apply managed policy and preview/drift read grants. A current write-permission
   maintainer requests `/pulumi test up`; `@Kravalg` approves `governance`.
   Preserve the repository's test-then-prod promotion contract: TEST apply/drift
   and PROD apply/drift at the same revision remain required for promotion,
   even though this capability is TEST-only and PROD has no new capability.
   Do not publish promotion success from TEST-only or stale-head evidence.
6. Verify the exact policy/attachments and native resource metadata. Keep
   `Issue215CutoverSessions` throughout. Its separate reviewed activation is a
   prerequisite to any downstream service apply; this change cannot bypass the
   deny-all hold. Then rerun the exact-head service PR comment plan and the
   separately authorized apply/drift sequence.

## Scope and offline proof

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
disabled PR #255 state. This candidate supersedes that state only after the live
installation prerequisite and separate source review; it does not assert that
governance promotion, operator activation or service deployment has completed.
