# TEST capability activation candidate

This local candidate is prepared against PR #275 head
`e7a46b463e6f123402886edc647d900060ec827b`, descended from authoritative main
`1ed394db0b5c9d9533d83490ea9cff74f6056f68`. It is not live installation evidence.
Do not publish or deploy it until the independent seed amendment completes the
exact readback required by [the installation runbook](amendment-installation.md).
There is a second unresolved prerequisite: reviewed service preview trust and
its live cutover must be installed before any expanded preview identity grant.

Current source `ci_bootstrap._deployment_role_subjects` excludes the generic
TEST `pull_request` subject only for `VilnaCRM-Org/bootstrap-infrastructure`;
it still emits that subject for `user-service-infrastructure`. The parent task's
fresh TEST readback also found generic service preview PR trust. Bootstrap
PR #244 being merged therefore does not establish the service's required trust
isolation. A service-specific reviewed source change is necessary so governance
cannot reintroduce generic PR trust after an operator removes it.

## Ordered activation

1. Independently install the reviewed PR #275 four-policy TEST amendment.
   Authenticate the complete resulting template, all four default policy
   documents, attachments, boundaries, guards and restored permanent deny-update
   stack policy. Retain the change-set ID, source SHA and readback digests. A
   successful CloudFormation status alone does not satisfy this prerequisite.
2. Separately review the service preview trust source correction for issue #185.
   Deploy it through the protected saved-plan path with the prerequisite
   capability still disabled. Read back the complete TEST preview role trust,
   immutable repository/owner ID conditions, protected preview environment and
   exact source-admission workflow. Verify that no generic `pull_request` subject
   remains and that reviewed source is required before expanded permissions.
   Do not combine trust removal and permission widening into an unverified
   concurrent rollout. This candidate does not implement or prove that cutover.
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
