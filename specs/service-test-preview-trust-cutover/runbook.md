# Service TEST preview trust prerequisite (#185 / #219)

Retire generic `pull_request` subjects from
`GitHubCiPreview-user-service-infrastructure-test` before granting new workload
metadata permissions for the service registry capability. Both conventional and
immutable-ID PR subject formats must be absent. Preserve the existing main,
`test` and `test-preview` subjects and repository/owner identity conditions.
No seed policy, capability flag, permissions document or apply/drift trust changes
are part of this source change.

At reviewed service main `61d585b3c90b1b4f01c5d81e5d24fbd4e829f8a4`,
`.github/workflows/self-deploy.yml` accepts `repository_dispatch`; its preflight
requires `refs/heads/main`, and `test_preview` uses `environment: test-preview`.
The job checks out the trusted workflow SHA and rechecks the exact source,
requester and review before requesting preview OIDC credentials.
`service_execution_host._trusted` checks main, workflow/source SHA equality and
the checkout. Automatic `pulumi-pr-guardrails.yml` PR previews use a local backend
and have no `id-token: write` permission. These source paths do not require the
retired PR subjects; source inspection is not a live deployment smoke test.
Existing [run 36324543713](https://github.com/VilnaCRM-Org/user-service-infrastructure/actions/runs/36324543713)
used `repository_dispatch` on that main SHA. Its Test Preview source recheck and
OIDC credential steps succeeded; the later saved-plan step failed. This confirms
the existing controller path, not successful deployment or post-cutover proof.

Apply this separately reviewed trust-only change through the protected governance
saved-plan path while `test-poc-identity.json` remains disabled. Inspect the exact
plan for the TEST service preview trust removal and stop on unrelated changes.
Retain the current protected approval and test-then-prod promotion requirements.
Read back the complete live trust document and confirm both PR subject formats
are absent, the immutable identity conditions remain, and the protected preview
environment admits only the intended trusted controller. Run the exact-head
trusted controller preview to prove its OIDC path still works. Do not widen the
service preview capability until this cutover and the independent TEST seed
amendment have both been verified. Keep `Issue215CutoverSessions`; its retirement
requires a separate reviewed activation.
