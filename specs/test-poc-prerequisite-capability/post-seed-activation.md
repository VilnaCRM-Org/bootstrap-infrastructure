# TEST capability activation (this PR)

This activation PR (#284, superseding #280) is the reviewed source change that
activates the TEST PoC prerequisite capability after the independent seed
amendment is installed. It is rebased on main after PR #275 and the TEST
preview-trust cutover in PR #276. It is not live seed-installation evidence, and
merging it deploys none of this capability. (`pulumi-test-deploy.yml` still
applies the base project on every push to main; that is unrelated to this
capability.) Merge it only inside the freeze window below, after every
[merge precondition](#merge-preconditions-nfr8) is recorded.

**Ordering precondition.** PR #283 merges first, through its own gate. Only then
is this PR retargeted or rebased onto the resulting main with fresh required
checks on the new head, and only then may the freeze window open. Do not open the
window while this PR is stacked on an unmerged base.
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
| FR5 | Packaged identity lifecycle `state: "enabled"`; [scope and offline proof](#scope-and-offline-proof-fr5-fr6-fr7-nfr5) |
| FR6 | Boundary, governor and attachment parity; [scope and offline proof](#scope-and-offline-proof-fr5-fr6-fr7-nfr5) |
| FR7 | TEST pin `ff2eaf29…`; the amendment cannot be replayed |
| NFR5 | TEST-only scope, PROD unchanged, merge deploys none of this capability |
| NFR6 | [Rollback and fail-forward](#rollback-and-fail-forward-nfr6) |
| NFR7 | [Freeze window and merge sequence](#freeze-window-and-merge-sequence-nfr7) |
| NFR8 | [Merge preconditions](#merge-preconditions-nfr8) |

## Ordered activation (FR5-FR7, NFR7)

1. Make this PR merge-ready before touching AWS: exact head reviewed by
   CodeRabbit and `@Kravalg`, every required check green on that head, no
   unresolved threads, branch current with main. Its TEST catalog is exactly the
   amendment result `ff2eaf296e5bd6e6bf8b02c7cdc31a2cfbcaef53fdea6173c64f77a3095effe7`;
   its provenance keeps `activation_authorized: false` because catalog metadata
   never authorizes an apply. It admits the single mutable attachment
   `arn:aws:iam::891377212104:policy/GitHubCiApply-user-service-infrastructure-test-poc-prerequisites`
   only on `GitHubCiApply-user-service-infrastructure-test`, then sets the
   packaged exact TEST repository identity to `"state": "enabled"`
   (`pulumi/infra/test-poc-identity.json`).
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
4. Record the [merge preconditions](#merge-preconditions-nfr8) as a PR comment
   (`governance-promotion.yml` re-runs on `edited`, so keep the evidence in a
   comment rather than editing the PR body after approvals), merge
   it through normal branch protection and close the freeze window as described
   below.
5. Install any required TEST governor identity policy update through the existing
   protected operator saved-plan path, on follow-up PR-B (see below). The seed
   amendment changes immutable
   ceilings and guards; it does not install the mutable governor identity Allow
   needed to manage the new service policy. Inspect the exact saved plan and
   stop on unreviewed scope. Do not substitute a direct local apply.
6. Use the protected governance PR-comment saved-plan path, on follow-up PR-C
   (see below), to install the service apply managed policy and preview/drift
   read grants. A current write-permission maintainer requests
   `/pulumi test up`; `@Kravalg` approves `governance`.
   Preserve the repository's test-then-prod promotion contract: TEST apply/drift
   and PROD apply/drift at the same revision remain required for promotion,
   even though this capability is TEST-only and PROD has no new capability.
   Do not publish promotion success from TEST-only or stale-head evidence.
7. Verify the exact policy/attachments and native resource metadata. Keep
   `Issue215CutoverSessions` throughout. Its separate reviewed activation is a
   prerequisite to any downstream service apply; this change cannot bypass the
   deny-all hold. Then rerun the exact-head service PR comment plan and the
   separately authorized apply/drift sequence.

**Post-merge commands need a follow-up PR.** `/pulumi` is refused on closed or
merged pull requests (`pulumi-pr-commands.yml`, "Reject closed or merged pull
requests"), so steps 5-7 and the freeze-closing operator TEST plan cannot run on
this PR after it merges. They run on reviewed follow-up PRs opened from the
merged main. `scripts/deployment_scopes.py` selects stacks only from changed
paths:

- **PR-B (operator, step 5 and freeze close).** Its only runtime change is under
  `pulumi/github-ci-bootstrap/` (for example a reviewed comment in
  `pulumi/github-ci-bootstrap/__main__.py`), which selects only `("operator",)`.
  `/pulumi test plan` is the first post-merge operator TEST plan; its enrollment
  check runs at the start of every stage. `/pulumi test up` then installs the
  governor identity update (step 5).
- **PR-C (governance, step 6).** Its only runtime change is under
  `pulumi/governance/`, which selects only `("governance",)`. Run
  `/pulumi test plan`, then `/pulumi test up`.

A change under `pulumi/infra/` or `pulumi/seed/` instead selects all three stacks
in `operator`, `governance`, `platform` order. Documentation, `specs/` and
`tests/` changes select no stack and cannot run these steps.

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
  this PR merges.

`/pulumi prod plan` and `/pulumi prod up` run the TEST sequence first, so both
failure modes also stop PROD promotions that include the operator stack. Keep the
gap short and explicit:

1. Complete ordered step 1 first. Do not start installation while review,
   required checks or rebases are outstanding.
2. Announce the freeze: no `/pulumi` commands whose scope includes the operator
   stack, other than the PR-B commands below, and no other merges to main
   (other than PR-B), until the window closes. A new main
   commit would require a rebase and fresh checks inside the window.
3. Install the seed amendment (ordered step 3). If installation fails or leaves a
   partial result, follow [rollback and fail-forward](#rollback-and-fail-forward-nfr6)
   and do not merge.
4. Record the merge preconditions, then merge this PR immediately with normal
   branch protection. If the seed is installed but the merge is blocked, follow
   [the seed-installed decision](#rollback-and-fail-forward-nfr6).
5. Open PR-B (see the follow-up PR note above), merge nothing else, and run
   `/pulumi test plan` then `/pulumi test up` on it. Close the window only after
   both hold: the first post-merge operator TEST plan passed its enrollment
   checks against the installed seed, and the step 5 governor identity policy
   was applied and read back as reviewed. A passing plan alone does not close the
   window. If step 5 fails, the window stays open (see the step 5 failure branch
   in [rollback and fail-forward](#rollback-and-fail-forward-nfr6)).

An administrator bypass merge is forbidden, including to shorten the window or
to work around a failing, pending or missing required check. Fix the cause, or
leave the PR unmerged and follow the rollback decisions.

## Merge preconditions (NFR8)

Record sanitized metadata only (IDs, SHAs, digests, run links) on this PR (as a
comment, never an edit of the PR body) before merging. Do not record credentials, stack exports or CI configuration payloads.

- [ ] CloudFormation change-set ID executed on the TEST seed stack in account
      `891377212104`, `eu-central-1`, with the complete paginated change set
      accepted by `validate_test_poc_change_set` as exactly four non-replacing
      `PolicyDocument` modifications.
- [ ] Source SHA of the reviewed amendment packet and the exact head SHA of this PR
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
- [ ] `verify_active_enrollment` on this PR's TEST registry passes for an
      independently authenticated, non-root, read-only observation of the
      installed account, run as the installer with the checked-out candidate
      source (see [active verification command](#active-verification-command)).
      `--active` trusts the code and catalog on disk, so also record:
  - `git rev-parse HEAD` in that checkout, equal to this PR's merge head SHA;
  - empty output from
    `git status --porcelain --ignored --untracked-files=all` (or state that the
    checkout is a fresh clone of that SHA with nothing added). Record this
    status BEFORE running either command below; both use `python3 -B -I` so they
    create no `__pycache__` or other files, and the status must still be empty
    afterwards;
  - the public seed KMS key ARN from the `--seed-key-binding` input;
  - the absolute `--aws-executable` path and that it is a trusted AWS CLI
    install outside the checkout;
  - the printed registry SHA-256 and verified counts; and
  - a reviewer's independent offline recomputation of
    `build_registry("test", ...).sha256` from the same head and binding (see
    below), equal to the printed registry SHA-256.
- [ ] This PR's exact head still has current approvals, green required checks and
      no unresolved threads.

### Active verification command

Operator workflow sessions (`GitHubOperator{Purpose}-test`) exist only on main
and check main's registry pin, so they cannot verify this PR's candidate
registry before merge. Use the installer-authenticated active mode instead. From
a clean checkout of the exact PR head, with an already-issued nonroot installer
session and no other credentials:

```text
python3 -B -I scripts/operator_seed_observation.py --active \
  --environment test --account-id 891377212104 \
  --seed-key-binding '<public DescribeKey binding JSON>' \
  --installer-role-arn <reviewed installer role ARN> \
  --aws-executable <absolute aws CLI path>
```

`--seed-key-binding` is one JSON object of at most 4096 bytes with exactly six
snake_case keys, every value a JSON string: `arn`, `key_id`, `aws_account_id`,
`key_manager`, `key_state` and `key_usage`. Copy them from the public
`aws kms describe-key` `KeyMetadata` fields `Arn`, `KeyId`, `AWSAccountId`,
`KeyManager`, `KeyState` and `KeyUsage`. The ARN must be in `eu-central-1` and
account `891377212104`, with `CUSTOMER`, `Enabled` and `ENCRYPT_DECRYPT`.
Missing, extra, duplicate or non-string fields are rejected
(`operator_seed_observation._key_binding`). Live `DescribeKey` must also equal
this binding.

`--aws-executable` is checked only for being absolute, executable and named
`aws` (`operator_aws_read.py`). The operator must point it at a trusted AWS CLI
installation outside the checkout, for example the system package, never a
path inside the PR tree or a user-writable directory.

It authenticates the installer by STS identity and immutable RoleId, reads only
STS/IAM/KMS metadata (never `GetSecretValue`), builds the registry and catalog
from the checked-out source, and calls `verify_active_enrollment`. It prints
only the registry SHA-256 and verified counts; expected output is 55 policies,
24 principals and 3 active executors with `activation_authorized: false`. Wrong
pins, extra attachments, missing guards and trust mismatches exit non-zero. The
same command without `--active` remains the disabled-trust initial check and
rejects active executor trust.

A reviewer recomputes the registry digest offline, with no credentials, from a
clean checkout of the same head and the same binding JSON:

```text
python3 -B -I -c 'import json, sys; sys.path.insert(0, "pulumi"); \
from seed import policy_registry as r; \
print(r.build_registry("test", account_id="891377212104", \
seed_key=r.SeedKeyBinding(**json.loads(sys.argv[1]))).sha256)' \
  '<same public DescribeKey binding JSON>'
```

The printed value must equal the `registry_sha256` from the installer run.
`scripts/run_security_mutation_tests.py` (`make test-mutation`) mutates the
catalog hash check, installer authentication, key-binding bounds, the
`verify_active_enrollment` checks and the `--active` routing. The tests must
kill every one of those mutants.

## Rollback and fail-forward (NFR6)

Default to fail-forward. The seed ceilings grant nothing without the governance
identity policy, and `Issue215CutoverSessions` still denies service sessions on
the TEST apply role. Withdraw only when the capability itself is wrong. Never run
a direct apply, cancel a Pulumi lock, retry a failed saved plan, edit the catalog
to match live state, publish synthetic success or bypass branch protection.

**Seed installation fails or is partial (before merge).** Restore the permanent
deny-update stack policy. Read back the stack status, template and four
default-version documents. If they still equal the `ef419680…` baseline, main
stays valid: leave this PR unmerged and close the freeze. Any mixed or
`UPDATE_ROLLBACK_FAILED` state keeps the freeze. Reconcile it through a
separately reviewed change set and never replay the executed one.

**Seed installed, merge blocked.** AWS holds the `ff2eaf29…` documents while
main pins `ef419680…`, so operator TEST runs fail closed. The only exits are:
fix forward and merge this PR, or author, review and merge a reversal packet
bound to `ff2eaf29…` that produces the `ef419680…` documents, with a change-set
validator for exactly those four reverse modifications, and restore the
`ef419680…` seed with it. No capability policy or attachment exists yet in this
case, so the governance deletion limits under withdrawal below do not apply.
The freeze stays open
until one of them completes. Do not edit the catalog to match live state, and do
not bypass branch protection.

**Operator governor identity update fails (ordered step 5).** The seed and merged
source stay. The freeze window stays open; this is the same rule as
window-closing step 5. Record the run ID, failed stage, saved-plan manifest hash and
sanitized diagnostics, and read back the governor identity policy. Do not apply
directly or retry the failed saved plan. Repair the cause through a reviewed
change, then run a fresh exact-head saved plan on PR-B (or its reviewed
successor), inspect it and apply it through the same protected path. Step 6 must
not start, and the freeze stays open, until
the governor identity policy is read back as reviewed.

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

**Capability must be withdrawn.** The packaged identity
(`pulumi/infra/test-poc-identity.json`) carries an explicit lifecycle `state`
that `infra.governance._TEST_POC_LIFECYCLE` maps to four consumers:

| `state` | Service documents (governance) | Governor exact-policy grant (operator) | Seed boundary ceiling |
| --- | --- | --- | --- |
| `enabled` | Allow capability | rendered | rendered |
| `withdrawn` | explicit Deny of the same actions and resources | rendered | rendered |
| `disabled` | absent | absent | absent |

Any other value, or a missing `state`, fails every render closed.

Withdrawal cannot delete the capability through the protected route. The
destructive-diff gate (`scripts/pulumi_ci_guardrails.py`, `aws:iam/` is a
critical type) rejects every IAM `delete` or `replace` on plan and again before
saved-plan replay, with no override (`docs/ci-guardrails.md`). The governance
stack also sets `protectResources: "true"`
(`pulumi/governance/Pulumi.test.yaml`), so Pulumi refuses to delete the
`poc-prerequisites` policy, its attachment and the preview/drift inline grants.
`withdrawn` therefore keeps the same three policy identities and replaces their
documents in place with explicit Deny statements for exactly the withdrawn
actions and resources (`_withdrawn_test_poc_statements`). No other service grant
allows those actions, so this restores the pre-capability effective access and
stays fail-closed. The governor keeps its exact-policy read/update grant, so the
operator stack, which `/pulumi test up` runs before governance whenever the
identity file changes, changes nothing. The ceiling keeps matching the
`ff2eaf29…` pin, and the attachment stays inside the seed guard's allowlist, so
active enrollment keeps passing.

1. **Withdrawal PR: `"state": "withdrawn"`.** A reviewed PR changes only the
   identity state plus tests and this runbook. On the open PR, run
   `/pulumi test plan`, review it, then `/pulumi test up` (`@Kravalg` approves
   `governance`). The operator plan must show no change. The governance plan may
   only update the `poc-prerequisites` apply policy (a new default version) and
   the preview/drift inline `poc-prerequisites` grants. Any `delete` or
   `replace`, or any other change, stops the run for review. Each Deny keeps the
   Action, Resource and Condition of the Allow it replaces, so it blocks exactly
   what was granted (for example only DKIM CNAME CREATE in the fixed zone, not
   every record change).
2. Read back the new default policy version and both inline documents (Deny
   only, same actions and resources), and confirm the apply role attachments are
   still `pulumi-backend`, `secret-read-deny`, `poc-prerequisites` and guards.
   Record them on the PR, then merge it.
3. Service stack: the Deny includes `s3:GetBucketVersioning` on
   `pulumi-user-service-infrastructure-test-state`, which no other service
   grant allows (`pulumi-backend` grants only ListBucket/GetObject/GetObjectVersion
   and write actions). The recorded TEST plan failure stopped at that backend
   observation, so a withdrawal halts `user-service-infrastructure` TEST plans,
   drift and applies at backend observation, before any resource refresh, until
   the capability is re-enabled. That service repository's runner code is not in
   this repository, so this needs confirmation there. Once the Deny is live, the `user-service-infrastructure`
   TEST preview, drift and apply roles can no longer read or change any ECR
   repositories, SES identity or DKIM records created under the capability, so
   that stack's refresh and drift fail while it still tracks them. Before the
   withdrawal PR, list those resources in its TEST state. Resolve them only
   through that repository's own reviewed change and protected path; its
   destructive-diff gate applies there too, so Route53 record deletes stay
   blocked. Record the result, or record that none were created. Never edit its
   state directly.
4. Health checks: the next operator TEST plan passes its enrollment checks,
   governance TEST drift is clean, the service apply role still carries
   `Issue215CutoverSessions`, and step 3 is recorded.
5. Evidence: PR SHA, governance and operator run IDs, saved-plan manifest
   hashes, the three document digests and sanitized readbacks.

Re-enabling sets `"state": "enabled"` through the same reviewed path, which
updates the same documents back to the Allow capability.

Deleting the policy and attachment, narrowing the governor, and reversing the
seed to the `ef419680…` catalog (`"state": "disabled"`) are not available. They
need separately reviewed changes to the destructive-diff control and the
resource protection, plus a reversal packet bound to `ff2eaf29…` with a
change-set validator for exactly the four reverse modifications. Reversing the
seed while the policy and attachment exist is unsafe. The mutable-attachment
check in `policy_registry.py` hard-codes the TEST `poc-prerequisites` ARN for
every catalog, so it would still admit the attachment. The failure comes from
the catalog itself: the four policy documents (including the governor apply
policy and the apply guard's two closed lists that reference that ARN) would
revert to their `ef419680…` versions, so the installed documents no longer match
and active enrollment fails on the document hash comparison until the reverse
change set is installed, while the attached policy loses its guard and
governor coverage. Never do any of this through a direct apply, a Pulumi state edit such
as `pulumi state unprotect`, or implicit break-glass.

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
