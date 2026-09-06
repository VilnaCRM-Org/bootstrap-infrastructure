# PR60 successor verification amendment

This is the active interpretation of issue #59. Its historical PRD, architecture,
stories and readiness report retain their original evidence; their earlier
scores and approvals do not prove current acceptance.

## Source and ownership

Assembly source: `54d6f664250483c8d3b77a52964f5ac575f87899`.
Initial actual main base after #193: `888b2424c2cc3fe475e1cf24c614004c49a4928e`.
The actual main base after #57 is
`e37eb3ff86105581b751df4526c1720dd469b0d2` (merged 2026-09-06).
Its tree is byte-identical to the validated #57 source head
`59d21e402a791d59f359a5879aa5be252391f1fe`. All four local operator commits
were replayed onto this actual squash commit without conflicts. The provisional
candidate is preserved at `backup/pr60-before-pr57-squash-20260906` (`d8cb30a`).
The records below bind checks to explicitly named historical revisions. For a
later revision, use that commit's CI and review receipts; publication alone does
not establish validation or acceptance.

The six isolated operator project files preserve project/stack names and the
complete `PlatformIamBoundaries` → `GitHubCiBootstrap` → `PlatformControlIam`
composition. `GovernanceAutomation` and `repositories.governance.json` preserve
operator-owned governor runner roles and immutable service/replication boundaries.
Their public repository/owner IDs come from the canonical inventory.
No delegated `governance.py` or `pulumi/governance` program, service scaffold or
onboarding implementation is added. Those remain #78 work. Existing controller,
trusted loader, IAM documents, content pins, provider/adoption dependencies and
neutral account helper remain installed unchanged.

Five added files retain their canonical bytes: the operator project manifest,
TEST/PROD public config, operator requirements and governance catalog. The
operator entrypoint, governor module and governor tests were initially copied
from canonical source, then deliberately corrected during review; they are no
longer byte-identical. The corrections reject invalid operator inputs before
registration and strengthen independent regression checks without widening IAM
grants. The example remains incomplete until both verified GitHub identity
placeholders are supplied. Other changes include selected tests, additive
mutation targets and corrected docs. The deployment-evidence exclusion now uses
the shared governance catalog constant; governance remains validated by its
separate per-kind catalog/fanout validator.

## Requirement and story reconciliation

| Original requirement/story | Current implementation and acceptance |
| --- | --- |
| Isolated AWS-only project; story 1.1 | Six operator project files; independent operator backend/checkpoint. `pulumiBackendUrl` names emitted platform CI state, never selects operator state. |
| OIDC/control owner; story 2.1 | Full operator graph and protected controls; platform root remains reference-only. Ownership migration and encrypted backups precede any replay. |
| Purpose-specific roles; story 2.1 | Fixed account, audience, immutable repo/owner IDs, exact branch/environment/subject. Ordinary `workflow` differs from reusable `job_workflow_ref`; a workflow name alone is not code attestation. `test-pr` cannot assume apply. |
| CI containers, four suffixes and payloads; story 3.1 | TEST `test-pr`/`test`, PROD `prod-preview`/`prod`; secret versions protected and encrypted. Config-read role/region outputs plus independent repository account pins. Manual payload changes require separate reviewed ownership reconciliation. |
| Every AWS job and output; stories 2.1/4.1 | Operator guide maps preview, apply, drift, IAM validation, evidence and triage to suffix/runtime roles. `governanceGithubVariables` describes prerequisites, not completed onboarding. |
| Local preview/apply; story 4.1 | Refreshed policy-checked saved plan; independent review and exact-plan replay, provider/checkpoint/source binding and metadata-only zero-drift receipt. Historical unsaved apply and repair examples are superseded. |
| Least privilege and quotas | Preserve actual union of grants, immutable boundaries and denies; governor policies have no wildcard exemption from platform document pins. Validate trust/managed/inline aggregate quotas and retained policies before live replay. |
| State and secret safety | Retain AWS S3/KMS and encrypted data-key continuity; no raw payload or checkpoint contents logged or committed. State-only initialization is an explicit trusted prerequisite, never a missing-state fallback. |
| Production approval and main-only execution | Retain protected `test-preview`/`prod-preview` preview/drift, `test`/`prod` apply, and `governance-preview`/`governance` governor environments with current immutable-ID trust. |
| Current checks and reviews; story 5.1 | Source checks, hosted/AI/BMAD review and live acceptance are distinct. Historical 24 resolved threads on original PR60 do not transfer approval to a successor. |

The original statement that fallback removal can wait until after bootstrap no
longer applies: the installed controller already requires saved plans and rejects
unsafe recovery. Nothing in this successor weakens that contract.

## Historical local evidence before the #57 rebase

The following checks were performed on the original #193-based assembly, not
the provisional #57-based candidate. PR57 runtime, KMS, trust, workflow and
alert documentation fixes are inherited from the provisional base; their newer
shared dependency hashes supersede the older canonical hashes.

- Exact-source hashes were verified for all eight unadapted additions and all ten
  then-unchanged shared dependencies against the pinned assembly plan.
- Focused operator/governor/account/trust/ownership/dependency/semantic-runner
  tests: 171 passed. Changed structural and delivery tests: 59 passed.
- New operator entrypoint and governor runtime: 214 statements and 52 branches,
  100% line and branch coverage.
- Ruff lint/format, Ty with repository settings, Xenon thresholds, YAML,
  catalog validation, all ten import contracts, dependency hygiene and Gitleaks
  directory scan passed.
- Semantic mutation: 82/82 killed, including all 69 installed cases and 13 new
  governor cases. Ordinary mutation: 83/83 killed, zero survivors, errors or
  timeouts. Both campaigns ran in isolated copies.
- Complete `make ci-pr-unprivileged` passed at
  `55f67221f66f72345b401750832cf55a3fa348d0`: 1380 unit, 181 structural,
  120 policy, 6 unprivileged integration and 72 CLI tests, plus quality,
  architecture, dependency, repository hygiene, security and unprivileged
  guardrails. Combined coverage: 8972 statements and 2624 branches, 100%.
  The actual-main battery is recorded separately below.


## Historical provisional #57-source rebase checks

The provisional base is `59d21e402a791d59f359a5879aa5be252391f1fe`.
The original candidate is preserved at local backup ref
`backup/pr60-before-pr57-source-20260906` (`e5f235c`). Three conflicts in the
GitHub secrets guide and two structural test files were resolved by preserving
complete #57 content and adding operator-specific sections and tests. The
operator prerequisite caveats now describe the included program while retaining
independent ownership review and the deferred delegated governance program.

- The remaining diff contains exactly 27 scoped paths. The only overlap with
  #57 is four operator-facing docs and two structural test files. All #57 runtime,
  KMS/trust, loader, controller and workflow files remain byte-identical.
- All eight unadapted canonical additions remain byte-identical to the pinned
  assembly source.
- Focused operator/governor/ownership/trust and structural tests: 224 passed.
  Existing KMS, CI trust and main-only regressions: 65 passed.
- Changed Python Ruff lint, conflict-file formatting, scoped Ty and whitespace
  checks passed. These checks did not collect or alter coverage.
- No full battery, mutation campaign, hosted review or live operation was repeated
  for that provisional rebase. The actual-main rebase and its validation are
  recorded below.

## Historical actual-main candidate (2026-09-06)

The previously published candidate `e1b3574cdaa8113e8bfc9a50d05360ee2b16e846` was validated and
published on actual #57 squash base `e37eb3ff86105581b751df4526c1720dd469b0d2`.
`make ci-pr-unprivileged` passed: 1594 unit, 188 structural, 120 policy,
173 integration and 72 CLI tests; 9206 statements and 2702 branches at 100%.
Full-battery log SHA-256:
`e16395a076930b3527234a1c84826275316cf66c377944271703e0d5fc006ce5`.
The isolated exact-source mutation campaign passed: 83/83 ordinary and 82/82
semantic mutants killed, with zero survivors, errors or timeouts. Mutation log
SHA-256: `5ae4b333fa230e7913f24cd40b58231f60e40525f14649e46bc9ec4d298cdbe7`.
The local validation receipt SHA-256 is
`3f04ca934ad7ba157d36eb5cfe50c45a2eb6e05ed3257a5bbd31e687387ee8c8`.

These results apply only to `e1b3574`, before the review corrections described
in Source and ownership. They do not validate a later commit. The subsequent
`7e2ae3b4f0adf1ba56676d74cb0cceca798c3bb4` local battery passed with 1613 unit,
188 structural, 120 policy, 173 integration and 72 CLI tests and 100% coverage
across 9226 statements and 2714 branches. Its source review and mutation-input
identity were recorded separately. Later commits require their own relevant CI
and review evidence. These dated source results do not establish an operator
resource deployment, owner acceptance or full BMAD PASS.

## Deferred external acceptance

The initial source assembly was local-only; subsequent publication and review
are recorded by GitHub against their specific commits. This amendment's local
source results do not substitute for current hosted approvals, real TEST/PROD
comment deployment and post-deployment acceptance. Historical BMALPH evidence
remains dated 2026-05-25 and cannot establish a later revision's readiness.

Operator paths correctly classify this change as governance. The installed
controller cannot apply the privileged operator project, while the delegated
program remains deferred to #78. Therefore this successor alone cannot produce
full governance comment-deployment proof. Preserve routing and required gates;
record any blocked gate as explicitly deferred under the user's current merge
authorization, with honest provenance. An operator receipt is not OIDC execution,
a protected-environment approval, or comment-deployment evidence.

Before any new live replay, bind the actual successor source, account/backend,
provider/checkpoint version, retained-policy inventory and reviewed plan again.
Require encrypted backups, canonical single ownership, reviewed trust/policies,
quotas and direct dependencies; reject unintended replacement/deletion or drift.
TEST and PROD, PR192 manual acceptance, and current hosted review remain separate
external evidence obligations. This amendment does not mark them complete.
