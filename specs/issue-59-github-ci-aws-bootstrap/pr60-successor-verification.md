# PR60 successor verification amendment

This is the active interpretation of issue #59. Its historical PRD, architecture,
stories and readiness report retain their original evidence; their earlier
scores and approvals do not prove current acceptance.

## Source and ownership

Assembly source: `54d6f664250483c8d3b77a52964f5ac575f87899`.
Initial actual main base after #193: `888b2424c2cc3fe475e1cf24c614004c49a4928e`.
The final base must also include the merged #57 successor before publication.
The assembly commit containing this amendment is the reviewable source revision;
validation records below identify the checks performed on its source tree.

The six isolated operator project files preserve project/stack names and the
complete `PlatformIamBoundaries` → `GitHubCiBootstrap` → `PlatformControlIam`
composition. `GovernanceAutomation` and `repositories.governance.json` preserve
operator-owned governor runner roles and immutable service/replication boundaries.
Their public repository/owner IDs come from the canonical inventory.
No delegated `governance.py` or `pulumi/governance` program, service scaffold or
onboarding implementation is added. Those remain #78 work. Existing controller,
trusted loader, IAM documents, content pins, provider/adoption dependencies and
neutral account helper remain installed unchanged.

Eight added exact-source files retain their canonical bytes: project manifest,
TEST/PROD public config, operator entrypoint, operator requirements, governor
module, governance catalog and governor tests. The example deliberately remains
incomplete until both verified GitHub identity placeholders are supplied. The
other changes are selected tests, additive mutation targets and corrected docs.
A bounded 27th path adds the exact canonical deployment-evidence exclusion for
`repositories.governance.json`. The first full battery exposed this dependency;
the existing evidence expectation is preserved, and governance remains validated
by the separate per-kind catalog/fanout validator.

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

## Local evidence

- Exact-source hashes verified for all eight unadapted files and all ten
  unchanged shared dependencies against the pinned assembly plan.
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
- The initial full battery passed 181 structural and 120 policy tests, quality,
  hygiene and catalog gates; its unit suite found the missing canonical fanout
  exclusion above. The separately completed remainder passed 6 unprivileged
  integration and 72 CLI tests, security scans/audit and unprivileged guardrails.
  After the exclusion, all 1380 unit tests passed; combined coverage is 100%
  across 8972 statements and 2624 branches. The final #57-base battery remains
  pending until the actual merge is available.

## Deferred external acceptance

No AWS or GitHub mutation occurred during this local assembly. No fresh hosted
AI approval, formal BMAD pass, actual comment deployment, TEST/PROD operator
replay or full acceptance is claimed. Historical BMALPH evidence remains dated
2026-05-25 and cannot establish this revision's readiness.

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
