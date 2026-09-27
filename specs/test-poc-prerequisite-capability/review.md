# Historical review of the earlier enabled proposal

This scorecard records the earlier #253 source proposal and its release failure.
PR #255 restores the previously installed active TEST seed catalog and packages
the new identity with `enabled: false`. Statements below about an active
governor allowlist amendment, seed amendment reversal, and boundary/catalog
equality describe that earlier proposal, not the current disabled package.
The current behavior and test references are in `impact.md` and
`requirements.md`. A source-stage PASS for the restoration does not replace
the full CI, review, live IAM and protected deployment acceptance still needed.

STATUS: FAIL (historical full acceptance)
Issues:
1. Draft PR #253 has failing checks at its previously published head. The repaired source needs new hosted CI and native effective-permission/deployment evidence. Full BMAD and release acceptance cannot pass.
2. The service TEST apply role retains `Issue215CutoverSessions`, an unconditional deny-all hold. This is required and deliberately prevents activation.
3. Docker Make targets cannot create a network because the host's predefined address pools are exhausted. Native validation and the CI repair source review below supersede the original local coverage limitations; a full Docker battery is not claimed.

Review engine: Codex manual fallback, 2026-09-23. No Claude execution, GitHub
publication, AWS mutation or hold-removal step occurred. The organization's actual
review contract was read from `user-service/scripts/ai-review-prompts/bmad-fr-nfr-review.md`
and its BMAD wrapper pinned categories. This scorecard separates a reviewed source
proposal from full hosted/live acceptance. It does not emit PASS gate markers.

## Source FR/NFR scorecard

Requirements are in `requirements.md`; graph relationships are in `impact.md`.

| Item | Score | Evidence and consequence |
| --- | --- | --- |
| FR1 exact TEST identity | 5/5 | Account/partition/region/repo/project/organization/repository-ID/owner-ID mismatch tests; missing identity pair test. |
| FR2 initial ECR/SES and read roles | 5/5 | Exact action-set/resource tests; role spec read/apply split; helper line and branch coverage. |
| FR3 bounded DNS | 5/5 source | Positive multiple-token batch; wrong/mixed name/type/action, missing keys, wrong zone tests; AWS documented ForAllValues conditions with Null guards. Native IAM evaluation remains pending. |
| FR4 identity/boundary/seed consistency | 5/5 source | Runtime/seed boundary equality; governor policy ARN and exact NotResource membership tests; full prior-catalog reconstruction. |
| NFR1 minimal scope | 5/5 source | Exact action enumeration; foreign/PROD resources rejected; PROD catalog byte-identical. |
| NFR2 hold and trust | 5/5 source | Trust implementation unchanged, service guards unchanged, previous catalog recovered after exact amendment reversal; no live mutation. |
| NFR3 quota/offline verification | 4/5 | New managed policy bounded below 6,144 characters; runtime governor size checks and seed tests. Native current attachment quota and whole-repository coverage remain unverified. |
| NFR4 evidence honesty | 5/5 | Runbook states namespace versus dynamic-token responsibilities, read-metadata exposure, installation order and explicit non-activation. |

## NFR catalog and expanded quality review

All source evidence below follows the concrete policy/role/seed relationships in
`impact.md`; no workload execution, database, UI, queue or runtime resource changes
exist in this patch.

| Category | Score | Checked dimensions and remaining work |
| --- | --- | --- |
| Performance | 5/5 scope | Static bounded policy rendering only; no new polling loop, data path or cloud workload. Generated change polling uses existing provider. |
| Usability | 5/5 scope | Runbook distinguishes creation-only failures, pending activation, static DNS cap and plan responsibility. No UI/accessibility surface changes. |
| Maintainability | 4/5 | Shared emitter avoids identity/boundary drift; exact seed reversal, Ruff, import and dependency checks; full aggregate coverage pending. |
| Availability | 4/5 | Existing hold preserved; excluded update/delete fails closed. Native installation/rollback evidence pending. |
| Interoperability | 4/5 | Pinned provider call review and AWS IAM condition documentation; no native IAM simulator/provider execution at this commit. |
| Security | 4/5 | Exact principals/resources, no PROD/publisher/workload grant; mixed-batch and absent-key tests; native full authorization intersection pending. |
| Manageability | 4/5 | Immutable catalog pins and explicit activation dependency; actual IAM versions/attachments and deployment evidence pending. |
| Automatability | 4/5 | Existing managed/inline Pulumi builders and saved-plan workflow retained; hosted current-head checks pending. |
| Dependability | 4/5 | Deterministic negative/positive tests and historical parity; hosted/live and aggregate coverage pending. |

Expanded dimensions map to the same checked evidence: Functional Suitability (4,
live phase not proven), Performance Resource Sustainability (5, no workload),
Compatibility Coexistence (4, native policy intersection pending), Interaction
Capability Accessibility (5, documentation-only interface), Reliability Resilience
(4, recovery excluded until separately reviewed), Security Privacy Accountability
(4, bounded DNS metadata exposure documented), Maintainability Testability (4,
aggregate coverage pending), Flexibility Portability (5, deliberate exact TEST
scope), Safety Harm Prevention (4, hold retained, native checks pending), Data
Quality Integrity (5, full catalog reversal), Operational Excellence Releaseability
(2, no installation/activation), Observability Diagnosability (4, no current hosted
run), Supply-Chain Integrity (5 source, no dependency/lock changes), Compliance
Governance (2, protected hosted acceptance absent), Sustainability Resource Impact
(5, no workload deployment), AI Automation Governance (5 source, no remote mutation
and no delegated authority beyond this worktree).

## Tests, QA and impact

Positive cases: correct identity, fixed ECR/SES creation, each preview/drift read
subset, two valid DNS records, boundary/catalog equality and new managed attachment.
Negative cases: foreign account/region/partition/project/repo/organization/immutable
IDs, missing identity pair, PROD, foreign resource suffixes, wrong DNS zone, parent
or sibling namespace, mixed invalid batch, TXT, UPSERT, DELETE and missing condition
keys. Governor guards reject foreign/admin/PROD policy ARNs. Existing seed tests
verify foreign attachments and complete immutable enrollment. No new sleeps, clocks,
randomness, shared cloud state, external network calls or retry masking exist in
these tests. Tests do not claim AWS authorization evaluation.

Runtime paths, architecture/layers, configuration/environment, CI role-policy
wiring, tests/fixtures, documentation, security/privacy and backward compatibility
are mapped in `impact.md`. Persistence/database, public API/schema, async events,
queues, dependency/lockfiles and workload operations are unchanged. The source
review found and corrected the governor guard's two exact NotResource inventories;
without that correction, creating the new managed policy would remain denied.

The pinned system-quality breadth list was reviewed against these impacts. All
attributes concerning runtime/UI/data-plane behavior are outside this grant-only
source patch. Applicable authorization, auditability, correctness, credibility,
deployability, inspectability, integrity, manageability, operability, provability,
recoverability, reliability, safety, securability, testability, traceability,
transparency and vulnerability cannot receive a full-acceptance 5/5 until the
hosted/native evidence above exists. A complete passing breadth scorecard is not
claimed. Required next step: rerun the full organization BMAD gate for the actual
current-head PR and installed-source acceptance, keeping this release FAIL visible.

## Validation evidence

- Capability suite: 27 passed; the three new/changed helper functions have no missing lines or branches in focused coverage.
- Governance automation/component/parity suite: 169 passed, 22 existing Pulumi S3 deprecation warnings.
- Final frozen-source seed/capability combined coverage run exits 0 (161 collected tests). The exact amendment check then gained a stricter four-policy/count assertion; its six historical-parity cases pass. Seed registry reaches 100% line/branch coverage; new helper paths have zero uncovered lines/branches. The earlier seed run overlapped a catalog/hash edit and is discarded as stale; final catalog and code were frozen for the successful run.
- Ruff full source/test tree, changed-file format, Bandit changed policy sources, 11 import contracts and deptry pass.
- Repository-contracted Ty passes with one pre-existing unused-ignore warning in `scripts/deployment_controller.py:397`. A preliminary uncontracted Ty run reported two existing invalid-argument diagnostics; repository flags explicitly ignore that category.
- Initial module-target coverage failed before collection because Pulumi AWS was registered twice. Directory-source collection succeeds; the parallel coverage file was combined before reporting. This is not a whole-repository coverage pass.
- `make test-repo-hygiene` failed before actionlint because Docker exhausted its address pools. Equivalent native actionlint (workflows and documented example), yamllint (the exact Make target path list) and hadolint all pass. No shared network was deleted.
- Full acceptance: FAIL. No hosted check, review, effective native permission or same-revision TEST/PROD deployment result is fabricated.

## CI repair source review

Review engine: Codex manual fallback, 2026-09-23. Reviewed against published
`8fb03b386c1b11582947fa8449b58e35612fe166`, with replacement history based on
`837df484438cf2a9ee0b8f65a984cb547014749e`. The actual organization FR/NFR
instructions and pinned categories were read again. This is a source repair
assessment; the full gate remains FAIL because draft/current-head hosted and live
acceptance are unresolved. No review status or comment was published.

The Structural and Local Battery failures came from executable account literals
in `infra/governance.py`. The fixed public identity now lives beside that module,
loads through a fixed path and cannot be overridden by stack configuration.
ARN construction follows exact identity equality. Missing, malformed or incomplete
identity files raise before emitting grants. `impact.md` records the shared
runtime and deployment-scope relationships.

Gitleaks 8.24.2 identifies prose on original line 64 as `generic-api-key`, in both
the original feature commit and update-branch merge. Rephrasing that prose removes
the synthetic match. A clean replacement commit is necessary because the scanner
correctly includes every PR commit and merge diff. Scanner rules, exclusions and
range semantics are unchanged.

| Requirement | Source review evidence | Score |
| --- | --- | --- |
| FR1 | Exact nine-field identity; foreign account/region/partition/repository/project and identity tests; missing/malformed/incomplete file tests; changed working directory test. | 5/5 source |
| FR2 | Direct old/new comparison across both purposes and each identity mismatch gives identical statements in 20 cases; existing exact action/resource tests pass. | 5/5 source |
| FR3 | DNS statements and condition guards unchanged; positive/mixed/absent-key tests pass. | 5/5 source |
| FR4 | TEST/PROD catalogs remain byte-identical to the published head; boundary and attachment parity tests pass. | 5/5 source |
| NFR1 | Accepted statement documents are equal; no capability scope or PROD policy change. | 5/5 source |
| NFR2 | Trust, service guards and live hold are unchanged; no AWS operation occurs. | 5/5 source |
| NFR3 | Full unit source coverage and policy coverage pass at 100%; credential-free integration passes; policy size assertions pass. | 5/5 source |
| NFR4 | Historical scanner constraint, Docker blocker and missing hosted/live acceptance remain explicit. | 5/5 source |

Quality review checks the existing category and expanded-dimension matrices above
against the repair: fixed configuration loading, packaging, complete caller scope,
fail-closed parsing, unchanged IAM statements, deterministic tests, unchanged
dependencies and unchanged scanner coverage. No HTTP/API, database, queue, UI,
workload lifecycle, availability SLO or retention behavior changes. Remaining
native IAM, activation, rollback, hosted governance and releaseability gaps retain
their original failing full-acceptance scores. No blanket full-quality PASS is
claimed.

Manual QA: Codex compared original/repaired helper output offline for 20
purpose/identity combinations and verified both catalogs, scanner configuration
and structural account tests remained byte-identical. The test helper reads the
packaged file from a changed directory and proves malformed/missing input stops
rendering. No new clocks, randomness, network dependencies or retry masking are
introduced. Parallel test suites use separate coverage databases.

Current validation: the structural/governance/seed selection passes 1,236 tests;
the expanded capability/component/parity selection passes 103 tests; policy
passes 249 tests at 100% coverage; credential-free integration passes 173 tests.
Full unit validation passes 5,819 tests with 3 skips and 100% line/branch coverage.
Ruff lint/format, 11 import contracts, contracted Ty and Bandit pass. Existing
Pulumi deprecation/runtime warnings and Ty's unused-ignore warning remain.
Final identity-path placement is covered by a fresh full unit run.

Required remaining work: publish the clean history through an authorized PR
update, rerun current-head hosted checks and external Qlty, complete required
review and protected installation/native evidence. The live deny hold remains in
place until its separately authorized activation prerequisites are met.
