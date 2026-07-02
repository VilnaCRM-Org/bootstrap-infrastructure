# Enterprise Quality Audit — 2026-07-02

Evidence-based audit of `bootstrap-infrastructure` against the full list of
[system quality attributes](https://en.wikipedia.org/wiki/List_of_system_quality_attributes)
(~93 attributes) plus two audit-specific dimensions: AI-native autonomous development
readiness and frontend best-practices applicability (this repository has no frontend surface,
so frontend practices were assessed for applicability only).

Each attribute was scored 1–5 by an independent audit agent with file-level evidence.
A score of 5 requires systematic enforcement (CI gate, policy, or test), not just documentation.
For every attribute below 5/5 a GitHub issue was filed with the evidence, gaps, and
acceptance criteria that define 5/5.

## Summary

- Attributes audited: **95**
- At 5/5: **3** — below 5/5 (issue filed): **92**
- Score distribution: 3× 5/5, 66× 4/5, 26× 3/5
- Average score: **3.76/5**

## Security & Trust

| Attribute | Score | Issue | Gap summary |
| --- | :-: | --- | --- |
| accountability | 3/5 | #80 | unowned alerts and missing CODEOWNERS enforcement |
| auditability | 4/5 | #81 | short evidence retention and single-account trail |
| confidentiality | 4/5 | #82 | gitleaks scans only the latest commit |
| credibility | 4/5 | #90 | stub SECURITY.md and empty CHANGELOG |
| integrity | 4/5 | #83 | unverified rulesets and unsigned releases |
| safety | 4/5 | #88 | alert response loop not closed |
| securability | 4/5 | #84 | manual OIDC and environment bootstrap |
| vulnerability | 4/5 | #86 | incomplete Dependabot coverage and image scanning |

## Reliability & Resilience

| Attribute | Score | Issue | Gap summary |
| --- | :-: | --- | --- |
| availability | 4/5 | #85 | no replica-lag or alert-path monitoring |
| degradability | 4/5 | #91 | no fallback alert route or degraded-state detection |
| dependability | 4/5 | #87 | unowned alerts and manual KPI freshness |
| durability | 4/5 | #89 | no immutable retention; 4-day alert queue |
| failure transparency | 3/5 | #92 | alert noise, no dedup or meta-monitoring |
| fault-tolerance | 4/5 | #93 | no generic transient retry; brittle error matching |
| recoverability | 4/5 | #95 | manual restore drills nearing staleness |
| redundancy | 4/5 | #96 | single-account copies; unreplicated audit buckets |
| reliability | 4/5 | #98 | close self-declared REL9/REL10/REL13 blockers |
| resilience | 4/5 | #100 | no automated game-days or canary alerts |
| robustness | 4/5 | #101 | untested inline triage script; fragile error matching |
| stability | 4/5 | #103 | update automation misses actions, docker, root deps |
| survivability | 3/5 | #105 | single-account blast radius, no immutable copy |

## Maintainability & Code Structure

| Attribute | Score | Issue | Gap summary |
| --- | :-: | --- | --- |
| analyzability | 4/5 | #94 | advisory quality reports lack enforcement thresholds |
| composability | 3/5 | #97 | duplicated helpers instead of shared components |
| evolvability | 4/5 | #99 | no ADRs, hand-maintained module registries |
| extensibility | 4/5 | #102 | manual registration friction for new modules |
| maintainability | 4/5 | #104 | hotspot module size and duplication ungated |
| modifiability | 4/5 | #106 | shotgun surgery in duplicated infra helpers |
| modularity | 3/5 | #107 | infra and scripts outside architecture contracts |
| orthogonality | 4/5 | #109 | private cross-imports and overlapping concerns |
| repairability | 4/5 | #111 | unowned triage backlog, no gate runbook |
| reusability | 3/5 | #113 | copy-paste over shared modules, undocumented API |
| serviceability | 4/5 | #115 | alert triage lacks ownership routing |
| simplicity | 3/5 | #118 | system-level sprawl in scripts and Makefile |
| understandability | 4/5 | #120 | docstring gaps and missing decision records |

## Testability & Correctness

| Attribute | Score | Issue | Gap summary |
| --- | :-: | --- | --- |
| accuracy | 4/5 | #108 | mock fidelity and global Ty suppressions |
| correctness | 4/5 | #110 | mutation scope and property-based testing |
| demonstrability | 4/5 | #112 | durable per-run test evidence artifacts |
| determinability | 4/5 | #114 | surface gate mode in check results |
| fidelity | 4/5 | #116 | pre-merge real exercise of infra stack |
| precision | 5/5 | — | Meets the 5/5 bar |
| predictability | 4/5 | #117 | pin runners, apt, and plugin acquisition |
| provability | 4/5 | #119 | extend test-strength proof beyond pulumi/app |
| repeatability | 4/5 | #121 | order-independence proof and network flake removal |
| reproducibility | 4/5 | #122 | canonical image digest and apt pinning |
| testability | 5/5 | — | Meets the 5/5 bar |

## Operations & Observability

| Attribute | Score | Issue | Gap summary |
| --- | :-: | --- | --- |
| administrability | 4/5 | #123 | manual environment bootstrap and hardcoded defaults |
| debuggability | 4/5 | #125 | shallow doctor and no debug modes |
| inspectability | 4/5 | #127 | no unified operations status rollup |
| manageability | 3/5 | #129 | alert triage floods issues without routing |
| observability | 3/5 | #131 | no metrics, alarms, or self-monitoring |
| operability | 3/5 | #134 | alert toil and missing per-signal runbooks |
| responsiveness | 3/5 | #136 | severity response targets unmeasured and unenforced |
| timeliness | 3/5 | #137 | evidence cadences defined but stale in practice |
| traceability | 4/5 | #139 | empty changelog and unlinked alert trail |
| transparency | 4/5 | #142 | no live health view; retrospective evidence only |

## Performance, Efficiency & Sustainability

| Attribute | Score | Issue | Gap summary |
| --- | :-: | --- | --- |
| affordability | 4/5 | #124 | automate cost-evidence freshness and threshold scaling |
| effectiveness | 4/5 | #126 | close no-go items and alert loop |
| efficiency | 3/5 | #128 | cache Docker toolchain, cut redundant CI work |
| elasticity | 3/5 | #130 | align fanout gates with live quota headroom |
| scalability | 3/5 | #132 | prove and partition multi-repo fanout |
| self-sustainability | 3/5 | #133 | close automation loops and freshness escalation |
| sustainability | 4/5 | #135 | add carbon evidence and enforce review cadence |

## Deployability, Portability & Interoperability

| Attribute | Score | Issue | Gap summary |
| --- | :-: | --- | --- |
| compatibility | 4/5 | #138 | enforce host tool minimums and consistent version floors |
| deployability | 4/5 | #140 | automate bootstrap and rollback paths |
| distributability | 3/5 | #141 | publish image artifacts and sync-ownership contract |
| installability | 4/5 | #143 | version-aware doctor and privileged setup verification |
| interchangeability | 3/5 | #144 | centralize org identity for template re-targeting |
| interoperability | 4/5 | #145 | publish attested standard artifacts for consumers |
| mobility | 3/5 | #147 | scripted, verified state and region migration |
| portability | 4/5 | #149 | verify arm64 and macOS paths in CI |
| seamlessness | 4/5 | #151 | remove image rebuild and token-passing seams |
| ubiquity | 3/5 | #153 | declare and widen the support envelope |
| upgradability | 3/5 | #155 | extend update automation to all ecosystems |

## Usability & Developer Experience

| Attribute | Score | Issue | Gap summary |
| --- | :-: | --- | --- |
| accessibility | 3/5 | #146 | colorless CLI output and docs a11y linting |
| convenience | 4/5 | #148 | doctor version checks and batch input validation |
| discoverability | 4/5 | #150 | CODEOWNERS and automated link checking |
| familiarity | 3/5 | #152 | remove cross-template boilerplate, domain-fit templates |
| interactivity | 4/5 | #154 | ChatOps help responses, actionable doctor output |
| intuitiveness | 4/5 | #156 | self-explaining env files and credential prompts |
| learnability | 4/5 | #157 | downstream adoption checklist, repo-specific contributing |
| localizability | 3/5 | #158 | language policy and spell-check automation |
| usability | 4/5 | #160 | close preflight and contributor-path gaps |

## Configurability & Adaptability

| Attribute | Score | Issue | Gap summary |
| --- | :-: | --- | --- |
| adaptability | 4/5 | #165 | remove CI-enforced VilnaCRM/project-name anchors |
| agility | 4/5 | #166 | cut PR feedback latency and sync lag |
| autonomy | 3/5 | #167 | close the alert triage automation loop |
| configurability | 4/5 | #168 | fix stale example config, add key reference |
| customizability | 4/5 | #169 | protect downstream customizations from template sync |
| flexibility | 4/5 | #170 | component opt-outs and topology variation |
| tailorability | 3/5 | #171 | org adoption checklist and template/instance separation |

## Process & Standards Compliance

| Attribute | Score | Issue | Gap summary |
| --- | :-: | --- | --- |
| process capabilities | 4/5 | #159 | close controls-drift, commit-lint, triage-ownership gaps |
| producibility | 4/5 | #161 | attach provenance and SBOM to releases |
| relevance | 4/5 | #162 | remove stale lineage and placeholder content |
| standards compliance | 4/5 | #164 | enforce commit convention, license metadata, community files |

## AI-Native Autonomous Development Readiness

| Attribute | Score | Issue | Gap summary |
| --- | :-: | --- | --- |
| AI-native autonomous development readiness | 4/5 | #163 | harness configs and full AGENTS.md drift enforcement |
| Frontend best practices applicability | 5/5 | — | Meets the 5/5 bar |

