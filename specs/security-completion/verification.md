# Completion verification ledger

Status: OPEN. This ledger accompanies the integration source; live deployment
run IDs are not yet assigned.
This ledger records evidence available on 2026-09-05; it is not merge approval.

## Baseline findings and PR relationships

- The organization inventory initially contained 135 open PRs across 15
  repositories. Six belonged to bootstrap-infrastructure. PR 57 → PR 60 → PR 78
  is the implementation chain included in the integration checkout; historical
  approvals and green checks do not certify the new patch or resolve threads.
- PR 79 targets msgpack 1.2.1 and overlaps the targeted dependency repair.
  PR 191 targets pip 26.1.2, which is superseded by the repaired lock's 26.2.
  Re-evaluate those PRs after the integration lands; neither is automatically
  closed, merged or considered reviewed by this ledger.
- Initial test-account IAM simulation allowed a live CI apply role to attach
  a policy and rewrite config-reader trust. Production CI roles and dedicated
  governance resources were initially absent. Replacement source policies and
  metadata previews do not establish that the deployed roles are repaired.
- An early test bootstrap preview proposed two creates and eleven updates with
  no deletion. Later ownership and policy changes supersede that plan.
- Manual organization-plugin review iteration 1/5 failed with ten findings.
  Iteration 2/5 failed with two new findings: duplicate state ownership and
  state/resource-policy/KMS isolation. Both are explicitly local degraded
  reviews; no Claude model or native plugin runner executed.

## Completed bounded evidence

- The final source battery passed 984 unit, six integration, 204 structural and
  117 policy tests, with 9014 statements and 2590 branches at 100%. Seven live
  integration cases were skipped and are not acceptance evidence. Ruff, Ty,
  complexity, all 11 import contracts, strict dependency hygiene/security,
  Bandit, actionlint, YAML and Dockerfile checks passed. This includes the final
  legacy trust, replication source-account, boundary dependency and parsed
  platform-only policy-pin changes. GitHub current-commit checks remain pending.
- The CI-secret reference correction passed 155 focused tests. Reference mode
  resolves metadata to the exact Secrets Manager ARN and fails on a missing
  operator prerequisite; it does not read secret values or allocate a secret.
  The affected module retained 100% statement/branch coverage.
- Ordinary mutation testing passed 83/83 mutants after measured fail-fast
  optimization. Every baseline test still executes, the timing multiplier is
  still 3, and no mutants or thresholds were excluded. Earlier 82/83 and 75/83
  attempts remain recorded as timing-suspicious failures, not passes. The
  mandatory 72-case semantic security campaign passed its 268-test baseline
  but killed only 71 mutants: the verified-SHA format guard survived because
  an old test failed at a later manifest mismatch. A matching malformed
  head/manifest regression now passes. A fresh complete `make test-mutation`
  exited 0: ordinary 83/83 and semantic 72/72 killed,271 baseline tests, zero
  survivors/errors/timeouts. Source manifest SHA256 is
  `aa9162aa3ab59d6820cae4a042360518aabbcec41671a35978e93e28a8aef3e3`.
  Later policy/legacy-trust/constructor changes passed the final source battery;
  the enumerated mutation functions/target tests were unchanged.
- The final read-only IAM campaign contains 111 validation records covering
  86 distinct canonical documents, with zero API errors, ERROR findings or
  SECURITY_WARNING findings. All 286 simulation cases and 770 action/resource
  decisions passed, including scoped service metadata and CreateKey tag
  conditions. Both account policy sets were simulated through the test-account
  API. These results are not real OIDC exchanges or SCP/resource-policy proof.
- The dedicated evidence App is installed only on bootstrap-infrastructure.
  Its private key is configured only in the protected governance-evidence
  environment; public issuer variables and exact permissions were verified.
  No real promotion report or test/prod deployment has been issued by this work.
- All eight configured GitHub environments were verified with exact main-only
  branch policies and administrator bypass disabled. Command environments use
  sole reviewer Kravalg with self-review prevented. The saved ruleset preserves
  24 checks, three reviews and test/prod deployments, and now dismisses stale
  reviews and requires last-push approval. The App-pinned 25th check remains
  pending trusted-controller installation and subsequent protected enrollment.
  Seven legacy privileged workflows remain deliberately disabled pending the
  hardened controller installation and reviewed activation sequence.
- Seven encrypted checkpoint candidates passed official local Pulumi CLI
  import/export rehearsal. The migration conserves 256 managed physical
  identities and resolves 23 duplicate ownership groups in the candidates.
  Refreshed test/prod operator previews pass with the mandatory policy pack,
  accepted native imports and explicit role-to-boundary property dependencies.
  Production platform still requires the operator-owned CI configuration.
  Revisioned manifests and preview proofs are maintained in the separate
  migration report. No live backend import or resource apply occurred.
- Five targeted lock updates (msgpack, click, GitPython, pip and setuptools)
  passed strict dependency hygiene/security checks and import contracts.
  No vulnerability ignore, broad upgrade or quality threshold reduction was used.

## Required execution ledger

| Area | Current state | Required closeout |
| --- | --- | --- |
| Final quality and mutation | Final source battery and both mutation campaigns passed with provenance | Exact published commit and current GitHub CI artifacts |
| Governance least privilege | Issue77 FR23/NFR5 prohibits wildcard escape hatches; parsed config now contains 13 platform identities/14 content pairs and zero service/governor pins | Generated scoped policies, no governance exceptions, mandatory policy pack and refreshed effective-permission cases |
| IAM isolation | Bounded API simulation/Analyzer evidence exists; immutable boundaries and state guards are implemented | Current policy hashes, real allowed/denied OIDC role/account cases, including session/resource-policy limits |
| GitHub App/protection | Environment key, eight main-only environments and saved review-freshness controls configured | Install trusted controller, enroll App-pinned check and prove actual current-head reporter run |
| State ownership | Seven local CLI rehearsals preserve identities; preview repairs and revisions continue | Reviewed final graph/backup versions, zero unintended replacement/deletion, authorized live migration and refresh proof |
| Test/prod bootstrap | Final test/prod operator previews pass; test-only execution and recovery procedure reviewed | Fresh live-backend saved plans, authorized operator execution and no-op/drift proof |
| Governance test/prod | Reproducible role/boundary IaC and protected workflow contracts implemented | Actual test apply/drift followed by prod apply/drift for the same PR SHA |
| New-repo onboarding | Runnable scaffold and trusted initializer have bounded offline tests | Isolated real repository metadata smoke, its own evidence App and applicable protected workflow proof |
| Service workload capabilities | Backend-only baseline and static-credential repair are explicit | Reviewed workload capability grant and coordinated infra/app PR validation before workload onboarding |
| Operational readiness | Historical issue17 records are expired or not current proof | Current alert, backup/restore, DR, security, quota, cost and readiness evidence |
| BMAD review contract | Exact organization reviewer instructions executed by Codex through its documented manual fallback; native Claude/Opus runner SKIPPED unauthenticated | Final stable matrix/scorecards with all required evidence, unchanged iteration ledger and truthful provider provenance; no paid Claude access is required for the permitted fallback |
| PR merge/reviews | No integration commit, push, merge or review-thread resolution is claimed here | Current checks, required independent reviews, resolved actionable threads and approved installation/activation ordering |

Use staged controller enrollment: preserve the existing 24 required checks,
three approvals and required test/prod deployments while installing the hardened
controller; activate the App-pinned 25th check afterward through the protected
ruleset flow. Keep the existing environment-only App key. Operator setup is
user-authorized, subject to the concrete plan and migration safety preconditions.
A private local-backend preview plan cannot be applied against the live S3
backend: generate a fresh exact live-backend plan after candidate import.
Local operator execution must remain labeled operator execution; it does not
establish protected workflow/OIDC proof.

## QA evidence rules

For each live case retain repository/PR, exact SHA, workflow/run/job, AWS account
and role, requested action, expected/observed result and nonsecret artifact link.
For negative cases prove denial before resource mutation. Do not count skipped
checks as passes. Record tool, authentication, upstream-image and environment
failures separately from product failures. Simulation, API metadata, private
preview, actual OIDC exchange, apply and no-op/drift are distinct evidence types.

Re-run a gate after relevant changes or a new concern. Preserve earlier failures
and explain their resolution. Local reports hold the exact source/policy hashes,
logs and revisioned migration receipts; they must be published as sanitized,
reviewable artifacts before being used for PR acceptance. Raw state, secret
values, credentials and keys are never review artifacts. Whole-system completion
remains false until the applicable open rows are closed.
