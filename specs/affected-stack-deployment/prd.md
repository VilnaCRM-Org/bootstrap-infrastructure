# Affected-stack comment deployment

Issue: https://github.com/VilnaCRM-Org/bootstrap-infrastructure/issues/215

Status: implementation in progress; no hosted operator acceptance claimed.
Baseline: `75ed065c9dd208444f068c752c34e1bd4810bf42` (merged PR #192).

## Problem and scope

The installed comment intake routes a request to either platform or governance
using `governance_paths.py`. That predicate identifies security review paths;
it does not identify every Pulumi program affected by a change. Shared modules
and catalog changes can require operator, governance and platform reconciliation.
A successful run of one program does not prove the other programs were applied.

Ordinary `/pulumi test up` and `/pulumi prod up` must deploy every affected
bootstrap program through GitHub Actions. The operator must have independently
protected, finite authority and must not administer its own execution authority,
directly or through another identity. No local root Pulumi apply may be necessary
for routine operation. Existing shared S3 state and KMS encryption remain in use.

This follow-up does not reopen PR #192 or reinterpret its historical evidence.
Comment progress UX (#214), review maintenance (#216), unrelated workload
features, and another backup restore drill are outside this delivery.

## Functional acceptance

| ID | Requirement | Required evidence |
| --- | --- | --- |
| STACK-FR1 | Select affected operator, governance and platform programs independently of security-review classification. Include shared runtime, configuration/catalog inputs, renames and deletions. Incomplete or unclassified input cannot become a docs-only success. | Changed-file fixtures and current base/head-bound production selection. |
| STACK-FR2 | Consume the authenticated original comment once, retaining immutable repository, actor, PR, head, base and source-run identity. Child stages cannot introduce a new request or bypass the claim. | Positive intake and denied edited, stale, replayed, unauthorized, forked and moved-source cases. |
| STACK-FR3 | For each selected environment, operator prerequisites precede dependent governance/platform planning. Every required TEST apply and refreshed drift completes before any PROD execution. Plan requests never apply. | Explicit scheduler tests and actual job dependency/result evidence. |
| STACK-FR4 | Each stack uses its own account-local preview/apply/drift capability and fixed project, stack, backend and KMS contract. Apply replays the exact reviewed plan; missing or mismatched plans fail. | Hosted identity metadata, plan manifests, apply and no-change drift for every selected TEST/PROD stack. |
| STACK-FR5 | Only an independent trusted publisher can issue aggregate promotion. Every selected scope must be represented; one scope's success cannot overwrite pending/failed aggregate acceptance. Proof binds all plans, required jobs and original request. | Missing-scope, mixed-run, stale-base/head, wrong-plan and incomplete-TEST negative tests plus live App-issued aggregate proof. |
| STACK-FR6 | Preserve generated service scaffold closure and its existing fixed service route. Scaffold validation does not grant this repository permission to deploy another repository. | Clean generated-checkout checks and unchanged bounded service authorization tests. |
| STACK-FR7 | Known documentation/test-only changes require appropriate credential-free validation, not unrelated infrastructure mutation. Empty cloud execution is never described as a successful real apply. | Docs-only selection and reporting tests. |

## Nonfunctional acceptance

| ID | Requirement | Required evidence |
| --- | --- | --- |
| STACK-NFR1 | OIDC only, exact repository/account/environment identity, protected owner approvals, finite IAM inventory, no static access keys or privileged loader/publisher credentials in PR code. | Trust/policy review and denied wrong-context probes. |
| STACK-NFR2 | Routine execution cannot change its own roles, policies, boundary, authentication root, installation state or enforcement code, including through delegated identities. Saved-plan validation alone is insufficient because a Pulumi program can issue direct SDK calls. | Independent control design, live ownership/policy metadata and meaningful transitive-escalation negative cases. |
| STACK-NFR3 | Preserve canonical S3/KMS state, checkpoint/provider identity and one resource owner. No local authoritative state, silent stack initialization or destructive recovery. | Backend/key/checkpoint continuity and full refreshed drift evidence. |
| STACK-NFR4 | Bounded concurrency and timeouts; no duplicate comment claims or parent/child concurrency deadlock. A partial failure keeps promotion incomplete and permits a new, independently authenticated request. | Scheduler/controller tests and failed-stage acceptance. |
| STACK-NFR5 | Existing CI, coverage, dependency, policy and review requirements remain enforced. Actual VilnaCRM BMAD FR/NFR review uses Codex when Claude is unavailable, with no invented live evidence. | Current-head checks, substantive AI and CODEOWNER reviews, full applicable BMAD scorecard. |

## Delivery order

1. Build and test selection, orchestration and aggregate-proof contracts together
   with the independent operator installation design. Do not activate a route
   that lacks its execution authority or trusted publisher.
2. Install reviewed trusted controller code and the independent authority in a
   bounded prerequisite delivery. Keep incomplete operator routing disabled.
   Document any installation-dependent acceptance explicitly; historical
   PR #193 exceptions are not automatic permission to bypass current rules.
3. Activate the complete route and exercise an exact-head acceptance PR through
   ordinary TEST and PROD comments. Finish every selected stack, verify actual
   account/resource metadata and full drift, then merge under normal gates.

Implementation components alone do not complete step 3. Installation receipts,
local operator applies and earlier single-scope deployments are prerequisites,
not evidence of this feature's hosted acceptance.

## Design decisions still requiring implementation evidence

- Identify the independent installer and immutable enforcement layer in each
  account. Do not infer capability from a role name or copy permissions from a
  root session into the routine runner.
- Decide and enforce how authority-changing PR program code is executed without
  allowing direct or transitive self-administration. A pinned trusted executor
  accepting validated declarative inputs and an independently enforced AWS
  ceiling are different designs; neither may be claimed installed by a diagram.
- Adapt the existing single-use preflight and dedicated App publisher to one
  coordinator. Existing platform/governance reporters must not publish partial
  success for coordinated requests.
