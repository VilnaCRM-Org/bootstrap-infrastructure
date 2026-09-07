# PR192 security-completion acceptance

This is a bounded closeout of the original security-completion requirements.
Implementation already merged through PR193, PR204, PR74 and PR213 is inherited
from current main. The old PR192 head
`54d6f664250483c8d3b77a52964f5ac575f87899` retains its historical implementation
and review ledger; do not replay its superseded changes or redate old evidence.

This file records acceptance inputs and required execution, not a live PASS.
The final BMAD comment and GitHub checks on
[PR192](https://github.com/VilnaCRM-Org/bootstrap-infrastructure/pull/192)
record the reviewed head and actual terminal outcomes.

## Completed prerequisite evidence

| Area | Applicable evidence | Limit |
| --- | --- | --- |
| Trusted controller and state ownership | PR193 and PR204 installed the protected controller and separated operator/platform/governance/service ownership. PR204 merged at `468543dd6b085561dd0946bb9fc40759f3f922a0`. | Historical results do not approve this PR head. |
| Platform OIDC execution | PR74 [run34123268352](https://github.com/VilnaCRM-Org/bootstrap-infrastructure/actions/runs/34123268352) completed TEST/PROD saved-plan apply and drift; PR74 merged at `10fcd4d54fc611ec2ada4f32d64bfa2bdbd72704`. | Platform proof, not operator or governance execution. |
| Operator IAM convergence | PR213 reconciled both canonical S3/KMS operator stacks using separately authorized temporary login credentials, TEST before PROD. Each apply updated one expected legacy IAM policy; each drift showed 107 unchanged resources. All six reviewed policy documents matched desired state. Receipt SHA256 `8ecf56e0935f7e3fac978c80cb76bca9b059065c4e0b5777fb1c1fa732503d3b`. | Actual one-time operator CLI execution, not hosted OIDC operator automation. |
| Governance OIDC execution | PR213 [run34129809476](https://github.com/VilnaCRM-Org/bootstrap-infrastructure/actions/runs/34129809476) completed nine successful jobs, protected approvals and exact-head App promotion/deployment records. | Governance stack only. |
| Scoped current IAM repair | PR213 merged at `ab47d51c4679a204fe89f3673371ba4d265f9a72`; its source/manual and release BMAD gates passed, with 25 required checks and human/AI approvals. | Reuse unchanged-source evidence only; current-head release gates remain required. |
| Operational readiness | PR213 [trusted publisher run34137795933](https://github.com/VilnaCRM-Org/bootstrap-infrastructure/actions/runs/34137795933) produced 16/16 final checks. Accepted TEST/PROD restore receipts and the owner's policy through October2027 retain their real original dates. | Run the installed read-only collector for this PR; do not repeat the completed restore drill or confuse owner-policy expiry with technical freshness. |
| Downstream metadata smoke | User-service PR40 [run34093806113](https://github.com/VilnaCRM-Org/user-service-infrastructure/actions/runs/34093806113) completed its protected TEST/PROD metadata flow with its dedicated issuer. | Backend-only permission smoke; no complete application workload or new capability grant is claimed. |

## Required current-head closeout

1. Preserve the installed main implementation, protected environments, remote
   S3/KMS state and least-privilege OIDC roles. No runtime feature, IAM grant,
   checkpoint migration, initializer or restore operation is added by these docs.
2. Run the required current-head quality/security/CI checks. Existing regression
   suites cover malformed, stale/replayed, wrong-scope, wrong-account and
   invalid-plan requests. Skipped live tests are not counted as passes.
3. Use an eligible writer's ordinary `/pulumi prod up` comment and independently
   approve the protected stages as Kravalg. Verify actual TEST apply/drift before
   PROD apply/drift, exact saved-plan/source/provider/backend bindings, no
   unexpected resource changes, intended AWS accounts/roles and App proof.
   Documentation-only changes use the existing platform smoke route; this
   validates that route without claiming the separate operator/governance ran.
4. Reuse prior unchanged negative/edge coverage and real AWS evidence where
   applicable. Investigate only a new failure or changed behavior; never rerun
   destructive recovery drills solely to produce another date.
5. Run the installed trusted Well-Architected publisher with an independently
   reviewed bounded evidence artifact. Preserve previous collector results when
   the dedicated App refreshes GitHub evidence; require its actual final PASS.
6. Complete the actual organization BMAD FR/NFR reviewer using the authorized
   Codex manual fallback. Publish current source/manual/release matrices and
   required markers with zero unresolved findings. Do not claim Claude execution.
7. Require two current approvals including CODEOWNER and an AI reviewer, resolve
   actionable review threads, and merge normally only when all required checks
   and current-head deployment evidence pass. Retain merger/commit/tree metadata.

## Explicit remaining broader work

- [Issue215](https://github.com/VilnaCRM-Org/bootstrap-infrastructure/issues/215):
  automatic affected-stack dependency execution and independently protected
  hosted operator authority. The current security-path classifier is not an
  affected-stack graph. PR192 closeout does not claim this implemented.
- The requested organization-wide one-CODEOWNER-plus-one-AI enforcement rollout
  remains separate from proving the actual two approvals on this bootstrap PR.
- [Issue214](https://github.com/VilnaCRM-Org/bootstrap-infrastructure/issues/214):
  live deployment-comment status improvements; no implementation in this PR.
- New service workload permissions require their own explicit reviewed capability
  grant and real workload validation; metadata smoke does not grant them.

Whole-goal autonomous bootstrap completion remains separate from this PR's
scoped merge verdict. Raw state, secrets, signing keys and tokens are never
committed, printed or included in acceptance artifacts.
