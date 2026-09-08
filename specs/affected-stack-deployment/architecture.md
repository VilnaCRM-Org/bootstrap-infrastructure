# Affected-stack controller architecture

Status: integration design, not an installed execution path.

## Controller and workers

Preserve the existing six-field immutable intake request. Dispatch it to one
trusted root controller. Scope, AWS roles, project paths and backend URLs are
derived from trusted source, never accepted from the comment or dispatch payload.

The root authenticates the original intake, verifies current writer permission,
open same-repository PR/head/base and protected environments, then consumes the
comment once. It records the complete selector result and its digest together
with the controller revision/run/attempt. Workers verify that contract and
current authorization; they never claim the comment again. Request freshness
is checked at admission, not reapplied after a legitimate approval wait.

The graph has six fixed account calls: TEST operator, governance, platform;
whole-TEST barrier; PROD operator, governance, platform. Each selected worker
finishes its plan, required validation gates, exact saved-plan apply and refreshed
drift before the next dependent worker plans. A plan command omits apply/drift.
A selected failed, cancelled, missing or skipped worker blocks its dependents.
Only an unselected worker may be skipped. Empty scope runs credential-free checks
and produces no account deployment record.

Extract platform execution into a reusable account workflow. Convert governance
execution into a reusable account workflow. Add an operator worker only after
its independent authority/runtime contract is implemented. Fixed relative
same-repository workflow calls use the trusted caller revision. Preserve the
existing isolated platform configuration loader, protected environments,
current-head/label rechecks and plan validation.

Only the root holds the PR concurrency lock. A caller account job holds the
matching backend lock through its worker's plan/apply/drift; the child must not
reacquire that lock. Preserve shared lock names used by scheduled platform jobs.
Each worker uses unique run/attempt/scope/account artifact names and has no
promotion App credentials.

## Aggregate evidence

Use a new central `Infrastructure Promotion` protocol/context. Keep generated
services on `Governance Promotion`. Old frozen single-scope publisher runs can
still write the old context; changing current source alone cannot make those
historical runs implement aggregate semantics.

The trusted aggregate publisher derives its required nodes from the original
selection, not from the receipts it finds. It verifies same-run artifact IDs,
digests, exact request/controller identity, successful required stages and
canonical account/project/backend/KMS/plan bindings for every required node.
Only complete PROD-up evidence can project successful TEST/PROD deployment
records. Test-only, plan, no-deployment or partial results cannot do so.

Bind the new required context to the dedicated App integration in the central
ruleset. Preserve existing unrelated checks and service defaults. Central
evidence collection must verify the new profile explicitly. Do not activate
aggregate execution while only the old single-scope requirement is enforced.

Before changing the root scope-reporting workflow, embed the existing
service-compatible workflow in the generated service template and remove the
root workflow from the generator's shared copy list. Shared authentication
helpers must remain importable without central-only modules in a clean scaffold.

## Independent operator authority

The routine operator may not own its executor IAM policies, trust, invariant
boundary, authentication provider control, seed state or trusted runtime pin.
Protecting only its role ARN does not prevent transitive escalation through
downstream IAM identities it can modify. Saved-plan replay still runs the Pulumi
program, so the plan is not a sandbox for arbitrary PR Python.

The installer, exact finite IAM inventory and enforcement model remain required
implementation decisions. A trusted pinned program accepting closed declarative
inputs requires a separate reviewed runtime installation path for program changes.
Arbitrary PR program execution instead requires independent controls covering
all transitive authority. Do not assume an Organizations SCP provides that ceiling:
the 2026-09-07 metadata audit found TEST standalone and PROD its organization's
management account. No operator AWS permissions are added by this design.

Installation, activation and live acceptance remain distinct. Finish the
controller and independent authority, install with activation disabled, verify
live identities/state/protections, then activate the reviewed route and capture
ordinary-comment TEST/PROD acceptance. Never substitute old single-scope or local
root receipts for the final aggregate acceptance.
