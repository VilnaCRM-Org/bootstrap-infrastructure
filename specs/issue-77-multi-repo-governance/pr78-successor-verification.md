# PR78 successor verification

## Scope and base

This candidate is provisionally based on PR60
`e1b3574cdaa8113e8bfc9a50d05360ee2b16e846`. Its source additions derive from
canonical `54d6f664250483c8d3b77a52964f5ac575f87899`; installed PR57/60 source
wins over older shared files. Rebase to the actual PR60 squash-main commit and
prove equivalent inherited source before publication. The 56-path scope contains
36 governance core/tests/docs/spec paths and20 complete service-template paths.
Full validation on the eventual base is pending.

## Required dependency closure

The installed trusted runner already authenticates the original comment and
current head and uses `PULUMI_DIR=pulumi/governance`. This increment adds that
six-file project, its `GovernanceStack`/`RepoGovernance` implementation, public
exports and the forbidden import contract. The operator project already owns the
OIDC provider, dedicated governor roles and immutable service/replication
boundaries. The governance project consumes the provider by exact account ARN
and manages only its catalog's service state buckets, KMS keys, configuration
secrets and bounded role trio. No operator resource is moved or re-created.

The catalog already identifies `user-service-infrastructure` as repository
`911736693`, owner `114362548`. No catalog grant changes are needed here. The
backend-only boundary cannot deploy the existing repository's workload. The
complete template generator refuses an existing output directory and brings its
Make, Docker, action, policy and helper dependencies from this newer checkout.
It is an example for review, never permission to overwrite actual service code.

## Requirement interpretation

| Requirements | Source contract and required evidence |
| --- | --- |
| FR1–FR9, FR21 | Catalog loop, exact repository identity, account-specific buckets/keys/roles, existing provider by `get()`, separate project and two accounts. Mocked entrypoint/component/identity/account tests and fresh live plan are required. |
| FR10–FR16 | Preserve installed CODEOWNERS, main-only environments, requester/approver separation, fresh-head original-comment authorization, test/prod ordering and saved-plan/promotion proof. No historical workflow restoration or operator authority in routine roles. |
| FR17–FR20 | Reviewed CODE/OPERATOR onboarding and complete clean-generated template; actual existing service remains preserved. Workload capability review, trusted state initialization and real self-deploy evidence remain required. |
| FR22–FR23, NFR4–NFR5,NFR8 | Preserve exact CI secret/KMS context denies, repo-only service access, immutable boundary ceilings and policy-pack validation without wildcard escape hatches or new digest pins. Actual governor KMS creation and bounded config-reader OIDC tests remain required. |
| FR24,NFR1–NFR3,NFR6–NFR7 | Current full tests,100% line/branch coverage, semantic/ordinary mutations, static/architecture/security checks and deterministic policy/identity preservation. Focused provisional-base evidence does not replace final-base CI. |

Historical wording that only `@Kravalg` may request apply is superseded by the
installed separation of duties: a current write-permission requester differs
from `@Kravalg`, who approves the protected environment. Names in ordinary OIDC
`workflow` claims are not source-code attestation. Required GitHub status and
deployment proof bind the actual current head and legitimate issuer.

## State and live acceptance

The reviewed historical TEST state contains96 operator and204 unique total
physical owners. Current metadata continuity must be rechecked before resource
updates; this source change does not migrate or import state. Governance owns an
isolated `/governance` prefix, distinct from operator-root and platform state.
A successful explicit absence check precedes any trusted state-only initialization;
never initialize after an arbitrary failure. Preserve the encrypted provider key
between GitHub jobs through the installed checkpoint-binding helper.

No live apply, current-head deployment, full BMAD PASS or manual owner acceptance
is claimed by this document. The real TEST/PROD governor roles, protected variables,
state prerequisites, policy/ownership preview and comment apply/drift must be
verified. A role-backed KMS CreateKey/tagging result and service config-reader
through its immutable boundary remain integration obligations. Failed access is
not permission to broaden IAM. Complete real service deployment additionally
requires its independent workload/task-role migration and scoped capabilities.

## Provisional validation

Focused provisional-base validation passed:339 tests covering the complete new
governance/scaffold contracts plus installed component, KMS, parity and triage
trust regressions. Changed Python Ruff lint/format, scoped Ty with unchanged
repository flags, Xenon, governance/template YAML and all three template
workflows pass. All11 import contracts are kept. The65 protected installed
source files remain byte-identical; governance.py matches canonical source.
Receipts are in the candidate's private `.artifacts` directory. No coverage
claim, full battery, mutation campaign or live operation was added for this
provisional base. Full validation waits for the actual PR60 squash base.
Historical PR78 has26 resolved review threads; its June approvals do not transfer
to this successor. New source defects must be fixed; unavailable installation or
owner evidence remains explicitly unfulfilled under current user authorization.
