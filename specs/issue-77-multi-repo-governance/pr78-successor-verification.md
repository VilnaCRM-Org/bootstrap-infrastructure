# PR78 successor verification

## Scope and base

This candidate is based on the actual PR60 squash-main commit
`d61978ded596fb219a7b9379637d97003ee0a433`. Its source additions derive from
canonical `54d6f664250483c8d3b77a52964f5ac575f87899`; installed PR57/60 source
wins over older shared files. The 58-path scope contains 36 governance
core/tests/docs/spec paths, 20 complete service-template paths, and two paths
for the initialized-empty-checkpoint helper and its regression tests.

The final rebase produced `eacd8bd7601e77bb55dac6e4618a4aff5da710c3` with all
377 tracked files byte-identical to tested commit
`e8c79ab3a0ce3651fb9b529c48e8b0cdbe0c1659`; both have Git tree
`7f97a18d2282e228c541b16f1f20919419e65501`. The subsequent independent source
review corrected the generated runtime integration described below. The core
Python implementation, IAM policies and workflow source are unchanged.

## Required dependency closure

The installed trusted runner already authenticates the original comment and
current head and uses `PULUMI_DIR=pulumi/governance`. This increment adds that
six-file project, its `GovernanceStack`/`RepoGovernance` implementation, public
exports and the forbidden import contract. The installed operator program
declares ownership of the OIDC provider, dedicated governor roles and immutable
service/replication boundaries; its live deployment and ownership migration
remain prerequisites. The governance project consumes the provider by exact account ARN
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

The reviewed historical TEST state contains 96 operator and 204 unique total
physical owners. Fresh PROD readback on 2026-09-06 confirmed its platform
checkpoint still owns 98 AWS resources and the operator checkpoint is absent.
The historical 21/77 PROD partition was a local rehearsal, not a live migration.
An independently reviewed GitHub/OIDC state transfer and full operator apply
must precede PROD governance deployment. Current metadata continuity must be
rechecked before resource updates; this source change does not migrate or import state. Governance owns an
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

## Local battery and review corrections

The credential-free battery passed: 250 structural, 120 policy, 1,824 unit,
173 integration and 72 CLI tests. Combined coverage is 100% across 9,521
statements and 2,758 branches. Quality, security, repository/catalog/dependency
checks and all 11 import contracts passed. The first unit run exposed one
missing scaffold length-boundary coverage branch; a meaningful accepted-64 /
rejected-65-character regression fixed it before the final passing run.

Both enumerated mutation campaigns passed: 83/83 component and 83/83 semantic
security mutants killed. These campaigns are not exhaustive mutation coverage
of every module. The campaigns ran against an isolated byte-identical archive;
the subsequent actual-main rebase changed no tracked file. The final local
validation receipt JSON has SHA256
`f47b0bf2a59de834e70dbb66e53ab7f23d531a70cdb7cd0f3100fbc67a4d5f97`.
The original logs retain the initial coverage failure and successful correction.

Of 65 protected installed paths, 64 remain byte-identical to the PR60 base;
the sole intentional runtime difference is the initialized-empty-checkpoint
helper. Its nonempty inventory, project/account/backend, pending-operation and
encrypted-provider continuity checks remain enforced. Governance runtime
matches the selected canonical implementation. Local checks do not establish
hosted current-head CI or live deployment and owner acceptance.
Historical PR78 has26 resolved review threads; its June approvals do not transfer
to this successor. New source defects must be fixed; unavailable installation or
owner evidence remains explicitly unfulfilled under current user authorization.

Independent BMAD source review then found two generated-runtime integration
defects: Compose omitted `AWS_ACCOUNT_ID`, and the plan/apply/drift Make recipes
used system Python outside the installed dependency environment. Compose now
forwards the account pin, and all three recipes use `uv run --frozen python`.
Four new regression cases exercise the generated account binding and actual
Make recipes; 73 affected unit/structural tests pass with Ruff and YAML checks.

A clean generated scaffold built successfully from its own Dockerfile and lock.
With container networking disabled and no AWS credentials, its actual uv runtime
imported the command helper and bound the forwarded account/project correctly.
All three real Make targets rejected missing secrets-provider configuration
before cloud access. These are local runtime acceptance probes, not AWS
deployment evidence. Hosted CI must validate the published final commit.
