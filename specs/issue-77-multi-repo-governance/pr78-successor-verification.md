# PR78 successor verification

## Scope and base

This candidate is based on the actual PR60 squash-main commit
`d61978ded596fb219a7b9379637d97003ee0a433`. Its source additions derive from
canonical `54d6f664250483c8d3b77a52964f5ac575f87899`; installed PR57/60 source
wins over older shared files. The initial 58-path scope contains 36 governance
core/tests/docs/spec paths, 20 complete service-template paths, and two paths
for the initialized-empty-checkpoint helper and its regression tests.
The live TEST attempt also required the root Makefile and its CLI regression
suite, bringing that reviewed diff to 60 paths. The later logging compatibility fix
also updates the shared state-bucket helper while preserving its platform default.

The final rebase produced `eacd8bd7601e77bb55dac6e4618a4aff5da710c3` with all
377 tracked files byte-identical to tested commit
`e8c79ab3a0ce3651fb9b529c48e8b0cdbe0c1659`; both have Git tree
`7f97a18d2282e228c541b16f1f20919419e65501`. The subsequent independent source
review corrected the runtime integration described below and removed one unused
private-function parameter. The next review iteration tightens invalid configuration
handling and the generated initializer workflow; supported-input IAM policy and
trust builders retain their existing semantics.

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

On the validated baseline, 64 of 65 protected installed paths remained
byte-identical to the PR60 base; the sole runtime difference was the initialized-empty-checkpoint
helper. The later live fix also changes the root Makefile's six shared-helper
recipes to select the installed uv environment. The helper's nonempty inventory,
project/account/backend, pending-operation and
encrypted-provider continuity checks remain enforced. Governance runtime
retains the selected implementation's policy semantics. Local checks do not establish
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

The first real `/pulumi test plan` comment reached the installed controller,
passed current-head authorization, received Kravalg's protected-environment
approval, and assumed the dedicated TEST preview role through OIDC. Run
`34040632449` then failed before preview because the root Makefile also used
system Python for the shared helper. All six affected container recipes now
use `uv run --frozen python`; host preparation and isolated credential-loader
commands retain their existing contract. The 72 CLI tests and six actual
network-disabled container precondition probes pass after this correction.
No IAM permission or trust was widened. The replacement comment run
`34041427160`, requested by original comment `5560123911`, passed TEST plan
creation and upload at `aaae5196e3e193cc4ec09dd6ef848bee14d8f98d` after Kravalg's
protected preview approval. It proposed 48 creates (40 AWS resources, two
providers, five components and the stack), with no updates, deletes or imports.
This is preview evidence; no apply was requested. Later review fixes require a
new current-head plan before any saved-plan replay.

Qlty's unused private parameter and test binding were removed. The S3 policy
test now reuses the installed strict IAM statement matcher while retaining
explicit-Deny precedence; it does not claim to evaluate effective AWS access
or IAM conditions. Explicit account/context parameters, ASCII account digits
and the scaffold's reviewed file allowlist remain intentional. No scanner or
quality threshold was disabled.

The full AI review identified further configuration and scaffold edge cases.
Managed-service backend overrides now accept only the exact derived bucket URL;
the controller backend remains separate. Required account/provider configuration
is read before AWS invokes, and any governance region override must match the
actual provider region. Invalid inputs fail before resource allocation. The
generated artifact binds its Python project and lock identity, publishes the
complete staged directory without overwriting a concurrent writer, and forwards
runner UID/GID into the image build. The initializer explicitly selects TEST or
PROD account/role variables, rejects malformed or cross-account values, and
verifies the existing checkpoint and encrypted provider after select or init.
Read/select/provider failures never become permission to initialize another stack.

The canonical specs and runbooks now distinguish service from controller
backends, service protected-environment trust from governance trust, the required
App-issued `Governance Promotion` proof from informational `Governance Apply`,
and exact central catalog authority from the narrower service boundary. Routine
delivery remains GitHub-comment based; local root Pulumi applies are not part of
the accepted operator workflow. Source tests and live deployment/owner evidence
remain separate requirements.

The combined review correction passes 1,875 unit tests and retains 100% combined
coverage across 9,546 statements and 2,766 branches. All 250 structural tests
pass. The affected Python quality, architecture, dependency, repository hygiene
and security gates pass without weakened thresholds. A new generated
`billing-infrastructure` checkout builds with UID/GID 1001; its matching lock
passes `uv lock --check --offline`. With networking disabled, the container writes
its runner-owned workspace, imports the full command dependencies and verifies
its account/project binding. All three actual plan/apply/drift Make precondition
probes reject missing provider configuration. No AWS resource operation occurs
in those local tests. Hosted final-head CI and live deployment remain required.

The baseline saved-plan review also found that central log bucket policies allow
`aws-logs/*`, while new governed buckets proposed `server-access/` destinations.
The service composition now passes `aws-logs/` to the shared state-bucket helper;
its existing platform default is preserved. Both primary and replica paths are
verified for TEST and PROD, along with unchanged default behavior. No log-bucket
policy or IAM grant is widened. The full unit recheck passes 1,879 tests with
100% combined coverage across 9,547 statements and 2,766 branches. The replacement
current-head plan must confirm these exact prefixes before apply. The original
preview established no actual log-delivery failure; it exposed an authorization
mismatch before installation.
