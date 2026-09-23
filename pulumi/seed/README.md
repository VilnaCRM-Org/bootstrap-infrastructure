# Independent seed policy registry

This package renders and verifies the closed IAM enrollment input for the TEST
and PROD accounts. It performs no AWS calls or Pulumi resource registration.
There is deliberately no `Pulumi.yaml`, deployment CLI, or `__main__.py`:
ordinary PR workers receive no administrative mutation path from this package.
The deployment selector requires operator, governance and platform validation
for seed runtime changes; only this exact README is documentation-only.
Selection does not authorize seed mutation: a guard-registry change still
requires independent enrollment and actual hash verification before the routine
graph can claim all changes were applied. Routine operator apply cannot perform
that enrollment.

Each public metadata catalog represents 24 principals and 55 managed policies:

| Policies | Count | Ownership |
|---|---:|---|
| Existing physical capability boundaries | 6 | Transfer unchanged ARNs from operator ownership to independent seed ownership |
| New purpose boundaries for existing roles | 8 | Independent seed |
| Existing-role immutable managed guards | 21 | Independent seed |
| Operator executor boundaries and identities | 6 | Independent seed |
| Operator executor immutable managed guards | 14 | Independent seed |

Twenty-one roles already exist; three operator executor roles are proposed. The
Config recorder keeps its existing trust, complete inline S3 delivery grant and
AWS-managed Config policy attachment. It has a frozen-grant exception instead of
an incomplete replacement boundary. Its AWS-managed version/document digest is
checked at initial enrollment; later AWS-managed changes remain external to the
routine operator's authority.

The catalogs contain public IAM policy documents, role/policy/secret/key ARNs,
backend paths and provenance digests. They contain no credential values, secret
payloads or Pulumi checkpoint content. Shared statements are indexed by their
canonical hashes to avoid duplicating immutable guards. Both complete catalogs
are hash-pinned in `policy_registry.py`; an inventory change requires a reviewed
catalog and code update. Runtime callers cannot substitute a different account,
resource list, guard set or policy document.

## Operator secret metadata read amendment

The `secret_resource_policy_read_amendment` adds only
`secretsmanager:GetResourcePolicy` on the two exact existing CI secrets in each
account. Pulumi AWS 7.23.0 reads the Secret resource policy after `DescribeSecret`.
All three executor purposes receive the action in their identity and boundary;
the closed-action guard permits it and the storage guard explicitly denies it
outside those two secrets. Secret values, KMS permissions, resource-policy writes,
trusts, attachments and policy ARNs remain unchanged.

This changes twelve existing managed-policy documents per account. Independently
review and install those exact policy-document updates, preserving active trusts
and all resource identities, then verify the new complete registry hashes before
ordinary execution. The three-role activation validator does not authorize policy
updates. Updating source catalogs alone is not evidence of installed permissions.

## Pure API

`build_registry(environment, account_id=..., seed_key=...)` returns immutable
typed policy and principal records. It resolves only `SeedKmsKeyArn`, checks the
complete principal/policy closure, preserves all six physical boundary ARNs,
hashes every rendered document, and enforces the 6,144-character policy limit and
ten-attachment limit. The full registry's largest policy is 6,102 characters in
TEST and 6,038 in PROD. Existing bootstrap apply uses ten attachments; new
operator preview/drift use five and apply uses seven.

Managed-policy basenames are unique across the entire account, regardless of
IAM path or letter case. The registry rejects duplicate basenames and invalid
names before rendering an installation. Independently compare the proposed
names with the complete live account policy inventory before creation; registry
validation alone cannot discover unrelated policies in AWS.

The `policy_name_correction` provenance entry records eleven exact ARN renames
per account, using short `G-`, `I-` or `C-` prefixes on the missing guard,
identity or ceiling policy. It preserves the other 38 proposed policy identities
and all six imported boundaries. Reversing the mapping reproduces the complete
previous catalog hash, including its policy documents and principal bindings.
Retained resources from a failed enrollment must be inventoried and reconciled
before retrying. A corrected template does not automatically adopt them, and
changing a policy name is a replacement. Never delete an existing policy merely
to clear a name collision; installation and recovery remain independently owned.

Supply `SeedKeyBinding` from independently collected `kms:DescribeKey`
`KeyMetadata` fields: `Arn`, `KeyId`, `AWSAccountId`, `KeyManager`, `KeyState`, and
`KeyUsage`. Missing input, aliases, placeholder IDs, wrong account/region, a
disabled/non-customer key, or reuse of a known routine operator key fail closed.
No seed key is invented or installed by this package. Offline format checks
cannot prove that an arbitrary UUID-shaped key exists: obtaining authentic
metadata from the independently authorized account remains the installer's
responsibility.

`verify_enrollment(registry, observation)` checks the complete observed set of
55 owned policies and 24 roles. Observations contain default-version documents,
exact attachments and boundary bindings, trust documents, and Config's complete
inline grants plus the observed AWS-managed document digest. The metadata
collector must compute that digest over the entire canonical AWS-managed policy,
not infer it from its name. Duplicate, missing, additional or changed entries
fail. Existing ordinary identity-policy documents remain editable within their
ceilings; the initial expected attachment set is not a perpetual freeze on
routine grants.

All three new executors must still have exactly
`disabled_trust_policy(account_id)` and no inline grants during verification.
The disabled document uses the selected account ARN as an AWS principal with
only a Deny for `sts:AssumeRole`. It has no Allow statement, so neither AWS nor
OIDC/SAML callers can assume it. A scalar wildcard principal is not used when
creating roles. The account ARN identifies the account, not only its root user.
See the [AWS principal contract](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html#principal-accounts)
and [trust-policy evaluation](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-denyallow.html).
The result records verified disabled enrollment and
always sets `activation_authorized=False`. It does not attest that metadata came
from AWS, authorize an apply, enable trust, or claim successful installation.

The positive executor boundaries are valid only with every paired immutable
guard. Explicit action/resource/context denies close resource-based role-session
grant bypasses. The full graph protects guard removal, guard/purpose-boundary
mutation, role creation/deletion/boundary rebinding, issuer changes and seed
authority. Never attach only the positive document or replace the guards with
editable inline policies. The new guard namespace is already protected by the
existing-role guard documents.

## Active runtime verification

`verify_active_enrollment` rechecks the complete enrolled policy/role inventory,
immutable guards, frozen Config grant and bounded project-specific attachments.
It requires the three exact executor OIDC trusts, using account-qualified environments such as `test-operator-preview`,
`test-operator`, and `test-operator-drift` (and the corresponding `prod-` names).
Account and purpose use distinct subjects so a TEST or drift token cannot assume
a PROD or apply role.
The result still grants no activation or deployment authority.

`scripts/operator_enrollment_runtime.py` collects metadata through an injected
authenticated read-only transport. It verifies the exact assumed operator role,
complete paginated inventories, policy default-version pointers and full policy
documents. Collection is not an atomic AWS snapshot; callers must recheck before
apply and rely on independently enforced immutable controls.

## Remaining integration

1. A separately authorized non-root hosted installer must collect metadata and
   prepare the complete preview. It needs an independent state/authority binding,
   a real separate seed KMS key, and an issuance/session quiescence procedure.
   Existing root-backed metadata profiles do not authorize an apply.
2. Move only the six existing boundary ownership records from the operator state
   to independent seed ownership, preserving physical ARNs and unchanged policy
   contents. Create the new policies/guards and enroll existing roles. Existing
   role ownership stays with the current three projects; Config stays frozen in
   its current source project. No extra restore/state migration is implied.
3. The later independent seed deployment template can consume these typed
   records. Create the three new executors with disabled trust, bind boundaries,
   attach every identity/guard, then verify actual metadata and hashes. Trust
   activation requires its own reviewed OIDC/runtime contract after verification.
4. Replace operator-side boundary creation with references in
   `github-ci-bootstrap/__main__.py`, `infra/platform_iam.py` and
   `infra/governance_automation.py`. Pass exact newly installed role boundary
   bindings through `ci_bootstrap.py`, `ci_config.py` and governance runner
   construction. Preserve independent attachments and reject frozen Config/OIDC
   changes instead of silently skipping them.
5. Integrate the root command worker with the three executor policies and exact
   backend/key/envelope bindings. Ordinary deployment scheduling must not report
   seed administrative changes as applied by a routine operator. Validate real
   provider API calls, transaction paths and OIDC claims before activation.

The earlier source and offline AWS simulator feasibility work justified the
catalogs; this package's tests check rendering, closure and metadata verification,
not fresh live authorization or complete IAM semantic equivalence.

```sh
uv run pytest tests/unit/test_seed_policy_registry.py --cov=seed --cov-branch \
  --cov-report=term-missing --cov-fail-under=100
uv run ruff check pulumi/seed tests/unit/test_seed_policy_registry.py
uv run bandit -q -r pulumi/seed
```
