# TEST runtime installer boundary

## Result

The existing operator seed and governor cannot install runtime roles. This
follow-up adds a separate TEST CloudFormation proposal for six fences and the
exact image-publisher role, with a seven-row Add-only change-set validator. The
two ECS roles remain disconnected governance source. Neither route has an
authenticated live installer or activation receipt yet.

## Exact stop condition

`seed/policy_registry.py::_validate_closure` fixes the existing enrollment at 55
policies and 24 principals. `operator_seed_installation.validate_installation`
rebuilds the complete pinned packet; adding the six runtime policies or three
runtime principals is rejected. Its CloudFormation template owns 55 policies and
three executor roles, retains physical resources and denies every stack update.
The separate activation packet changes only the three executor trust documents.
It cannot install runtime resources or amend a governor fence.

The TEST `GitHubGovernanceApply` guard unconditionally denies `iam:CreateRole`
and `iam:PutRolePermissionsBoundary`. Its `iam:*` / `NotResource` statement also
denies all IAM operations on the three new runtime roles and six new policies.
Adding identity Allows alone cannot enable installation. Removing those Denies
globally would weaken the existing enrollment and is forbidden.

The earlier staged Pulumi `PocRuntimeFences` competed with the independently
owned CloudFormation graph and has been removed. The separate runtime packet
establishes one proposed owner for six fences and publisher role, but document
equality alone does not authenticate an installer or prove live ownership.

## Smallest coherent next amendment

1. Keep the original catalog and activation protocol intact. Define a distinct,
   versioned TEST amendment with explicit baseline and result digests. Bind its
   independently authenticated installer and complete observed stack/template,
   policy versions, boundaries and attachments. Caller-supplied account metadata
   or an `activation_authorized` flag is not authentication.
2. Choose one independent owner for the six new fence policies and publisher. A separate
   CloudFormation stack avoids moving the original 55 policies. A Pulumi owner
   instead requires its reviewed backend/key, installer authority and immutable
   protection contract; the existing seed KMS/backend must not be silently reused.
   Stop on any existing name or other state owner; no automatic adoption/import.
   The staged `issue219-runtime-fences-test` packet chooses the separate
   CloudFormation owner. Its installer must authenticate that the stack, six
   policy names and publisher role name are absent, recheck GitHub OIDC and the
   protected environment, create the reviewed seven-resource template, verify
   the complete change set, policy versions and role bindings, then enable and
   read back termination protection and the permanent deny-update stack policy.
   An offline packet is not an installer.
3. Amend the existing governor boundary and guard documents through their current
   independent CloudFormation owner. Bind exact old/new documents and exact
   reviewed change-set identity. Permit only specified in-place policy updates;
   forbid replacement/deletion and restore the deny-update stack policy on both
   success and failure. Preserve every unrelated statement and principal binding.
4. Add corresponding operator-owned governor identity grants. Preview/drift need
   reads of the exact ECS roles and six fences only. Apply needs the reviewed
   provider operation set on the exact two ECS roles, with each role bound to its
   own boundary and sole guard. Explicitly protect guard detachment, boundary
   removal/rebinding, all fence writes, foreign role creation, self-management and
   PassRole. Never solve this by widening the existing wildcard denial exceptions
   to an entire role/policy prefix. Verify the full resulting policy/attachment
   quotas and effective identity/boundary/guard intersection before installation.
5. Reconcile the governor-owned ECS role state separately from fence and
   publisher state.
   Require native fence/ownership readback before the reviewed saved-plan apply.
   Keep task trust disabled and task grants empty until the runtime contract is
   reviewed. Publisher creation requires the exact repo IDs, workflow,
   environment, main ref and dispatch claims, with authenticated
   protected-environment/OIDC evidence.

These are missing implementation contracts, not authorization to make a live
change. The next source amendment can remain TEST-only; PROD application rollout
is outside this PoC. Runtime log/secret, SQS/SES, workload CRUD and ECS PassRole
remain separate capabilities.

## Offline evidence

`tests/unit/test_poc_installation_boundary.py` exercises rejection of runtime
inventory appended to either seed installation or activation, the governor's
existing unconditional denials, and preservation of the 58-resource executor-only
activation graph. `tests/unit/test_poc_runtime_fence_stack.py` checks the exact
seven-resource retained graph and rejects incomplete, foreign, existing or
destructive change-set rows. Synthetic observations do not establish live
installation.
