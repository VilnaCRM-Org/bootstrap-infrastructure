# Source impact relationships

Operational correction: the packaged identity now has `enabled: false`, and
the active TEST seed catalog remains at the previously installed hash. The
graph below describes the proposed capability **after** independent seed
installation and a separate gate-enabling review; it is not currently emitted.

```text
RepoGovernance._repo_settings (immutable catalog identity)
  -> _governance_role_specs -> _governance_policy_documents
     -> _test_poc_capability_statements
        -> infra/test-poc-identity.json (packaged exact public identity)
  -> ci_bootstrap._create_roles / _create_role
     -> apply customer-managed Policy + RolePolicyAttachment
     -> preview/drift inline RolePolicy

GovernanceAutomationArgs + ManagedRepository
  -> _test_poc_statements -> _test_poc_capability_statements
  -> service_boundary_policy (independent maximum)
  -> _managed_policy_resources -> governance_repo_iam_policy
     -> exact new apply policy management ARN

seed/catalogs/test.json -> policy_registry.load_catalog (canonical integrity pin)
  -> build_registry -> independent boundary/governor immutable documents
  -> verify_active_enrollment -> _mutable_attachment_sets
     -> exact TEST apply attachment membership
```

Role trust/subjects, generic ci_bootstrap policy generation, state policies,
service seed guards, platform policies, PROD catalog, workflows and downstream
resource definitions are unchanged. The active TEST seed catalog and governor
guard NotResource inventories remain at their previously installed values: they
do not yet allow management or attachment of the proposed prerequisite policy.
The staged policy can be installed only through a separately reviewed seed
amendment. The service cannot modify its boundary, guard or IAM identities.
The existing inline deny-all hold is outside this change and remains mandatory.

Runtime imports add the governance policy helper to governance automation;
11 import-linter contracts pass. No new dependency or CLI entrypoint exists.
The active catalog remains unchanged by this correction. Its complete inventory
and disabled enrollment are checked by
`test_complete_deterministic_inventory_and_disabled_enrollment`; the staged
boundary, policy documents and closed attachment allowlist are checked by
`test_staged_identity_boundary_governor_matches_but_seed_remains_closed` and
`test_active_seed_guard_denies_staged_policy_until_independent_install`.
The removed prerequisite amendment reversal test is not evidence for this
disabled state.

The identity file is a fixed module-relative input, with no stack-config override.
Missing or invalid input raises before policy statements are returned. Keeping it
under `pulumi/infra/` makes `deployment_scopes._central_impact` classify changes as
shared runtime impact for operator, governance and platform consumers. Runtime
copies retain the complete Pulumi tree; the file has no credentials. Component
code interpolates accepted account/region values only after exact identity equality.

The downstream trusted plan validator remains responsible for exact dynamic DNS
tokens/values. The IAM capability is only the static namespace cap. No AWS or
remote mutation is performed by this source preparation.
