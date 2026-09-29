# Source impact relationships

Post-seed activation (PR #280, FR5-FR7): the packaged identity has
`enabled: true` and the active TEST seed catalog pin is the amendment result
`ff2eaf29…`. Source now emits the graph below. It becomes live only through
the ordered protected deployments in [post-seed-activation.md](post-seed-activation.md),
after the seed installation readback; merging is not installation. The earlier
`enabled: false` correction describes the superseded PR #255 state.

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
resource definitions are unchanged. The active TEST seed catalog carries the
installed amendment: the service boundary, the governance preview/drift read
ceilings and the governance apply guard's two closed resource lists now admit
the exact prerequisite policy, and `_mutable_attachment_sets` admits it only on
the TEST service apply role (FR6, FR7). The service cannot modify its boundary,
guard or IAM identities. The existing inline deny-all hold is outside this
change and remains mandatory.

Runtime imports add the governance policy helper to governance automation;
11 import-linter contracts pass. No new dependency or CLI entrypoint exists.
The active catalog's complete inventory and disabled seed executors are checked
by `test_complete_deterministic_inventory_and_disabled_enrollment`. The enabled
boundary, policy documents and single-role attachment allowlist are checked by
`test_enabled_identity_boundary_governor_and_attachment_allowlist_match` and
`test_active_seed_guard_admits_only_exact_prerequisite_policy`;
`catalog_before_test_poc_prerequisites` proves the catalog delta is exactly the
four reviewed documents over baseline `ef419680…`. The former disabled-state
tests were renamed with inverted assertions and are not evidence for this state.

The identity file is a fixed module-relative input, with no stack-config override.
Missing or invalid input raises before policy statements are returned. Keeping it
under `pulumi/infra/` makes `deployment_scopes._central_impact` classify changes as
shared runtime impact for operator, governance and platform consumers. Runtime
copies retain the complete Pulumi tree; the file has no credentials. Component
code interpolates accepted account/region values only after exact identity equality.

The downstream trusted plan validator remains responsible for exact dynamic DNS
tokens/values. The IAM capability is only the static namespace cap. No AWS or
remote mutation is performed by this source preparation.
