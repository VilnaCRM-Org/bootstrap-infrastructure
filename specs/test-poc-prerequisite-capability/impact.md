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
resource definitions are unchanged. TEST governor guard NotResource inventories
add exactly one managed policy ARN to permit its lifecycle. The service cannot
modify its boundary, guard or IAM identities. The existing inline deny-all hold
is outside this change and remains mandatory.

Runtime imports add the governance policy helper to governance automation;
11 import-linter contracts pass. No new dependency or CLI entrypoint exists.
The seed amendment reversal test removes exactly the prerequisite statements
and exact Resource/NotResource references, then reproduces the entire previous
TEST catalog hash. Historical amendment checks continue against that recovered
catalog, guarding unnoticed changes across all 55 policies and principal records.

The identity file is a fixed module-relative input, with no stack-config override.
Missing or invalid input raises before policy statements are returned. Keeping it
under `pulumi/infra/` makes `deployment_scopes._central_impact` classify changes as
shared runtime impact for operator, governance and platform consumers. Runtime
copies retain the complete Pulumi tree; the file has no credentials. Component
code interpolates accepted account/region values only after exact identity equality.

The downstream trusted plan validator remains responsible for exact dynamic DNS
tokens/values. The IAM capability is only the static namespace cap. No AWS or
remote mutation is performed by this source preparation.
