# TEST workload capability: requirements traceability

Scope: source proposal for PR #285 (publisher-only runtime seed stack; supersedes #281). This is
not installation evidence; every test is an offline fixture. Related documents:
[runtime enrollment](runtime-enrollment.md) and [installer stop](installability-stop.md).

## Functional requirements

| ID | Requirement | Source | Tests (under `tests/unit/`) |
| --- | --- | --- | --- |
| FR-01 | The publisher stack owns exactly the publisher boundary, guard and role; ECS fences are excluded. | `seed/poc_runtime_fence_stack.py::build_fence_stack_packet` | `test_poc_runtime_fence_stack.py::test_publisher_stack_owns_only_publisher_fences_and_role`, `::test_ecs_fence_records_are_not_owned_by_publisher_stack` |
| FR-02 | The create change set has exactly three Add rows; Modify, Import, replacement, delete, nested, foreign, non-resource and obsolete seven-row and six-row sets are rejected. | `validate_fence_create_changes` | `test_poc_runtime_fence_stack.py::test_complete_synthetic_create_change_set_accepted`, `::test_create_change_set_rejects_foreign_or_destructive_rows`, `::test_create_change_set_rejects_missing_duplicate_or_malformed_rows`, `::test_non_resource_change_rejected`, `::test_obsolete_change_sets_rejected` |
| FR-03 | Packet tampering is rejected. | `validate_fence_stack_packet` | `test_poc_runtime_fence_stack.py::test_packet_tampering_rejected` |
| FR-04 | Fail closed on publisher ownership, binding, fence-ownership or source-inventory drift. | `_verified_publisher`, `_publisher_fences` | `test_poc_runtime_fence_stack.py::test_publisher_ownership_fails_closed`, `::test_publisher_fence_binding_fails_closed`, `::test_duplicate_publisher_fence_record_rejected`, `::test_publisher_fence_ownership_fails_closed`, `::test_stack_packet_rejects_changed_source_inventory`, `::test_stack_packet_rejects_incomplete_or_foreign_enrollment`, `::test_publisher_cannot_lose_its_independent_owner_or_exact_guard`, `::test_publisher_cannot_bind_a_foreign_boundary` |
| FR-05 | Publisher trust uses only `aud`/`sub` with the exact closed claim set. | `seed/poc_runtime.py::publisher_trust` | `test_poc_runtime.py::test_publisher_trust_uses_only_supported_iam_keys_and_exact_subject`, `::test_publisher_trust_rejects_default_foreign_incomplete_or_duplicate_claims`, `::test_observed_custom_subject_is_fixed_for_independent_publisher` |
| FR-06 | The publisher grant is finite regional ECR push; the guard denies everything else. | `seed/poc_runtime.py` | `test_poc_runtime.py::test_publisher_identity_and_boundary_intersection`, `::test_publisher_guard_denies_unreviewed_apis_even_with_broad_grants`, `::test_only_authorization_token_and_caller_identity_have_global_allow` |
| FR-07 | Post-create verifier requires the exact three-resource state, field by field; ECS roles are neither required nor accepted. | `seed/poc_publisher_stack_verification.py` | `test_poc_publisher_stack_verification.py::test_complete_publisher_stack_verified_without_ecs_roles`, `::test_each_post_create_field_fails_closed`, `::test_malformed_observation_rejected` |
| FR-08 | The runtime verifier requires the exact `PUBLISHER_SUBJECT`; `None` is rejected. | `seed/poc_runtime_verification.py` | `test_poc_runtime_verification.py::test_publisher_subject_must_equal_reviewed_subject`, `::test_publisher_subject_is_required`, `::test_default_subject_denied`, `::test_enrollment_digest_binds_publisher_trust` |
| FR-09 | The runtime verifier rejects target, inventory, document or role drift. | `seed/poc_runtime_verification.py` | `test_poc_runtime_verification.py::test_complete_enrollment_does_not_authorize_activation`, `::test_wrong_target_rejected`, `::test_incomplete_or_foreign_inventory_rejected`, `::test_changed_default_policy_rejected`, `::test_changed_role_grants_or_fences_rejected` |
| FR-10 | The ECS role component stays unwired, governance-only, with explicit TEST provider and fence readback. | `infra/poc_runtime_enrollment.py` | `test_poc_runtime_enrollment.py::test_governance_proposes_only_ecs_roles_not_independent_publisher`, `::test_task_inline_policy_empty_block_survives_serialization`, `::test_governance_rejects_changed_seed_documents_before_roles`, `::test_wrong_provider_target_or_project_rejected_before_enrollment` |
| FR-11 | The execution role is pull-only with ECS trust. | `seed/poc_runtime.py` | `test_poc_runtime.py::test_execution_pull_intersection_and_regional_denials`, `::test_execution_guard_denies_every_non_pull_capability`, `::test_execution_trust_only_admits_test_ecs_service` |
| FR-12 | PassRole covers only the exact ECS pair. | `seed/poc_pass_role.py` | `test_poc_pass_role.py::test_apply_requires_matching_identity_and_boundary`, `::test_wrong_or_missing_service_is_explicitly_denied`, `::test_read_roles_cannot_use_shared_boundary_allow`, `::test_broad_identity_cannot_pass_other_roles`, `::test_foreign_target_or_unknown_purpose_is_rejected`, `::test_generation_is_deterministic_and_does_not_grant_iam_management` |
| FR-13 | Runtime inventory cannot enter the operator seed installer. | `seed/policy_registry.py` | `test_poc_installation_boundary.py::test_runtime_append_rejected_by_seed_installer`, `::test_governor_explicitly_blocks_runtime_installation`, `::test_executor_activation_keeps_runtime_resources_outside_seed_stack` |
| FR-14 | Render the stack and IAM documents; validate with AWS only when credentials exist. | `scripts/render_runtime_seed_policies.py` | `test_render_runtime_seed_policies.py::test_render_writes_exact_template_and_every_iam_document`, `::test_main_renders_only_without_credentials_or_when_requested`, `::test_validation_runs_read_only_calls_with_exact_policy_types`, `::test_blocking_findings_fail_validation`, `::test_failed_aws_call_blocks_validation`, `::test_missing_aws_cli_blocks_validation` |

## Non-functional requirements

| ID | Requirement | Evidence |
| --- | --- | --- |
| NFR-01 | Offline: no AWS or network in unit or mutation runs. | `tests/security_mutation_guard.py`; stubbed renderer tests |
| NFR-02 | 100% line and branch coverage. | `make test-unit`, `make test-coverage` |
| NFR-03 | Every enumerated poc guard and requirement mutant is killed. | `scripts/run_security_mutation_tests.py`, `make test-mutation` |
| NFR-04 | IAM quotas (managed policy at most 6144, trust at most 2048 characters). | `test_poc_runtime.py::test_policy_size_and_unknown_fence_rejected`, `::test_enrollment_has_closed_owner_and_attachment_inventory` |
| NFR-05 | Deterministic canonical template and digest. | `test_poc_runtime_fence_stack.py::test_packet_tampering_rejected`, `test_render_runtime_seed_policies.py::test_render_writes_exact_template_and_every_iam_document` |
| NFR-06 | No verifier authorizes activation. | The positive tests of FR-07 and FR-09 assert `activation_authorized is False`. |
| NFR-07 | Operator procedures (pre-execution subject capture, break-glass revocation, obsolete change-set deletion) are documented in [runtime enrollment](runtime-enrollment.md) but have no automated test. This is a stated gap. | Documentation only |
