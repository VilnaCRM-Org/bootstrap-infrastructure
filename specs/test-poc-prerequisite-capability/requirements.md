# TEST PoC initial prerequisite grant

Base: `e849dbfb1e9a1b6a543c9b9ae757f6328e682a9d`. Service source reviewed:
`7e8748fea7505c4a804cc31643229f0cd498f205` (mail identity, registry phase projection,
registry resource owner, and `pulumi/Pulumi.test.yaml`). Provider: Pulumi AWS
7.23.0; upstream Terraform provider commit
`4981ec2b44ea4892c1ee4f0c1ed23b761a55f44d`.

## Requirements

FR2, FR4 and NFR1 describe the staged, disabled PR #255 state. PR #280
([post-seed-activation.md](post-seed-activation.md)) enables the packaged identity
and pins the installed amendment catalog, so FR5, FR6 and NFR5 supersede them.
Their original evidence tests were renamed with inverted assertions; the old
names no longer exist and are history, not current evidence.

| ID | Requirement | Evidence |
| --- | --- | --- |
| FR1 | Only the exact TEST account, region, organization, service project/repository and immutable repository/owner IDs receive the capability. | `test_other_resources_receive_no_capability`, `test_other_identities_receive_no_capability` |
| FR2 | **Superseded by FR5.** After separate seed installation and gate enablement, TEST apply can create/tag the fixed two ECR repositories and one SES identity; preview/drift can read their metadata. The packaged capability is currently disabled. | Historical: `test_only_initial_prerequisite_actions_and_exact_resources`; removed `test_packaged_capability_remains_disabled_until_seed_installation` |
| FR3 | Once enabled, every DNS change is CREATE, CNAME and inside the reviewed DKIM namespace and exact zone; missing keys and mixed unauthorized batches fail. | DNS negative/positive tests in `test_governance_test_poc_capability.py`; `test_explicitly_disabled_identity_still_emits_no_capability` |
| FR4 | **Superseded by FR6.** Proposed boundary and governed identity documents agree, while the active TEST seed boundary, governor guard and mutable attachment allowlist stay closed until a separate seed amendment is installed. | Historical: removed `test_staged_identity_boundary_governor_matches_but_seed_remains_closed` and `test_active_seed_guard_denies_staged_policy_until_independent_install`; `test_complete_deterministic_inventory_and_disabled_enrollment` |
| NFR1 | **Superseded by NFR5.** No active new grants; the staged capability excludes PROD, publisher, runtime, send-mail, delete, DNS UPSERT and lifecycle grants. | Historical: packaged-disabled and exact action-set tests; PROD catalog unchanged; active seed guard test |
| NFR2 | Preserve trust, existing service guards and `Issue215CutoverSessions`; this source change does not directly mutate AWS. | Trust/create-role code unchanged; four-document TEST catalog delta checked by `catalog_before_test_poc_prerequisites`; `test_complete_deterministic_inventory_and_disabled_enrollment` |
| NFR3 | Managed policies fit quotas; source can be tested without AWS credentials. | Policy length assertion, governor `_document` guard, focused offline suite |
| NFR4 | Record residual IAM limitations, installation dependency and acceptance honestly. | Runbook and review scorecard |

### Post-seed activation (PR #280)

| ID | Requirement | Evidence |
| --- | --- | --- |
| FR5 | Supersedes FR2. The packaged exact TEST identity is enabled. Governance renders the `poc-prerequisites` apply managed policy and preview/drift metadata-read grants for the fixed two ECR repositories, one SES identity, DKIM CNAME CREATE and the exact backend bucket-versioning read. An explicitly disabled identity still emits no capability. | `test_packaged_capability_matches_installed_test_seed`, `test_only_initial_prerequisite_actions_and_exact_resources`, `test_explicitly_disabled_identity_still_emits_no_capability` |
| FR6 | Supersedes FR4. The rendered service boundary equals the active TEST seed `GovernanceBoundary-user-service-infrastructure-test` pin. The governor apply policy manages the exact prerequisite policy ARN. The only new mutable attachment is that policy on `GitHubCiApply-user-service-infrastructure-test`, and the TEST governance apply guard's two closed resource lists admit only that exact ARN. | `test_enabled_identity_boundary_governor_and_attachment_allowlist_match`, `test_active_seed_guard_admits_only_exact_prerequisite_policy`, `test_current_mutable_grants_can_change_only_inside_each_project_catalog` |
| FR7 | The active TEST catalog pin is the amendment result `ff2eaf296e5bd6e6bf8b02c7cdc31a2cfbcaef53fdea6173c64f77a3095effe7`. It differs from baseline `ef419680ab38a437ba2e374839c29437b4ca3243fab665ef29e81c01bed47dd3` only in the four reviewed policy documents, and the amendment generator cannot replay against it. | `policy_registry.load_catalog` pin check; `catalog_before_test_poc_prerequisites` baseline hash assertion; `test_installed_catalog_rejects_replaying_seed_amendment` |
| NFR5 | Supersedes NFR1. Grants remain TEST-only for the exact identity and still exclude PROD, publisher, runtime, send-mail, delete, DNS UPSERT and lifecycle. The PROD catalog, pin and mutable attachment sets are unchanged. Merging performs no AWS mutation; grants become live only through the ordered protected deployments. | `test_missing_identity_pair_and_prod_have_no_role_capability`, `test_initial_creation_allows_exact_resources_and_rejects_neighbors`, PROD attachment assertion in `test_enabled_identity_boundary_governor_and_attachment_allowlist_match` |
| NFR6 | Governance TEST apply failure, drift and capability withdrawal follow the documented fail-forward/rollback decisions without direct applies, lock cancellation, catalog edits to match live state or synthetic success. | [Rollback and fail-forward](post-seed-activation.md#rollback-and-fail-forward-nfr6); documentation only, no live evidence yet |
| NFR7 | Seed installation and the PR #280 merge happen inside one announced freeze window, in the documented order, with no operator TEST runs and no admin bypass merge. | [Freeze window](post-seed-activation.md#freeze-window-and-merge-sequence-nfr7); documentation only, no live evidence yet |
| NFR8 | Merge requires the recorded seed readback evidence and an authenticated `verify_active_enrollment` pass against the PR #280 TEST registry. | [Merge preconditions](post-seed-activation.md#merge-preconditions-nfr8); operator evidence pending |

## Action rationale

This is creation-only capability for the trusted initial prerequisite phase.
The source creates repositories with immutable image tags and scan-on-push,
then reads repository metadata and tags. It creates an SESv2 EmailIdentity with
RSA-2048 Easy DKIM, then reads identity metadata and tags. Tag/Untag allows Pulumi
tag reconciliation without changing repository or SES configuration. No image
upload/download/token or sending API is included.

The pinned [SES provider](https://github.com/hashicorp/terraform-provider-aws/blob/4981ec2b44ea4892c1ee4f0c1ed23b761a55f44d/internal/service/sesv2/email_identity.go)
uses CreateEmailIdentity and GetEmailIdentity for initial creation. Its conditional
configuration/DKIM update and delete APIs are intentionally excluded. SESv2
supports exact identity resources for these actions in its
[authorization reference](https://docs.aws.amazon.com/service-authorization/latest/reference/list_sesv2.html).

The pinned [Route53 provider](https://github.com/hashicorp/terraform-provider-aws/blob/4981ec2b44ea4892c1ee4f0c1ed23b761a55f44d/internal/service/route53/record.go)
uses CREATE when `allow_overwrite=false` for a new record, then reads the record
and polls the change. Existing-record updates use UPSERT and are excluded.
AWS documents the multi-valued name/type/action conditions and suffix matching
in [Route53 IAM conditions](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/specifying-conditions-route53.html).
All three keys require `Null=false`, preventing an absent-key vacuous match.

DNS delegation covers the DKIM namespace, including deeper labels; it does not
prove three SES-generated tokens, token alphabet/length, CNAME target, TTL or
absence of routing options. Those are trusted plan-admission responsibilities.
Zone metadata reads and generated-ID GetChange reads cannot be narrowed to the
three future records. Native effective-permission tests remain pending.
