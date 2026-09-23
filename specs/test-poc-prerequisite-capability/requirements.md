# TEST PoC initial prerequisite grant

Base: `e849dbfb1e9a1b6a543c9b9ae757f6328e682a9d`. Service source reviewed:
`7e8748fea7505c4a804cc31643229f0cd498f205` (mail identity, registry phase projection,
registry resource owner, and `pulumi/Pulumi.test.yaml`). Provider: Pulumi AWS
7.23.0; upstream Terraform provider commit
`4981ec2b44ea4892c1ee4f0c1ed23b761a55f44d`.

## Requirements

| ID | Requirement | Evidence |
| --- | --- | --- |
| FR1 | Only the exact TEST account, region, organization, service project/repository and immutable repository/owner IDs receive the capability. | `test_other_resources_receive_no_capability`, `test_other_identities_receive_no_capability` |
| FR2 | Apply can create/tag the fixed two ECR repositories and one SES identity; preview/drift can read their metadata. | `test_only_initial_prerequisite_actions_and_exact_resources`, `test_identity_boundary_seed_and_governor_match` |
| FR3 | Every DNS change is CREATE, CNAME and inside the reviewed DKIM namespace and exact zone; missing keys and mixed unauthorized batches fail. | DNS negative/positive tests in `test_governance_test_poc_capability.py` |
| FR4 | Seed boundary, governed identity documents, governor policy inventory and mutable apply attachment allowlist agree. | `test_identity_boundary_seed_and_governor_match`, seed amendment reversal tests |
| NFR1 | No PROD, publisher, runtime, IAM, send-mail, delete, DNS UPSERT or lifecycle grants. | Exact action-set tests; PROD catalog unchanged; exact amendment reversal |
| NFR2 | Preserve trust, existing service guards and `Issue215CutoverSessions`; no live mutation. | Trust/create-role code unchanged; seed amendment reversal; no AWS/push operations |
| NFR3 | Managed policies fit quotas; source can be tested without AWS credentials. | Policy length assertion, governor `_document` guard, focused offline suite |
| NFR4 | Record residual IAM limitations, installation dependency and acceptance honestly. | Runbook and review scorecard |

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
