# Central TEST runtime enrollment slice

`infra/poc_runtime_enrollment.py` now contains actual Pulumi resource components,
not only policy fragments. No current deployment entrypoint imports them. They
are staged source for independent enrollment, not an installed or fully activated
capability. Existing immutable catalogs are not silently extended.

## Ownership and registration

`PocRuntimeFences` requires the `independent-seed` Pulumi project and an explicit
AWS provider. Native caller account and provider region must equal TEST
`891377212104` / `eu-central-1` before registration. It registers six protected
managed policies, one boundary and one guard for each role. Policy paths are
`/issue219/test/{boundary,guard}/`; basenames use each exact role name followed by
`-Boundary` or `-Guard`. It creates no roles or attachments.

`PocRuntimeRoles` requires the `governance` project and the same target checks.
Before role registration, it reads every exact policy ARN and compares the native
default policy document with the complete expected document. Missing/changed
policies stop preparation. It registers these three protected roles, each with
its exact boundary, sole managed guard attachment, explicit inline-policy set,
one-hour session limit and central ownership tags:

- `user-service-infrastructure-test-EcsExecution`
- `user-service-infrastructure-test-EcsTask`
- `user-service-test-ImagePublisher`

Role ARNs are exported by purpose. The task role retains no inline grants,
deny-all boundary and guard, and disabled trust. The execution role has only the
closed ECR pull grant below. Publisher trust is disabled by default; a separately
supplied exact customized subject selects the publisher's reviewed trust. No
environment/config boolean enables task access, PassRole or a seed-catalog bypass.

The disabled trust uses a specific TEST account principal with an explicit Deny
and no Allow; it avoids an invalid wildcard-principal role trust. These classes
do not take ownership of existing resource state or suppress create collisions.
The independent installer must inspect live names and ownership first.

## Complete publisher grant

AWS's [repository-specific push policy](https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-push-iam.html)
requires six repository actions. The actual application publisher also performs
`DescribeImages` after push. The closed set is:

`ecr:BatchCheckLayerAvailability`, `ecr:BatchGetImage`,
`ecr:CompleteLayerUpload`, `ecr:DescribeImages`, `ecr:InitiateLayerUpload`,
`ecr:PutImage`, `ecr:UploadLayerPart`.

Each is restricted to the two exact TEST repository ARNs ending in
`repository/user-service-test-web` and `repository/user-service-test-worker`.
Only `ecr:GetAuthorizationToken` and `sts:GetCallerIdentity` use `Resource: "*"`.
Every ECR Allow requires `aws:RequestedRegion=eu-central-1`.

The identity and boundary contain matching Allows. The immutable guard explicitly
denies actions outside this finite set, repository actions outside the two ARNs,
and ECR use outside the selected region or without regional context. Consequently
a broader identity or direct repository-policy role-session grant cannot authorize
foreign repository writes. There is no repository creation/deletion, policy
mutation, image deletion, IAM, PassRole, state, Secrets Manager or KMS permission.

## Execution-role pull increment

`user-service-infrastructure-test-EcsExecution` receives
`ecr:BatchCheckLayerAvailability`, `ecr:BatchGetImage` and
`ecr:GetDownloadUrlForLayer` for those same two exact repositories. Only
`ecr:GetAuthorizationToken` and `sts:GetCallerIdentity` have global resources.
All ECR Allows require `eu-central-1`; the immutable guard explicitly denies
other actions, other repositories, and missing/wrong regional context. The
matching identity and boundary grant no image push, resource creation, log write,
secret/KMS read, mail, queue access, IAM management or PassRole.

Its trust admits only `ecs-tasks.amazonaws.com`, with SourceAccount
`891377212104` and SourceArn `arn:aws:ecs:eu-central-1:891377212104:*`.
[AWS does not support a specific cluster in this trust condition](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html).
Exact deployer PassRole and the reviewed task-definition graph remain separate
required controls. ECR pull belongs to the execution role, not the task role.
This source component is still disconnected from all live entrypoints; creating
it later does not supply the log/secret permissions needed by the real workload.

`seed/poc_runtime_verification.py` checks complete observed six-policy and
three-role inventories, default policy versions/documents, boundaries, attachment
sets, trust and inline grants. It rejects task-role activation, omitted/extra
grants, foreign targets and default publisher subjects. Its digest binds the
expected enrollment including publisher trust. It always returns
`activation_authorized=False`: caller-provided metadata is not authenticated AWS
evidence, nor proof of governor authority, immutable ownership or atomicity.

This increment deliberately stops before a live installer integration. The
existing seed catalog/installer admits exactly 55 policies and 24 principals,
with three new roles interpreted as operator executors. Appending these runtime
roles would break that security contract. A separate complete registry/governor
amendment must preserve the installed controls, grant exact central role
operations without fence mutation, update full-policy quotas, and define a
reviewed state/ownership transition. Neither that amendment nor a deployable
installer is claimed by this source increment.

The bounded [installer assessment](installability-stop.md) records the exact
current denials, ownership boundary and minimum independent amendment contract.
Its regression tests prevent runtime enrollment from entering the existing
operator installation or trust-activation packet implicitly.

## OIDC evidence and remaining installation requirements

The [ordinary application workflow](https://github.com/VilnaCRM-Org/user-service/blob/fe6433deda87f90b515af3406af59349d0fd0f38/.github/workflows/publish-poc-images.yml)
uses environment `poc-test-images`, main ref and `workflow_dispatch`; its
[publisher](https://github.com/VilnaCRM-Org/user-service/blob/fe6433deda87f90b515af3406af59349d0fd0f38/scripts/poc_image_publisher.py)
authenticates the delegated request/build artifacts before OIDC and reads back
native image digests. The proposed role ARN matches that workflow.

Trust uses only AWS-supported issuer `aud` and `sub` keys. The exact subject must
include `repo`, `repository_id=646535009`, `repository_owner_id=114362548`,
`environment=poc-test-images`, `ref=refs/heads/main`, the exact ordinary
`workflow_ref`, and `event_name=workflow_dispatch`. Both documented legacy and
immutable repo spellings are supported; key order is preserved. Missing, extra,
duplicate, foreign, PR, or reusable-workflow claims reject.

The 2026-09-23 authenticated GitHub metadata read returned `use_default=true`,
`use_immutable_subject=false`. The environment endpoint returned 404, which is
not proof that the required protected environment is usable. Current metadata
therefore does not meet the activation contract. No OIDC setting was changed.
[GitHub's subject customization contract](https://docs.github.com/en/actions/reference/security/oidc#customizing-the-subject-claims-for-an-organization-or-repository)
supports the proposed claims, but source validation is not token authentication.

Before connecting these components to protected deployment entrypoints:

1. Review/install the complete independent registry amendment for the six new
   policies and three principals, preserving all existing records. The ordinary
   three-executor seed activation validator is not a runtime-enrollment route.
2. Amend the governor's identity, boundary and immutable guards only for these
   exact role/policy reads and centrally owned role operations. Current authority
   intentionally rejects these new roles; no bypass was added here.
3. Verify real policy documents/default versions, immutability controls, trust,
   complete attachments/inline grants, role/policy name collisions, actual quotas
   and existing OIDC provider ownership. Byte equality alone does not prove these
   controls are installed or that a read is an atomic AWS snapshot.
4. Verify #185 current-head admission; approved publisher workflow on main;
   protected environment/main-only branch policy, reviewer and no bypass;
   customized subject configuration and authenticated native subject metadata.
5. Install through reviewed saved plans. Prove native publisher allow/deny cases
   and repository resource-policy intersection, then actual two-image publication.
   ECS log/secret and task mail/queue grants, deployment PassRole and workload CRUD remain
   separate amendments requiring real bindings and evidence.

Focused tests exercise real mock resource registrations, ownership/provider
rejection, changed-fence rejection, disabled task trust, publisher claim rejection,
quota fit and positive/negative policy cases. They do not establish live IAM,
OIDC, image publication or workload acceptance.

## Pull increment validation — 2026-09-23

After merging authoritative main `4f7a16e` into the existing branch, 362 focused
runtime, PassRole, seed-registry and independent-installer tests passed. A separate
141-test coverage run measured all four PoC modules at 100% statement and branch
coverage (183 statements, 48 branches). Full-repository Ruff lint/format,
changed-module Ty/Bandit and the strict exported dependency audit passed;
960 Pulumi structural tests also passed. GitPython is now 3.1.60. An initial empty
coverage-target argument collected no data; the successful run used `coverage run`
and a scoped threshold report.
No AWS calls, deployment, settings change, native OIDC exercise or installer
authorization is claimed by these offline checks.
