# Central TEST runtime enrollment slice

`infra/poc_runtime_enrollment.py` contains the disconnected governance-owned
ECS role proposal. `seed/poc_runtime_fence_stack.py` renders the **publisher
stack**, a separate CloudFormation owner for exactly three resources: the
publisher boundary, the publisher guard and the
`user-service-test-ImagePublisher` role. Neither source packet has been
installed; the ECS proposal remains disconnected and incomplete for a running
workload. Existing immutable catalogs are not silently extended. Requirement
traceability is in [requirements](requirements.md).

The four ECS boundary and guard policies are deliberately excluded. The stack
retains its resources and denies every update, so including them would freeze
the ECS fences before the workload has its log, Secrets Manager (`AWSCURRENT`
via ECS secrets), KMS decrypt, SQS and SES grants. They move to a later reviewed
runtime amendment; their builders remain tested, unwired source.

## Ownership and registration

The independent CloudFormation packet (stack `issue219-runtime-fences-test`,
contract `issue219-test-publisher-seed/v3`) owns two retained managed policies,
`user-service-test-ImagePublisher-{Boundary,Guard}` under
`/issue219/test/{boundary,guard}/`, plus the protected
`user-service-test-ImagePublisher` role. The publisher has the exact customized
OIDC trust, its boundary, sole guard and finite ECR push inline policy. Its
offline validator requires exactly three Add rows and rejects ECS fence rows. A
separately authenticated installer must verify absent stack/policy/role names,
TEST account and region, GitHub OIDC template and environment, complete
change-set provenance, installed default policy documents and attachments,
termination protection and the permanent deny-update stack policy.

### Obsolete staged change sets

Two staged change sets on the `REVIEW_IN_PROGRESS` stack
`issue219-runtime-fences-test` are obsolete and must never be executed:

- `poc-runtime-fences-six-add-203c41e-20260928`: the earlier six-policy change
  set (six fences, no role), staged from source revision `203c41e`.
- `poc-runtime-seed-seven-e8930dd-20260928`: six fences plus the publisher role,
  staged from source revision `e8930dd`.

`validate_fence_create_changes` rejects both row sets. The required disposal is
`DeleteStack` on the `REVIEW_IN_PROGRESS` stack `issue219-runtime-fences-test`
through a reviewed operator call: deleting that stack removes every change set
attached to it, including both above, so no per-change-set `DeleteChangeSet` is
needed. Before deleting, confirm the stack has no resources (a CREATE change set
never created any). Afterwards confirm the stack name is absent (`DescribeStacks`
fails) before staging the new change set, otherwise the absent-stack
precondition fails.

`PocRuntimeRoles` requires the `governance` project and the same target checks.
Before role registration, it reads every exact policy ARN and compares the native
default policy document with the complete expected document. Missing/changed
policies stop preparation. The publisher stack does not install the ECS fences,
so this preflight fails closed until the later runtime amendment installs them. It proposes only these two protected ECS roles, each with
its exact boundary, sole managed guard attachment, explicit inline-policy set,
one-hour session limit and central ownership tags:

- `user-service-infrastructure-test-EcsExecution`
- `user-service-infrastructure-test-EcsTask`

Role ARNs are exported by purpose. The task role retains no inline grants,
deny-all boundary and guard, and disabled trust. The execution role has only the
closed ECR pull grant below. The independent packet owns publisher trust. No
environment/config boolean enables task access, PassRole or a seed-catalog bypass.

The disabled trust uses a specific TEST account principal with an explicit Deny
and no Allow; it avoids an invalid wildcard-principal role trust. The role
component and fence packet do not take ownership of existing resource state or
suppress create collisions.
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

`seed/poc_runtime_verification.py` verifies the later full six-policy/three-role
enrollment (not the publisher stack). It checks complete observed inventories,
default policy versions/documents, boundaries, attachment sets, trust and inline
grants, and rejects task-role activation, omitted/extra grants and foreign
targets. The caller must supply the observed publisher subject and it must equal
`PUBLISHER_SUBJECT` exactly: `None`, default, alternative-spelling and
extra-claim subjects are rejected. Its digest binds the expected enrollment
including publisher trust. It always returns `activation_authorized=False`:
caller-provided metadata is not authenticated AWS evidence, nor proof of
governor authority, immutable ownership or atomicity.

## Post-create publisher stack verification

`seed/poc_publisher_stack_verification.py::verify_publisher_stack` compares the
complete post-create state: target account/region, stack name, `CREATE_COMPLETE`,
canonical template, termination protection, the deny-update stack policy, exactly
three stack resources with physical IDs, two managed policies at default version
`v1` with exact documents, and the role ARN, path, permissions boundary, single
guard attachment, inline policy set, `MaxSessionDuration`, tags and trust. The
ECS roles and fences are neither required nor accepted. Inputs must be
authenticated, fully paginated and URL-decoded: DescribeStacks, GetTemplate,
GetStackPolicy, ListStackResources, GetPolicy/GetPolicyVersion, GetRole,
ListAttachedRolePolicies, ListRolePolicies/GetRolePolicy and ListRoleTags. It
returns `activation_authorized=False`. After the break-glass amendment,
`verify_amended_publisher_stack` applies the same checks with `UPDATE_COMPLETE`
against the reviewed amended template (disabled role trust only).

## Local rendering and optional AWS validation

`make validate-runtime-seed-policies` renders `template.json`, `stack-policy.json`,
`amended-template.json` (the break-glass template built by `_amended_packet()`),
`break-glass-during-update-policy.json`, every IAM document and `manifest.json`
to `.artifacts/runtime-seed-policies/`; the `template.json` SHA-256 equals the
packet digest and the manifest records the amended template and during-update
policy digests. AWS validation runs only when at least one of these variables is
set and non-empty in the renderer's environment
(`CREDENTIAL_VARIABLES` in `scripts/render_runtime_seed_policies.py`):
`AWS_ACCESS_KEY_ID`, `AWS_PROFILE`, `AWS_WEB_IDENTITY_TOKEN_FILE`,
`AWS_CONTAINER_CREDENTIALS_FULL_URI` and
`AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`. `docker-compose.yml` forwards only
`PULUMI_BACKEND_URL`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,
`AWS_SESSION_TOKEN`, `AWS_PROFILE` and `AWS_REGION` from the host, and it also
loads `env_file: .env` (optional), so any trigger variable placed in `.env` starts
validation even when the host shell is clean. The read-only `~/.aws` bind mount
is not itself a trigger. When triggered it calls read-only IAM Access Analyzer
`validate-policy` per identity policy (trust documents with `RESOURCE_POLICY` /
`AWS::IAM::AssumeRolePolicyDocument`) and CloudFormation `validate-template`.
Exit code 1 means ERROR or SECURITY_WARNING findings; 2 means a missing CLI or
failed call. `RUNTIME_SEED_POLICY_ARGS=--render-only` renders without AWS.
Skipped validation does not satisfy the installation precondition. It never
creates, updates, executes or deletes a stack or change set.

## Pre-execution OIDC subject capture

The pinned subject comes from configuration metadata, not from a real token.
Before executing any change set:

1. Dispatch the ordinary `publish-poc-images.yml` on `refs/heads/main` through
   the protected `poc-test-images` environment, with a reviewed diagnostic step
   (`permissions: id-token: write`) placed before any AWS credential step.
2. Request a token with audience `sts.amazonaws.com` and print only the decoded
   `sub`. Never print, upload, cache or store the raw token,
   `ACTIONS_ID_TOKEN_REQUEST_TOKEN` or the request URL:

   ```bash
   python3 - <<'PY'
   import base64, json, os, urllib.request
   url = os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"] + "&audience=sts.amazonaws.com"
   auth = {"Authorization": "Bearer " + os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]}
   token = json.load(urllib.request.urlopen(urllib.request.Request(url, headers=auth)))["value"]
   payload = token.split(".")[1]
   print(json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))["sub"])
   PY
   ```

3. Record the job URL, run ID, head SHA and the printed subject. Compare it byte
   for byte with `seed.poc_runtime.PUBLISHER_SUBJECT`, and its SHA-256 with the
   template `Metadata.PublisherSubjectSha256`.
4. Any difference, including key order or repo spelling, stops execution.
   Changing the subject needs a reviewed source change and a regenerated packet;
   never hand-edit the change set or trust.

## Break-glass revocation of publisher trust

Run this only with an audited break-glass identity outside GitHub CI that holds
`iam:UpdateAssumeRolePolicy`, `iam:PutRolePolicy`, `cloudformation:CreateChangeSet`,
`cloudformation:DeleteChangeSet` and `cloudformation:UpdateStack` on the publisher
role and stack. `docs/governance-stack.md` defines no such publisher-specific
grant (the seed installer operator identity in that guide is not authorized for
this stack), so the holder must be named and reviewed before use; do not
improvise authority during an incident.

1. **Contain.** Call `iam:UpdateAssumeRolePolicy` to set
   `seed.poc_runtime.disabled_trust()`. Add the AWS "revoke older sessions"
   inline deny (`aws:TokenIssueTime` before the revocation time). Optionally
   disable the workflow or lock the environment. Record CloudTrail event IDs.
   Stack policies do not restrict direct IAM calls; this step intentionally
   creates drift.
2. **Reviewed amendment.** Disable trust in source, regenerate the packet and
   review the digest. Render the files with `make validate-runtime-seed-policies`
   (or `RUNTIME_SEED_POLICY_ARGS=--render-only`): `amended-template.json` is the
   template built by `_amended_packet()` and
   `break-glass-during-update-policy.json` is the narrow during-update policy
   from `break_glass_during_update_policy_json()`; record both SHA-256 values from
   `manifest.json` (`amended_template_sha256`,
   `break_glass_during_update_policy_sha256`). The amended template differs from
   the reviewed one only in the publisher role's `AssumeRolePolicyDocument` (it
   becomes `disabled_trust()`). The narrow policy allows only `Update:Modify` on
   `LogicalResourceId/<publisher logical id>` and denies `Update:Replace` and
   `Update:Delete` on `*`. `ExecuteChangeSet` has no temporary stack-policy
   parameter and the permanent policy denies `Update:*`, so a change set cannot
   be executed under it. Use one of these reviewed sequences:
   - Preferred: first create a review-only UPDATE change set from the
     byte-identical `amended-template.json`, confirm exactly one `Modify` row
     with `Replacement: False` on the publisher logical ID, then delete that
     change set (it is never executed). Then run the update directly:

     ```bash
     aws cloudformation create-change-set --stack-name issue219-runtime-fences-test \
       --change-set-name issue219-review --change-set-type UPDATE \
       --template-body file://amended-template.json \
       --capabilities CAPABILITY_NAMED_IAM
     aws cloudformation describe-change-set --stack-name issue219-runtime-fences-test \
       --change-set-name issue219-review
     aws cloudformation delete-change-set --stack-name issue219-runtime-fences-test \
       --change-set-name issue219-review
     aws cloudformation update-stack --stack-name issue219-runtime-fences-test \
       --template-body file://amended-template.json \
       --capabilities CAPABILITY_NAMED_IAM \
       --stack-policy-during-update-body file://break-glass-during-update-policy.json
     aws cloudformation wait stack-update-complete \
       --stack-name issue219-runtime-fences-test
     ```

     The override applies to that update only; the permanent deny-update policy
     is not modified. Do not restore or read back anything until the wait
     reports the terminal `UPDATE_COMPLETE` status (a failed or rolled-back
     update is an incident).
   - Alternative: `SetStackPolicy` to the same
     `break-glass-during-update-policy.json`, create an UPDATE change set from
     `amended-template.json` with `--capabilities CAPABILITY_NAMED_IAM`, confirm the
     single `Modify` row, `ExecuteChangeSet`, run
     `aws cloudformation wait stack-update-complete`, and only then
     `SetStackPolicy` back to the permanent deny (`Deny Update:* Principal *
     Resource *`). Treat an interruption before the restore as an incident.

   Afterwards read back `GetStackPolicy` and `DescribeStacks` and record the
   canonical policy digest (it must equal the permanent deny-update policy) and
   `EnableTerminationProtection=true`. Termination protection is never lowered.
3. **Reconcile.** After at least `MaxSessionDuration` (3600 s), remove the
   revocation inline policy. The step-1 direct `UpdateAssumeRolePolicy` created
   drift; the amendment sets the same disabled document in the template, so run
   `detect-stack-drift` and require `IN_SYNC` for all three resources. Do not
   run `verify_publisher_stack` (it requires `CREATE_COMPLETE` and the enabled
   trust). Instead collect the authenticated reads listed above and run
   `verify_amended_publisher_stack`, which requires `UPDATE_COMPLETE`, checks the
   same per-field state against the reviewed amended template (only the role
   trust differs) and rejects the enabled trust. Retain the evidence.
4. **Removal** is a separate reviewed amendment: because resources are Retain,
   stack deletion leaves the role and policies behind.

This increment deliberately stops before a live installer integration. The
existing seed catalog/installer admits exactly 55 policies and 24 principals,
with three new roles interpreted as operator executors. Appending these runtime
roles would break that security contract. A separate complete registry/governor
amendment must preserve installed controls and grant exact ECS role operations
without fence mutation. The publisher instead belongs to the independent
CloudFormation owner. Neither ECS amendment nor a deployable installer is
claimed by this source increment.

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
`workflow_ref`, and `event_name=workflow_dispatch`. `publisher_trust` structurally accepts either documented repo spelling, but
production always passes the constant `PUBLISHER_SUBJECT` and the runtime verifier
requires exact equality with it, so only the pinned legacy `repo:` spelling is
accepted at install and verify time; an immutable-form or reordered subject is
rejected and stops execution pending a reviewed amendment. Key order is preserved. Missing, extra,
duplicate, foreign, PR, or reusable-workflow claims reject.

The 2026-09-28 GitHub API read returned `use_default=false` with exactly the
seven subject claim keys above, in the order pinned by the packet. The
`poc-test-images` environment has Kravalg as required reviewer, admin bypass
disabled and a single `main` branch policy. Recheck all of these immediately
before installation; metadata is not an authenticated live token.
[GitHub's subject customization contract](https://docs.github.com/en/actions/reference/security/oidc#customizing-the-subject-claims-for-an-organization-or-repository)
supports the proposed claims, but source validation is not token authentication.

Before connecting these components to protected deployment entrypoints:

1. Delete the obsolete stack record (and with it both change sets), then review/install the three-resource
   publisher stack, preserving all existing records. The ordinary
   three-executor seed activation validator is not a runtime-enrollment route.
2. Install the four ECS fences only through the later reviewed runtime
   amendment, then amend the governor's identity, boundary and immutable guards
   only for the two exact ECS roles and policy reads. Current authority intentionally rejects
   these roles; no bypass was added here.
3. Verify real policy documents/default versions, immutability controls, trust,
   complete attachments/inline grants, role/policy name collisions, actual quotas
   and existing OIDC provider ownership. Byte equality alone does not prove these
   controls are installed or that a read is an atomic AWS snapshot.
4. Verify #185 current-head admission; approved publisher workflow on main;
   protected environment/main-only branch policy, reviewer and no bypass;
   customized subject configuration and authenticated native subject metadata,
   and the real-token `sub` captured above.
5. Install through a reviewed change set and protected saved plans. Prove native
   publisher allow/deny cases and repository policy intersection, then publish
   both images. ECS log/secret and task mail/queue grants, deployment PassRole
   and workload CRUD remain required before the real service can run.

Focused tests exercise real mock resource registrations, ownership/provider
rejection, changed-fence rejection, disabled task trust, publisher claim rejection,
quota fit and positive/negative policy cases. They do not establish live IAM,
OIDC, image publication or workload acceptance.

## Pull increment validation — 2026-09-23 (historical)

Historical record for source `4f7a16e`. It predates the publisher-only
narrowing and does not validate the current head.

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
