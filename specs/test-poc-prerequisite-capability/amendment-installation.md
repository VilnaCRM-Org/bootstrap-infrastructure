# TEST prerequisite seed amendment

This is a one-time, TEST-only installation prerequisite for the user-service
registry/SES/DKIM plan. The active TEST catalog and the packaged capability flag
remain unchanged. PROD is outside this amendment. The source generator performs
no AWS calls and grants no permission by itself.

`seed.test_poc_prerequisite_amendment.build_catalog()` binds the proposed result
to the current active TEST catalog hash and updates exactly four policy documents:
the `GovernanceBoundary-user-service-infrastructure-test` ceiling, the TEST
governance preview/drift policy-read ceilings, and the TEST governance apply
guard's two closed resource lists. The service boundary gains only the fixed ECR
repository, SES identity, DKIM DNS and backend bucket-versioning statements from
the reviewed staged capability. No role, trust, attachment, PROD policy, policy
name or resource owner changes. `scripts/operator_seed_installation.build_amendment`
renders a candidate CloudFormation template from the active seed template and
permits only those four in-place `PolicyDocument` modifications in its temporary
stack policy. The permanent deny-update policy is part of the packet.

The installed TEST stack still carries catalog `9079c481…` and registry
`9af7ae78…` metadata from before the AWS-managed `AWS_ConfigRole` v73 repin.
On 2026-09-27, read-only CloudFormation inspection found that its complete
58-resource graph has SHA-256 `6b11513a41d10de7fe3f6ba325d11552f9891049e3e1b9cd29e8e3ead25d3ce2`,
identical to the current rendered source. The complete live template has
canonical SHA-256 `8b86a7ff6e9d5194908262eb72188907c11457c2caebbc5654ba0fca7089497c`.
The packet reconstructs and pins that entire installed template as its
baseline, then advances metadata to the proposed result with the four policy
edits. Reauthenticate these values at installation time; this read-only
observation does not authorize an update.

Before live installation, an independently authenticated non-root operator must:

1. Confirm the TEST account, KMS seed key metadata, the complete current seed
   stack template and stack policy, the four live policy default-version documents,
   every target attachment and available managed-policy version quota. The live
   template must equal the packet's complete `baseline_template`; source pins and
   caller-supplied metadata alone do not establish this.
2. Review the complete old/new template and exact four-policy diff. Create one
   CloudFormation change set under the narrow temporary stack policy. Authenticate
   the account, stack, full paginated change set, proposed template and change-set
   ID. `validate_test_poc_change_set` must accept exactly four non-replacing policy-document
   changes. The complete template exceeds CloudFormation's inline size limit, so
   use an independently protected S3 `TemplateURL` artifact bound to its digest.
   A missing, extra, dynamic or replacement row stops installation.
3. Execute only that change-set ID. Restore the permanent deny-update stack policy
   on success or failure. Read back the complete stack template, policy versions,
   documents, attachments, boundaries and guards. Any partial result requires
   reconciliation before another attempt; do not blindly replay a change set.
4. Only after exact live readback, update the active TEST catalog hash and the
   service apply-role mutable attachment allowlist in a separate reviewed change.
   Then enable `test-poc-identity.json` and deploy the governance identity grant
   through the protected saved-plan path. Preserve `Issue215CutoverSessions` until
   its separately reviewed activation; an identity Allow does not override it.

The source follow-up, its ordered protected deployments and remaining separate
activation dependencies are in [post-seed-activation.md](post-seed-activation.md).
That candidate is not evidence that this installation has completed.

The current [TEST plan failure](https://github.com/VilnaCRM-Org/user-service-infrastructure/actions/runs/36324543713)
stopped during backend bucket-versioning observation before a saved plan existed.
The fixed public stage output does not disclose the AWS error code, so an IAM deny
remains a source-supported diagnosis, not a confirmed live service response. After
installation, rerun the exact-head PR comment plan, then apply/drift and native
ECR/SES/Route53 readback. The packet does not claim those tests have passed.
