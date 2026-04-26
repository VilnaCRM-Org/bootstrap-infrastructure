# Implementation Readiness: Well-Architected 5/5 Remediation Roadmap

## Readiness Summary
Issue #17 is ready for planning review, not implementation in this PR. The scope is large enough that implementation should proceed through multiple focused PRs, starting with P0 safety and blast-radius work. The current planning artifacts define the sequencing, acceptance criteria, evidence model, and no-go conditions needed before code changes begin.

## Alignment Checks

| Area | Status | Notes |
| --- | --- | --- |
| Problem definition | Ready | Issue #17 provides pillar scores, question-level gaps, priority groups, and completion criteria. |
| Scope boundary | Ready | This PR is planning-only and excludes Pulumi, workflow, AWS, branch-protection, and stack mutations. |
| Epic decomposition | Ready | Eight epics preserve the issue priority model and cover all listed roadmap items. |
| Evidence model | Ready | Future controls require repo, CI, AWS metadata, or external-control evidence. |
| Secret safety | Ready | Future validation must avoid stack exports, decrypted config, cloud-secret payloads, and environment dumps. |
| Implementation readiness | Partially ready | P0 items are implementable first; some P1/P2 items need owners and external evidence decisions. |

## Recommended Implementation Order

1. Epic 1: make same-repo AWS-backed guardrails mandatory and evidence-backed.
2. Epic 2: fix replication-region defaulting, allowlist validation, and RTO/RPO assumptions.
3. Epic 3: reduce bootstrap automation IAM blast radius and document remaining wildcards.
4. Epic 4 and Epic 5: add monitoring, alerting, incident process, restore runbooks, and restore validation.
5. Epic 6 and Epic 7: add cost controls, repo-fanout preflight, quota checks, and cleanup cadence.
6. Epic 8: add lifecycle, sustainability, and conditional future policy coverage.
7. Run a follow-up Well-Architected review and update scores only after implementation evidence exists.

## External Dependencies

| Dependency | Needed For | Evidence Required |
| --- | --- | --- |
| GitHub branch protection settings | Epic 1 | Required status checks, reviewer rules, and skip policy evidence. |
| AWS account and organization cost controls | Epic 6 | Budget, anomaly detection, or external FinOps control evidence. |
| Alert routing destination | Epic 4 | SNS, ChatOps, ticketing, or external incident tool ownership and routing evidence. |
| Backup Vault Lock decision | Epic 5 | In-repo implementation evidence or external-control exemption. |
| Quota ownership | Epic 7 | Service quota thresholds, approval owner, and escalation path. |
| Sustainability goals | Epic 8 | Owner-approved goals for region selection, retention, backups, and cleanup. |

## Risk Controls For Future PRs

- Keep each implementation PR focused on one epic or one tightly related story group.
- Update docs and tests in the same PR as any infrastructure or workflow behavior change.
- Use `pulumi -C pulumi ...` for direct Pulumi commands.
- Use AWS KMS Pulumi secrets providers; do not add passphrase-backed shared backend guidance.
- Prefer metadata-only AWS validation such as identity, bucket, KMS, IAM, Backup, Budget, EventBridge, CloudWatch, or quota descriptions.
- Validate risky changes in ephemeral stacks such as `pr-<number>` or `smoke`, then destroy the stack after validation.
- Do not treat skipped privileged checks as success for same-repo infrastructure changes unless the skip policy explicitly allows it.

## No-Go Conditions

Future implementation should pause if:
- A story requires reading or printing raw secrets, decrypted Pulumi config, stack exports, or cloud-secret payloads.
- Required branch-protection or external-control evidence cannot be obtained.
- A P0 safety control conflicts with current GitHub environment or AWS account setup.
- A proposed cost, quota, or monitoring control has no owner.
- A future PR widens infrastructure behavior without matching tests or docs.

## Validation For This Planning PR

This PR should be validated by:
- Confirming the staged diff contains only files under `specs/issue-17-well-architected-5-of-5/`.
- Running the focused structural project test after removing ignored local BMAD/BMALPH/Ralph generated tooling from the worktree.
- Running markdown or repository hygiene checks if available and low-noise.

No Pulumi preview, Pulumi apply, AWS deployment, branch-protection mutation, or GitHub environment mutation is required for this planning-only PR.
