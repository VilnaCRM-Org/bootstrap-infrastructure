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
| Question coverage | Ready | `question-matrix.md` covers all 57 AWS Well-Architected questions with current evidence, gaps, target proof, owner role, and cadence. |
| FR/NFR coverage | Ready | PRD and architecture cover current repo functions, non-functional constraints, evidence freshness, and score-claim gates. |
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
| Well-Architected review owner | Epic 0 | Owner for question-matrix updates, score changes, evidence expiry, and follow-up review. |

## Risk Controls For Future PRs

- Keep each implementation PR focused on one epic or one tightly related story group.
- Update docs and tests in the same PR as any infrastructure or workflow behavior change.
- Use `pulumi -C pulumi ...` for direct Pulumi commands.
- Use AWS KMS Pulumi secrets providers; do not add passphrase-backed shared backend guidance.
- Prefer metadata-only AWS validation such as identity, bucket, KMS, IAM, Backup, Budget, EventBridge, CloudWatch, or quota descriptions.
- Validate risky changes in ephemeral stacks such as `pr-<number>` or `smoke`, then destroy the stack after validation.
- Do not treat skipped privileged checks as success for same-repo infrastructure changes unless the skip policy explicitly allows it.
- Do not raise a question score unless the `question-matrix.md` row includes implemented evidence, owner, freshness SLA, fallback action, and comparison with `main`.
- Prefer existing OIDC-backed GitHub workflows for test-account Pulumi apply evidence when local Pulumi or KMS backend metadata is not safely configured.

## Test-Account Validation Strategy

The planning PR itself does not mutate Pulumi resources, but the user requested a real AWS test-account validation path before merge. The safe validation strategy is:

| Step | Method | Secret-safety rule | Expected evidence |
| --- | --- | --- | --- |
| Local AWS identity sanity check | `aws sts get-caller-identity` | Metadata-only output; do not inspect credentials. | Confirms AWS CLI can reach an account before any deploy attempt. |
| Local Pulumi readiness check | `pulumi -C pulumi ...` only when Pulumi is installed and KMS backend metadata is configured. | Do not run stack export, show secrets, decrypt, or print environment values. | If local prerequisites are absent, local apply is skipped and CI deploy is used. |
| Branch test deploy | Dispatch `Pulumi Test Deploy` on the PR branch. | Uses GitHub OIDC and configured environment metadata without printing secret values. | Workflow URL, head SHA, preview result, destructive diff result, IAM validation result, apply result, and post-apply drift result. |
| Post-run review | `gh run view` and `gh pr checks` | Inspect logs only for status and failure causes; do not print secrets. | PR comment or readiness update with run conclusion and remaining blockers. |

Current local readiness observations for this planning update:

- AWS CLI caller identity resolved successfully with metadata-only validation.
- Local `pulumi` was not installed in the shell, so direct local `pulumi -C pulumi up` was not a safe available path.
- Required Pulumi backend and KMS provider environment metadata was not present in the local shell; values were not printed.
- Therefore, real test-account apply evidence should be captured through the existing OIDC-backed GitHub `Pulumi Test Deploy` workflow for this PR branch.

GitHub test-account validation attempt for this PR branch:

| Date | Workflow run | Head SHA | Result | Implication |
| --- | --- | --- | --- | --- |
| 2026-04-26 | `https://github.com/VilnaCRM-Org/bootstrap-infrastructure/actions/runs/24967209875` | `814425df2297aaf1cc9f23475bc6167b5ccb069b` | Failed at `Validate test deployment prerequisites` before AWS credentials were assumed. Missing metadata variable names were `AWS_APPLY_ROLE_ARN`, `AWS_DRIFT_ROLE_ARN`, `PULUMI_BACKEND_URL`, `PULUMI_PREVIEW_STACKS`, and `PULUMI_DRIFT_STACKS`. | No Pulumi preview/apply ran and no AWS resources were changed. Merge readiness still needs the test environment metadata configured or a Pulumi ESC-backed replacement implemented in a future PR. |

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
- Confirming the question matrix contains all 57 AWS Well-Architected questions.
- Dispatching or observing the existing `Pulumi Test Deploy` workflow when a real test-account apply is required for merge readiness.

No branch-protection mutation or GitHub environment mutation is required for this planning-only PR. Direct local Pulumi apply is not required when the existing test-account workflow provides equivalent OIDC-backed deploy evidence without exposing local secrets.
