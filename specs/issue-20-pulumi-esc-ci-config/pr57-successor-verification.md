# PR57 Successor Verification

> **Staged activation:** The installed scheduled v1 workflow remains byte-for-byte
> unchanged. The v2 consumer is staged at
> [`docs/examples/operations-alert-triage-v2.yml`](../../docs/examples/operations-alert-triage-v2.yml). GitHub does not execute workflows
> from this documentation path. Local acknowledgment tests exercise that exact
> template and do not attest to live v2 consumption. Backfill/reconcile are
> protected manual preparation only; existing scheduling is not disabled.

This successor assembles the remaining alert cutover from hardened commit
`0d8a7089acbd7923960c16500e142fd3dc69190f` on the installed controller source.
It preserves all installed IAM documents, loader pins, provider continuity,
controller permissions and required checks. The separate #60 operator program
and #78 governance/service programs are not included.

## Current contract

AWS Secrets Manager stores account-local CI configuration in the fixed suffixes
`test-pr`, `test`, `prod-preview`, and `prod`. Independently pinned repository
variables `AWS_TEST_ACCOUNT_ID` and `AWS_PROD_ACCOUNT_ID` are validated before
configuration-role assumption; all returned role/backend/KMS values must agree.
The protected `test`, `test-preview`, `prod-preview`, `prod`, `governance`,
`governance-preview`, and `operations-alert-reconcile` environments remain in use.
Configuration suffixes do not replace approval or main-only branch restrictions.
The installed trusted main controller validates original comments, current
permissions, scope, fresh PR head and verified same-head deployment evidence.
No apply/drift role fallback is permitted.

Alert fingerprint version 2 hashes complete stable JSON, independent of display
sanitization. Issue bodies show the first 10 occurrences and an omitted count.
Known AWS Backup/Copy/Restore events require typed authenticated envelopes;
benign completed events may be acknowledged, malformed events are quarantined,
and actionable events require durable issue handling. Successful audit upload
and issue operations precede private allowlisted SQS deletion. The EventBridge
pattern is conservative; it does not perform full schema validation.

## Operational follow-up

Before enabling the v2 scheduled consumer, record an SRE-confirmed stream mapping
and protected reconciliation. Preserve old issues if full stable identity is
unknown; no v1 hash fallback is allowed. Validate actual SNS/SQS routing and
redelivery, deployed EventBridge changes, current CI payload metadata and exact
main-only environment controls. Cleanup is manual, dry-run-first and limited to
legacy environment variables. A local test is not live acceptance or BMAD PASS.

The archived May 25 evidence is retained without changing its dated conclusions.
No AWS, GitHub issue, configuration or queue operation is performed by assembly.
Validation results are recorded below after the candidate checks complete.

## Local validation

- 1,401 unit tests passed, covering 8,294 statements and 2,272 branches at 100%.
- 346 focused runtime, integration, structural and shared-helper tests passed.
- The exact unprivileged integration target's two files passed all 8 tests.
- Ruff and formatting, Ty, Xenon (B/B/A), Actionlint and Yamllint passed;
  changed runtime files passed Bandit. Every changed relative document link resolves.
- The assembly matches the reviewed 41-path scope. Monitoring AST comparison
  confirms only the Backup event pattern changes; installed IAM, loader,
  controller and policy pins remain identical.

These are local source checks. A bounded artifact search found no valid
SRE v1-to-v2 mapping receipt; scheduled v2 activation must remain staged pending
that evidence. The successor is rebound to the actual controller squash commit
`888b2424c2cc3fe475e1cf24c614004c49a4928e`, whose tree equals the reviewed
installation source.

## Staging validation

All 268 selected structural, classifier, renderer, event-pattern and staged
acknowledgment tests passed after staging. Actionlint and Yamllint validate the
inert template explicitly; the normal Make targets retain that lint coverage.
The scheduled v1 workflow has an exact whole-file SHA regression in addition to
the existing handler regression. Only a subsequent reviewed activation may
change it. This staging adds no role, trust, policy, scheduler flag or workflow
credential permission.
