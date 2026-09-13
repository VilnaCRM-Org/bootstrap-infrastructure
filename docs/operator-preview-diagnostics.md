# Operator preview failure diagnostics

The trusted operator runner reports a fixed stage, process category and bounded
exit code when execution fails. These public fields contain no exception text,
child output, credentials or stack data. A failure remains a failure.

For a failed preview after authenticated contract and checkpoint binding, the
runner can additionally write `operator-public/operator-diagnostic.encrypted.json`.
The workflow uploads only that ciphertext file, with one-day retention, as
`operator-diagnostic-preview-<run_id>-<run_attempt>-<account>-<head_sha>`.
Apply and drift do not capture private diagnostics.

The encrypted payload retains at most 1 MiB from each child stream and records
truncation explicitly. The existing total stream limits and execution deadline
still apply. A built-in validation failure can retain a private reason bounded
to 4 KiB. Diagnostic encryption or upload failure never permits deployment or
changes a failed job into a successful one; a missing artifact is not evidence
that the original error was harmless.

The diagnostic envelope uses the existing account-pinned KMS key and encryption
context. Its separate authenticated type and schema prevent treating diagnostics
as a saved plan. This adds no IAM grant. Anyone already authorized to decrypt
that context may be able to read sensitive content in the diagnostic payload.
Do not publish decrypted payloads or attach them to issues, PRs or normal logs.

## Investigating a failure

1. Record the failed run, attempt, account, PR head and public failure category.
   Download only its exact diagnostic artifact and verify its GitHub artifact
   digest before use. Do not substitute an artifact from another attempt.
2. Use the reviewed `operator_plan_envelope.open_diagnostic` implementation
   with the authentic contract/execution bindings and an authorized native KMS
   reader. Keep ciphertext recovery and any decrypted content in private storage;
   do not print raw payloads to a shared terminal or copy them into public evidence.
3. Report the specific actionable finding with secret values removed. Keep the
   original failed deployment result and its identity separate from diagnostic
   observations. Correct and review the cause before requesting another normal
   comment-driven deployment.

The diagnostic artifact is evidence for investigation, not deployment authority,
a promotion receipt or permission to bypass source review and environment gates.
