# AGENTS

This repository manages AWS bootstrap infrastructure with Pulumi. Changes here can affect shared cloud resources, so agents must keep the scope tight and operate defensively.

## Working rules
1. Make the smallest change that satisfies the task.
2. Prefer updating automation, docs, or examples before mutating shared AWS resources.
3. Run the narrowest useful validation for the files you touched.
4. Use `pulumi -C pulumi ...` for all Pulumi CLI commands.
5. Use AWS KMS as the Pulumi secrets provider. Do not introduce `PULUMI_CONFIG_PASSPHRASE` into docs, code, workflows, or local instructions.

## Secret handling
These rules are mandatory for AI coding agents in this repository.

1. Never read, print, summarize, diff, or copy raw secret material.
2. Treat the following as off-limits unless the user explicitly asks for a secret-management task:
   - `.env`, `.env.*`, and shell files that export credentials
   - AWS shared credentials/config files, access keys, session tokens, and STS credentials
   - Pulumi stack files or exports containing `secure:` values or `encryptedkey` metadata
   - GitHub Actions secrets, deploy keys, private keys, certificates, kubeconfigs, and token files
   - payloads from AWS Secrets Manager, SSM SecureString parameters, or KMS decrypt operations
3. Never run commands that reveal secrets in terminal output. This includes `env`, `printenv`, `docker compose config`, `docker inspect`, `pulumi config --show-secrets`, `pulumi stack output --show-secrets`, `pulumi stack export`, `aws secretsmanager get-secret-value`, `aws ssm get-parameter --with-decryption`, and `aws kms decrypt`, unless the user explicitly requests that exact action.
4. Prefer metadata-only operations such as `aws sts get-caller-identity`, `aws kms describe-key`, `pulumi stack ls`, and `pulumi config` without secret-revealing flags.
5. When a secret must be set, write it directly with `pulumi config set --secret ...` or the relevant cloud secret store command without echoing the value back into the terminal transcript.
6. Never commit secret values, decrypted outputs, copied stack exports, or temporary files containing secrets.

## Pulumi workflow
1. Initialize or select stacks with `--secrets-provider "$PULUMI_SECRETS_PROVIDER"` where the value is an `awskms://...` URI.
2. Migrate legacy passphrase stacks with `pulumi stack change-secrets-provider`.
3. Prefer ephemeral agent-owned stacks such as `smoke` or `pr-<number>` for validation. Shared `test` and `prod` stacks are not scratch space.
4. Destroy ephemeral validation stacks after the check completes.

## Review-driven changes
1. Use `gh pr view <PR>` and `gh pr checks <PR>` for context.
2. Pull review threads with `gh api graphql` and resolve every actionable thread.
3. Keep refactors minimal and directly tied to review feedback.
4. Re-run the relevant checks before pushing.
