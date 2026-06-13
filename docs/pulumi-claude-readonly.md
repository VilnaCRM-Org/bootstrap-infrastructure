# Claude read-only AWS access

AI-native DevOps with Claude Code against AWS, done securely. The boundary that
actually holds is a **read-only IAM role with secret reads explicitly denied**,
assumed with **short-lived, MFA-gated credentials**. Claude Code permission
rules and the PreToolUse hook are defense-in-depth on top — they reduce prompts
and catch accidents, but they are not the security boundary.

> Account model: this repository is a **single AWS account** with `test` and
> `prod` separated by Pulumi stacks. "Read-only to test and prod" therefore means
> read-only to the account. The role is environment-scoped only to avoid a name
> collision between the two stacks.

## 1. The role (managed here, in Pulumi)

`infra/iam/readonly.py` provisions `ClaudeReadOnly-<repo>-<env>` when the
`claudeReadonlyPrincipalArns` config lists at least one principal:

- Trust policy: only the listed IAM principals may `sts:AssumeRole`, and only
  with `aws:MultiFactorAuthPresent = true`.
- `max_session_duration = 3600` (1h) — prod re-auths often.
- AWS-managed `ReadOnlyAccess` attached, **plus** an explicit `Deny` on the
  sensitive reads `ReadOnlyAccess` would otherwise grant
  (`secretsmanager:GetSecretValue`, `kms:Decrypt`, `ssm:GetParameter*`,
  `lambda:GetFunction`, `ec2:GetPasswordData`, `*:GetAuthorizationToken`,
  `sts:GetSessionToken`, `cognito-identity:Get*`). This closes the
  "read-only still leaks secrets / is an exfiltration primitive" gap, which
  matters here because the stack uses KMS + Pulumi secrets heavily.

Enable it:

```bash
# One IAM user ARN per developer laptop allowed to assume the read-only role.
pulumi config set --path 'claudeReadonlyPrincipalArns[0]' \
  arn:aws:iam::891377212104:user/<your-iam-user>
pulumi up            # exports claudeReadonlyRoleArn
```

## 2. The laptop (assume-role + MFA bridge — no long-lived prod keys)

This replaces the old static prod access keys. The base IAM user holds keys with
**only** `sts:AssumeRole` power; everything real comes from the short-lived role
session.

`~/.aws/config` (note: **no `[default]` profile**, so a bare `aws …` errors
instead of silently hitting the account):

```ini
[profile bootstrap-ro-test]
role_arn         = arn:aws:iam::891377212104:role/ClaudeReadOnly-bootstrap-infrastructure-test
source_profile   = bootstrap            # base IAM user, AssumeRole-only
mfa_serial       = arn:aws:iam::891377212104:mfa/<your-iam-user>
duration_seconds = 3600
region           = eu-central-1

[profile bootstrap-ro-prod]
role_arn         = arn:aws:iam::891377212104:role/ClaudeReadOnly-bootstrap-infrastructure-prod
source_profile   = bootstrap
mfa_serial       = arn:aws:iam::891377212104:mfa/<your-iam-user>
duration_seconds = 3600
region           = eu-central-1
```

`~/.aws/credentials` holds only the base user's keys under `[bootstrap]`. Verify:

```bash
aws sts get-caller-identity --profile bootstrap-ro-test   # prompts for MFA code
```

Then **delete the old long-lived prod access keys** in IAM.

### Target end-state

When `prod` moves to its own AWS account (the real blast-radius upgrade), switch
this role to an IAM Identity Center (SSO) permission set and use
`aws configure sso` / `aws sso login` — no keys on disk at all.

## 3. Claude Code guardrails (defense-in-depth)

`.claude/settings.json` (committed) pins the session to `bootstrap-ro-test`,
runs in `plan` mode, allows read verbs (`describe-*`/`get-*`/`list-*`/`s3 ls`),
and denies mutating verbs, secret reads, prod profiles, and `pulumi up`/
`destroy` / `terraform apply`. `.claude/hooks/aws-readonly-guard.sh` is a
PreToolUse backstop that also inspects chained/compound commands the glob
matcher can miss. For prod **reads**, use a gitignored
`.claude/settings.local.json` with `AWS_PROFILE=bootstrap-ro-prod`.

These are deliberately *not* the boundary — a determined bypass defeats a regex
over shell text. The read-only IAM credentials are what make a bypass harmless.

## 4. Attribution & audit

The role is dedicated to the agent, so CloudTrail cleanly attributes its calls
(`AssumedRole` sessions). Alert on `AccessDenied` from the role's sessions — a
spike signals a prompt-injection trying to escalate.
