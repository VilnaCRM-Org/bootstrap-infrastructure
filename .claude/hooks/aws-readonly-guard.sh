#!/usr/bin/env bash
# PreToolUse guard: block obvious AWS/Pulumi/Terraform mutations as
# defense-in-depth. This is NOT a security boundary -- the read-only IAM role
# (ClaudeReadOnly-*, secret reads explicitly denied) is. A determined bypass
# (env indirection, wrappers, unusual spacing) defeats a regex over shell text;
# the IAM credentials are what actually hold.
set -euo pipefail

INPUT="$(cat)"
CMD="$(printf '%s' "$INPUT" | jq -r '.tool_input.command // empty')"

[ -z "$CMD" ] && exit 0

deny() {
  jq -n --arg reason "$1" \
    '{hookSpecificOutput: {hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: $reason}}'
  exit 0
}

# Never let the agent target a prod profile from this read-only workspace.
if printf '%s' "$CMD" | grep -Eiq '(--profile[= ]+[^ ]*prod|AWS_PROFILE=[^ ]*prod)'; then
  deny "Blocked: prod AWS profile is out of scope for this read-only workspace. Run prod reads in a separate, MFA-gated session."
fi

# Block mutating AWS CLI verbs (covers chained/compound commands the
# permission glob matcher can miss).
AWS_MUTATING='(create|delete|put|update|modify|remove|attach|detach|associate|disassociate|run-instances|terminate|reboot|deploy|invoke|reset|enable|disable|tag-resource|untag-resource|authorize-|revoke-|s3[[:space:]]+(rm|cp|mv|sync|rb))'
if printf '%s' "$CMD" | grep -Eiq "(^|[;&|]|\bxargs |\btimeout )[[:space:]]*aws[[:space:]]" \
  && printf '%s' "$CMD" | grep -Eiq "aws[[:space:]].*($AWS_MUTATING)"; then
  deny "Blocked: AWS mutating command detected. This workspace is read-only. If a change is truly intended, run it from a session with write credentials against the right account."
fi

# Block AWS read actions that return secrets/credentials in plaintext.
if printf '%s' "$CMD" | grep -Eiq 'aws[[:space:]].*(secretsmanager[[:space:]]+get-secret-value|kms[[:space:]]+decrypt|get-password-data|get-session-token|(ssm[[:space:]]+get-parameter))'; then
  deny "Blocked: command reads secret/credential material. The read-only role denies these; do not attempt to exfiltrate secrets."
fi

# Block destructive IaC operations.
if printf '%s' "$CMD" | grep -Eiq '(pulumi[[:space:]]+(up|destroy|cancel|import)|pulumi[[:space:]]+state[[:space:]]+delete|terraform[[:space:]]+(apply|destroy|import))'; then
  deny "Blocked: destructive IaC operation. This workspace only previews/inspects infrastructure."
fi

exit 0
