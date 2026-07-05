# Red-Team Security Audit — 2026-07-05

Offensive-security review of `bootstrap-infrastructure`, conducted as an adversary attempting
to break the system from four vantage points: an external attacker opening a malicious pull
request, a low-privilege contributor abusing `/pulumi` PR-comment commands, a compromised
third-party dependency/action, and an insider with limited AWS access seeking privilege escalation.

## Method

A subagent loop of **10 attack-surface finders** probed the repository in parallel, each mapped to
an OWASP framework across all editions:

- **OWASP Top 10 CI/CD Security Risks** (CICD-SEC-1…10)
- **OWASP Web Top 10** (2010, 2013, 2017, 2021) and **API Security Top 10** (2019, 2023)
- **Cloud/IaC hardening** (CIS AWS Foundations, Checkov-class checks)
- **IAM privilege-escalation** vectors, supply-chain/SLSA, secrets exposure, code injection, and denial-of-wallet

Every raw finding was then subjected to **3 adversarial verifiers** (exploitability, existing-mitigation,
and severity-accuracy lenses) instructed to *refute* it; a finding was confirmed only if ≥2 verifiers
could not break it. A completeness critic seeded a second finder round.

## Result

- Round 1: 24 raw findings → **15 confirmed**, 9 refuted by adversarial verification.
- Round 2: 19 additional findings → **0 confirmed**, 19 refuted (Round 1 had already captured the real issues).
- **15 confirmed vulnerabilities**: 10 filed as new `security` issues (#181–#190), 5 deduplicated into existing issues (#82, #159, #181).

Severity breakdown: 5× high, 5× medium, 5× low

## Confirmed findings

| Severity | Issue | OWASP / standard | Vulnerability | Component |
| --- | --- | --- | --- | --- |
| high | #181 (new) | CICD-SEC-1 (Insufficient Flow Control), CICD-SEC-2 (Inadequate IAM) | /pulumi PR-command authorization relies on author_association, letting read/triage collaborators and org members trigger privileged AWS applies | `.github/workflows/pulumi-pr-commands.yml + scripts/pulumi_pr_comment.py + .github/workflows/pulumi-pr-command-runner.yml` |
| high | #184 (new) | CICD-SEC-1 (Insufficient Flow Control) | Destructive-infrastructure safety gate is bypassable via a PR label that triage-level users can apply | `scripts/pulumi_ci_guardrails.py (load_destructive_override) + .github/workflows/pulumi-pr-command-runner.yml + .github/workflows/pulumi-pr-guardrails.yml` |
| high | #182 (new) | CICD-SEC-5 (Insufficient PBAC) / AWS IAM Privilege Escalation (PutRolePolicy on controlled role) | GitHub Actions automation (bootstrap) OIDC role can self-escalate to full AWS account admin via iam:PutRolePolicy on its own ARN | `pulumi/infra/automation.py (automation role inline policy / _automation_iam_role_resources)` |
| high | #181 (existing) | CICD-SEC-4 (Poisoned Pipeline Execution) / CICD-SEC-1 Insufficient Flow Control | PR-comment Pulumi commands authorize on author_association (OWNER/MEMBER/COLLABORATOR) allowing read/triage collaborators and any org member to trigger real AWS applies against the unprotected test environment | `scripts/pulumi_pr_comment.py (authorization) + scripts/configure_github_repository_controls.py (no test/prod-preview environment protection)` |
| high | #183 (new) | CICD-SEC-1 (Insufficient Flow Control Mechanisms) | PR-comment Pulumi runner bypasses the shared state concurrency group, letting concurrent applies race — and auto-`pulumi cancel` recovery escalates the lock race into Pulumi state corruption | `.github/workflows/pulumi-pr-command-runner.yml (concurrency) + scripts/run_pulumi_command.py (lock-cancel recovery)` |
| medium | #185 (new) | CICD-SEC-4 (Poisoned Pipeline Execution), CICD-SEC-6 (Insufficient Credential Hygiene) | PR guardrails and /pulumi runner execute untrusted PR-head code with AWS OIDC and a long-lived PULUMI_ACCESS_TOKEN, with no in-workflow reviewed-PR requirement | `.github/workflows/pulumi-pr-guardrails.yml (preview job) + .github/workflows/pulumi-pr-command-runner.yml` |
| medium | #181 (existing) | CICD-SEC-4 (Poisoned Pipeline Execution); also CICD-SEC-1 Insufficient Flow Control / CWE-863 Incorrect Authorization | PR-comment Pulumi command pipeline authorizes privileged AWS apply on github.event.comment.author_association, letting a read/triage collaborator or any org member trigger PPE | `.github/workflows/pulumi-pr-commands.yml + scripts/pulumi_pr_comment.py (authorization), consumed by .github/workflows/pulumi-pr-command-runner.yml` |
| medium | #82 (existing) | CICD-SEC-6 (Insufficient Credential Hygiene); A05:2021 Security Misconfiguration | Gitleaks secret-scan gate only inspects the latest commit (--log-opts="-1"), missing secrets in every other commit | `Makefile (test-secrets target) / .github/workflows/security-scans.yml` |
| medium | #181 (existing) | API5:2023 (Broken Function Level Authorization); A01:2021 Broken Access Control | PR-comment Pulumi execution authorized by author_association, granting AWS-mutating capability to read/triage collaborators and any org member | `scripts/pulumi_pr_comment.py + .github/workflows/pulumi-pr-commands.yml + .github/workflows/pulumi-pr-command-runner.yml` |
| medium | #159 (existing) | CICD-SEC-1 (Insufficient Flow Control Mechanisms) / A05:2021 Security Misconfiguration | require_code_owner_review is enabled in the branch ruleset but no CODEOWNERS file exists, so mandatory owner review silently no-ops for all security-critical paths | `scripts/_github_repository_controls.py (default_pull_request_rule / ruleset verification) + absent CODEOWNERS` |
| low | — | A09:2021 Security Logging and Monitoring Failures; CIS AWS Foundations 3.x (CloudTrail log integrity), Checkov CKV_AWS_18/CKV2 S3 object-lock | Audit, state, and backup data stores lack immutability (no S3 Object Lock, no MFA-Delete, no Backup Vault Lock) and object-level deletion is unmonitored, enabling log/state tampering and anti-forensics | `pulumi/infra/operations_monitoring.py (CloudTrail bucket), pulumi/infra/pulumi_state.py (state buckets), pulumi/infra/security_account_controls.py (Config bucket), pulumi/infra/logging_bucket.py (central log bucket), pulumi/infra/backup.py (Backup vault)` |
| low | #187 (new) | A02:2021 Cryptographic Failures; Checkov CKV_AWS_145 (S3 encrypted with KMS CMK) | Pulumi state, AWS Config, and central-logging buckets encrypt with SSE-S3 (AES256) rather than a customer-managed KMS key, and the encryption guardrail accepts any sseAlgorithm | `pulumi/infra/pulumi_state.py, pulumi/infra/security_account_controls.py, pulumi/infra/logging_bucket.py; guardrail policy/guardrails.py` |
| low | #188 (new) | CICD-SEC-1 (Insufficient Flow Control Mechanisms) / A05:2021 Security Misconfiguration | Branch ruleset does not dismiss stale approvals on push and does not require last-push approval, enabling post-approval malicious commit injection with a single review | `scripts/_github_repository_controls.py default_pull_request_rule()` |
| low | #189 (new) | CICD-SEC-1 (Insufficient Flow Control Mechanisms) | Denial-of-wallet: no per-actor or repository-wide rate limit on PR-comment-triggered Pulumi pipelines; a single collaborator can fan out unbounded expensive AWS apply/preview runs | `.github/workflows/pulumi-pr-commands.yml + .github/workflows/pulumi-pr-command-runner.yml` |
| low | #190 (new) | CICD-SEC-1 (Insufficient Flow Control Mechanisms) | Operations alert triage creates a brand-new GitHub issue every 30 minutes with no dedup; an insider (even with denied AWS calls) can sustain the alert stream to flood the issue tracker and burn triage CI runs | `.github/workflows/operations-alert-triage.yml (issue creation) + pulumi/infra/operations_monitoring.py (event patterns)` |

## Themes

1. **PR-comment `/pulumi` automation is the dominant risk surface.** Authorization rests on
   `github.event.comment.author_association` (OWNER/MEMBER/COLLABORATOR), so any org member or a
   read/triage collaborator can trigger privileged AWS operations; the destructive-action safety
   gate is bypassable via a PR label; concurrent comment-triggered runs can race the Pulumi state
   lock; and there is no per-actor rate limit (denial-of-wallet). See #181, #183, #184, #185, #189.
2. **IAM self-escalation.** The automation/bootstrap OIDC role can grant itself account admin via
   `iam:PutRolePolicy` on its own ARN — a classic privilege-escalation primitive. See #182.
3. **Governance controls that silently no-op.** `require_code_owner_review` is enabled in the branch
   ruleset but no CODEOWNERS file exists (#159); stale approvals are not dismissed on push (#188).
4. **Data-integrity / anti-forensics.** Audit, state, and backup stores lack immutability (Object Lock,
   MFA-Delete, Vault Lock) and use SSE-S3 rather than customer-managed KMS keys. See #186, #187.
5. **Secret-scan coverage gap.** The gitleaks gate inspects only the latest commit. Folded into #82.

## Verification integrity

The audit deliberately over-generated candidates and then destroyed the weak ones: **28 of 43**
raw findings were refuted by the adversarial verifiers (including the entire second round), so the
15 confirmed issues survived a skeptical, mitigation-aware re-review rather than being taken at face value.

