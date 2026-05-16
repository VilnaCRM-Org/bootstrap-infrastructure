# Data Classification And Retention

This matrix is the repository-owned classification and retention evidence for
bootstrap infrastructure. It is safe to publish because it records data classes,
owners, and control expectations rather than object contents, stack secrets,
invoices, user data, or incident details.

## Classification Rules

| Classification | Meaning | Handling rule |
| --- | --- | --- |
| `internal` | Operational metadata, resource names, workflow summaries, and non-secret evidence. | May appear in repository docs and CI summaries when it does not reveal secrets or private incident details. |
| `confidential` | Infrastructure state, access logs, backup metadata, IAM policy documents, and security findings. | Store only in approved AWS/GitHub systems with encryption, access control, and retention controls. Do not print full contents in public artifacts. |
| `secret` | Tokens, private keys, decrypted Pulumi config, secret stack outputs, and credentials. | Never commit or upload in normal artifacts; keep in secret managers or GitHub environment secrets. |

## Data Class Matrix

| Data class | Examples | Classification | Primary location | Retention and lifecycle | Storage class or deletion rationale | Owner | Evidence |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Pulumi state | Stack state objects and checkpoints | `confidential` | Repository state S3 bucket | Versioning and noncurrent object expiration are managed by stack code. | Standard storage for active state; replicas and backups preserve recovery objectives. | SRE | `pulumi/infra/pulumi_state.py`, restore drill evidence |
| Pulumi secrets config | Encrypted secret values and secrets-provider metadata | `secret` | Shared Pulumi backend with AWS KMS secrets provider | Managed by Pulumi backend and KMS key rotation. | Do not export to CI logs or evidence files. | Maintainer plus security reviewer | `docs/github-actions-secrets.md`, `pulumi/Pulumi.*.yaml` |
| Central logs | S3 access logs and CloudTrail delivery objects | `confidential` | Central logging S3 bucket | Lifecycle transitions are managed by stack code. | Lower-cost storage is acceptable for retained logs after active investigation window. | SRE | `pulumi/infra/logging_bucket.py`, CloudTrail metadata evidence |
| AWS Config snapshots | Configuration recorder delivery objects | `confidential` | Dedicated AWS Config delivery S3 bucket | Lifecycle expiration is managed by stack code. | SSE-S3 is used with bucket policies blocking insecure transport and SSE-C. | Security reviewer plus SRE | `pulumi/infra/security_account_controls.py` |
| Backup recovery points | AWS Backup-managed state/log recovery data | `confidential` | AWS Backup vault | Retention is managed by backup plan lifecycle. | Retain for restore objectives; do not treat backups as analytics data. | SRE | `pulumi/infra/backup.py`, restore drill evidence |
| Cross-region replicas | Replicated state and log objects | `confidential` | Replica S3 buckets in allowlisted paired region | Replica lifecycle follows the stack retention model. | Replica storage is justified by recovery objectives; region changes require cost and sustainability review. | SRE | `docs/well-architected-operating-evidence.md` |
| ECR runner images | Optional automation runner images | `internal` unless image embeds secrets | ECR repository | Immutable tags, scan-on-push, and lifecycle caps are enforced. | Delete stale images through lifecycle policy to limit storage and scan surface. | Platform owner | `pulumi/infra/automation.py` |
| CI preview artifacts | Pulumi preview JSON, plan summaries, guardrail reports | `internal` to `confidential` | GitHub Actions artifacts | Short workflow retention; do not upload stack exports or decrypted config. | Keep enough for PR review, then expire. | Maintainer | `.github/workflows/*`, `docs/ci-guardrails.md` |
| Saved Pulumi plans | Binary Pulumi plan files and manifest hashes | `confidential` | GitHub Actions artifact and `.artifacts/pulumi-plan` | Short workflow retention; manifest rejects stale or tampered plans. | Apply only when commit, backend, stack, preview hash, and plan hash match. | Maintainer | `scripts/run_pulumi_command.py` |
| Cost metadata | Budget names, anomaly monitor ARNs, thresholds, alert route metadata | `internal` | Pulumi outputs and metadata evidence files | Review monthly; do not include invoices or detailed spend exports in public evidence. | Metadata is enough for public repo evidence; private cost reports remain external. | FinOps owner | `docs/cost-performance-sustainability.md` |
| Well-Architected evidence | Question matrix, external-control records, quota summaries | `internal` | `specs/issue-17-well-architected-5-of-5/` | Refresh per PR or quarterly depending on evidence type. | Evidence must stay non-secret and reproducible. | Platform maintainers | `scripts/collect_well_architected_evidence.py` |
| Local developer config | `.env`, local AWS profile references, temporary backend paths | `secret` when credentials are present | Developer workstation | Not committed; `.env.empty` is the only committed fallback. | Local exceptions require owner-approved rotation and cleanup outside this repository. | Maintainer | `.gitignore`, `docs/security-baseline.md` |

## Review Rules

- New data classes must define classification, owner, retention, storage class,
  deletion behavior, and evidence location before merge.
- Public evidence may include resource counts, ARNs already used as metadata
  handles, dates, and owner roles; it must not include object contents,
  decrypted values, private incident detail, invoices, or personal data.
- Region, replication, lifecycle, or retention changes must update this matrix
  and the cost/sustainability evidence in the same pull request.
- Missing classification or retention evidence keeps Security and
  Sustainability score claims below 5/5.
