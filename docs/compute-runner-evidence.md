# Compute Runner Evidence

This record captures the current compute-adjacent evidence for SEC6. The
bootstrap workload does not provision always-on runtime compute; the remaining
compute surface is the optional ECR runner image used by automation workflows.

## Metadata

| Field | Value |
| --- | --- |
| Workload | `bootstrap-infrastructure` |
| Environment | `test` |
| Region | `eu-central-1` |
| Evidence owner | Platform owner plus security reviewer |
| Review cadence | Monthly and per runner image change |
| Secret safety | Do not add image layer contents, credentials, or private vulnerability tickets. |

## Current State

Live AWS metadata checked on 2026-05-09:

- ECR repository `pulumi-runner/bootstrap-infrastructure-test` exists in
  account `891377212104`.
- The repository uses immutable tags.
- Scan-on-push is enabled.
- The repository currently contains the `main` image index plus related image
  artifacts from 2026-03-15.

The latest scan result for image digest
`sha256:70922fea54b93062662749b2be5669b28fb5cb396c9b0f17600350049c40e681`
completed on 2026-03-15 and reported:

| Severity | Count |
| --- | ---: |
| Critical | 4 |
| High | 18 |
| Medium | 24 |
| Low | 1 |

The tagged image-index digest had no scan object, and the small related OCI
artifact returned an unsupported image scan status. Those outcomes do not clear
the underlying runner-image finding set.

## Remediation Gate

SEC6 remains below 5/5 until the runner image is rebuilt or removed and a fresh
ECR or Inspector scan shows no unaccepted critical or high findings. Any
accepted finding requires a security-reviewer exception with CVE, package,
runtime exposure, compensating control, owner, and expiry date.

Future always-on compute remains out of scope for the current workload. Adding
EC2, ECS, EKS, Lambda, a self-hosted runner, or a public runtime endpoint must
add owner-approved patching, hardening, utilization, monitoring, vulnerability
SLA, and incident-response evidence in the same PR.
