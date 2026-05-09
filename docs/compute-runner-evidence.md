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
- The Dockerfile now pins `python:3.11.15-slim-bookworm`, whose Docker Hub image
  index was created on 2026-05-08. This removes the stale `python:3.11.9`
  base-image pin from the repository, but live ECR evidence remains blocked
  until a rebuilt image is pushed and scanned.

The refreshed scan result for image digest
`sha256:70922fea54b93062662749b2be5669b28fb5cb396c9b0f17600350049c40e681`
completed on 2026-05-09 and reported:

| Severity | Count |
| --- | ---: |
| Critical | 5 |
| High | 36 |
| Medium | 32 |
| Low | 3 |

The tagged image-index digest had no scan object, and the small related OCI
artifact returned an unsupported image scan status. Those outcomes do not clear
the underlying runner-image finding set.

Rebuild probes on 2026-05-09:

- `python:3.11.15-slim-bookworm` built successfully and was pushed under a
  temporary `sha-sec6-base-refresh-20260509` tag. ECR scan reported no critical
  findings but still reported 9 high findings in Debian packages. The temporary
  tag and related untagged image artifacts were deleted after validation.
- `python:3.11.15-slim-trixie` built successfully and was pushed under a
  temporary `sha-sec6-trixie-refresh-20260509` tag. ECR scan reported 1 critical
  and 6 high findings, so this base was not adopted. The temporary tag and
  related untagged image artifacts were deleted after validation.

## Remediation Gate

SEC6 remains below 5/5 until the runner image is rebuilt from the current base
image or removed, and a fresh ECR or Inspector scan shows no unaccepted critical
or high findings. Any
accepted finding requires a security-reviewer exception with CVE, package,
runtime exposure, compensating control, owner, and expiry date.

Future always-on compute remains out of scope for the current workload. Adding
EC2, ECS, EKS, Lambda, a self-hosted runner, or a public runtime endpoint must
add owner-approved patching, hardening, utilization, monitoring, vulnerability
SLA, and incident-response evidence in the same PR.
