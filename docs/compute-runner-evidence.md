# Compute Runner Evidence

This record captures the current compute-adjacent evidence for SEC6. The
bootstrap workload does not provision always-on runtime compute. The optional
ECR runner repository is retained for future automation images, but it has no
current image inventory.

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
- Repository encryption is AES-256.
- The repository image inventory is empty after stale image cleanup on
  2026-05-09.
- The Dockerfile now pins `python:3.11.15-slim-bookworm`, whose Docker Hub image
  index was created on 2026-05-08. This removes the stale `python:3.11.9`
  base-image pin from the repository.

## Stale Image Cleanup

No active workflow references
`pulumi-runner/bootstrap-infrastructure-test:main`. The prior `main` image
index and related image artifacts were created on 2026-03-15, and the image
index `lastRecordedPullTime` was also 2026-03-15, matching creation-time use
rather than ongoing demand.

Before deletion, the refreshed scan result for image digest
`sha256:70922fea54b93062662749b2be5669b28fb5cb396c9b0f17600350049c40e681`
completed on 2026-05-09 and reported:

| Severity | Count |
| --- | ---: |
| Critical | 5 |
| High | 36 |
| Medium | 32 |
| Low | 3 |

The tagged image-index digest had no scan object, and the small related OCI
artifact returned an unsupported image scan status.

Because the image was unused and vulnerable, the following stale inventory was
deleted from ECR on 2026-05-09:

- `sha256:e41b055db0504b678f099346d2444084d558fae0347a0eb4755738bcc957bf5f`
- `sha256:70922fea54b93062662749b2be5669b28fb5cb396c9b0f17600350049c40e681`
- `sha256:4535f4b7b1b7cb1a2a0d0eb11d94ad7964afabae26329e93ada31c15308ad820`

Post-cleanup `describe-images` returned an empty image list for the repository.

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

SEC6 is clear for the current workload because there is no always-on runtime
compute and no deployable runner image remains in ECR. Any future runner image
must be pushed to the immutable, scan-on-push repository only with a fresh ECR
or Inspector scan showing no unaccepted critical or high findings. Any accepted
finding requires a security-reviewer exception with CVE, package, runtime
exposure, compensating control, owner, and expiry date.

Future always-on compute remains out of scope for the current workload. Adding
EC2, ECS, EKS, Lambda, a self-hosted runner, or a public runtime endpoint must
add owner-approved patching, hardening, utilization, monitoring, vulnerability
SLA, and incident-response evidence in the same PR.
