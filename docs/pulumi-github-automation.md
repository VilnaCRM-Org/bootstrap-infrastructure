# Pulumi GitHub Automation

This repository supports GitHub-driven Pulumi operations for the `test` environment by combining:

- a stack-managed Amazon ECR runner repository
- a stack-managed GitHub OIDC automation role
- a comment-driven dispatcher workflow plus a trusted runner workflow that run `pulumi plan` and `pulumi up`
- a scheduled drift workflow that fails when `refresh --preview-only --expect-no-changes` detects drift

## Runner Image

The bootstrap stack now creates a private ECR repository for the Pulumi runner image.

Expected outputs:

- `runnerRepositoryName`
- `runnerRepositoryUrl`
- `automationRoleArn`

The runner image is built from this repository's `Dockerfile`, then published by `pulumi-runner-image.yml` with:

- immutable tags
- scan-on-push enabled
- lifecycle cleanup for old tags

The workflow pushes:

- `sha-<commit>`
- `main` for pushes to `main`

## GitHub PR Commands

Supported PR comments:

- `pulumi plan`
- `pulumi up`
- `/pulumi plan`
- `/pulumi up`

Guardrails:

- only comments on pull requests are considered
- only `OWNER`, `MEMBER`, and `COLLABORATOR` authors are accepted
- only branches in the same repository are accepted; forks are rejected to avoid exposing AWS credentials
- the `issue_comment` workflow only dispatches a trusted `workflow_dispatch` runner; it does not check out PR code itself
- the workflow uses the PR-head runner image tag when present and falls back to `main`

The command flow is:

1. Resolve the PR head SHA and repository.
2. Dispatch `pulumi-pr-command-runner.yml` on the trusted default branch with the PR number, head SHA, and command.
3. Re-validate that the PR head still matches the queued SHA.
4. Assume the GitHub OIDC automation role in AWS.
5. Pull the ECR runner image.
6. Run `./scripts/run_pulumi_command.sh plan` or `up`.
7. Upload the full log as a workflow artifact.
8. Post a PR comment with the status, image reference, run URL, and log tail.

This is intentionally close to the Atlantis operator model: the PR becomes the control plane, and the workflow run plus artifact become the debug surface.

## Drift Detection

`pulumi-drift.yml` runs on a schedule and on `workflow_dispatch`.
It pulls the `main` runner image and executes:

```bash
./scripts/run_pulumi_command.sh drift
```

This maps to `pulumi refresh --preview-only --expect-no-changes`, so any unexpected infrastructure drift causes the workflow to fail without mutating stack state.

## Required GitHub Variables

Set these repository variables before enabling the automation flows:

- `PULUMI_TEST_ROLE_ARN`
- `PULUMI_TEST_SECRETS_PROVIDER`
- `PULUMI_STATE_BUCKET`
- `PULUMI_TEST_RUNNER_ECR_REPOSITORY`

The `test` job environment should also exist in GitHub so the automation role can trust the subject:

```text
repo:VilnaCRM-Org/bootstrap-infrastructure:environment:test
```

## Local Parity

The GitHub workflows are backed by the same local entrypoints:

```bash
make runner-image-build
make runner-image-smoke
make runner-image-push RUNNER_ECR_REPOSITORY=pulumi-runner/bootstrap-infrastructure-test RUNNER_IMAGE_TAG=sha-<commit>
make pulumi-plan-ci
make pulumi-up-ci
make pulumi-drift-ci
```
