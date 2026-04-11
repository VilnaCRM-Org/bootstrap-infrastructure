# Autorelease Action

## Overview

This repository publishes stable releases from Git tags instead of committing a
version bump back to the protected default branch. The first stable release must
be seeded manually. After that, the GitHub Actions autorelease workflow can tag
the next version and create the matching GitHub release automatically.

## Why This Flow Exists

The default branch is protected by pull-request, code-scanning, and code-quality
rules. A release workflow that tries to commit `CHANGELOG.md` or a bumped
version file directly to `main` will fail under those rules. Tag-only releases
avoid rewriting protected history while still producing deterministic versioned
artifacts.

## Release Model

1. Seed the first stable release manually.
   Use the commit you want to treat as the first stable release and publish a
   GitHub release with a semver tag such as `v0.2.0`.
2. Let autorelease derive the next version from Git tags.
   The workflow uses the latest stable semver tag as the current version source.
3. Publish later releases automatically.
   Every subsequent qualifying push to `main` can create the next tag and the
   matching GitHub release without committing back to the branch.

## Workflow Behavior

- `push` on `main` runs the normal production autorelease flow.
- The workflow does not update `pyproject.toml` or `CHANGELOG.md` in Git.
- The workflow pushes only tags and then creates the GitHub release body from
  the generated changelog text.

## Token Requirements

The workflow uses `REPO_GITHUB_TOKEN` when present and falls back to the
repository-scoped `GITHUB_TOKEN`. The token needs `contents: write` so it can
push tags and publish releases.

## Manual Seed Release

If the repository has historical tags without GitHub releases, clean that state
up before enabling automatic stable releases:

1. Delete any stray tag that points to an unpublished failed workflow commit.
2. Create the first stable release manually from the intended default-branch
   commit.
3. Verify the new release tag is now the latest stable semver tag.

After that seed release exists, the autorelease workflow can advance from that
tag automatically.
