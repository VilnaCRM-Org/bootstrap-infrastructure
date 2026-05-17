# PR Comment Pulumi Promotion Readiness

## BMALPH Status

`bmalph status -C .` and `bmalph doctor -C .` show this repository is not
initialized for generated BMALPH/Ralph framework state. `bmalph init --dry-run`
would create `_bmad/`, `bmalph/`, `.ralph/`, and `.agents/skills/` files, which
the repository instructions explicitly keep out of committed planning changes.
The canonical planning artifacts for this feature therefore live under
`specs/pr-comment-pulumi-promotion/`.

## Implementation Plan

- Add a tested Python comment parser.
- Add a comment intake workflow that dispatches trusted exact-SHA commands.
- Add a repository-dispatch runner with test-first production sequencing.
- Extend structural workflow tests and OIDC role-contract tests.
- Update docs for PR comment commands and required environment variables.

## Verification Plan

- `uv run pytest -q tests/unit/test_pulumi_pr_comment.py`
- `uv run pytest -q tests/pulumi/test_delivery_contracts.py`
- `make test-repo-hygiene`
- `make test-pulumi`
- `make test-unit`
