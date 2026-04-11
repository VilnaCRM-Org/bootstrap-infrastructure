# uv and Rust-Native Python Tooling

This document records the implemented Python tooling changes from
[issue #16](https://github.com/VilnaCRM-Org/bootstrap-infrastructure/issues/16).

## What changed

- Poetry was removed from the active Pulumi/Python workflow.
- `uv` now owns dependency locking, syncing, and command execution.
- `uv.lock` is committed and used by the Docker image and local development.
- Ruff and Ty were added as dedicated CI checks and `make` targets.

## Runtime model

The Docker workspace keeps its `uv` virtual environment outside the bind-mounted
repository tree at `/home/dev/.venvs/bootstrap-infrastructure`.

That design matters for two reasons:

- the host checkout can no longer shadow the interpreter with an incompatible
  local `.venv`
- Pulumi Automation still shells out through `pip` for plugin discovery, so the
  container seeds the managed environment once before syncing dependencies

If you need a local host-side environment outside Docker, create it the same
way:

```bash
export UV_PROJECT_ENVIRONMENT="${HOME}/.venvs/bootstrap-infrastructure"
uv venv --seed "${UV_PROJECT_ENVIRONMENT}"
uv sync --all-groups
```

## Quality gates

The repository now treats the following commands as the baseline Python quality
surface:

- `make test-ruff`
- `make test-ty`
- `make test-quality`

Ruff is used for linting and formatting drift checks. Ty is enabled as a
required check, with a narrow set of explicit ignores for current Pulumi API
false positives around `Output.apply` and the coverage bootstrap shim.

## CI coverage

GitHub Actions now includes a dedicated `python-quality.yml` workflow that runs:

- `make test-ruff`
- `make test-ty`
- `make test-maintainability`
- `make test-architecture`
- `make test-dependency-hygiene`
- `make test-coverage`

The aggregate `pulumi-local.yml` workflow also covers the quality gates by
running `make ci-pr`, which includes the non-mutation structural, quality, unit,
integration, and CLI checks while keeping mutation isolated in its dedicated
workflow.
