# CI Guardrails

This repository uses two CI layers beyond the Pulumi runtime tests.

## Python Quality Checks

The `python-quality.yml` workflow enforces local operator commands:

- `make check-format`
- `make check-lint`
- `make check-spelling`
- `make check-toml`
- `make check-types`
- `make check-ty`
- `make check-package`

These checks ensure the Pulumi Python code stays formatted, linted, spell-checked, type-checked, and buildable with a valid `uv.lock`.
The format/lint layer is powered by Rust-native tooling: `ruff` for code quality, `typos` for repository spelling, `taplo` for TOML manifest validation, and `ty` for an additional static analysis pass over Pulumi code and tests.

## DevSecOps Guardrails

The `devsecops-guardrails.yml` workflow adds defensive checks that are cheap to run but high signal for infrastructure code:

- `make check-bandit`
- `make check-deps`
- `make check-sbom`
- `make check-yaml`
- `make check-actionlint`
- `make check-docker`
- `make check-shell`
- `make check-iac`
- `make check-qlty`
- `make test-cost`

This combination covers application security, dependency risk, SBOM generation, workflow hygiene, Dockerfile hygiene, shell hygiene, IaC policy scanning, low-cost resource governance, and a repo-local mirror of the Qlty cloud scan.

## Qlty Parity

The repository now commits its Qlty configuration in [`.qlty/qlty.toml`](/home/kravtsov/Projects/bootstrap-infrastructure/.qlty/qlty.toml) so the external `qlty check` status is reproducible from the workspace.

Local command:
```bash
make check-qlty
```

This runs `qlty check --all --summary --no-progress --level note --fail-level note` and fails on any reported issue.
The companion GitHub Actions job installs the official Qlty CLI and executes the same Make target, so local and CI behavior stay aligned.

## Deployment Workflows

Deployment is split by environment so the repository does not rely on mutable `workflow_dispatch` inputs:

- `pulumi.yml`: deploys the `test` stack
- `pulumi-prod.yml`: deploys the `prod` stack

This keeps the deploy workflows easier to reason about and aligns better with GitHub Actions policy scanners.
