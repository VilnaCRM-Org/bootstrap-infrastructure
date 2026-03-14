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
- `make test-cost`

This combination covers application security, dependency risk, SBOM generation, workflow hygiene, Dockerfile hygiene, shell hygiene, IaC policy scanning, and low-cost resource governance.

## Deployment Workflows

Deployment is split by environment so the repository does not rely on mutable `workflow_dispatch` inputs:

- `pulumi.yml`: deploys the `test` stack
- `pulumi-prod.yml`: deploys the `prod` stack

This keeps the deploy workflows easier to reason about and aligns better with GitHub Actions policy scanners.
