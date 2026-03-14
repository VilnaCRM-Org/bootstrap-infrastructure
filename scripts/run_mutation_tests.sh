#!/usr/bin/env bash
set -euo pipefail

cd /workspace

mutation_tests=(
  tests/unit/test_config.py
  tests/unit/test_policies.py
  tests/unit/test_mutation_targets.py
)
mutation_cov_targets=(
  --cov=infra.config
  --cov=infra.iam.github_oidc
)

poetry run pytest -q "${mutation_tests[@]}" \
  "${mutation_cov_targets[@]}" \
  --cov-report=term
