#!/usr/bin/env bash
set -euo pipefail

cd "${WORKSPACE:-/workspace}"

mutation_tests=(
  tests/unit/test_config.py
  tests/unit/test_policies.py
  tests/unit/test_mutation_targets.py
)

# Coverage instrumentation re-imports Pulumi packages during collection and
# trips Pulumi's resource-package registration guard in this containerized test
# environment. Keep the mutation guard deterministic by running the focused
# tests directly; full coverage remains enforced by the unit and integration
# suites.
uv run --frozen --no-sync pytest -q "${mutation_tests[@]}"
