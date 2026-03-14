#!/usr/bin/env bats

assert_output_contains() {
  local expected="$1"
  [[ "$output" == *"$expected"* ]]
}

@test "make help renders the target list" {
  run make help
  [ "$status" -eq 0 ]
  assert_output_contains "check-format"
  assert_output_contains "pulumi-preview"
  assert_output_contains "test-cost"
  assert_output_contains "test-bats"
  assert_output_contains "test-e2e"
}

@test "make all resolves to help output" {
  run make all
  [ "$status" -eq 0 ]
  assert_output_contains "Targets:"
}

@test "make start composes the environment" {
  run make -n start
  [ "$status" -eq 0 ]
  assert_output_contains "docker compose"
  assert_output_contains "up -d"
}

@test "make pulumi-preview uses the pulumi subdirectory" {
  run make -n pulumi-preview
  [ "$status" -eq 0 ]
  assert_output_contains "pulumi -C pulumi preview"
}

@test "make pulumi-up uses the pulumi subdirectory" {
  run make -n pulumi-up
  [ "$status" -eq 0 ]
  assert_output_contains "pulumi -C pulumi up"
}

@test "make pulumi-refresh uses the pulumi subdirectory" {
  run make -n pulumi-refresh
  [ "$status" -eq 0 ]
  assert_output_contains "pulumi -C pulumi refresh"
}

@test "make pulumi-destroy uses the pulumi subdirectory" {
  run make -n pulumi-destroy
  [ "$status" -eq 0 ]
  assert_output_contains "pulumi -C pulumi destroy"
}

@test "make pulumi-stack-select wires select and init" {
  run make -n pulumi-stack-select STACK=test PULUMI_SECRETS_PROVIDER=awskms://alias/example?region=eu-central-1
  [ "$status" -eq 0 ]
  assert_output_contains "stack select \"test\" --non-interactive"
  assert_output_contains "stack init \"test\" --non-interactive --secrets-provider \"awskms://alias/example?region=eu-central-1\""
}

@test "make pulumi-stack-migrate-secrets uses change-secrets-provider" {
  run make -n pulumi-stack-migrate-secrets STACK=test PULUMI_SECRETS_PROVIDER=awskms://alias/example?region=eu-central-1
  [ "$status" -eq 0 ]
  assert_output_contains "stack change-secrets-provider \"awskms://alias/example?region=eu-central-1\""
}

@test "make sh opens a shell in the container" {
  run make -n sh
  [ "$status" -eq 0 ]
  assert_output_contains "run --rm pulumi sh"
}

@test "make down stops docker compose" {
  run make -n down
  [ "$status" -eq 0 ]
  assert_output_contains "docker compose"
  assert_output_contains "down"
}

@test "make clean removes generated artifacts" {
  run make -n clean
  [ "$status" -eq 0 ]
  assert_output_contains "find . -type d -name __pycache__"
  assert_output_contains "rm -rf .venv dist build"
}

@test "make test-unit runs pytest for unit tests" {
  run make -n test-unit
  [ "$status" -eq 0 ]
  assert_output_contains "pytest -q tests/unit"
}

@test "make test-integration runs pytest for integration tests" {
  run make -n test-integration
  [ "$status" -eq 0 ]
  assert_output_contains "pytest -q tests/integration tests/unit"
}

@test "make test-pulumi runs structural tests" {
  run make -n test-pulumi
  [ "$status" -eq 0 ]
  assert_output_contains "pytest -q tests/pulumi"
}

@test "make test-cost runs the cost guardrail suite" {
  run make -n test-cost
  [ "$status" -eq 0 ]
  assert_output_contains "pytest -q tests/cost"
}

@test "make test-mutation runs the mutation script" {
  run make -n test-mutation
  [ "$status" -eq 0 ]
  assert_output_contains "./scripts/run_mutation_tests.sh"
}

@test "make test-e2e runs the e2e pytest suite" {
  run make -n test-e2e
  [ "$status" -eq 0 ]
  assert_output_contains "pytest -q tests/e2e"
}

@test "make test-bats runs bats coverage" {
  run make -n test-bats
  [ "$status" -eq 0 ]
  assert_output_contains "tests/bats"
}

@test "make test runs the complete battery" {
  run make -n test
  [ "$status" -eq 0 ]
  assert_output_contains "make test-pulumi"
  assert_output_contains "make test-cost"
  assert_output_contains "make test-unit"
  assert_output_contains "make test-integration"
  assert_output_contains "make test-mutation"
  assert_output_contains "make test-e2e"
  assert_output_contains "make test-bats"
}

@test "make check-format runs Black in check mode" {
  run make -n check-format
  [ "$status" -eq 0 ]
  assert_output_contains "black --check"
}

@test "make check-lint runs Flake8" {
  run make -n check-lint
  [ "$status" -eq 0 ]
  assert_output_contains "flake8"
}

@test "make check-types runs mypy" {
  run make -n check-types
  [ "$status" -eq 0 ]
  assert_output_contains "mypy"
}

@test "make check-package validates Poetry metadata and bytecode" {
  run make -n check-package
  [ "$status" -eq 0 ]
  assert_output_contains "poetry check --lock"
  assert_output_contains "python -m compileall"
}

@test "make check-bandit runs Bandit over pulumi sources" {
  run make -n check-bandit
  [ "$status" -eq 0 ]
  assert_output_contains "bandit -q -r pulumi"
}

@test "make check-deps runs the dependency audit" {
  run make -n check-deps
  [ "$status" -eq 0 ]
  assert_output_contains "pip_audit"
}

@test "make check-yaml runs yamllint" {
  run make -n check-yaml
  [ "$status" -eq 0 ]
  assert_output_contains "yamllint"
}

@test "make check-actionlint runs actionlint in Docker" {
  run make -n check-actionlint
  [ "$status" -eq 0 ]
  assert_output_contains "actionlint"
}

@test "make check-docker runs hadolint in Docker" {
  run make -n check-docker
  [ "$status" -eq 0 ]
  assert_output_contains "hadolint"
}

@test "make check-shell runs ShellCheck in Docker" {
  run make -n check-shell
  [ "$status" -eq 0 ]
  assert_output_contains "shellcheck"
}

@test "make check-iac runs Checkov in Docker" {
  run make -n check-iac
  [ "$status" -eq 0 ]
  assert_output_contains "checkov"
}

@test "make check-static runs the Python quality aggregate" {
  run make -n check-static
  [ "$status" -eq 0 ]
  assert_output_contains "make check-format"
  assert_output_contains "make check-lint"
  assert_output_contains "make check-types"
  assert_output_contains "make check-package"
}

@test "make check-security runs the DevSecOps aggregate" {
  run make -n check-security
  [ "$status" -eq 0 ]
  assert_output_contains "make check-bandit"
  assert_output_contains "make check-deps"
  assert_output_contains "make check-yaml"
  assert_output_contains "make check-actionlint"
  assert_output_contains "make check-docker"
  assert_output_contains "make check-shell"
  assert_output_contains "make check-iac"
}

@test "make ci runs the full local CI aggregate" {
  run make -n ci
  [ "$status" -eq 0 ]
  assert_output_contains "make check-static"
  assert_output_contains "make check-security"
  assert_output_contains "make test"
}
