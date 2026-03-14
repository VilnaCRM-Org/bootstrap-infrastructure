#!/usr/bin/env bats

assert_output_contains() {
  local expected="$1"
  if [[ "$output" == *"$expected"* ]]; then
    return 0
  fi

  printf 'expected: %s\n' "$expected" >&2
  printf 'actual: %s\n' "$output" >&2
  return 1
}

@test "make help renders the target list" {
  run make help
  [ "$status" -eq 0 ]
  assert_output_contains "check-format"
  assert_output_contains "check-qlty"
  assert_output_contains "check-ty"
  assert_output_contains "check-secrets"
  assert_output_contains "check-iam"
  assert_output_contains "pulumi-preview"
  assert_output_contains "pulumi-plan-ci"
  assert_output_contains "runner-image-build"
  assert_output_contains "test-cost"
  assert_output_contains "test-policy"
  assert_output_contains "test-crossguard"
  assert_output_contains "test-bats"
  assert_output_contains "test-e2e"
  assert_output_contains "check-coverage"
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

@test "make pulumi-plan-ci uses the shared Pulumi command runner" {
  run make -n pulumi-plan-ci
  [ "$status" -eq 0 ]
  assert_output_contains "./scripts/run_pulumi_command.sh plan"
}

@test "make pulumi-up-ci uses the shared Pulumi command runner" {
  run make -n pulumi-up-ci
  [ "$status" -eq 0 ]
  assert_output_contains "./scripts/run_pulumi_command.sh up"
}

@test "make pulumi-drift-ci uses the shared Pulumi command runner" {
  run make -n pulumi-drift-ci
  [ "$status" -eq 0 ]
  assert_output_contains "./scripts/run_pulumi_command.sh drift"
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
  assert_output_contains "docker compose --env-file .env down"
}

@test "make runner-image-build builds the local automation image" {
  run make -n runner-image-build
  [ "$status" -eq 0 ]
  assert_output_contains "docker compose --env-file .env build pulumi"
}

@test "make runner-image-smoke checks the local automation image toolchain" {
  run make -n runner-image-smoke
  [ "$status" -eq 0 ]
  assert_output_contains "pulumi version"
  assert_output_contains "aws --version"
  assert_output_contains "uv --version"
}

@test "make runner-image-push calls the shared ECR publish script" {
  run make -n runner-image-push RUNNER_ECR_REPOSITORY=pulumi-runner/bootstrap-infrastructure-test RUNNER_IMAGE_TAG=sha-example
  [ "$status" -eq 0 ]
  assert_output_contains "./scripts/publish_runner_image.sh"
  assert_output_contains "RUNNER_ECR_REPOSITORY=\"pulumi-runner/bootstrap-infrastructure-test\""
  assert_output_contains "RUNNER_IMAGE_TAG=\"sha-example\""
}

@test "make clean removes generated artifacts" {
  run make -n clean
  [ "$status" -eq 0 ]
  assert_output_contains "find . -type d -name __pycache__"
  assert_output_contains "rm -rf .venv .mypy_cache .ruff_cache .coverage-artifacts dist build"
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

@test "make test-policy runs the policy pack suite" {
  run make -n test-policy
  [ "$status" -eq 0 ]
  assert_output_contains "pytest -q tests/policy"
}

@test "make test-crossguard aliases the policy pack suite" {
  run make -n test-crossguard
  [ "$status" -eq 0 ]
  assert_output_contains "make test-policy"
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
  assert_output_contains "make test-policy"
  assert_output_contains "make test-unit"
  assert_output_contains "make test-integration"
  assert_output_contains "make test-mutation"
  assert_output_contains "make test-e2e"
  assert_output_contains "make test-bats"
  assert_output_contains "make check-coverage"
}

@test "make check-format runs Ruff format in check mode" {
  run make -n check-format
  [ "$status" -eq 0 ]
  assert_output_contains "ruff format --check"
}

@test "make check-lint runs Ruff" {
  run make -n check-lint
  [ "$status" -eq 0 ]
  assert_output_contains "ruff check"
}

@test "make check-spelling runs typos" {
  run make -n check-spelling
  [ "$status" -eq 0 ]
  assert_output_contains "typos"
}

@test "make check-toml runs Taplo" {
  run make -n check-toml
  [ "$status" -eq 0 ]
  assert_output_contains "taplo lint"
  assert_output_contains "taplo format --check"
}

@test "make check-types runs mypy" {
  run make -n check-types
  [ "$status" -eq 0 ]
  assert_output_contains "mypy"
}

@test "make check-ty runs Astral Ty" {
  run make -n check-ty
  [ "$status" -eq 0 ]
  assert_output_contains "--extra-search-path /workspace/pulumi policy_pack scripts tests"
}

@test "make check-package validates uv lock state and bytecode" {
  run make -n check-package
  [ "$status" -eq 0 ]
  assert_output_contains "uv lock --check"
  assert_output_contains "uv sync --check"
  assert_output_contains "python -m compileall"
}

@test "make check-qlty runs the repo-local Qlty scan" {
  run make -n check-qlty
  [ "$status" -eq 0 ]
  assert_output_contains "qlty check --all --summary --no-progress --level note --fail-level note"
}

@test "make check-bandit runs Bandit over pulumi sources" {
  run make -n check-bandit
  [ "$status" -eq 0 ]
  assert_output_contains "bandit -q -r pulumi policy_pack"
}

@test "make check-deps runs the dependency audit" {
  run make -n check-deps
  [ "$status" -eq 0 ]
  assert_output_contains "pip_audit"
}

@test "make check-sbom exports a CycloneDX SBOM" {
  run make -n check-sbom
  [ "$status" -eq 0 ]
  assert_output_contains "uv export"
  assert_output_contains "cyclonedx1.5"
}

@test "make check-secrets runs Gitleaks" {
  run make -n check-secrets
  [ "$status" -eq 0 ]
  assert_output_contains "gitleaks"
  assert_output_contains ".gitleaks.toml"
}

@test "make check-iam runs the IAM Access Analyzer validator" {
  run make -n check-iam REQUIRE_AWS_ACCESS_ANALYZER=1
  [ "$status" -eq 0 ]
  assert_output_contains "scripts/validate_iam_policies.py"
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

@test "make check-coverage combines and enforces coverage" {
  run make -n check-coverage
  [ "$status" -eq 0 ]
  assert_output_contains "coverage combine"
  assert_output_contains "coverage report --show-missing --fail-under=100"
}

@test "make check-static runs the Python quality aggregate" {
  run make -n check-static
  [ "$status" -eq 0 ]
  assert_output_contains "make check-format"
  assert_output_contains "make check-lint"
  assert_output_contains "make check-spelling"
  assert_output_contains "make check-toml"
  assert_output_contains "make check-types"
  assert_output_contains "make check-ty"
  assert_output_contains "make check-package"
}

@test "make check-security runs the DevSecOps aggregate" {
  run make -n check-security
  [ "$status" -eq 0 ]
  assert_output_contains "make check-bandit"
  assert_output_contains "make check-deps"
  assert_output_contains "make check-sbom"
  assert_output_contains "make check-secrets"
  assert_output_contains "make check-iam"
  assert_output_contains "make check-yaml"
  assert_output_contains "make check-actionlint"
  assert_output_contains "make check-docker"
  assert_output_contains "make check-shell"
  assert_output_contains "make check-iac"
  assert_output_contains "make check-qlty"
}

@test "make ci runs the full local CI aggregate" {
  run make -n ci
  [ "$status" -eq 0 ]
  assert_output_contains "make check-static"
  assert_output_contains "make check-security"
  assert_output_contains "make test"
}
