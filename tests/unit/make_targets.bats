#!/usr/bin/env bats

# Unit-level checks for the Makefile interface. These tests inspect commands with dry runs so we
# do not require Docker or cloud credentials during CI.

assert_compose_env_file() {
  [[ "$output" == *"docker compose --env-file .env "* ]] \
    || [[ "$output" == *"docker compose --env-file .env.empty "* ]]
}

plain_output() {
  printf '%s' "$1" | sed -E $'s/\\x1B\\[[0-9;]*[mK]//g'
}

assert_help_target() {
  local target="$1"
  local plain
  plain="$(plain_output "$output")"
  printf '%s\n' "$plain" | grep -Eq "^[[:space:]]+${target}[[:space:]]+"
}

@test "make help lists every public target" {
  run make help
  [ "$status" -eq 0 ]
  local expected_targets=(
    all
    build
    ci
    ci-pr
    clean
    doctor
    down
    help
    nightly-quality
    publish-pulumi-preview-summary
    pulumi-preview
    pulumi-up
    pulumi-refresh
    pulumi-destroy
    report-dead-code
    report-docstrings
    report-maintainability-trends
    report-quality
    report-sbom
    sh
    start
    test
    test-cli
    test-actionlint
    test-architecture
    test-bandit
    test-coverage
    test-crossguard
    test-dependency-hygiene
    test-deps-security
    test-dockerfile
    test-destructive-diff
    test-drift
    test-guardrails
    test-iam-validation
    test-integration
    test-lockfile
    test-maintainability
    test-mutation
    test-policy
    test-pulumi
    test-quality
    test-preview
    test-repo-hygiene
    test-ruff
    test-security
    test-secrets
    test-ty
    test-unit
    test-yaml
  )

  for target in "${expected_targets[@]}"; do
    assert_help_target "$target"
  done
}

@test "make all delegates to the help output" {
  run make all
  [ "$status" -eq 0 ]
  [[ "$output" == *"Usage:"* ]]
  [[ "$output" == *"Targets:"* ]]
}

@test "make start uses docker compose with .env" {
  run make -n start
  [ "$status" -eq 0 ]
  [[ "$output" == *"./scripts/prepare_docker_context.py"* ]]
  assert_compose_env_file
  [[ "$output" == *"up -d"* ]]
}

@test "make build builds the Pulumi development image" {
  run make -n build
  [ "$status" -eq 0 ]
  assert_compose_env_file
  [[ "$output" == *"build pulumi"* ]]
}

@test "make doctor checks prerequisites without printing env values" {
  run make -n doctor
  [ "$status" -eq 0 ]
  [[ "$output" == *"COMPOSE_ENV_FILE="* ]]
  [[ "$output" == *"./scripts/doctor.py"* ]]
  [[ "$output" != *"AWS_SECRET_ACCESS_KEY"* ]]
}

@test "make publish-pulumi-preview-summary uses the Python helper" {
  run make -n publish-pulumi-preview-summary
  [ "$status" -eq 0 ]
  [[ "$output" == *"./scripts/publish_pulumi_preview_summary.py"* ]]
}

@test "make doctor runtime output avoids echoing synthetic secret values when docker is available" {
  if ! command -v docker >/dev/null 2>&1 \
    || ! docker info >/dev/null 2>&1 \
    || ! docker compose version >/dev/null 2>&1; then
    skip "docker runtime is unavailable inside the Bats execution environment"
  fi

  run env AWS_SECRET_ACCESS_KEY=SECRET123 AWS_ACCESS_KEY_ID=KEY123 make doctor
  [ "$status" -eq 0 ]
  [[ "$output" != *"SECRET123"* ]]
  [[ "$output" != *"KEY123"* ]]
}

@test "make pulumi-preview executes preview inside container" {
  run env GITHUB_TOKEN=ghs_test_token make -n pulumi-preview
  [ "$status" -eq 0 ]
  assert_compose_env_file
  [[ "$output" == *"-e GITHUB_TOKEN"* ]]
  [[ "$output" != *"ghs_test_token"* ]]
  [[ "$output" == *"stack select"* ]]
  [[ "$output" == *"./scripts/prepare_policy_pack.py"* ]]
  [[ "$output" == *"pulumi --cwd pulumi preview --stack"* ]]
  [[ "$output" == *"--policy-pack /workspace/policy"* ]]
}

@test "make pulumi-up executes deployment inside container" {
  run make -n pulumi-up
  [ "$status" -eq 0 ]
  assert_compose_env_file
  [[ "$output" == *"stack select"* ]]
  [[ "$output" == *"./scripts/prepare_policy_pack.py"* ]]
  [[ "$output" == *"pulumi --cwd pulumi up --stack"* ]]
  [[ "$output" == *"--policy-pack /workspace/policy"* ]]
}

@test "make pulumi-refresh executes refresh inside container" {
  run env GITHUB_TOKEN=ghs_test_token make -n pulumi-refresh
  [ "$status" -eq 0 ]
  assert_compose_env_file
  [[ "$output" == *"-e GITHUB_TOKEN"* ]]
  [[ "$output" != *"ghs_test_token"* ]]
  [[ "$output" == *"stack select"* ]]
  [[ "$output" != *"--create --non-interactive"* ]]
  [[ "$output" == *"pulumi --cwd pulumi refresh --stack"* ]]
}

@test "make pulumi-destroy executes destroy inside container" {
  run env GITHUB_TOKEN=ghs_test_token make -n pulumi-destroy
  [ "$status" -eq 0 ]
  assert_compose_env_file
  [[ "$output" == *"-e GITHUB_TOKEN"* ]]
  [[ "$output" != *"ghs_test_token"* ]]
  [[ "$output" == *"stack select"* ]]
  [[ "$output" != *"--create --non-interactive"* ]]
  [[ "$output" == *"pulumi --cwd pulumi destroy --stack"* ]]
}

@test "make sh opens a throwaway shell in the Pulumi container" {
  run make -n sh
  [ "$status" -eq 0 ]
  assert_compose_env_file
  [[ "$output" == *"run --rm pulumi sh"* ]]
}

@test "make down stops docker compose without depending on the env file" {
  run make -n down
  [ "$status" -eq 0 ]
  [[ "$output" == *"docker compose down"* ]]
  [[ "$output" != *"--env-file"* ]]
}

@test "make test-unit executes the unit suite with coverage" {
  run make -n test-unit
  [ "$status" -eq 0 ]
  assert_compose_env_file
  [[ "$output" == *"rm -f .coverage.unit .coverage.unit.*"* ]]
  [[ "$output" == *"pytest -q tests/unit"* ]]
  [[ "$output" == *"PYTEST_ADDOPTS="* ]]
  [[ "$output" == *"coverage report --show-missing"* ]]
  [[ "$output" == *"--fail-under=100"* ]]
}

@test "make test-integration executes the integration suite and coverage merge" {
  run make -n test-integration
  [ "$status" -eq 0 ]
  assert_compose_env_file
  [[ "$output" == *"rm -f .coverage.integration .coverage.integration.*"* ]]
  [[ "$output" == *"pytest -q tests/integration"* ]]
  [[ "$output" == *"coverage combine"* ]]
  [[ "$output" == *"coverage report --show-missing"* ]]
  [[ "$output" == *"--fail-under=100"* ]]
}

@test "make test-pulumi executes the structural suite" {
  run make -n test-pulumi
  [ "$status" -eq 0 ]
  assert_compose_env_file
  [[ "$output" == *"pytest -q tests/pulumi"* ]]
}

@test "make test-policy executes the policy suite with full coverage" {
  run make -n test-policy
  [ "$status" -eq 0 ]
  assert_compose_env_file
  [[ "$output" == *"rm -f .coverage.policy .coverage.policy.*"* ]]
  [[ "$output" == *"pytest -q tests/policies"* ]]
  [[ "$output" == *"--cov=./policy"* ]]
  [[ "$output" == *".coverage.policy"* ]]
  [[ "$output" == *"coverage report --show-missing --include='policy/*' --fail-under=100"* ]]
}

@test "make test-crossguard delegates to the policy suite" {
  run make -n test-crossguard
  [ "$status" -eq 0 ]
  [[ "$output" == *"make test-policy"* ]]
}

@test "make test-ruff executes Ruff lint and formatting checks" {
  run make -n test-ruff
  [ "$status" -eq 0 ]
  assert_compose_env_file
  [[ "$output" == *"uv run ruff check pulumi policy scripts tests"* ]]
  [[ "$output" == *"uv run ruff format --check pulumi policy scripts tests"* ]]
}

@test "make test-maintainability executes Radon and Xenon gates" {
  run make -n test-maintainability
  [ "$status" -eq 0 ]
  assert_compose_env_file
  [[ "$output" == *"uv run radon cc -s -a pulumi policy scripts"* ]]
  [[ "$output" == *"uv run radon mi -s -n B pulumi policy scripts"* ]]
  [[ "$output" == *"uv run xenon --max-absolute B --max-modules B --max-average A pulumi policy scripts"* ]]
}

@test "make test-ty executes the Ty type checker" {
  run make -n test-ty
  [ "$status" -eq 0 ]
  assert_compose_env_file
  [[ "$output" == *"uv run ty check"* ]]
  [[ "$output" == *"--ignore missing-argument"* ]]
  [[ "$output" == *"--ignore invalid-argument-type"* ]]
  [[ "$output" == *"--ignore conflicting-declarations"* ]]
  [[ "$output" == *"pulumi"* ]]
  [[ "$output" == *"policy"* ]]
  [[ "$output" == *"scripts"* ]]
}

@test "make test-architecture executes Import Linter with repo-local paths" {
  run make -n test-architecture
  [ "$status" -eq 0 ]
  assert_compose_env_file
  [[ "$output" == *"PYTHONPATH=/workspace/pulumi:/workspace"* ]]
  [[ "$output" == *"uv run lint-imports --config pyproject.toml"* ]]
}

@test "make test-lockfile executes uv lock check" {
  run make -n test-lockfile
  [ "$status" -eq 0 ]
  assert_compose_env_file
  [[ "$output" == *"uv lock --check"* ]]
}

@test "make test-dependency-hygiene executes lockfile and deptry checks" {
  run make -n test-dependency-hygiene
  [ "$status" -eq 0 ]
  [[ "$output" == *"make test-lockfile"* ]]
  [[ "$output" == *"uv run deptry ."* ]]
}

@test "make test-coverage combines suite coverage and enforces branch threshold" {
  run make -n test-coverage
  [ "$status" -eq 0 ]
  assert_compose_env_file
  [[ "$output" == *".coverage.unit"* ]]
  [[ "$output" == *".coverage.integration"* ]]
  [[ "$output" == *".coverage.policy"* ]]
  [[ "$output" == *"uv run coverage combine --keep .coverage.unit .coverage.integration .coverage.policy"* ]]
  [[ "$output" == *"coverage report --show-missing --fail-under=100"* ]]
}

@test "make test-bandit executes Bandit against runtime sources" {
  run make -n test-bandit
  [ "$status" -eq 0 ]
  assert_compose_env_file
  [[ "$output" == *"uv run bandit -q -c pyproject.toml -r pulumi policy scripts"* ]]
}

@test "make test-actionlint executes actionlint inside the container" {
  run make -n test-actionlint
  [ "$status" -eq 0 ]
  assert_compose_env_file
  [[ "$output" == *"actionlint -color"* ]]
}

@test "make test-yaml executes yamllint against operational YAML" {
  run make -n test-yaml
  [ "$status" -eq 0 ]
  assert_compose_env_file
  [[ "$output" == *"uv run yamllint -c .yamllint.yml"* ]]
  [[ "$output" == *"docker-compose.yml"* ]]
  [[ "$output" == *"policy"* ]]
  [[ "$output" == *"pulumi"* ]]
}

@test "make test-dockerfile executes hadolint" {
  run make -n test-dockerfile
  [ "$status" -eq 0 ]
  assert_compose_env_file
  [[ "$output" == *"hadolint --config .hadolint.yaml Dockerfile"* ]]
}

@test "make test-secrets executes gitleaks against tracked Git content" {
  run make -n test-secrets
  [ "$status" -eq 0 ]
  assert_compose_env_file
  [[ "$output" == *"gitleaks git . --config .gitleaks.toml --no-banner --redact"* ]]
}

@test "make test-deps-security executes pip-audit in strict mode" {
  run make -n test-deps-security
  [ "$status" -eq 0 ]
  assert_compose_env_file
  [[ "$output" == *"XDG_CACHE_HOME=/tmp/xdg-cache"* ]]
  [[ "$output" == *"uv run pip-audit --strict"* ]]
}

@test "make test-preview generates Pulumi preview artifacts" {
  run env GITHUB_TOKEN=ghs_test_token make -n test-preview
  [ "$status" -eq 0 ]
  assert_compose_env_file
  [[ "$output" == *"-e GITHUB_TOKEN"* ]]
  [[ "$output" != *"ghs_test_token"* ]]
  [[ "$output" == *"./scripts/run_pulumi_preview.py"* ]]
}

@test "make test-destructive-diff enforces destructive resource guardrails" {
  run env GITHUB_TOKEN=ghs_test_token make -n test-destructive-diff
  [ "$status" -eq 0 ]
  assert_compose_env_file
  [[ "$output" == *"-e GITHUB_TOKEN"* ]]
  [[ "$output" != *"ghs_test_token"* ]]
  [[ "$output" == *"pulumi_ci_guardrails.py destructive-gate"* ]]
}

@test "make test-iam-validation validates previewed IAM policies" {
  run env GITHUB_TOKEN=ghs_test_token make -n test-iam-validation
  [ "$status" -eq 0 ]
  assert_compose_env_file
  [[ "$output" == *"-e GITHUB_TOKEN"* ]]
  [[ "$output" != *"ghs_test_token"* ]]
  [[ "$output" == *"pulumi_ci_guardrails.py validate-iam"* ]]
}

@test "make test-security delegates to the security scan battery" {
  run make -n test-security
  [ "$status" -eq 0 ]
  [[ "$output" == *"make test-secrets"* ]]
  [[ "$output" == *"make test-deps-security"* ]]
  [[ "$output" == *"make test-bandit"* ]]
}

@test "make test-guardrails delegates to preview and destructive diff only" {
  run make -n test-guardrails
  [ "$status" -eq 0 ]
  [[ "$output" == *"make test-preview"* ]]
  [[ "$output" == *"make test-destructive-diff"* ]]
  [[ "$output" != *"make test-iam-validation"* ]]
}

@test "make test-battery runs the aggregate developer battery" {
  run make -n test-battery
  [ "$status" -eq 0 ]
  [[ "$output" == *"make test-pulumi"* ]]
  [[ "$output" == *"make test-policy"* ]]
  [[ "$output" == *"make test-quality"* ]]
  [[ "$output" == *"make test-repo-hygiene"* ]]
  [[ "$output" == *"make test-unit"* ]]
  [[ "$output" == *"make test-integration"* ]]
  [[ "$output" == *"make test-coverage"* ]]
  [[ "$output" == *"make test-cli"* ]]
}

@test "make test-drift executes the non-destructive drift helper" {
  run env GITHUB_TOKEN=ghs_test_token make -n test-drift
  [ "$status" -eq 0 ]
  assert_compose_env_file
  [[ "$output" == *"-e GITHUB_TOKEN"* ]]
  [[ "$output" != *"ghs_test_token"* ]]
  [[ "$output" == *"./scripts/run_pulumi_drift_check.py"* ]]
}

@test "make test-quality delegates to the Rust-based quality suite" {
  run make -n test-quality
  [ "$status" -eq 0 ]
  [[ "$output" == *"make test-ruff"* ]]
  [[ "$output" == *"make test-ty"* ]]
  [[ "$output" == *"make test-maintainability"* ]]
  [[ "$output" == *"make test-architecture"* ]]
  [[ "$output" == *"make test-dependency-hygiene"* ]]
}

@test "make test-repo-hygiene delegates to workflow, yaml, and Dockerfile checks" {
  run make -n test-repo-hygiene
  [ "$status" -eq 0 ]
  [[ "$output" == *"make test-actionlint"* ]]
  [[ "$output" == *"make test-yaml"* ]]
  [[ "$output" == *"make test-dockerfile"* ]]
}

@test "make test-mutation executes the mutation helper script" {
  run env \
    MUTATION_PATHS="pulumi/app" \
    MUTATION_COVERAGE_TARGETS="tests/unit/test_guardrails.py" \
    MUTATION_RUNNER="uv run pytest -q tests/unit/test_guardrails.py" \
    make -n test-mutation
  [ "$status" -eq 0 ]
  assert_compose_env_file
  [[ "$output" == *"-e MUTATION_PATHS=\"pulumi/app\""* ]]
  [[ "$output" == *"-e MUTATION_COVERAGE_TARGETS=\"tests/unit/test_guardrails.py\""* ]]
  [[ "$output" == *"-e MUTATION_RUNNER=\"uv run pytest -q tests/unit/test_guardrails.py\""* ]]
  [[ "$output" == *"./scripts/run_mutation_tests.py"* ]]
}

@test "make test-cli runs the Bats suite inside the container" {
  run make -n test-cli
  [ "$status" -eq 0 ]
  assert_compose_env_file
  [[ "$output" == *"COMPOSE_TARGET=test"* ]]
  [[ "$output" == *"bats tests/unit"* ]]
}

@test "make test runs the aggregate local battery" {
  run make -n test
  [ "$status" -eq 0 ]
  [[ "$output" == *"make doctor"* ]]
  [[ "$output" == *"make test-battery"* ]]
}

@test "make ci runs the full local equivalent of the pull-request CI battery" {
  run make -n ci
  [ "$status" -eq 0 ]
  [[ "$output" == *"make ci-pr"* ]]
  [[ "$output" == *"make test-mutation"* ]]
}

@test "make ci-pr runs the non-mutation PR battery" {
  run make -n ci-pr
  [ "$status" -eq 0 ]
  [[ "$output" == *"make doctor"* ]]
  [[ "$output" == *"make build"* ]]
  [[ "$output" == *"make test-battery"* ]]
  [[ "$output" != *"make test-mutation"* ]]
}

@test "make clean removes compose state and Python build artifacts" {
  run make -n clean
  [ "$status" -eq 0 ]
  [[ "$output" == *"docker compose down -v"* ]]
  [[ "$output" == *"find . -type d -name __pycache__"* ]]
  [[ "$output" == *"find . -type f -name \"*.pyc\""* ]]
  [[ "$output" == *"rm -rf .venv policy/.venv dist build *.egg-info"* ]]
}

@test "make report-quality delegates to every scheduled quality report" {
  run make -n report-quality
  [ "$status" -eq 0 ]
  [[ "$output" == *"make report-maintainability-trends"* ]]
  [[ "$output" == *"make report-dead-code"* ]]
  [[ "$output" == *"make report-docstrings"* ]]
  [[ "$output" == *"make report-sbom"* ]]
}

@test "make nightly-quality delegates to the quality report battery" {
  run make -n nightly-quality
  [ "$status" -eq 0 ]
  [[ "$output" == *"make report-quality"* ]]
}

@test "make report-maintainability-trends generates the Wily report" {
  run make -n report-maintainability-trends
  [ "$status" -eq 0 ]
  [[ "$output" == *"./scripts/report_maintainability_trends.py"* ]]
  [[ "$output" == *"QUALITY_ARTIFACT_DIR="* ]]
}

@test "make report-dead-code executes Vulture with repo config" {
  run make -n report-dead-code
  [ "$status" -eq 0 ]
  [[ "$output" == *"uv run vulture --config pyproject.toml"* ]]
  [[ "$output" == *'status=$?'* ]]
  [[ "$output" == *'"$status" -ne 3'* ]]
  [[ "$output" == *"vulture.txt"* ]]
}

@test "make report-docstrings executes docstr-coverage with repo config" {
  run make -n report-docstrings
  [ "$status" -eq 0 ]
  [[ "$output" == *"uv run docstr-coverage "* ]]
  [[ "$output" == *"docstr-coverage.txt"* ]]
}

@test "make report-sbom generates a CycloneDX SBOM" {
  run make -n report-sbom
  [ "$status" -eq 0 ]
  [[ "$output" == *"uv run cyclonedx-py environment"* ]]
  [[ "$output" == *"python-environment.cdx.json"* ]]
}
