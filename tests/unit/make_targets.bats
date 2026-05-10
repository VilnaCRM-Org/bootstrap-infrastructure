#!/usr/bin/env bats

# Unit-level checks for the Makefile interface. These tests inspect commands with dry runs so we
# do not require Docker or cloud credentials during CI.

assert_compose_env_file() {
  [[ "$output" == *"docker compose --env-file .env "* ]] \
    || [[ "$output" == *"docker compose --env-file .env.empty "* ]]
}

assert_pulumi_secrets_provider_passthrough() {
  [[ "$output" == *"-e PULUMI_SECRETS_PROVIDER"* ]]
  [[ "$output" == *"-e PULUMI_BACKEND_URL"* ]]
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
    ci-pr-unprivileged
    clean
    doctor
    down
    help
    nightly-quality
    publish-pulumi-preview-summary
    pulumi-preview
    pulumi-plan
    pulumi-up
    pulumi-up-plan
    pulumi-refresh
    pulumi-destroy
    report-dead-code
    report-docstrings
    report-maintainability-trends
    report-quality
    report-sbom
    report-alert-route-observation
    report-security-account-attestation
    report-well-architected-evidence
    sh
    start
    test
    test-cli
    test-actionlint
    test-architecture
    test-bandit
    test-coverage
    test-crossguard
    test-cost-proxy
    test-dependency-hygiene
    test-deps-security
    test-dockerfile
    test-destructive-diff
    test-drift
    test-guardrails
    test-guardrails-unprivileged
    test-iam-validation
    test-iam-validation-unprivileged
    test-integration
    test-integration-unprivileged
    test-lockfile
    test-maintainability
    test-mutation
    test-policy
    test-pulumi
    test-quality
    test-preview
    test-preview-unprivileged
    test-repo-hygiene
    test-repository-catalogs
    test-repository-fanout
    test-ruff
    test-security
    test-secrets
    test-ty
    test-unit
    test-yaml
    verify-well-architected-questions
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

@test "make defaults Pulumi stack to test before prod" {
  local pulumi_dir="$BATS_TEST_TMPDIR/pulumi"
  local extra_makefile="$BATS_TEST_TMPDIR/print-default.mk"
  mkdir -p "$pulumi_dir"
  touch "$pulumi_dir/Pulumi.prod.yaml"
  touch "$pulumi_dir/Pulumi.test.yaml"
  touch "$pulumi_dir/Pulumi.example.yaml"
  cat >"$extra_makefile" <<'EOF'
print-default-stack:
	@printf '%s\n' "$(DEFAULT_PULUMI_STACK)"
EOF

  run make --no-print-directory PULUMI_DIR="$pulumi_dir" \
    -f Makefile -f "$extra_makefile" print-default-stack
  [ "$status" -eq 0 ]
  [ "$output" = "test" ]
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
  [[ "$output" == *"./scripts/run_pulumi_command.py preview"* ]]
  assert_pulumi_secrets_provider_passthrough
}

@test "make pulumi-preview passes explicit PULUMI_DIR override into docker compose" {
  local pulumi_dir="$BATS_TEST_TMPDIR/custom-pulumi"

  run make -n PULUMI_DIR="$pulumi_dir" pulumi-preview
  [ "$status" -eq 0 ]
  [[ "$output" == *"-e PULUMI_DIR=\"$pulumi_dir\""* ]]
  [[ "$output" == *"./scripts/run_pulumi_command.py preview"* ]]
}

@test "make pulumi-plan saves a deployment plan inside container" {
  run make -n pulumi-plan
  [ "$status" -eq 0 ]
  assert_compose_env_file
  assert_pulumi_secrets_provider_passthrough
  [[ "$output" == *"-e PULUMI_PLAN_DIR=\".artifacts/pulumi-plan\""* ]]
  [[ "$output" == *"-e PULUMI_COMMIT_SHA=\"\""* ]]
  [[ "$output" == *"./scripts/run_pulumi_command.py plan"* ]]
}

@test "make pulumi-up executes deployment inside container" {
  run make -n pulumi-up
  [ "$status" -eq 0 ]
  assert_compose_env_file
  assert_pulumi_secrets_provider_passthrough
  [[ "$output" == *"./scripts/run_pulumi_command.py up"* ]]
}

@test "make pulumi-up-plan applies a saved plan inside container" {
  run make -n pulumi-up-plan
  [ "$status" -eq 0 ]
  assert_compose_env_file
  assert_pulumi_secrets_provider_passthrough
  [[ "$output" == *"-e PULUMI_PLAN_DIR=\".artifacts/pulumi-plan\""* ]]
  [[ "$output" == *"-e PULUMI_EXPECTED_SHA=\"\""* ]]
  [[ "$output" == *"./scripts/run_pulumi_command.py up-plan"* ]]
}

@test "make pulumi-refresh executes refresh inside container" {
  run env GITHUB_TOKEN=ghs_test_token make -n pulumi-refresh
  [ "$status" -eq 0 ]
  assert_compose_env_file
  [[ "$output" == *"-e GITHUB_TOKEN"* ]]
  [[ "$output" != *"ghs_test_token"* ]]
  assert_pulumi_secrets_provider_passthrough
  [[ "$output" == *"./scripts/run_pulumi_command.py refresh"* ]]
}

@test "make pulumi-destroy executes destroy inside container" {
  run env GITHUB_TOKEN=ghs_test_token make -n pulumi-destroy
  [ "$status" -eq 0 ]
  assert_compose_env_file
  [[ "$output" == *"-e GITHUB_TOKEN"* ]]
  [[ "$output" != *"ghs_test_token"* ]]
  assert_pulumi_secrets_provider_passthrough
  [[ "$output" == *"./scripts/run_pulumi_command.py destroy"* ]]
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
  [[ "$output" == *"coverage run --parallel-mode -m pytest -q tests/integration"* ]]
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

@test "make test-repository-catalogs validates repository catalog JSON" {
  run make -n test-repository-catalogs
  [ "$status" -eq 0 ]
  assert_compose_env_file
  [[ "$output" == *"uv run python ./scripts/validate_repository_catalogs.py"* ]]
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
  [[ "$output" == *"gitleaks git . --log-opts=\"-1\" --config .gitleaks.toml --no-banner --redact"* ]]
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

@test "make test-preview-unprivileged clears stale cost proxy artifacts" {
  run make -n test-preview-unprivileged
  [ "$status" -eq 0 ]
  [[ "$output" == *"rm -f .artifacts/pulumi-preview/*.json .artifacts/pulumi-preview/summary.md .artifacts/pulumi-preview/cost-proxy.md"* ]]
  [[ "$output" == *"rm -rf .artifacts/pulumi-preview/reports"* ]]
  [[ "$output" == *"pulumi_ci_guardrails.py summarize"* ]]
}

@test "make test-destructive-diff enforces destructive resource guardrails" {
  run env GITHUB_TOKEN=ghs_test_token make -n test-destructive-diff
  [ "$status" -eq 0 ]
  assert_compose_env_file
  [[ "$output" == *"-e GITHUB_TOKEN"* ]]
  [[ "$output" != *"ghs_test_token"* ]]
  [[ "$output" == *"pulumi_ci_guardrails.py destructive-gate"* ]]
}

@test "make test-cost-proxy enforces static cost and quota guardrails" {
  run make -n test-cost-proxy
  [ "$status" -eq 0 ]
  assert_compose_env_file
  [[ "$output" == *"-e PULUMI_SECRETS_PROVIDER"* ]]
  [[ "$output" == *"-e PULUMI_BACKEND_URL"* ]]
  [[ "$output" == *"-e PULUMI_PREVIEW_STACKS"* ]]
  [[ "$output" == *"rm -f .artifacts/pulumi-preview/reports/cost-proxy.json .artifacts/pulumi-preview/reports/cost-proxy.md .artifacts/pulumi-preview/cost-proxy.md"* ]]
  [[ "$output" == *"pulumi_ci_guardrails.py cost-proxy"* ]]
  [[ "$output" == *"reports/cost-proxy.json"* ]]
  [[ "$output" == *"reports/cost-proxy.md"* ]]
}

@test "make test-iam-validation validates previewed IAM policies" {
  run env GITHUB_TOKEN=ghs_test_token make -n test-iam-validation
  [ "$status" -eq 0 ]
  assert_compose_env_file
  [[ "$output" == *"-e GITHUB_TOKEN"* ]]
  [[ "$output" != *"ghs_test_token"* ]]
  [[ "$output" == *"pulumi_ci_guardrails.py validate-iam"* ]]
}

@test "make test-repository-fanout estimates static quota fanout" {
  run make -n test-repository-fanout
  [ "$status" -eq 0 ]
  assert_compose_env_file
  [[ "$output" == *"validate_repository_catalogs.py --fanout-report"* ]]
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
  [[ "$output" == *"make test-cost-proxy"* ]]
  [[ "$output" != *"make test-iam-validation"* ]]
}

@test "make test-battery runs the aggregate developer battery" {
  run make -n test-battery
  [ "$status" -eq 0 ]
  [[ "$output" == *"make test-pulumi"* ]]
  [[ "$output" == *"make test-policy"* ]]
  [[ "$output" == *"make test-repository-fanout"* ]]
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

@test "make report-well-architected-evidence executes metadata collector" {
  run env \
    PR_NUMBER=22 \
    AWS_ACCOUNT_ID=123456789012 \
    OPERATIONS_TOPIC_ARN=arn:aws:sns:us-east-1:123456789012:bootstrap-test-operations \
    DEPENDABOT_EXCEPTION_EVIDENCE=docs/dependabot-exception-2026-06-10.json \
    SECURITY_ACCOUNT_ATTESTATION_EVIDENCE=docs/security-account-attestation-2026-06-10.json \
    make -n report-well-architected-evidence
  [ "$status" -eq 0 ]
  [[ "$output" == *"./scripts/collect_well_architected_evidence.py"* ]]
  [[ "$output" == *".artifacts/well-architected/evidence.json"* ]]
  [[ "$output" == *".artifacts/well-architected/evidence.md"* ]]
  [[ "$output" == *'PR_NUMBER:-'* ]]
  [[ "$output" == *'OPERATIONS_TOPIC_ARN:-'* ]]
  [[ "$output" == *'DEPENDABOT_EXCEPTION_EVIDENCE:-'* ]]
  [[ "$output" == *"--dependabot-exception-evidence"* ]]
  [[ "$output" == *'SECURITY_ACCOUNT_ATTESTATION_EVIDENCE:-'* ]]
  [[ "$output" == *"--security-account-attestation-evidence"* ]]
  [[ "$output" != *"bootstrap-test-operations"* ]]
  [[ "$output" != *"dependabot-exception-2026-06-10"* ]]
  [[ "$output" != *"security-account-attestation-2026-06-10"* ]]
}

@test "make verify-well-architected-questions compares against AWS docs" {
  run env \
    QUESTION_MATRIX_EVIDENCE=specs/question-matrix-evidence.json \
    AWS_WA_TOC_JSON=docs/aws-wa-toc.json \
    AWS_WA_QUESTION_VERIFY_OUTPUT=.artifacts/well-architected/question-verification.json \
    make -n verify-well-architected-questions
  [ "$status" -eq 0 ]
  [[ "$output" == *"./scripts/verify_well_architected_questions.py"* ]]
  [[ "$output" == *'QUESTION_MATRIX_EVIDENCE:-'* ]]
  [[ "$output" == *'AWS_WA_TOC_JSON:-'* ]]
  [[ "$output" == *'AWS_WA_QUESTION_VERIFY_OUTPUT:-'* ]]
  [[ "$output" == *"--toc-json"* ]]
  [[ "$output" == *"--output"* ]]
  [[ "$output" != *"docs/aws-wa-toc.json"* ]]
  [[ "$output" != *"question-verification.json"* ]]
}

@test "make report-alert-route-observation renders monthly alert route evidence" {
  run env \
    ALERT_ROUTE_OBSERVATION_OUTPUT=docs/alert-route-observation-2026-06-09.md \
    ALERT_ROUTE_REVIEWER=sre-reviewer \
    ALERT_ROUTE_OWNER=sre \
    ALERT_ROUTE_DOWNSTREAM=incident-route \
    ALERT_ROUTE_SEVERITY=sev2 \
    ALERT_ROUTE_FALLBACK=queue-owner-review \
    ALERT_ROUTE_DECISION=accepted \
    make -n report-alert-route-observation
  [ "$status" -eq 0 ]
  [[ "$output" == *"./scripts/record_alert_route_observation.py"* ]]
  [[ "$output" == *'ALERT_ROUTE_EVIDENCE:-.artifacts/well-architected/evidence.json'* ]]
  [[ "$output" == *"--downstream-route"* ]]
  [[ "$output" == *"ALERT_ROUTE_DOWNSTREAM"* ]]
  [[ "$output" != *"incident-route"* ]]
  [[ "$output" != *"sre-reviewer"* ]]
}

@test "make report-security-account-attestation renders security evidence" {
  run env \
    SECURITY_ACCOUNT_ATTESTATION_OUTPUT=docs/security-account-attestation-2026-06-10.md \
    SECURITY_ACCOUNT_REVIEWER=security-reviewer \
    SECURITY_ACCOUNT_ATTESTATION_JSON_OUTPUT=docs/security-account-attestation-2026-06-10.json \
    SECURITY_ACCOUNT_OWNER=security-owner \
    SECURITY_ACCOUNT_HUMAN_ACCESS=accepted \
    SECURITY_ACCOUNT_ACTIVE_KEY_DECISION=exception \
    SECURITY_ACCOUNT_PERMISSIONS_BOUNDARY=exemption \
    SECURITY_ACCOUNT_APPROVAL=approved \
    make -n report-security-account-attestation
  [ "$status" -eq 0 ]
  [[ "$output" == *"./scripts/record_security_account_attestation.py"* ]]
  [[ "$output" == *'SECURITY_ACCOUNT_EVIDENCE:-.artifacts/well-architected/evidence.json'* ]]
  [[ "$output" == *"SECURITY_ACCOUNT_ATTESTATION_JSON_OUTPUT"* ]]
  [[ "$output" == *"--json-output"* ]]
  [[ "$output" == *"--human-access-posture"* ]]
  [[ "$output" == *"SECURITY_ACCOUNT_HUMAN_ACCESS"* ]]
  [[ "$output" != *"security-reviewer"* ]]
  [[ "$output" != *"approved"* ]]
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
