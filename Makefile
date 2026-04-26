# Parameters
PROJECT            = bootstrap-infrastructure
ENV_FILE           = .env
EMPTY_ENV_FILE     = .env.empty
COMPOSE_SERVICE   ?= pulumi
PULUMI_DIR        ?= pulumi
EFFECTIVE_ENV_FILE := $(firstword $(wildcard $(ENV_FILE)) $(wildcard $(EMPTY_ENV_FILE)))

COMPOSE_ENV_FILE := $(if $(EFFECTIVE_ENV_FILE),$(EFFECTIVE_ENV_FILE),$(EMPTY_ENV_FILE))
UID ?= $(shell id -u 2>/dev/null || echo 1000)
GID ?= $(shell id -g 2>/dev/null || echo 1000)
USER ?= $(shell id -un 2>/dev/null || echo dev)

export UID
export GID
export USER

# Executables
DOCKER_COMPOSE    = docker compose
COMPOSE_ENV_FLAG  = $(if $(COMPOSE_ENV_FILE),--env-file $(COMPOSE_ENV_FILE),)
COMPOSE           = $(DOCKER_COMPOSE) $(COMPOSE_ENV_FLAG)
COMPOSE_GITHUB_TOKEN = $(if $(GITHUB_TOKEN),-e GITHUB_TOKEN,)
COMPOSE_PULUMI_ENV = -e PULUMI_DIR -e PULUMI_SECRETS_PROVIDER -e PULUMI_STACK \
	-e PULUMI_PREVIEW_STACKS -e PULUMI_DRIFT_STACKS -e PULUMI_PLAN_FILE \
	-e PULUMI_PLAN_DIR -e POLICY_PACK_DIR
REPO_PYTHON      ?= python3
PULUMI_CWD_FLAG   = -C $(PULUMI_DIR)
POLICY_PACK_DIR   = /workspace/policy
POLICY_PACK_FLAG  = --policy-pack $(POLICY_PACK_DIR)
DEFAULT_PULUMI_STACK ?= $(shell \
	if [ -f "$(PULUMI_DIR)/Pulumi.dev.yaml" ]; then \
		echo dev; \
	elif [ -f "$(PULUMI_DIR)/Pulumi.test.yaml" ]; then \
		echo test; \
	else \
		find $(PULUMI_DIR) -maxdepth 1 -type f -name 'Pulumi.*.yaml' ! -name 'Pulumi.yaml' ! -name 'Pulumi.example.yaml' 2>/dev/null | sed -E 's#.*/Pulumi\.(.+)\.yaml$$#\1#' | sort | head -n 1; \
	fi)
PULUMI_STACK     ?= $(DEFAULT_PULUMI_STACK)
PULUMI_SECRETS_PROVIDER ?=
export PULUMI_STACK
PULUMI_LOGIN_CMD  = pulumi $(PULUMI_CWD_FLAG) login "$${PULUMI_BACKEND_URL:-file:///workspace/.pulumi-backend}" >/dev/null
COVERAGE_OPTS            ?= --cov=./pulumi --cov-report=term-missing
UNIT_COVERAGE_INCLUDE    ?= pulumi/*,scripts/*
UNIT_COVERAGE_OPTS       ?= $(COVERAGE_OPTS) --cov=./scripts
POLICY_COVERAGE_OPTS     ?= --cov=./policy --cov-report=
INTEGRATION_COVERAGE_INCLUDE ?= pulumi/__main__.py,pulumi/app/*
TOTAL_COVERAGE_INCLUDE   ?= pulumi/*,policy/*,scripts/*
BRANCH_COVERAGE_MIN      ?= 100
QUALITY_ARTIFACT_DIR     ?= .artifacts/quality
SBOM_ARTIFACT_DIR        ?= .artifacts/sbom
DOCSTRING_PATHS          ?= pulumi/app policy scripts/pulumi_ci_guardrails.py
WILY_TARGETS             ?= pulumi policy scripts
YAML_LINT_PATHS          ?= .github/workflows docker-compose.yml policy pulumi .hadolint.yaml .yamllint.yml
MUTATION_TEST_TARGETS    ?= tests/unit/test_environment_component.py tests/unit/test_guardrails.py
MUTATION_TESTS_DIR       ?= tests/unit
INTEGRATION_COVERAGE_ENV  = -e COVERAGE_FILE=/workspace/.coverage.integration \
	-e COVERAGE_PROCESS_START=/workspace/.coveragerc \
	-e COVERAGE_RCFILE=/workspace/.coveragerc
UNIT_COVERAGE_ENV         = -e COVERAGE_FILE=/workspace/.coverage.unit \
	-e COVERAGE_RCFILE=/workspace/.coveragerc
POLICY_COVERAGE_ENV       = -e COVERAGE_FILE=/workspace/.coverage.policy \
	-e COVERAGE_RCFILE=/workspace/.coveragerc
TOTAL_COVERAGE_ENV        = -e COVERAGE_FILE=/workspace/.coverage.total \
	-e COVERAGE_RCFILE=/workspace/.coveragerc

# Misc
.DEFAULT_GOAL     = help
.RECIPEPREFIX    +=
.PHONY: help doctor build start publish-pulumi-preview-summary pulumi-preview pulumi-plan \
        pulumi-up pulumi-up-plan pulumi-refresh \
        pulumi-destroy sh down ci ci-pr ci-pr-unprivileged nightly-quality report-quality \
        report-maintainability-trends report-dead-code report-docstrings \
        report-sbom test-quality test-ruff test-ty test-maintainability \
        test-architecture test-dependency-hygiene test-lockfile test-coverage \
        test-bandit test-actionlint test-yaml test-dockerfile \
        test-deps-security test-destructive-diff test-drift test-guardrails \
        test-guardrails-unprivileged test-iam-validation \
        test-iam-validation-unprivileged test-preview test-preview-unprivileged \
        test-security test-secrets test-repo-hygiene test-repository-catalogs \
        test-unit test-integration test-integration-unprivileged test-pulumi test-policy \
        test-crossguard test-mutation test-battery test-cli test all clean

pulumi-preview pulumi-plan pulumi-up pulumi-up-plan pulumi-refresh pulumi-destroy test-preview \
test-destructive-diff test-iam-validation test-drift: export GITHUB_TOKEN := $(GITHUB_TOKEN)

all: help ## Display help (default goal).

help: ## Display the available Make targets.
	@printf "\033[33mUsage:\033[0m\n  make [target] [arg=\"val\"...]\n\n\033[33mTargets:\033[0m\n"
	@grep -E '^[-a-zA-Z0-9_\.\/]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[32m%-15s\033[0m %s\n", $$1, $$2}'

doctor: ## Check local prerequisites and effective paths without printing secrets.
	@COMPOSE_ENV_FILE="$(COMPOSE_ENV_FILE)" COMPOSE_SERVICE="$(COMPOSE_SERVICE)" PULUMI_DIR="$(PULUMI_DIR)" $(REPO_PYTHON) ./scripts/doctor.py

build: ## Build the Pulumi development image used by local and CI checks.
	$(COMPOSE) build $(COMPOSE_SERVICE)

start: ## Prepare the Docker-backed workspace and start the Pulumi development environment.
	$(REPO_PYTHON) ./scripts/prepare_docker_context.py
	$(COMPOSE) up -d

publish-pulumi-preview-summary: ## Generate Pulumi preview artifacts and publish the summary for CI.
	$(REPO_PYTHON) ./scripts/publish_pulumi_preview_summary.py

pulumi-preview: ## Preview infrastructure changes from inside the Pulumi container.
	@$(COMPOSE) run --rm $(COMPOSE_GITHUB_TOKEN) $(COMPOSE_PULUMI_ENV) \
		$(COMPOSE_SERVICE) $(REPO_PYTHON) ./scripts/run_pulumi_command.py preview

pulumi-plan: ## Save a reviewed Pulumi update plan for the selected stack.
	@$(COMPOSE) run --rm $(COMPOSE_GITHUB_TOKEN) $(COMPOSE_PULUMI_ENV) \
		$(COMPOSE_SERVICE) $(REPO_PYTHON) ./scripts/run_pulumi_command.py plan

pulumi-up: ## Apply the current Pulumi infrastructure plan.
	@$(COMPOSE) run --rm $(COMPOSE_GITHUB_TOKEN) $(COMPOSE_PULUMI_ENV) \
		$(COMPOSE_SERVICE) $(REPO_PYTHON) ./scripts/run_pulumi_command.py up

pulumi-up-plan: ## Apply a saved Pulumi update plan for the selected stack.
	@$(COMPOSE) run --rm $(COMPOSE_GITHUB_TOKEN) $(COMPOSE_PULUMI_ENV) \
		$(COMPOSE_SERVICE) $(REPO_PYTHON) ./scripts/run_pulumi_command.py up-plan

pulumi-refresh: ## Sync the Pulumi stack with live cloud resources.
	@$(COMPOSE) run --rm $(COMPOSE_GITHUB_TOKEN) $(COMPOSE_PULUMI_ENV) \
		$(COMPOSE_SERVICE) $(REPO_PYTHON) ./scripts/run_pulumi_command.py refresh

pulumi-destroy: ## Tear down the Pulumi stack (irreversible; use with caution).
	@$(COMPOSE) run --rm $(COMPOSE_GITHUB_TOKEN) $(COMPOSE_PULUMI_ENV) \
		$(COMPOSE_SERVICE) $(REPO_PYTHON) ./scripts/run_pulumi_command.py destroy

sh: ## Open a shell inside the Pulumi container.
	$(COMPOSE) run --rm $(COMPOSE_SERVICE) sh

down: ## Stop the Docker Compose environment.
	$(DOCKER_COMPOSE) down

test-unit: ## Execute fast unit tests for the Pulumi application layer.
	rm -f .coverage.unit .coverage.unit.*
	$(COMPOSE) run --rm $(UNIT_COVERAGE_ENV) -e PYTEST_ADDOPTS="$(UNIT_COVERAGE_OPTS)" \
		$(COMPOSE_SERVICE) uv run pytest -q tests/unit
	$(COMPOSE) run --rm $(UNIT_COVERAGE_ENV) \
		$(COMPOSE_SERVICE) uv run coverage report --show-missing --include='$(UNIT_COVERAGE_INCLUDE)' --fail-under=100

test-integration: ## Execute Pulumi automation-based integration tests.
	rm -f .coverage.integration .coverage.integration.*
	$(COMPOSE) run --rm $(INTEGRATION_COVERAGE_ENV) \
		$(COMPOSE_SERVICE) uv run pytest -q tests/integration
	$(COMPOSE) run --rm -e COVERAGE_FILE=/workspace/.coverage.integration \
		-e COVERAGE_RCFILE=/workspace/.coveragerc \
		$(COMPOSE_SERVICE) uv run coverage combine
	$(COMPOSE) run --rm -e COVERAGE_FILE=/workspace/.coverage.integration \
		-e COVERAGE_RCFILE=/workspace/.coveragerc \
		$(COMPOSE_SERVICE) uv run coverage report --show-missing --fail-under=100 --include='$(INTEGRATION_COVERAGE_INCLUDE)'

test-integration-unprivileged: ## Execute credential-free integration contracts.
	rm -f .coverage.integration .coverage.integration.*
	$(COMPOSE) run --rm $(INTEGRATION_COVERAGE_ENV) \
		$(COMPOSE_SERVICE) uv run coverage run --parallel-mode -m pytest -q \
		tests/integration/test_guardrail_contracts.py
	$(COMPOSE) run --rm -e COVERAGE_FILE=/workspace/.coverage.integration \
		-e COVERAGE_RCFILE=/workspace/.coveragerc \
		$(COMPOSE_SERVICE) uv run coverage combine

test-pulumi: ## Perform structural checks on Pulumi project configuration.
	$(COMPOSE) run --rm $(COMPOSE_SERVICE) uv run pytest -q tests/pulumi

test-repository-catalogs: ## Validate repository catalog JSON files against schema and loader rules.
	$(COMPOSE) run --rm $(COMPOSE_SERVICE) uv run python ./scripts/validate_repository_catalogs.py

test-policy: ## Execute Pulumi policy-pack tests and guardrail coverage.
	rm -f .coverage.policy .coverage.policy.*
	$(COMPOSE) run --rm $(POLICY_COVERAGE_ENV) -e PYTEST_ADDOPTS="$(POLICY_COVERAGE_OPTS)" \
		$(COMPOSE_SERVICE) uv run pytest -q tests/policies
	$(COMPOSE) run --rm $(POLICY_COVERAGE_ENV) \
		$(COMPOSE_SERVICE) uv run coverage report --show-missing --include='policy/*' --fail-under=100

test-crossguard: ## Alias for the Pulumi CrossGuard policy-pack suite.
	$(MAKE) test-policy

test-ruff: ## Run Ruff lint and format checks against Python sources.
	$(COMPOSE) run --rm $(COMPOSE_SERVICE) uv run ruff check pulumi policy scripts tests
	$(COMPOSE) run --rm $(COMPOSE_SERVICE) uv run ruff format --check pulumi policy scripts tests

# Ty still needs a few targeted ignores for Pulumi's dynamic resource APIs and
# the coverage bootstrap shim: missing-argument, invalid-argument-type, and
# conflicting-declarations are false positives there, not blanket suppressions.
test-ty: ## Run the Ty static type checker against Python sources.
	$(COMPOSE) run --rm $(COMPOSE_SERVICE) uv run ty check \
		--extra-search-path policy \
		--extra-search-path scripts \
		--ignore missing-argument \
		--ignore invalid-argument-type \
		--ignore conflicting-declarations \
		pulumi policy scripts

test-maintainability: ## Enforce pragmatic complexity and maintainability thresholds.
	$(COMPOSE) run --rm $(COMPOSE_SERVICE) uv run radon cc -s -a pulumi policy scripts
	$(COMPOSE) run --rm $(COMPOSE_SERVICE) uv run radon mi -s -n B pulumi policy scripts
	$(COMPOSE) run --rm $(COMPOSE_SERVICE) uv run xenon --max-absolute B --max-modules B --max-average A pulumi policy scripts

test-architecture: ## Enforce import-direction contracts for runtime and policy code.
	$(COMPOSE) run --rm -e PYTHONPATH=/workspace/pulumi:/workspace \
		$(COMPOSE_SERVICE) uv run lint-imports --config pyproject.toml

test-lockfile: ## Require dependency metadata and uv.lock to stay in sync.
	$(COMPOSE) run --rm $(COMPOSE_SERVICE) uv lock --check

test-dependency-hygiene: ## Catch stale, missing, and misplaced Python dependencies.
	$(MAKE) test-lockfile
	$(COMPOSE) run --rm $(COMPOSE_SERVICE) uv run deptry .

test-coverage: ## Enforce combined branch coverage after runtime and policy suites run.
	$(COMPOSE) run --rm $(TOTAL_COVERAGE_ENV) $(COMPOSE_SERVICE) bash -lc '\
		if [ ! -f .coverage.unit ] || [ ! -f .coverage.integration ] || [ ! -f .coverage.policy ]; then \
			echo "error: run test-unit, test-integration, and test-policy before test-coverage" >&2; \
			exit 1; \
		fi; \
		uv run coverage combine --keep .coverage.unit .coverage.integration .coverage.policy >/dev/null \
		&& uv run coverage report --show-missing --fail-under=$(BRANCH_COVERAGE_MIN) --include="$(TOTAL_COVERAGE_INCLUDE)"'

test-bandit: ## Lint Python sources for common security hazards.
	$(COMPOSE) run --rm $(COMPOSE_SERVICE) uv run bandit -q -c pyproject.toml -r pulumi policy scripts

test-actionlint: ## Lint GitHub Actions workflows with actionlint.
	$(COMPOSE) run --rm $(COMPOSE_SERVICE) actionlint -color

test-yaml: ## Lint GitHub workflows, Pulumi stacks, and operational YAML.
	$(COMPOSE) run --rm $(COMPOSE_SERVICE) uv run yamllint -c .yamllint.yml $(YAML_LINT_PATHS)

test-dockerfile: ## Lint the development Dockerfile with hadolint.
	$(COMPOSE) run --rm $(COMPOSE_SERVICE) hadolint --config .hadolint.yaml Dockerfile

test-secrets: ## Scan tracked Git content for accidentally committed secrets.
	$(COMPOSE) run --rm $(COMPOSE_SERVICE) gitleaks git . --config .gitleaks.toml --no-banner --redact

test-deps-security: ## Audit Python dependencies for known vulnerabilities.
	$(COMPOSE) run --rm -e XDG_CACHE_HOME=/tmp/xdg-cache $(COMPOSE_SERVICE) bash -lc 'uv export --all-groups --format requirements.txt --no-hashes --no-emit-project --frozen -o /tmp/pip-audit-requirements.txt >/dev/null && uv run pip-audit --strict -r /tmp/pip-audit-requirements.txt'

test-preview: ## Generate non-destructive Pulumi previews for configured stacks.
	@$(COMPOSE) run --rm $(COMPOSE_GITHUB_TOKEN) $(COMPOSE_PULUMI_ENV) $(COMPOSE_SERVICE) \
		$(REPO_PYTHON) ./scripts/run_pulumi_preview.py

test-preview-unprivileged: ## Generate an unprivileged placeholder preview artifact.
	mkdir -p .artifacts/pulumi-preview
	rm -f .artifacts/pulumi-preview/*.json .artifacts/pulumi-preview/summary.md
	printf '%s\n' '{"changeSummary": {}, "steps": []}' > .artifacts/pulumi-preview/unprivileged.json
	$(REPO_PYTHON) ./scripts/pulumi_ci_guardrails.py summarize \
		.artifacts/pulumi-preview/unprivileged.json | tee .artifacts/pulumi-preview/summary.md

test-destructive-diff: ## Fail when Pulumi previews delete or replace critical resources.
	$(COMPOSE) run --rm $(COMPOSE_GITHUB_TOKEN) $(COMPOSE_PULUMI_ENV) $(COMPOSE_SERVICE) bash -lc '\
		event_arg=""; \
		if [ -f .artifacts/github-event.json ]; then \
			event_arg="--event-path .artifacts/github-event.json"; \
		fi; \
		if ! compgen -G ".artifacts/pulumi-preview/*.json" >/dev/null; then \
			$(REPO_PYTHON) ./scripts/run_pulumi_preview.py >/dev/null; \
		fi; \
		uv run python ./scripts/pulumi_ci_guardrails.py destructive-gate $$event_arg .artifacts/pulumi-preview/*.json'

test-iam-validation: ## Validate previewed IAM policies with AWS IAM Access Analyzer.
	$(COMPOSE) run --rm $(COMPOSE_GITHUB_TOKEN) $(COMPOSE_PULUMI_ENV) $(COMPOSE_SERVICE) bash -lc '\
		if ! compgen -G ".artifacts/pulumi-preview/*.json" >/dev/null; then \
			$(REPO_PYTHON) ./scripts/run_pulumi_preview.py >/dev/null; \
		fi; \
		uv run python ./scripts/pulumi_ci_guardrails.py validate-iam .artifacts/pulumi-preview/*.json'

test-iam-validation-unprivileged: ## Extract preview IAM inputs without AWS credentials.
	@bash -lc 'if ! compgen -G ".artifacts/pulumi-preview/*.json" >/dev/null; then \
		$(MAKE) test-preview-unprivileged >/dev/null; \
	fi'
	$(REPO_PYTHON) ./scripts/pulumi_ci_guardrails.py iam-inputs \
		.artifacts/pulumi-preview/*.json --output .artifacts/pulumi-preview/iam-inputs.json

test-security: ## Run secret, dependency, and workflow security checks.
	$(MAKE) test-secrets
	$(MAKE) test-deps-security
	$(MAKE) test-bandit

test-guardrails: ## Run real preview generation and destructive-diff guardrails.
	$(MAKE) test-preview
	$(MAKE) test-destructive-diff

test-guardrails-unprivileged: ## Run guardrails without AWS-backed Pulumi credentials.
	$(MAKE) test-preview-unprivileged
	$(MAKE) test-destructive-diff
	$(MAKE) test-iam-validation-unprivileged

test-drift: ## Perform a non-destructive drift check against configured shared stacks.
	@$(COMPOSE) run --rm $(COMPOSE_GITHUB_TOKEN) $(COMPOSE_PULUMI_ENV) $(COMPOSE_SERVICE) \
		$(REPO_PYTHON) ./scripts/run_pulumi_drift_check.py

test-quality: ## Run blocking Python quality, architecture, and dependency gates.
	$(MAKE) test-ruff
	$(MAKE) test-ty
	$(MAKE) test-maintainability
	$(MAKE) test-architecture
	$(MAKE) test-dependency-hygiene

test-repo-hygiene: ## Lint GitHub Actions, YAML, and the Dockerfile.
	$(MAKE) test-actionlint
	$(MAKE) test-yaml
	$(MAKE) test-dockerfile

test-mutation: ## Run mutation testing suite against Pulumi components.
	$(COMPOSE) run --rm \
		$(if $(strip $(MUTATION_PATHS)),-e MUTATION_PATHS="$(MUTATION_PATHS)") \
		-e MUTATION_TEST_TARGETS="$(MUTATION_TEST_TARGETS)" \
		-e MUTATION_TESTS_DIR="$(MUTATION_TESTS_DIR)" \
		$(if $(strip $(MUTATION_COVERAGE_TARGETS)),-e MUTATION_COVERAGE_TARGETS="$(MUTATION_COVERAGE_TARGETS)") \
		$(if $(strip $(MUTATION_RUNNER)),-e MUTATION_RUNNER="$(MUTATION_RUNNER)") \
		$(COMPOSE_SERVICE) $(REPO_PYTHON) ./scripts/run_mutation_tests.py

test-cli: ## Validate Makefile front-ends via Bats.
	COMPOSE_TARGET=test $(COMPOSE) run --build --rm $(COMPOSE_SERVICE) bats tests/unit

report-maintainability-trends: ## Build and publish Wily maintainability trend reports.
	mkdir -p $(QUALITY_ARTIFACT_DIR)
	$(COMPOSE) run --rm \
		-e QUALITY_ARTIFACT_DIR="$(QUALITY_ARTIFACT_DIR)" \
		-e WILY_TARGETS="$(WILY_TARGETS)" \
		$(COMPOSE_SERVICE) $(REPO_PYTHON) ./scripts/report_maintainability_trends.py

report-dead-code: ## Run the advisory dead-code report for reusable Python modules.
	mkdir -p $(QUALITY_ARTIFACT_DIR)
	$(COMPOSE) run --rm $(COMPOSE_SERVICE) bash -lc '\
		uv run vulture --config pyproject.toml > $(QUALITY_ARTIFACT_DIR)/vulture.txt; \
		status=$$?; \
		if [ "$$status" -ne 0 ] && [ "$$status" -ne 3 ]; then \
			exit "$$status"; \
		fi'

report-docstrings: ## Run the advisory docstring coverage report for reusable modules.
	mkdir -p $(QUALITY_ARTIFACT_DIR)
	$(COMPOSE) run --rm $(COMPOSE_SERVICE) bash -lc '\
		uv run docstr-coverage $(DOCSTRING_PATHS) > $(QUALITY_ARTIFACT_DIR)/docstr-coverage.txt'

report-sbom: ## Generate a CycloneDX SBOM for the synced Python environment.
	mkdir -p $(SBOM_ARTIFACT_DIR)
	$(COMPOSE) run --rm $(COMPOSE_SERVICE) bash -lc '\
		python_env="$${UV_PROJECT_ENVIRONMENT:-.venv}" \
		&& uv run cyclonedx-py environment "$${python_env}" --pyproject pyproject.toml --output-reproducible --of JSON -o $(SBOM_ARTIFACT_DIR)/python-environment.cdx.json'

report-quality: ## Run scheduled quality reports and generate fresh artifacts.
	$(MAKE) report-maintainability-trends
	$(MAKE) report-dead-code
	$(MAKE) report-docstrings
	$(MAKE) report-sbom

nightly-quality: ## Alias for the scheduled quality-report battery.
	$(MAKE) report-quality

test-battery:
	$(MAKE) test-pulumi
	$(MAKE) test-repository-catalogs
	$(MAKE) test-policy
	$(MAKE) test-quality
	$(MAKE) test-repo-hygiene
	$(MAKE) test-unit
	$(MAKE) test-integration
	$(MAKE) test-coverage
	$(MAKE) test-cli

test: ## Run the faster developer battery without the image build or mutation suite.
	$(MAKE) doctor
	$(MAKE) test-battery

ci-pr: ## Run the GitHub PR battery except the dedicated mutation workflow.
	$(MAKE) doctor
	$(MAKE) build
	$(MAKE) test-battery
	$(MAKE) test-security
	$(MAKE) test-guardrails

ci-pr-unprivileged: ## Run the PR battery without AWS-backed Pulumi credentials.
	$(MAKE) doctor
	$(MAKE) build
	$(MAKE) test-pulumi
	$(MAKE) test-repository-catalogs
	$(MAKE) test-policy
	$(MAKE) test-quality
	$(MAKE) test-repo-hygiene
	$(MAKE) test-unit
	$(MAKE) test-integration-unprivileged
	$(MAKE) test-coverage
	$(MAKE) test-cli
	$(MAKE) test-security
	$(MAKE) test-guardrails-unprivileged

ci: ## Run the full local equivalent of all GitHub checks, including mutation.
	$(MAKE) ci-pr
	$(MAKE) test-mutation

clean: ## Remove Docker Compose artifacts, Python caches, and build artifacts.
	$(DOCKER_COMPOSE) down -v 2>/dev/null || true
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	rm -rf .venv policy/.venv dist build *.egg-info 2>/dev/null || true
