# Parameters
PROJECT            = bootstrap-infrastructure
ENV_FILE           = .env
COMPOSE_SERVICE   ?= pulumi
PULUMI_DIR        ?= pulumi
STACK             ?=
PULUMI_SECRETS_PROVIDER ?=
PULUMI_STACK      ?=
AWS_REGION        ?= eu-central-1
RUNNER_IMAGE_SOURCE ?= $(PROJECT)-pulumi:latest
RUNNER_IMAGE_TAG  ?= local
RUNNER_ECR_REPOSITORY ?=
RUNNER_IMAGE_ADDITIONAL_TAGS ?=
BATS_DOCKER_IMAGE ?= bats/bats:1.11.1
EFFECTIVE_ENV_FILE := $(firstword $(wildcard $(ENV_FILE)))
ACTIONLINT_IMAGE  ?= rhysd/actionlint:1.7.7
CHECKOV_IMAGE     ?= bridgecrew/checkov:3.2.487
GITLEAKS_IMAGE    ?= zricethezav/gitleaks:v8.30.0
HADOLINT_IMAGE    ?= hadolint/hadolint:v2.14.0
SHELLCHECK_IMAGE  ?= koalaman/shellcheck:stable
SHFMT_IMAGE       ?= mvdan/shfmt:v3.11.0
PYTHON_FORMAT_PATHS = pulumi/__main__.py pulumi/infra policy_pack scripts/*.py tests
PYTHON_LINT_PATHS   = pulumi/__main__.py pulumi/infra policy_pack scripts/*.py tests
PYTHON_TYPE_PATHS   = pulumi/__main__.py pulumi/infra policy_pack scripts/*.py
PYTHON_TY_PATHS     = pulumi policy_pack scripts tests
YAML_LINT_PATHS     = .github/workflows pulumi/Pulumi.yaml pulumi/Pulumi.test.yaml pulumi/Pulumi.test.yaml.example pulumi/Pulumi.prod.yaml.example
SHELLCHECK_PATHS    = /work/scripts/run_mutation_tests.sh /work/scripts/run_pulumi_command.sh /work/scripts/publish_runner_image.sh
SHFMT_PATHS        := scripts/*.sh
SPELLCHECK_PATHS    = .
TOML_LINT_PATHS     = pyproject.toml
RADON_PATHS         = pulumi/infra policy_pack scripts
XENON_IGNORE_PATHS  = .git,.venv,pulumi/venv,__pycache__,.coverage-artifacts,.quality-reports
INTERROGATE_PATHS   = pulumi/infra/config.py pulumi/infra/utils pulumi/infra/iam pulumi/infra/pulumi_secrets.py scripts/analyze_pulumi_preview.py scripts/validate_iam_policies.py
VULTURE_PATHS       = pulumi/infra policy_pack scripts
WILY_PATHS          = pulumi/infra policy_pack scripts
QUALITY_REPORT_DIR ?= .quality-reports
QLTY ?= qlty

export COMPOSE_ENV_FILE := $(EFFECTIVE_ENV_FILE)
UID ?= $(shell id -u 2>/dev/null || echo 1000)
GID ?= $(shell id -g 2>/dev/null || echo 1000)
USER ?= $(shell id -un 2>/dev/null || echo dev)

export UID
export GID
export USER

# Executables
DOCKER_COMPOSE    = docker compose
COMPOSE_ENV_FLAG  = $(if $(EFFECTIVE_ENV_FILE),--env-file $(EFFECTIVE_ENV_FILE),)
COMPOSE           = $(DOCKER_COMPOSE) $(COMPOSE_ENV_FLAG)
UV_RUN            = uv run --frozen --no-sync
PYTEST_COV_OPTS   = --cov=./pulumi --cov=./policy_pack --cov-branch --cov-report=
COVERAGE_DIR ?= .coverage-artifacts

# Misc
.DEFAULT_GOAL     = help
.RECIPEPREFIX    +=
.PHONY: all help start pulumi-preview pulumi-up pulumi-refresh pulumi-destroy \
        pulumi-plan-ci pulumi-up-ci pulumi-drift-ci \
        pulumi-stack-select pulumi-stack-migrate-secrets sh down clean \
        runner-image-build runner-image-smoke runner-image-push \
        check-format check-lint check-radon check-xenon check-imports check-deptry \
        check-spelling check-toml check-types check-ty check-package check-qlty \
        check-bandit check-deps check-sbom check-secrets check-iam check-yaml check-actionlint \
        check-docker check-shell check-iac check-static check-security check-coverage \
        report-wily report-vulture report-docstrings report-sbom ci \
        test-unit test-integration test-pulumi test-policy test-crossguard test-mutation test-e2e \
        test-bats test-cost test

all: help ## Display help (default goal).

help:
	@printf "\033[33mUsage:\033[0m\n  make [target] [arg=\"val\"...]\n\n\033[33mTargets:\033[0m\n"
	@grep -E '^[-a-zA-Z0-9_\.\/]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[32m%-15s\033[0m %s\n", $$1, $$2}'

start: ## Initialize and start the Pulumi development environment.
	$(COMPOSE) up -d

pulumi-preview: ## Preview infrastructure changes from inside the Pulumi container.
	$(COMPOSE) run --rm $(COMPOSE_SERVICE) pulumi -C $(PULUMI_DIR) preview

pulumi-up: ## Apply the current Pulumi infrastructure plan.
	$(COMPOSE) run --rm $(COMPOSE_SERVICE) pulumi -C $(PULUMI_DIR) up

pulumi-refresh: ## Sync the Pulumi stack with live cloud resources.
	$(COMPOSE) run --rm $(COMPOSE_SERVICE) pulumi -C $(PULUMI_DIR) refresh

pulumi-destroy: ## Tear down the Pulumi stack (irreversible; use with caution).
	$(COMPOSE) run --rm $(COMPOSE_SERVICE) pulumi -C $(PULUMI_DIR) destroy

pulumi-plan-ci: ## Execute the GitHub automation Pulumi plan flow via the shared command runner.
	$(COMPOSE) run --rm $(COMPOSE_SERVICE) bash -lc "./scripts/run_pulumi_command.sh plan"

pulumi-up-ci: ## Execute the GitHub automation Pulumi apply flow via the shared command runner.
	$(COMPOSE) run --rm $(COMPOSE_SERVICE) bash -lc "./scripts/run_pulumi_command.sh up"

pulumi-drift-ci: ## Execute the GitHub automation drift check via the shared command runner.
	$(COMPOSE) run --rm $(COMPOSE_SERVICE) bash -lc "./scripts/run_pulumi_command.sh drift"

define require_var
@if [ -z "$($(1))" ]; then \
  echo "$(1) is required." >&2; \
  exit 1; \
fi
endef

pulumi-stack-select: ## Select or create STACK with the AWS KMS secrets provider in PULUMI_SECRETS_PROVIDER.
	$(call require_var,STACK)
	$(call require_var,PULUMI_SECRETS_PROVIDER)
	$(COMPOSE) run --rm $(COMPOSE_SERVICE) bash -lc 'pulumi -C "$(PULUMI_DIR)" stack select "$(STACK)" --non-interactive || pulumi -C "$(PULUMI_DIR)" stack init "$(STACK)" --non-interactive --secrets-provider "$(PULUMI_SECRETS_PROVIDER)"'

pulumi-stack-migrate-secrets: ## Migrate STACK to the AWS KMS secrets provider in PULUMI_SECRETS_PROVIDER.
	$(call require_var,STACK)
	$(call require_var,PULUMI_SECRETS_PROVIDER)
	$(COMPOSE) run --rm $(COMPOSE_SERVICE) pulumi -C $(PULUMI_DIR) stack change-secrets-provider "$(PULUMI_SECRETS_PROVIDER)" --stack "$(STACK)" --non-interactive

sh: ## Open a shell inside the Pulumi container.
	$(COMPOSE) run --rm $(COMPOSE_SERVICE) sh

down: ## Stop the Docker Compose environment.
	$(COMPOSE) down

runner-image-build: ## Build the GitHub automation runner image locally.
	$(COMPOSE) build $(COMPOSE_SERVICE)

runner-image-smoke: ## Verify the runner image includes the required CLI toolchain.
	$(COMPOSE) run --rm $(COMPOSE_SERVICE) bash -lc "pulumi version && aws --version && uv --version && typos --version && taplo --version"

runner-image-push: ## Push the locally built runner image into ECR.
	$(call require_var,RUNNER_ECR_REPOSITORY)
	$(call require_var,RUNNER_IMAGE_TAG)
	AWS_REGION="$(AWS_REGION)" RUNNER_IMAGE_SOURCE="$(RUNNER_IMAGE_SOURCE)" RUNNER_ECR_REPOSITORY="$(RUNNER_ECR_REPOSITORY)" RUNNER_IMAGE_TAG="$(RUNNER_IMAGE_TAG)" RUNNER_IMAGE_ADDITIONAL_TAGS="$(RUNNER_IMAGE_ADDITIONAL_TAGS)" ./scripts/publish_runner_image.sh

define run_or_skip
@if [ -d "$(1)" ]; then \
  $(COMPOSE) run --rm $(COMPOSE_SERVICE) $(2); \
else \
  echo "Skipping $(3): directory $(1) not found"; \
fi
endef

define coverage_pytest
bash -lc "mkdir -p \"$(COVERAGE_DIR)\" && COVERAGE_FILE=$(COVERAGE_DIR)/$(1) $(UV_RUN) pytest -q $(2) $(PYTEST_COV_OPTS)"
endef

test-unit: ## Execute fast unit tests for the Pulumi application layer (if present).
	$(call run_or_skip,tests/unit,$(call coverage_pytest,.coverage.unit,tests/unit),"unit tests")

test-integration: ## Execute Pulumi automation-based integration tests (if present).
	$(call run_or_skip,tests/integration,$(call coverage_pytest,.coverage.integration,tests/integration tests/unit),"integration tests")

test-pulumi: ## Perform structural checks on Pulumi project configuration (if present).
	$(call run_or_skip,tests/pulumi,$(call coverage_pytest,.coverage.pulumi,tests/pulumi),"Pulumi structural tests")

test-policy: ## Execute Pulumi Policy Pack guardrail tests (if present).
	$(call run_or_skip,tests/policy,$(call coverage_pytest,.coverage.policy,tests/policy),"Pulumi policy tests")

test-crossguard: ## Execute Pulumi CrossGuard policy tests (alias for test-policy).
	$(MAKE) test-policy

test-mutation: ## Run mutation testing suite against Pulumi components (if present).
	$(call run_or_skip,scripts,bash -lc "COVERAGE_FILE=$(COVERAGE_DIR)/.coverage.mutation ./scripts/run_mutation_tests.sh","mutation tests")

test-e2e: ## Execute end-to-end Pulumi CLI smoke tests (requires PULUMI_E2E_SECRETS_PROVIDER).
	$(call run_or_skip,tests/e2e,$(call coverage_pytest,.coverage.e2e,tests/e2e),"e2e tests")

test-bats: ## Execute Bats coverage for Make targets.
	@if command -v bats >/dev/null 2>&1; then \
	  bats tests/bats; \
	else \
	  docker run --rm -v "$(PWD):/code" -w /code --entrypoint /bin/sh $(BATS_DOCKER_IMAGE) -lc "apk add --no-cache make >/dev/null && bats tests/bats"; \
	fi

check-format: ## Verify Python formatting with Ruff.
	$(COMPOSE) run --rm $(COMPOSE_SERVICE) bash -lc "mkdir -p \"\$$HOME/.ruff_cache\" && RUFF_CACHE_DIR=\"\$$HOME/.ruff_cache\" $(UV_RUN) ruff format --check $(PYTHON_FORMAT_PATHS)"

check-lint: ## Run Python lint checks with Ruff.
	$(COMPOSE) run --rm $(COMPOSE_SERVICE) bash -lc "mkdir -p \"\$$HOME/.ruff_cache\" && RUFF_CACHE_DIR=\"\$$HOME/.ruff_cache\" $(UV_RUN) ruff check $(PYTHON_LINT_PATHS)"

check-radon: ## Enforce Radon maintainability index thresholds for repo Python modules.
	$(COMPOSE) run --rm $(COMPOSE_SERVICE) $(UV_RUN) python scripts/check_radon_maintainability.py

check-xenon: ## Enforce Xenon complexity ceilings for Pulumi, policy, and helper modules.
	$(COMPOSE) run --rm $(COMPOSE_SERVICE) $(UV_RUN) xenon -a A -m A -b C -i "$(XENON_IGNORE_PATHS)" $(RADON_PATHS)

check-imports: ## Enforce import-layer boundaries between infra, policy, and scripts packages.
	$(COMPOSE) run --rm $(COMPOSE_SERVICE) $(UV_RUN) lint-imports --config .importlinter

check-deptry: ## Validate runtime and dev dependency hygiene against the uv project metadata.
	$(COMPOSE) run --rm $(COMPOSE_SERVICE) $(UV_RUN) deptry .

check-spelling: ## Run typo detection across repository sources.
	$(COMPOSE) run --rm $(COMPOSE_SERVICE) typos $(SPELLCHECK_PATHS)

check-toml: ## Lint and format-check repository TOML manifests with Taplo.
	$(COMPOSE) run --rm $(COMPOSE_SERVICE) bash -lc "taplo lint $(TOML_LINT_PATHS) && taplo format --check $(TOML_LINT_PATHS)"

check-types: ## Run static type checks for Pulumi Python code.
	$(COMPOSE) run --rm $(COMPOSE_SERVICE) $(UV_RUN) mypy $(PYTHON_TYPE_PATHS)

check-ty: ## Run Astral Ty static analysis across the policy pack and test code.
	$(COMPOSE) run --rm $(COMPOSE_SERVICE) bash -lc "$(UV_RUN) ty check --project . --extra-search-path /workspace/pulumi policy_pack scripts tests"

check-package: ## Validate the uv lockfile, synced environment, and Python bytecode compilation.
	$(COMPOSE) run --rm $(COMPOSE_SERVICE) bash -lc "uv lock --check && uv sync --check --frozen --all-groups --no-install-project --no-editable && pycache_dir=\$$(mktemp -d \"\$$HOME/pycache.XXXXXX\") && trap 'rm -rf \"\$$pycache_dir\"' EXIT && PYTHONPYCACHEPREFIX=\$$pycache_dir python -m compileall -q $(PYTHON_FORMAT_PATHS)"

check-qlty: ## Run the repo-local Qlty code health configuration.
	@command -v $(QLTY) >/dev/null 2>&1 || { echo "qlty CLI is required. Install it from https://qlty.sh" >&2; exit 1; }
	$(QLTY) check --all --summary --no-progress --level note --fail-level note

check-bandit: ## Run Bandit security checks on Pulumi Python sources.
	$(COMPOSE) run --rm $(COMPOSE_SERVICE) $(UV_RUN) bandit -q -r pulumi policy_pack -c pyproject.toml

check-deps: ## Audit locked Python dependencies for known vulnerabilities.
	$(COMPOSE) run --rm $(COMPOSE_SERVICE) bash -lc "mkdir -p \"\$$TMPDIR\" && requirements_file=\$$(mktemp \"\$$TMPDIR/requirements.XXXXXX.txt\") && trap 'rm -f \"\$$requirements_file\"' EXIT && uv export --frozen --all-groups --format requirements.txt --no-emit-project --output-file \"\$$requirements_file\" >/dev/null && $(UV_RUN) python -m pip_audit -r \"\$$requirements_file\" --desc"

check-sbom: ## Export a CycloneDX SBOM from the locked uv dependency graph.
	$(COMPOSE) run --rm $(COMPOSE_SERVICE) bash -lc "mkdir -p \"\$$TMPDIR\" && sbom_file=\$$(mktemp \"\$$TMPDIR/sbom.XXXXXX.json\") && trap 'rm -f \"\$$sbom_file\"' EXIT && uv export --preview-features sbom-export --frozen --all-groups --format cyclonedx1.5 --no-emit-project --output-file \"\$$sbom_file\" >/dev/null && python -m json.tool \"\$$sbom_file\" >/dev/null"

check-secrets: ## Scan the repository for leaked secrets with Gitleaks.
	docker run --rm -v "$(CURDIR):/repo" -w /repo $(GITLEAKS_IMAGE) detect --no-banner --source . --config .gitleaks.toml --redact --exit-code 1

check-iam: ## Validate generated IAM and resource policies with AWS IAM Access Analyzer.
	$(COMPOSE) run --rm -e REQUIRE_AWS_ACCESS_ANALYZER="$(REQUIRE_AWS_ACCESS_ANALYZER)" $(COMPOSE_SERVICE) bash -lc "$(UV_RUN) python scripts/validate_iam_policies.py"

check-yaml: ## Lint GitHub Actions and Pulumi YAML manifests.
	$(COMPOSE) run --rm $(COMPOSE_SERVICE) $(UV_RUN) yamllint -c .yamllint $(YAML_LINT_PATHS)

check-actionlint: ## Lint GitHub Actions workflows.
	docker run --rm -v "$(CURDIR):/work" -w /work $(ACTIONLINT_IMAGE) -color

check-docker: ## Lint the Dockerfile with Hadolint.
	docker run --rm -i $(HADOLINT_IMAGE) hadolint --failure-threshold error - < Dockerfile

check-shell: ## Lint and format-check repository shell scripts with ShellCheck and shfmt.
	docker run --rm -v "$(CURDIR):/work" $(SHELLCHECK_IMAGE) $(SHELLCHECK_PATHS)
	docker run --rm -v "$(CURDIR):/work" -w /work $(SHFMT_IMAGE) -d -i 2 -ci -bn $(SHFMT_PATHS)

check-iac: ## Run Checkov against GitHub Actions and Dockerfile definitions.
	docker run --rm -v "$(CURDIR):/work" $(CHECKOV_IMAGE) -d /work --config-file /work/.checkov.yml

report-wily: ## Build scheduled Wily maintainability trend reports.
	$(COMPOSE) run --rm $(COMPOSE_SERVICE) $(UV_RUN) python scripts/run_wily_report.py --report-dir '$(QUALITY_REPORT_DIR)/wily' $(WILY_PATHS)

report-vulture: ## Produce a scheduled dead-code report with Vulture.
	$(COMPOSE) run --rm $(COMPOSE_SERVICE) bash -lc "mkdir -p '$(QUALITY_REPORT_DIR)' && $(UV_RUN) vulture $(VULTURE_PATHS) --min-confidence 80 | tee '$(QUALITY_REPORT_DIR)/vulture.txt'"

report-docstrings: ## Measure docstring coverage for reusable infra and guardrail modules.
	$(COMPOSE) run --rm $(COMPOSE_SERVICE) bash -lc "mkdir -p '$(QUALITY_REPORT_DIR)' && $(UV_RUN) docstr-coverage --skip-file-doc --skip-private --fail-under 80 $(INTERROGATE_PATHS) | tee '$(QUALITY_REPORT_DIR)/docstr-coverage.txt'"

report-sbom: ## Export a CycloneDX SBOM artifact from the locked uv dependency graph.
	$(COMPOSE) run --rm $(COMPOSE_SERVICE) bash -lc "mkdir -p '$(QUALITY_REPORT_DIR)' && uv export --preview-features sbom-export --frozen --all-groups --format cyclonedx1.5 --no-emit-project --output-file '$(QUALITY_REPORT_DIR)/sbom.cyclonedx.json' >/dev/null && python -m json.tool '$(QUALITY_REPORT_DIR)/sbom.cyclonedx.json' >/dev/null"

check-static: ## Run static formatting, lint, type, and packaging checks.
	$(MAKE) check-format
	$(MAKE) check-lint
	$(MAKE) check-radon
	$(MAKE) check-xenon
	$(MAKE) check-imports
	$(MAKE) check-deptry
	$(MAKE) check-spelling
	$(MAKE) check-toml
	$(MAKE) check-types
	$(MAKE) check-ty
	$(MAKE) check-package

check-security: ## Run security and policy checks for code, manifests, and build assets.
	$(MAKE) check-bandit
	$(MAKE) check-deps
	$(MAKE) check-sbom
	$(MAKE) check-secrets
	$(MAKE) check-iam
	$(MAKE) check-yaml
	$(MAKE) check-actionlint
	$(MAKE) check-docker
	$(MAKE) check-shell
	$(MAKE) check-iac
	$(MAKE) check-qlty

test-cost: ## Execute cost and governance guardrail tests for the Pulumi stack.
	$(call run_or_skip,tests/cost,$(call coverage_pytest,.coverage.cost,tests/cost),"cost guardrail tests")

check-coverage: ## Combine Python suite coverage and require 100% coverage for Pulumi and policy code.
	$(COMPOSE) run --rm $(COMPOSE_SERVICE) bash -lc "shopt -s nullglob && files=( $(COVERAGE_DIR)/.coverage.* ) && if [ \$${#files[@]} -eq 0 ]; then echo 'No coverage artifacts found.' >&2; exit 1; fi && $(UV_RUN) coverage combine --keep \"\$${files[@]}\" && $(UV_RUN) coverage report --show-missing --fail-under=100"

test: ## Run the complete Pulumi-focused test battery.
	$(MAKE) test-pulumi
	$(MAKE) test-cost
	$(MAKE) test-policy
	$(MAKE) test-unit
	$(MAKE) test-integration
	$(MAKE) test-mutation
	$(MAKE) test-e2e
	$(MAKE) test-bats
	$(MAKE) check-coverage

ci: ## Run the full local CI battery, including static checks and tests.
	$(MAKE) check-static
	$(MAKE) check-security
	$(MAKE) test

clean: ## Remove Docker Compose artifacts, Python caches, and build artifacts.
	$(COMPOSE) down -v 2>/dev/null || true
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	rm -rf .venv .mypy_cache .ruff_cache .coverage-artifacts .quality-reports .wily dist build *.egg-info 2>/dev/null || true
