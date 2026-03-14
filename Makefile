# Parameters
PROJECT            = bootstrap-infrastructure
ENV_FILE           = .env
COMPOSE_SERVICE   ?= pulumi
PULUMI_DIR        ?= pulumi
STACK             ?=
PULUMI_SECRETS_PROVIDER ?=
BATS_DOCKER_IMAGE ?= bats/bats:1.11.1
EFFECTIVE_ENV_FILE := $(firstword $(wildcard $(ENV_FILE)))
ACTIONLINT_IMAGE  ?= rhysd/actionlint:1.7.7
CHECKOV_IMAGE     ?= bridgecrew/checkov:3.2.487
HADOLINT_IMAGE    ?= hadolint/hadolint:latest
SHELLCHECK_IMAGE  ?= koalaman/shellcheck:stable
PYTHON_FORMAT_PATHS = pulumi/__main__.py pulumi/infra tests
PYTHON_LINT_PATHS   = pulumi/__main__.py pulumi/infra tests
PYTHON_TYPE_PATHS   = pulumi/__main__.py pulumi/infra
PYTHON_TY_PATHS     = pulumi tests
YAML_LINT_PATHS     = .github/workflows pulumi/Pulumi.yaml pulumi/Pulumi.test.yaml pulumi/Pulumi.test.yaml.example pulumi/Pulumi.prod.yaml.example
SHELLCHECK_PATHS    = /work/scripts/run_mutation_tests.sh
SPELLCHECK_PATHS    = .
TOML_LINT_PATHS     = pyproject.toml
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
PYTEST_COV_OPTS_UNIT = --cov=./pulumi --cov-report=term-missing --cov-fail-under=100
PYTEST_COV_OPTS_INT  = --cov=./pulumi --cov-report=term-missing --cov-fail-under=100
COVERAGE_DIR ?= $(if $(CI),/tmp,.)

# Misc
.DEFAULT_GOAL     = help
.RECIPEPREFIX    +=
.PHONY: all help start pulumi-preview pulumi-up pulumi-refresh pulumi-destroy \
        pulumi-stack-select pulumi-stack-migrate-secrets sh down clean \
        check-format check-lint check-spelling check-toml check-types check-ty check-package check-qlty \
        check-bandit check-deps check-sbom check-yaml check-actionlint \
        check-docker check-shell check-iac check-static check-security ci \
        test-unit test-integration test-pulumi test-mutation test-e2e \
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

define run_or_skip
@if [ -d "$(1)" ]; then \
  $(COMPOSE) run --rm $(COMPOSE_SERVICE) $(2); \
else \
  echo "Skipping $(3): directory $(1) not found"; \
fi
endef

test-unit: ## Execute fast unit tests for the Pulumi application layer (if present).
	$(call run_or_skip,tests/unit,bash -c "COVERAGE_FILE=$(COVERAGE_DIR)/.coverage.unit $(UV_RUN) pytest -q tests/unit $(PYTEST_COV_OPTS_UNIT)","unit tests")

test-integration: ## Execute Pulumi automation-based integration tests (if present).
	$(call run_or_skip,tests/integration,bash -c "COVERAGE_FILE=$(COVERAGE_DIR)/.coverage.integration $(UV_RUN) pytest -q tests/integration tests/unit $(PYTEST_COV_OPTS_INT)","integration tests")

test-pulumi: ## Perform structural checks on Pulumi project configuration (if present).
	$(call run_or_skip,tests/pulumi,$(UV_RUN) pytest -q tests/pulumi,"Pulumi structural tests")

test-mutation: ## Run mutation testing suite against Pulumi components (if present).
	$(call run_or_skip,scripts,bash -lc "COVERAGE_FILE=$(COVERAGE_DIR)/.coverage.mutation ./scripts/run_mutation_tests.sh","mutation tests")

test-e2e: ## Execute end-to-end Pulumi CLI smoke tests (requires PULUMI_E2E_SECRETS_PROVIDER).
	$(call run_or_skip,tests/e2e,$(UV_RUN) pytest -q tests/e2e,"e2e tests")

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

check-spelling: ## Run typo detection across repository sources.
	$(COMPOSE) run --rm $(COMPOSE_SERVICE) typos $(SPELLCHECK_PATHS)

check-toml: ## Lint and format-check repository TOML manifests with Taplo.
	$(COMPOSE) run --rm $(COMPOSE_SERVICE) bash -lc "taplo lint $(TOML_LINT_PATHS) && taplo format --check $(TOML_LINT_PATHS)"

check-types: ## Run static type checks for Pulumi Python code.
	$(COMPOSE) run --rm $(COMPOSE_SERVICE) $(UV_RUN) mypy $(PYTHON_TYPE_PATHS)

check-ty: ## Run Astral Ty static analysis across Pulumi and test code.
	$(COMPOSE) run --rm $(COMPOSE_SERVICE) $(UV_RUN) ty check $(PYTHON_TY_PATHS)

check-package: ## Validate the uv lockfile, synced environment, and Python bytecode compilation.
	$(COMPOSE) run --rm $(COMPOSE_SERVICE) bash -lc "uv lock --check && uv sync --check --frozen --all-groups --no-install-project --no-editable && pycache_dir=\$$(mktemp -d \"\$$HOME/pycache.XXXXXX\") && trap 'rm -rf \"\$$pycache_dir\"' EXIT && PYTHONPYCACHEPREFIX=\$$pycache_dir python -m compileall -q $(PYTHON_FORMAT_PATHS)"

check-qlty: ## Run the repo-local Qlty code health configuration.
	@command -v $(QLTY) >/dev/null 2>&1 || { echo "qlty CLI is required. Install it from https://qlty.sh" >&2; exit 1; }
	$(QLTY) check --all --summary --no-progress --level note --fail-level note

check-bandit: ## Run Bandit security checks on Pulumi Python sources.
	$(COMPOSE) run --rm $(COMPOSE_SERVICE) $(UV_RUN) bandit -q -r pulumi -c pyproject.toml

check-deps: ## Audit locked Python dependencies for known vulnerabilities.
	$(COMPOSE) run --rm $(COMPOSE_SERVICE) bash -lc "mkdir -p \"\$$TMPDIR\" && requirements_file=\$$(mktemp \"\$$TMPDIR/requirements.XXXXXX.txt\") && trap 'rm -f \"\$$requirements_file\"' EXIT && uv export --frozen --all-groups --format requirements.txt --no-emit-project --output-file \"\$$requirements_file\" >/dev/null && $(UV_RUN) python -m pip_audit -r \"\$$requirements_file\" --desc"

check-sbom: ## Export a CycloneDX SBOM from the locked uv dependency graph.
	$(COMPOSE) run --rm $(COMPOSE_SERVICE) bash -lc "mkdir -p \"\$$TMPDIR\" && sbom_file=\$$(mktemp \"\$$TMPDIR/sbom.XXXXXX.json\") && trap 'rm -f \"\$$sbom_file\"' EXIT && uv export --preview-features sbom-export --frozen --all-groups --format cyclonedx1.5 --no-emit-project --output-file \"\$$sbom_file\" >/dev/null && python -m json.tool \"\$$sbom_file\" >/dev/null"

check-yaml: ## Lint GitHub Actions and Pulumi YAML manifests.
	$(COMPOSE) run --rm $(COMPOSE_SERVICE) $(UV_RUN) yamllint -c .yamllint $(YAML_LINT_PATHS)

check-actionlint: ## Lint GitHub Actions workflows.
	docker run --rm -v "$(CURDIR):/work" -w /work $(ACTIONLINT_IMAGE) -color

check-docker: ## Lint the Dockerfile with Hadolint.
	docker run --rm -i $(HADOLINT_IMAGE) hadolint --failure-threshold error - < Dockerfile

check-shell: ## Lint repository shell scripts with ShellCheck.
	docker run --rm -v "$(CURDIR):/work" $(SHELLCHECK_IMAGE) $(SHELLCHECK_PATHS)

check-iac: ## Run Checkov against GitHub Actions and Dockerfile definitions.
	docker run --rm -v "$(CURDIR):/work" $(CHECKOV_IMAGE) -d /work --config-file /work/.checkov.yml

check-static: ## Run static formatting, lint, type, and packaging checks.
	$(MAKE) check-format
	$(MAKE) check-lint
	$(MAKE) check-spelling
	$(MAKE) check-toml
	$(MAKE) check-types
	$(MAKE) check-ty
	$(MAKE) check-package

check-security: ## Run security and policy checks for code, manifests, and build assets.
	$(MAKE) check-bandit
	$(MAKE) check-deps
	$(MAKE) check-sbom
	$(MAKE) check-yaml
	$(MAKE) check-actionlint
	$(MAKE) check-docker
	$(MAKE) check-shell
	$(MAKE) check-iac
	$(MAKE) check-qlty

test-cost: ## Execute cost and governance guardrail tests for the Pulumi stack.
	$(call run_or_skip,tests/cost,$(UV_RUN) pytest -q tests/cost,"cost guardrail tests")

test: ## Run the complete Pulumi-focused test battery.
	$(MAKE) test-pulumi
	$(MAKE) test-cost
	$(MAKE) test-unit
	$(MAKE) test-integration
	$(MAKE) test-mutation
	$(MAKE) test-e2e
	$(MAKE) test-bats

ci: ## Run the full local CI battery, including static checks and tests.
	$(MAKE) check-static
	$(MAKE) check-security
	$(MAKE) test

clean: ## Remove Docker Compose artifacts, Python caches, and build artifacts.
	$(COMPOSE) down -v 2>/dev/null || true
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	rm -rf .venv .mypy_cache .ruff_cache dist build *.egg-info 2>/dev/null || true
