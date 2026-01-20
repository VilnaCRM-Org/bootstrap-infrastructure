# Parameters
PROJECT            = bootstrap-infrastructure
ENV_FILE           = .env
COMPOSE_SERVICE   ?= pulumi
EFFECTIVE_ENV_FILE := $(firstword $(wildcard $(ENV_FILE)))

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

# Misc
.DEFAULT_GOAL     = help
.RECIPEPREFIX    +=
.PHONY: all help start pulumi-preview pulumi-up pulumi-refresh pulumi-destroy \
        sh down clean test-unit test-integration test-pulumi test-mutation test

all: help ## Display help (default goal).

help:
	@printf "\033[33mUsage:\033[0m\n  make [target] [arg=\"val\"...]\n\n\033[33mTargets:\033[0m\n"
	@grep -E '^[-a-zA-Z0-9_\.\/]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[32m%-15s\033[0m %s\n", $$1, $$2}'

start: ## Initialize and start the Pulumi development environment.
	$(COMPOSE) up -d

pulumi-preview: ## Preview infrastructure changes from inside the Pulumi container.
	$(COMPOSE) run --rm $(COMPOSE_SERVICE) pulumi preview

pulumi-up: ## Apply the current Pulumi infrastructure plan.
	$(COMPOSE) run --rm $(COMPOSE_SERVICE) pulumi up

pulumi-refresh: ## Sync the Pulumi stack with live cloud resources.
	$(COMPOSE) run --rm $(COMPOSE_SERVICE) pulumi refresh

pulumi-destroy: ## Tear down the Pulumi stack (irreversible; use with caution).
	$(COMPOSE) run --rm $(COMPOSE_SERVICE) pulumi destroy

sh: ## Open a shell inside the Pulumi container.
	$(COMPOSE) run --rm $(COMPOSE_SERVICE) sh

down: ## Stop the Docker Compose environment.
	$(DOCKER_COMPOSE) down

define run_or_skip
@if [ -d "$(1)" ]; then \
  $(COMPOSE) run --rm $(COMPOSE_SERVICE) $(2); \
else \
  echo "Skipping $(3): directory $(1) not found"; \
fi
endef

test-unit: ## Execute fast unit tests for the Pulumi application layer (if present).
	$(call run_or_skip,tests/unit,poetry run pytest -q tests/unit,"unit tests")

test-integration: ## Execute Pulumi automation-based integration tests (if present).
	$(call run_or_skip,tests/integration,poetry run pytest -q tests/integration,"integration tests")

test-pulumi: ## Perform structural checks on Pulumi project configuration (if present).
	$(call run_or_skip,tests/pulumi,poetry run pytest -q tests/pulumi,"Pulumi structural tests")

test-mutation: ## Run mutation testing suite against Pulumi components (if present).
	$(call run_or_skip,scripts,poetry run bash -lc "./scripts/run_mutation_tests.sh","mutation tests")

test: ## Run the complete Pulumi-focused test battery.
	$(MAKE) test-pulumi
	$(MAKE) test-unit
	$(MAKE) test-integration
	$(MAKE) test-mutation

clean: ## Remove Docker Compose artifacts, Python caches, and build artifacts.
	$(DOCKER_COMPOSE) down -v 2>/dev/null || true
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	rm -rf .venv dist build *.egg-info 2>/dev/null || true
