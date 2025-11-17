# Parameters
PROJECT            = infrastructure-template
ENV_FILE           = .env
EMPTY_ENV_FILE     = .env.empty
COMPOSE_SERVICE   ?= pulumi
EFFECTIVE_ENV_FILE := $(firstword $(wildcard $(ENV_FILE)) $(wildcard $(EMPTY_ENV_FILE)))

export COMPOSE_ENV_FILE := $(if $(EFFECTIVE_ENV_FILE),$(EFFECTIVE_ENV_FILE),$(EMPTY_ENV_FILE))
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
.PHONY: help start pulumi-preview pulumi-up pulumi-refresh pulumi-destroy \
        sh down test-unit test-integration test-pulumi test-mutation test all clean

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

test-unit: ## Execute fast unit tests for the Pulumi application layer.
	$(COMPOSE) run --rm $(COMPOSE_SERVICE) poetry run pytest -q tests/unit

test-integration: ## Execute Pulumi automation-based integration tests.
	$(COMPOSE) run --rm $(COMPOSE_SERVICE) poetry run pytest -q tests/integration

test-pulumi: ## Perform structural checks on Pulumi project configuration.
	$(COMPOSE) run --rm $(COMPOSE_SERVICE) poetry run pytest -q tests/pulumi

test-mutation: ## Run mutation testing suite against Pulumi components.
	$(COMPOSE) run --rm $(COMPOSE_SERVICE) bash -lc "./scripts/run_mutation_tests.sh"

test: ## Run the complete Pulumi-focused test battery.
	$(MAKE) test-pulumi
	$(MAKE) test-unit
	$(MAKE) test-integration

clean: ## Remove Docker Compose artifacts, Python caches, and build artifacts.
	$(DOCKER_COMPOSE) down -v 2>/dev/null || true
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	rm -rf .venv dist build *.egg-info 2>/dev/null || true
