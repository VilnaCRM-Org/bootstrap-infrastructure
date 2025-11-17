# Parameters
PROJECT        = infrastructure-template
ENV_FILE       = .env

# Executables: local only
DOCKER_COMPOSE = docker compose
DOCKER         = docker

# Executables
PULUMI         = pulumi
EXEC_APP       = $(DOCKER_COMPOSE) exec app

# Misc
.DEFAULT_GOAL  = help
.RECIPEPREFIX  +=
.PHONY: $(filter-out vendor node_modules,$(MAKECMDGOALS))

help:
	@printf "\033[33mUsage:\033[0m\n  make [target] [arg=\"val\"...]\n\n\033[33mTargets:\033[0m\n"
	@grep -E '^[-a-zA-Z0-9_\.\/]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[32m%-15s\033[0m %s\n", $$1, $$2}'

start: ## Initialize and start Pulumi development environment
	${DOCKER_COMPOSE} up -d --build
#"${PULUMI} login --local && ${PULUMI} install"

health: ## Check if containers are healthy
	@$(DOCKER_COMPOSE) ps --format json | python3 -c "import json, sys; data=json.load(sys.stdin); sys.exit(0 if all((svc.get('Health') in (None, '', 'healthy')) for svc in data) else 1)"

up: ## Start the container for development
	$(DOCKER_COMPOSE) up --detach && $(MAKE) health

build: ## Builds the images (PHP, caddy)
	$(DOCKER_COMPOSE) build --pull --no-cache

down: ## Stop the docker hub
	$(DOCKER_COMPOSE) down --remove-orphans

sh: ## Log to the docker container
	@$(EXEC_APP) sh

pulumi: ## Pulumi command proxy (usage: make pulumi ARGS="version")
	@$(EXEC_APP) ${PULUMI} $(ARGS)

pulumi-preview: ## Preview infrastructure changes
	@$(EXEC_APP) ${PULUMI} preview

pulumi-up: ## Apply infrastructure changes
	@$(EXEC_APP) ${PULUMI} up

pulumi-refresh: ## Refresh stack state
	@$(EXEC_APP) ${PULUMI} refresh

pulumi-destroy: ## Destroy infrastructure (use with caution)
	@$(EXEC_APP) ${PULUMI} destroy
