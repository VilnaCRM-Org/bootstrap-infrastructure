COMPOSE ?= docker compose
.PHONY: start pulumi-plan pulumi-up-plan test-drift test-destructive-diff initialize-stack
start:
	$(COMPOSE) build
pulumi-plan:
	$(COMPOSE) run --rm pulumi python3 scripts/run_pulumi_command.py plan
pulumi-up-plan:
	$(COMPOSE) run --rm pulumi python3 scripts/run_pulumi_command.py up-plan
test-drift:
	$(COMPOSE) run --rm pulumi python3 scripts/run_pulumi_command.py drift
test-destructive-diff:
	$(COMPOSE) run --rm pulumi uv run --frozen python scripts/pulumi_ci_guardrails.py destructive-gate .artifacts/pulumi-preview/*.json --event-path .artifacts/pulumi-preview/pull-request-event.json
initialize-stack:
	$(COMPOSE) run --rm pulumi uv run --frozen python scripts/initialize_service_stack.py initialize
