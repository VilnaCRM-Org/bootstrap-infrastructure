"""Build the credential-stage order for an authenticated affected-stack request.

This pure scheduling component does not authenticate requests, grant AWS access,
or attest deployment success. The trusted coordinator must perform those checks.
"""

from __future__ import annotations

from dataclasses import dataclass

from deployment_scopes import STACK_ORDER


@dataclass(frozen=True)
class DeploymentStep:
    """One fixed stack operation and the operation that must precede it."""

    key: str
    environment: str
    scope: str
    operation: str
    predecessor: str | None


def deployment_schedule(
    scopes: tuple[str, ...], *, command: str, target_environment: str
) -> tuple[DeploymentStep, ...]:
    """Serialize selected stacks and finish the full TEST graph before PROD.

    A plan request contains no apply or drift stages. A docs-only selection has
    no cloud stages; it is not a successful deployment. Reject noncanonical
    scope inputs rather than silently dropping unknown or duplicate entries.
    """
    if command not in {"plan", "up"}:
        raise ValueError("Unsupported deployment command")
    if target_environment not in {"test", "prod"}:
        raise ValueError("Unsupported deployment environment")
    if not isinstance(scopes, tuple):
        raise ValueError("Deployment scopes must be unique and in dependency order")
    canonical = tuple(scope for scope in STACK_ORDER if scope in scopes)
    if scopes != canonical:
        raise ValueError("Deployment scopes must be unique and in dependency order")
    environments = ("test", "prod") if target_environment == "prod" else ("test",)
    operations = ("plan", "apply", "drift") if command == "up" else ("plan",)
    steps: list[DeploymentStep] = []
    predecessor = None
    for environment in environments:
        for scope in scopes:
            for operation in operations:
                key = f"{environment}_{scope}_{operation}"
                steps.append(
                    DeploymentStep(key, environment, scope, operation, predecessor)
                )
                predecessor = key
    return tuple(steps)
