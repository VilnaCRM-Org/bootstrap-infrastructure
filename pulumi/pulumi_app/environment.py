from __future__ import annotations

from typing import Optional

import pulumi


class EnvironmentSettings(pulumi.ComponentResource):
    """
    EnvironmentSettings consolidates the Pulumi project configuration into a reusable component.
    It exposes the selected environment, service name, and a derived stack tag plus default tags
    that can be reused by other resources.
    """

    def __init__(
        self,
        name: str,
        *,
        environment: Optional[str] = None,
        service_name: Optional[str] = None,
        opts: Optional[pulumi.ResourceOptions] = None,
    ) -> None:
        super().__init__("infrastructure-template:core:EnvironmentSettings", name, None, opts)

        config = pulumi.Config()

        resolved_environment = environment or config.get("environment") or "dev"

        resolved_service = service_name or config.get("serviceName") or pulumi.get_project()

        self.environment = pulumi.Output.from_input(resolved_environment)
        self.service_name = pulumi.Output.from_input(resolved_service)

        self.stack_tag = pulumi.Output.all(self.service_name, self.environment).apply(
            lambda args: f"{args[0]}-{args[1]}"
        )

        self.default_tags = pulumi.Output.all(self.service_name, self.environment).apply(
            lambda args: {"Project": args[0], "Environment": args[1]}
        )

        self.register_outputs(
            {
                "environment": self.environment,
                "serviceName": self.service_name,
                "stackTag": self.stack_tag,
                "defaultTags": self.default_tags,
            }
        )
