from collections.abc import Callable
from contextlib import ExitStack, contextmanager
from unittest.mock import patch

import pulumi
from pulumi.runtime import mocks, settings, stack, sync_await

from pulumi_app.environment import EnvironmentSettings


class SimpleMocks(mocks.Mocks):
    def new_resource(self, args: mocks.MockResourceArgs) -> tuple[str, dict]:
        return f"{args.name}_id", args.inputs

    def call(self, args: mocks.MockCallArgs) -> dict:
        return args.inputs


def _run_pulumi_program(program: Callable[[], None]) -> dict[str, object]:
    test_mocks = SimpleMocks()
    monitor = mocks.MockMonitor(test_mocks)
    mocks.set_mocks(
        test_mocks,
        project="infrastructure-template",
        stack="unit",
        monitor=monitor,
    )

    try:
        sync_await._sync_await(stack.run_pulumi_func(program))
        root = settings.get_root_resource()
        assert root is not None, "Pulumi Stack was not initialised"

        resolved: dict[str, object] = {}
        for name, value in root.outputs.items():
            if isinstance(value, pulumi.Output):
                resolved[name] = sync_await._sync_await(value.future())
            else:
                resolved[name] = value
        return resolved
    finally:
        settings.reset_options(project=None, stack=None)


@contextmanager
def mocked_pulumi_context(
    config_values: dict[str, object] | None = None, *, project_name: str | None = None
) -> None:
    config_values = config_values or {}
    with ExitStack() as stack:
        config_patch = stack.enter_context(patch("pulumi_app.environment.pulumi.Config"))
        config_instance = config_patch.return_value
        config_instance.get.side_effect = lambda key, default=None: config_values.get(key, default)

        if project_name is not None:
            stack.enter_context(
                patch("pulumi_app.environment.pulumi.get_project", return_value=project_name)
            )

        yield


def test_stack_tag_combines_service_and_environment() -> None:
    def program() -> None:
        env_settings = EnvironmentSettings(
            "unit", environment="staging", service_name="billing"
        )
        pulumi.export("stackTag", env_settings.stack_tag)

    outputs = _run_pulumi_program(program)
    assert outputs["stackTag"] == "billing-staging"


def test_default_tags_use_service_and_environment() -> None:
    def program() -> None:
        env_settings = EnvironmentSettings(
            "unit", environment="production", service_name="edge"
        )
        pulumi.export("defaultTags", env_settings.default_tags)

    outputs = _run_pulumi_program(program)
    assert outputs["defaultTags"] == {"Project": "edge", "Environment": "production"}


def test_environment_falls_back_to_config_value() -> None:
    def program() -> None:
        env_settings = EnvironmentSettings("unit")
        pulumi.export("environment", env_settings.environment)
        pulumi.export("serviceName", env_settings.service_name)
        pulumi.export("stackTag", env_settings.stack_tag)
        pulumi.export("defaultTags", env_settings.default_tags)

    with mocked_pulumi_context({"environment": "qa"}):
        outputs = _run_pulumi_program(program)

    assert outputs["environment"] == "qa"
    assert outputs["serviceName"] == "infrastructure-template"
    assert outputs["stackTag"] == "infrastructure-template-qa"
    assert outputs["defaultTags"] == {
        "Project": "infrastructure-template",
        "Environment": "qa",
    }


def test_environment_defaults_to_dev_when_unset() -> None:
    def program() -> None:
        env_settings = EnvironmentSettings("unit")
        pulumi.export("environment", env_settings.environment)
        pulumi.export("serviceName", env_settings.service_name)
        pulumi.export("stackTag", env_settings.stack_tag)
        pulumi.export("defaultTags", env_settings.default_tags)

    with mocked_pulumi_context():
        outputs = _run_pulumi_program(program)

    assert outputs["environment"] == "dev"
    assert outputs["serviceName"] == "infrastructure-template"
    assert outputs["stackTag"] == "infrastructure-template-dev"
    assert outputs["defaultTags"] == {
        "Project": "infrastructure-template",
        "Environment": "dev",
    }


def test_service_name_falls_back_to_config_value() -> None:
    def program() -> None:
        env_settings = EnvironmentSettings("unit", environment="qa")
        pulumi.export("serviceName", env_settings.service_name)
        pulumi.export("stackTag", env_settings.stack_tag)
        pulumi.export("defaultTags", env_settings.default_tags)

    with mocked_pulumi_context({"serviceName": "billing"}):
        outputs = _run_pulumi_program(program)

    assert outputs["serviceName"] == "billing"
    assert outputs["stackTag"] == "billing-qa"
    assert outputs["defaultTags"] == {"Project": "billing", "Environment": "qa"}


def test_service_name_defaults_to_project_name() -> None:
    def program() -> None:
        env_settings = EnvironmentSettings("unit", environment="qa")
        pulumi.export("serviceName", env_settings.service_name)
        pulumi.export("stackTag", env_settings.stack_tag)
        pulumi.export("defaultTags", env_settings.default_tags)

    with mocked_pulumi_context(project_name="project-fallback"):
        outputs = _run_pulumi_program(program)

    assert outputs["serviceName"] == "project-fallback"
    assert outputs["stackTag"] == "project-fallback-qa"
    assert outputs["defaultTags"] == {"Project": "project-fallback", "Environment": "qa"}


def test_component_uses_expected_type_token() -> None:
    captured: dict[str, EnvironmentSettings] = {}

    def program() -> None:
        env_settings = EnvironmentSettings("unit")
        captured["resource"] = env_settings
        pulumi.export("environment", env_settings.environment)

    _run_pulumi_program(program)

    resource = captured.get("resource")
    assert resource is not None, "EnvironmentSettings instance was not created"
    assert getattr(resource, "_type", None) == "infrastructure-template:core:EnvironmentSettings"


def test_register_outputs_maps_component_properties() -> None:
    original_register = pulumi.ComponentResource.register_outputs

    def program() -> None:
        env_settings = EnvironmentSettings("unit", environment="qa", service_name="svc")
        pulumi.export("stackTag", env_settings.stack_tag)
        pulumi.export("defaultTags", env_settings.default_tags)

    with patch.object(
        pulumi.ComponentResource,
        "register_outputs",
        autospec=True,
        wraps=original_register,
    ) as mock_register:
        _run_pulumi_program(program)

    env_calls = [
        register_call
        for register_call in mock_register.call_args_list
        if isinstance(register_call.args[0], EnvironmentSettings)
    ]
    assert env_calls, "EnvironmentSettings.register_outputs was not invoked"

    resource, outputs = env_calls[0].args
    assert set(outputs.keys()) == {"environment", "serviceName", "stackTag", "defaultTags"}
    assert outputs["environment"] is resource.environment
    assert outputs["serviceName"] is resource.service_name
    assert outputs["stackTag"] is resource.stack_tag
    assert outputs["defaultTags"] is resource.default_tags
