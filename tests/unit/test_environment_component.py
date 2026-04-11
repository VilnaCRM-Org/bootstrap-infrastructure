"""Unit tests for the EnvironmentSettings Pulumi component."""

import asyncio
import re
import runpy
import sys
from collections.abc import Callable, Iterator
from contextlib import ExitStack, contextmanager
from pathlib import Path
from unittest.mock import call, patch

import pytest
from app.environment import (
    EnvironmentSettings,
    _default_tags_from_parts,
    _stack_metadata_from_outputs,
    _stack_tag_from_parts,
    resolve_config_value,
)
from pulumi.runtime import mocks, settings, stack

import pulumi

PROJECT_ROOT = Path(__file__).resolve().parents[2]
PULUMI_MAIN = PROJECT_ROOT / "pulumi" / "__main__.py"
_PENDING_OUTPUT_ASSERTIONS: list[Callable[[], None]] = []


class SimpleMocks(mocks.Mocks):
    """Pulumi mocks that echo inputs for unit testing."""

    def new_resource(self, args: mocks.MockResourceArgs) -> tuple[str, dict]:
        """Return a synthetic resource ID and echo inputs."""
        return f"{args.name}_id", args.inputs

    def call(self, args: mocks.MockCallArgs) -> dict:
        """Return inputs directly for mocked invoke calls."""
        return args.inputs


def _run_pulumi_program(program: Callable[[], None]) -> None:
    """Execute a Pulumi program with mocks."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        test_mocks = SimpleMocks()
        monitor = mocks.MockMonitor(test_mocks)
        mocks.set_mocks(
            test_mocks,
            project="bootstrap-infrastructure",
            stack="unit",
            monitor=monitor,
        )
        loop.run_until_complete(stack.run_pulumi_func(program))
        loop.run_until_complete(asyncio.sleep(0))
        for assertion in _PENDING_OUTPUT_ASSERTIONS:
            assertion()
    finally:
        _PENDING_OUTPUT_ASSERTIONS.clear()
        settings.reset_options(project=None, stack=None)
        loop.close()
        asyncio.set_event_loop(None)


def _assert_output_value(output: pulumi.Output, expected: object) -> None:
    """Assert a Pulumi Output resolves to the expected value."""
    called = False

    def check(value: object) -> None:
        nonlocal called
        called = True
        assert value == expected, f"Expected {expected!r}, got {value!r}"

    def verify_called() -> None:
        assert called, "Expected Output.apply callback to run under Pulumi mocks"

    output.apply(check)
    _PENDING_OUTPUT_ASSERTIONS.append(verify_called)


@contextmanager
def mocked_pulumi_context(
    config_values: dict[str, object] | None = None, *, project_name: str | None = None
) -> Iterator[object]:
    """Patch Pulumi config/project helpers for deterministic tests."""
    config_values = config_values or {}
    with ExitStack() as stack:
        config_patch = stack.enter_context(patch("app.environment.pulumi.Config"))
        config_instance = config_patch.return_value
        config_instance.get.side_effect = lambda key, default=None: config_values.get(
            key, default
        )

        if project_name is not None:
            stack.enter_context(
                patch("app.environment.pulumi.get_project", return_value=project_name)
            )

        yield config_instance


def test_stack_tag_combines_service_and_environment() -> None:
    """Combine explicit service/environment into a stack tag."""

    def program() -> None:
        """Export the derived stack tag for assertion."""
        env_settings = EnvironmentSettings(
            "unit", environment="staging", service_name="billing"
        )
        pulumi.export("stackTag", env_settings.stack_tag)
        _assert_output_value(env_settings.stack_tag, "billing-staging")

    _run_pulumi_program(program)


def test_default_tags_use_service_and_environment() -> None:
    """Build default tags from explicit service/environment values."""

    def program() -> None:
        """Export default tags for explicit values."""
        env_settings = EnvironmentSettings(
            "unit", environment="production", service_name="edge"
        )
        pulumi.export("defaultTags", env_settings.default_tags)
        _assert_output_value(
            env_settings.default_tags,
            {
                "Project": "edge",
                "Environment": "production",
                "Owner": "platform",
                "CostCenter": "engineering",
            },
        )

    _run_pulumi_program(program)


def test_environment_falls_back_to_config_value() -> None:
    """Use the config value when environment is not passed."""

    def program() -> None:
        """Export resolved fields for config-based environment."""
        env_settings = EnvironmentSettings("unit")
        pulumi.export("environment", env_settings.environment)
        pulumi.export("serviceName", env_settings.service_name)
        pulumi.export("stackTag", env_settings.stack_tag)
        pulumi.export("defaultTags", env_settings.default_tags)
        _assert_output_value(env_settings.environment, "qa")
        _assert_output_value(env_settings.service_name, "bootstrap-infrastructure")
        _assert_output_value(env_settings.stack_tag, "bootstrap-infrastructure-qa")
        _assert_output_value(
            env_settings.default_tags,
            {
                "Project": "bootstrap-infrastructure",
                "Environment": "qa",
                "Owner": "platform",
                "CostCenter": "engineering",
            },
        )

    with mocked_pulumi_context({"environment": "qa"}) as config_instance:
        _run_pulumi_program(program)

    assert config_instance.get.call_args_list == [
        call("environment"),
        call("serviceName"),
        call("owner"),
        call("costCenter"),
    ]


def test_environment_defaults_to_dev_when_unset() -> None:
    """Default environment to dev when no config is set."""

    def program() -> None:
        """Export resolved fields for default environment."""
        env_settings = EnvironmentSettings("unit")
        pulumi.export("environment", env_settings.environment)
        pulumi.export("serviceName", env_settings.service_name)
        pulumi.export("stackTag", env_settings.stack_tag)
        pulumi.export("defaultTags", env_settings.default_tags)
        _assert_output_value(env_settings.environment, "dev")
        _assert_output_value(env_settings.service_name, "bootstrap-infrastructure")
        _assert_output_value(env_settings.stack_tag, "bootstrap-infrastructure-dev")
        _assert_output_value(
            env_settings.default_tags,
            {
                "Project": "bootstrap-infrastructure",
                "Environment": "dev",
                "Owner": "platform",
                "CostCenter": "engineering",
            },
        )

    with mocked_pulumi_context():
        _run_pulumi_program(program)


def test_service_name_falls_back_to_config_value() -> None:
    """Use the config value when service name is not passed."""

    def program() -> None:
        """Export resolved fields for config-based service name."""
        env_settings = EnvironmentSettings("unit", environment="qa")
        pulumi.export("serviceName", env_settings.service_name)
        pulumi.export("stackTag", env_settings.stack_tag)
        pulumi.export("defaultTags", env_settings.default_tags)
        _assert_output_value(env_settings.service_name, "billing")
        _assert_output_value(env_settings.stack_tag, "billing-qa")
        _assert_output_value(
            env_settings.default_tags,
            {
                "Project": "billing",
                "Environment": "qa",
                "Owner": "platform",
                "CostCenter": "engineering",
            },
        )

    with mocked_pulumi_context({"serviceName": "billing"}):
        _run_pulumi_program(program)


def test_service_name_defaults_to_project_name() -> None:
    """Default service name to the Pulumi project name."""

    def program() -> None:
        """Export resolved fields for project-name fallback."""
        env_settings = EnvironmentSettings("unit", environment="qa")
        pulumi.export("serviceName", env_settings.service_name)
        pulumi.export("stackTag", env_settings.stack_tag)
        pulumi.export("defaultTags", env_settings.default_tags)
        _assert_output_value(env_settings.service_name, "project-fallback")
        _assert_output_value(env_settings.stack_tag, "project-fallback-qa")
        _assert_output_value(
            env_settings.default_tags,
            {
                "Project": "project-fallback",
                "Environment": "qa",
                "Owner": "platform",
                "CostCenter": "engineering",
            },
        )

    with mocked_pulumi_context(project_name="project-fallback"):
        _run_pulumi_program(program)


def test_default_tags_allow_owner_and_cost_center_overrides() -> None:
    """Let stack config override the template defaults for shared tags."""

    def program() -> None:
        """Export default tags for owner and cost-center overrides."""
        env_settings = EnvironmentSettings("unit", environment="qa")
        pulumi.export("defaultTags", env_settings.default_tags)
        _assert_output_value(
            env_settings.default_tags,
            {
                "Project": "bootstrap-infrastructure",
                "Environment": "qa",
                "Owner": "team-platform",
                "CostCenter": "cost-123",
            },
        )

    with mocked_pulumi_context({"owner": "team-platform", "costCenter": "cost-123"}):
        _run_pulumi_program(program)


def test_default_tags_trim_owner_and_cost_center_config_values() -> None:
    """Normalize padded config values before exporting shared tags."""

    def program() -> None:
        """Export normalized tags from config-backed owner values."""
        env_settings = EnvironmentSettings("unit", environment="qa")
        pulumi.export("defaultTags", env_settings.default_tags)
        _assert_output_value(
            env_settings.default_tags,
            {
                "Project": "bootstrap-infrastructure",
                "Environment": "qa",
                "Owner": "team-platform",
                "CostCenter": "cost-123",
            },
        )

    with mocked_pulumi_context(
        {"owner": " team-platform ", "costCenter": " cost-123 "}
    ):
        _run_pulumi_program(program)


def test_default_tags_fall_back_when_owner_and_cost_center_are_blank() -> None:
    """Replace blank owner metadata with the documented template defaults."""

    def program() -> None:
        """Export default tags for blank config values."""
        env_settings = EnvironmentSettings("unit", environment="qa")
        pulumi.export("defaultTags", env_settings.default_tags)
        _assert_output_value(
            env_settings.default_tags,
            {
                "Project": "bootstrap-infrastructure",
                "Environment": "qa",
                "Owner": "platform",
                "CostCenter": "engineering",
            },
        )

    with mocked_pulumi_context({"owner": "   ", "costCenter": ""}):
        _run_pulumi_program(program)


def test_default_tags_allow_explicit_owner_and_cost_center_overrides() -> None:
    """Honor explicit owner and cost-center overrides before config defaults."""

    def program() -> None:
        """Export default tags for explicit tag overrides."""
        env_settings = EnvironmentSettings(
            "unit",
            environment="qa",
            service_name="billing",
            owner="payments",
            cost_center="finops",
        )
        pulumi.export("defaultTags", env_settings.default_tags)
        _assert_output_value(
            env_settings.default_tags,
            {
                "Project": "billing",
                "Environment": "qa",
                "Owner": "payments",
                "CostCenter": "finops",
            },
        )

    _run_pulumi_program(program)


def test_default_tags_trim_explicit_owner_and_cost_center_overrides() -> None:
    """Normalize explicit owner overrides before exporting default tags."""

    def program() -> None:
        """Export default tags for explicit padded tag overrides."""
        env_settings = EnvironmentSettings(
            "unit",
            environment="qa",
            service_name="billing",
            owner=" payments ",
            cost_center=" finops ",
        )
        pulumi.export("defaultTags", env_settings.default_tags)
        _assert_output_value(
            env_settings.default_tags,
            {
                "Project": "billing",
                "Environment": "qa",
                "Owner": "payments",
                "CostCenter": "finops",
            },
        )

    _run_pulumi_program(program)


def test_resolve_config_value_preserves_explicit_configured_and_default_paths() -> None:
    """Keep resolution semantics stable for explicit, configured, and default values."""
    assert resolve_config_value("prod", "staging", default="dev") == "prod"
    assert resolve_config_value(None, "staging", default="dev") == "staging"
    assert resolve_config_value(None, None, default="dev") == "dev"


def test_stack_metadata_helpers_keep_the_four_field_layout() -> None:
    """Map service, environment, owner, and cost center without index drift."""
    metadata = _stack_metadata_from_outputs(
        ["billing", "qa", "team-platform", "cost-123"]
    )

    assert metadata == ("billing", "qa", "team-platform", "cost-123")
    assert _stack_tag_from_parts(metadata) == "billing-qa"
    assert _default_tags_from_parts(metadata) == {
        "Project": "billing",
        "Environment": "qa",
        "Owner": "team-platform",
        "CostCenter": "cost-123",
    }


def test_stack_metadata_helpers_reject_shape_drift() -> None:
    """Reject unexpected Output.all shapes before indexing tag metadata."""
    with pytest.raises(
        ValueError, match=r"^expected service, environment, owner, and cost center$"
    ):
        _stack_metadata_from_outputs(["billing", "qa", "team-platform"])


def _assert_config_error(config_values: dict[str, object], message: str) -> None:
    """Assert invalid config is rejected inside the mocked Pulumi runtime."""

    def program() -> None:
        """Instantiate the component to trigger config validation."""
        EnvironmentSettings("unit")

    with mocked_pulumi_context(config_values):
        with pytest.raises(ValueError, match=rf"^{re.escape(message)}\.$"):
            _run_pulumi_program(program)


def test_environment_rejects_blank_config_value() -> None:
    """Reject empty environment config instead of silently defaulting."""
    _assert_config_error({"environment": ""}, "environment must not be empty")


def test_environment_rejects_padded_config_value() -> None:
    """Reject padded environment config to keep exported identifiers stable."""
    _assert_config_error(
        {"environment": " qa "},
        "environment must not contain surrounding whitespace",
    )


def test_service_name_rejects_invalid_config_value() -> None:
    """Reject service config that would produce invalid stack metadata."""
    _assert_config_error(
        {"serviceName": "Billing_API"},
        "service name must use lowercase letters, digits, and hyphens only",
    )


def test_component_registers_expected_type_token() -> None:
    """Pass the expected type token into the public ComponentResource API."""
    captured: dict[str, tuple[str, str]] = {}
    original_init = pulumi.ComponentResource.__init__

    def tracked_init(
        self: pulumi.ComponentResource,
        type_token: str,
        name: str,
        props: object = None,
        opts: object = None,
        *args: object,
        **kwargs: object,
    ) -> None:
        if isinstance(self, EnvironmentSettings):
            captured["component"] = (type_token, name)
        original_init(self, type_token, name, props, opts, *args, **kwargs)

    def program() -> None:
        """Capture the component instance for type checks."""
        env_settings = EnvironmentSettings("unit")
        pulumi.export("environment", env_settings.environment)

    with patch.object(pulumi.ComponentResource, "__init__", new=tracked_init):
        _run_pulumi_program(program)

    assert captured.get("component") == (
        "bootstrap-infrastructure:core:EnvironmentSettings",
        "unit",
    )


def test_main_exports_expected_outputs() -> None:
    """Execute the Pulumi entrypoint and validate exported outputs."""

    def program() -> None:
        """Run the pulumi __main__ module inside the mocked runtime."""
        inserted_path = str(PROJECT_ROOT / "pulumi")
        sys.path.insert(0, inserted_path)
        try:
            module_globals = runpy.run_path(str(PULUMI_MAIN))
        finally:
            sys.path.remove(inserted_path)

        env_settings = module_globals["settings"]
        _assert_output_value(env_settings.environment, "dev")
        _assert_output_value(env_settings.service_name, "bootstrap-infrastructure")
        _assert_output_value(env_settings.stack_tag, "bootstrap-infrastructure-dev")
        _assert_output_value(
            env_settings.default_tags,
            {
                "Project": "bootstrap-infrastructure",
                "Environment": "dev",
                "Owner": "platform",
                "CostCenter": "engineering",
            },
        )

    with mocked_pulumi_context():
        _run_pulumi_program(program)


def test_register_outputs_maps_component_properties() -> None:
    """Register outputs for component properties consistently."""
    original_register = pulumi.ComponentResource.register_outputs

    def program() -> None:
        """Export component outputs for register_outputs tracking."""
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
    assert set(outputs.keys()) == {
        "environment",
        "serviceName",
        "stackTag",
        "defaultTags",
    }
    assert outputs["environment"] is resource.environment
    assert outputs["serviceName"] is resource.service_name
    assert outputs["stackTag"] is resource.stack_tag
    assert outputs["defaultTags"] is resource.default_tags
