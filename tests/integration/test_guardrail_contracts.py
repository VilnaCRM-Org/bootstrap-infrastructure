"""Integration-level guardrail contracts for Pulumi environment metadata."""

from __future__ import annotations

import asyncio
import re
from collections.abc import Callable

import pytest
from app.environment import (
    EnvironmentSettings,
    _stack_metadata_from_outputs,
    resolve_config_value,
)
from pulumi.runtime import mocks, settings, stack


class _IntegrationMocks(mocks.Mocks):
    """Pulumi mocks that keep component construction local to the test process."""

    def new_resource(self, args: mocks.MockResourceArgs) -> tuple[str, dict]:
        """Echo inputs so component registration can complete under test."""
        return f"{args.name}_id", args.inputs

    def call(self, args: mocks.MockCallArgs) -> dict:
        """Return invoke inputs unchanged for deterministic tests."""
        return args.inputs


def _run_with_mocks(program: Callable[[], None]) -> None:
    """Execute a Pulumi program inside the integration suite process."""
    try:
        previous_loop = asyncio.get_event_loop()
    except RuntimeError:
        previous_loop = None

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        test_mocks = _IntegrationMocks()
        monitor = mocks.MockMonitor(test_mocks)
        mocks.set_mocks(
            test_mocks,
            project="bootstrap-infrastructure",
            stack="integration",
            monitor=monitor,
        )
        loop.run_until_complete(stack.run_pulumi_func(program))
        loop.run_until_complete(asyncio.sleep(0))
    finally:
        settings.reset_options(project=None, stack=None)
        loop.close()
        if previous_loop is not None and not previous_loop.is_closed():
            asyncio.set_event_loop(previous_loop)
        else:
            asyncio.set_event_loop(None)


def test_environment_settings_support_default_resolution_under_pulumi_mocks() -> None:
    """Exercise the component path that falls back to committed defaults."""

    def program() -> None:
        EnvironmentSettings("integration-settings")

    _run_with_mocks(program)


def test_environment_helpers_cover_configured_and_shape_guard_paths() -> None:
    """Exercise integration-only helper branches kept behind the component layer."""
    assert (
        resolve_config_value(None, "configured", default="fallback") == "configured"
    )  # nosec B101
    with pytest.raises(
        ValueError, match="expected service, environment, owner, and cost center"
    ):
        _stack_metadata_from_outputs(["service", "environment", "owner"])


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        (
            {"environment": 1, "service_name": "billing"},  # type: ignore[dict-item]
            "environment must be a string",
        ),
        (
            {"environment": "", "service_name": "billing"},
            "environment must not be empty",
        ),
        (
            {"environment": " qa ", "service_name": "billing"},
            "environment must not contain surrounding whitespace",
        ),
        (
            {"environment": "dev", "service_name": "Billing_API"},
            "service name must use lowercase letters, digits, and hyphens only",
        ),
    ],
)
def test_environment_settings_reject_invalid_identifier_inputs(
    kwargs: dict[str, object], message: str
) -> None:
    """Exercise identifier validation through the Pulumi component path."""

    def program() -> None:
        EnvironmentSettings("integration-settings", **kwargs)

    with pytest.raises(ValueError, match=rf"^{re.escape(message)}\.$"):
        _run_with_mocks(program)
