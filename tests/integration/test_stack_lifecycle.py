"""Pulumi Automation API integration tests for stack lifecycle."""

from __future__ import annotations

import os
import shutil
import uuid
from pathlib import Path

import pulumi.automation as auto
import pytest
from pulumi.automation.errors import RuntimeError as AutomationRuntimeError

PROJECT_ROOT = Path(__file__).resolve().parents[2]
PULUMI_WORKDIR = PROJECT_ROOT / "pulumi"

pytestmark = [
    pytest.mark.skipif(
        shutil.which("pulumi") is None,
        reason="Pulumi CLI binary is not available in PATH.",
    ),
    pytest.mark.usefixtures("ensure_pulumi_secrets_provider"),
]


def _stack_name() -> str:
    """Return a unique stack name for the test run."""
    return f"it-{uuid.uuid4().hex[:8]}"


def _copy_workdir(tmp_path: Path, *, name: str) -> Path:
    """Copy the Pulumi program into an isolated temporary work directory."""
    work_dir = tmp_path / name
    shutil.copytree(
        PULUMI_WORKDIR,
        work_dir,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo", ".pytest_cache"),
    )
    return work_dir


def _workspace_options(work_dir: Path) -> auto.LocalWorkspaceOptions:
    """Pass the prepared Pulumi environment through Automation API workspaces."""
    env_vars = {
        key: value
        for key, value in os.environ.items()
        if key.startswith("PULUMI_")
        or key in {"COVERAGE_FILE", "COVERAGE_PROCESS_START"}
    }
    return auto.LocalWorkspaceOptions(
        work_dir=str(work_dir),
        pulumi_home=env_vars.get("PULUMI_HOME"),
        env_vars=env_vars,
    )


def test_pulumi_stack_preview_and_up_cycle(tmp_path: Path) -> None:
    """Validate preview/up/destroy behavior for the baseline stack."""
    work_dir = _copy_workdir(tmp_path, name="pulumi-program")

    stack = auto.create_or_select_stack(
        stack_name=_stack_name(),
        work_dir=str(work_dir),
        opts=_workspace_options(work_dir),
    )
    stack.set_config("environment", auto.ConfigValue(value="integration"))
    stack.set_config("serviceName", auto.ConfigValue(value="integration-test"))

    try:
        preview_result = stack.preview()
        assert preview_result.change_summary is not None

        up_result = stack.up()

        assert up_result.outputs["stackTag"].value == "integration-test-integration"
        assert up_result.outputs["serviceName"].value == "integration-test"
        assert up_result.outputs["environment"].value == "integration"
        assert up_result.outputs["defaultTags"].value == {
            "Project": "integration-test",
            "Environment": "integration",
            "Owner": "platform",
            "CostCenter": "engineering",
        }
    finally:
        try:
            stack.destroy(on_output=None)
        except Exception as exc:  # pragma: no cover - best-effort cleanup
            print(f"Pulumi destroy failed: {exc}")
        try:
            stack.workspace.remove_stack(stack.name)
        except Exception as exc:  # pragma: no cover - best-effort cleanup
            print(f"Pulumi stack removal failed: {exc}")


@pytest.mark.parametrize(
    ("config_key", "config_value", "message"),
    [
        ("environment", "", "environment must not be empty"),
        (
            "environment",
            " qa ",
            "environment must not contain surrounding whitespace",
        ),
        (
            "serviceName",
            "Billing_API",
            "service name must use lowercase letters, digits, and hyphens only",
        ),
    ],
)
def test_invalid_stack_config_fails_preview(
    tmp_path: Path,
    config_key: str,
    config_value: str,
    message: str,
) -> None:
    """Reject invalid environment metadata during a real Pulumi preview."""
    work_dir = _copy_workdir(tmp_path, name=f"invalid-{config_key}")
    stack = auto.create_or_select_stack(
        stack_name=_stack_name(),
        work_dir=str(work_dir),
        opts=_workspace_options(work_dir),
    )
    baseline = {
        "environment": "integration",
        "serviceName": "integration-test",
    }
    for key, value in baseline.items():
        stack.set_config(key, auto.ConfigValue(value=value))
    stack.set_config(config_key, auto.ConfigValue(value=config_value))

    try:
        with pytest.raises(AutomationRuntimeError) as exc_info:
            stack.preview()
        assert message in str(exc_info.value), str(exc_info.value)
    finally:
        try:
            stack.workspace.remove_stack(stack.name)
        except Exception as exc:  # pragma: no cover - best-effort cleanup
            print(f"Pulumi stack removal failed: {exc}")
