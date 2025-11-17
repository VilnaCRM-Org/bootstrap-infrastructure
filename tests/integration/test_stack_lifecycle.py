from __future__ import annotations

import shutil
import uuid
from pathlib import Path

import pytest
import pulumi.automation as auto


PROJECT_ROOT = Path(__file__).resolve().parents[2]
PULUMI_WORKDIR = PROJECT_ROOT / "pulumi"

pytestmark = pytest.mark.skipif(
    shutil.which("pulumi") is None, reason="Pulumi CLI binary is not available in PATH."
)


def _stack_name() -> str:
    return f"it-{uuid.uuid4().hex[:8]}"


def test_pulumi_stack_preview_and_up_cycle(tmp_path: Path) -> None:
    work_dir = tmp_path / "pulumi-program"
    shutil.copytree(
        PULUMI_WORKDIR,
        work_dir,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo", ".pytest_cache"),
    )

    stack = auto.create_or_select_stack(stack_name=_stack_name(), work_dir=str(work_dir))
    stack.set_config("environment", auto.ConfigValue(value="integration"))
    stack.set_config("serviceName", auto.ConfigValue(value="integration-test"))

    try:
        preview_result = stack.preview()
        assert preview_result.change_summary is not None

        up_result = stack.up()

        assert up_result.outputs["stackTag"].value == "integration-test-integration"
        assert up_result.outputs["serviceName"].value == "integration-test"
        assert up_result.outputs["environment"].value == "integration"
    finally:
        stack.destroy(on_output=None)
        stack.workspace.remove_stack(stack.name)
