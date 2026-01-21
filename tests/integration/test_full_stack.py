import runpy
from pathlib import Path

from infra import config


def test_stack_executes():
  config.managed_repositories.cache_clear()
  config.settings.repo = "repo"
  config.settings.environment = "test"
  config.settings.managed_repo_overrides = None
  stack_path = Path(__file__).resolve().parents[2] / "pulumi" / "__main__.py"
  runpy.run_path(stack_path)
