import runpy
from pathlib import Path

from infra import config


def test_stack_executes(monkeypatch):
    config.managed_repositories.cache_clear()
    try:
        monkeypatch.setattr(config.settings, "repo", "repo")
        monkeypatch.setattr(config.settings, "environment", "test")
        monkeypatch.setattr(config.settings, "replication_region", "us-west-2")
        monkeypatch.setattr(config.settings, "managed_repo_overrides", None)
        stack_path = Path(__file__).resolve().parents[2] / "pulumi" / "__main__.py"
        runpy.run_path(str(stack_path))
    finally:
        config.managed_repositories.cache_clear()
