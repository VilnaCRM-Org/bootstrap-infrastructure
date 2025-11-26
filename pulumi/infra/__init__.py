"""
Lazy exports for infrastructure submodules.

Pulumi entrypoints (for example, ``pulumi.__main__``) import modules such as
``infra.logging_bucket`` for their side effects, but unit tests often import
``infra.config`` without needing those resources. To avoid triggering Pulumi
side effects during test discovery, only import the submodules once they are
explicitly accessed.
"""

from importlib import import_module
from typing import Any, Dict, Iterable

__all__ = ("logging_bucket", "pulumi_state")

_SUBMODULES: Dict[str, str] = {
  "logging_bucket": "infra.logging_bucket",
  "pulumi_state": "infra.pulumi_state",
}


def __getattr__(name: str) -> Any:
  module_path = _SUBMODULES.get(name)
  if module_path is None:
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")
  module = import_module(module_path)
  globals()[name] = module
  return module


def __dir__() -> Iterable[str]:
  return sorted(set(list(globals().keys()) + list(__all__)))
