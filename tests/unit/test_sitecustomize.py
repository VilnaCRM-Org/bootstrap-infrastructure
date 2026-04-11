"""Unit tests for the best-effort coverage startup shim."""

from __future__ import annotations

import builtins
import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SITECUSTOMIZE_PATH = PROJECT_ROOT / "pulumi" / "sitecustomize.py"


def _load_sitecustomize(
    monkeypatch: pytest.MonkeyPatch, coverage_module: object | None
) -> None:
    """Execute sitecustomize with a controlled coverage module."""
    module_name = "sitecustomize_under_test"
    monkeypatch.delitem(sys.modules, module_name, raising=False)
    monkeypatch.delitem(sys.modules, "coverage", raising=False)
    if coverage_module is not None:
        monkeypatch.setitem(sys.modules, "coverage", coverage_module)

    spec = importlib.util.spec_from_file_location(module_name, SITECUSTOMIZE_PATH)
    assert spec is not None
    assert spec.loader is not None

    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, module_name, module)
    spec.loader.exec_module(module)


def test_sitecustomize_starts_coverage_when_available(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Run coverage startup when the dependency is importable."""
    calls: list[str] = []

    _load_sitecustomize(
        monkeypatch,
        SimpleNamespace(process_startup=lambda: calls.append("started")),
    )

    assert calls == ["started"]


def test_sitecustomize_handles_coverage_startup_errors(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Keep Python startup best-effort when coverage initialization fails."""

    def fail() -> None:
        raise RuntimeError("boom")

    _load_sitecustomize(monkeypatch, SimpleNamespace(process_startup=fail))

    captured = capsys.readouterr()
    assert "coverage subprocess startup failed: boom" in captured.err


def test_sitecustomize_skips_startup_when_coverage_is_unavailable(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Skip coverage startup cleanly when the dependency is unavailable."""
    original_import = builtins.__import__

    def fail_for_coverage(
        name: str,
        globals_dict: object | None = None,
        locals_dict: object | None = None,
        fromlist: tuple[str, ...] = (),
        level: int = 0,
    ) -> object:
        if name == "coverage":
            raise ImportError("coverage missing")
        return original_import(name, globals_dict, locals_dict, fromlist, level)

    monkeypatch.delitem(sys.modules, "coverage", raising=False)
    monkeypatch.setattr(builtins, "__import__", fail_for_coverage)

    _load_sitecustomize(monkeypatch, coverage_module=None)

    captured = capsys.readouterr()
    assert captured.err == ""
