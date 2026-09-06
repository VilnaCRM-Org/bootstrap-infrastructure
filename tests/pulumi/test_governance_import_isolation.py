"""Static guard: the governance component imports no policy/app/scripts code.

The import-linter contract in ``pyproject.toml`` already forbids
``infra.governance`` from importing the graphed ``policy`` and ``app`` root
packages. ``scripts`` is CLI tooling that is intentionally not part of the
import-linter graph, so this AST check closes the remaining half of the
architecture's ``infra.governance -> {policy, app, scripts}`` isolation rule
without graphing the whole scripts package.
"""

from __future__ import annotations

import ast
from pathlib import Path

_GOVERNANCE_MODULE = (
    Path(__file__).resolve().parents[2] / "pulumi" / "infra" / "governance.py"
)
_FORBIDDEN_ROOTS = {"policy", "app", "scripts"}


def _imported_root_packages(source: str) -> set[str]:
    """Return the top-level package name of every import in the module."""
    roots: set[str] = set()
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                roots.add(alias.name.split(".", 1)[0])
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            roots.add(node.module.split(".", 1)[0])
    return roots


def test_governance_module_imports_no_policy_app_or_scripts() -> None:
    """governance.py must not import the policy pack, app layer, or scripts."""
    source = _GOVERNANCE_MODULE.read_text(encoding="utf-8")
    leaked = _imported_root_packages(source) & _FORBIDDEN_ROOTS
    assert leaked == set(), (  # nosec B101
        f"governance.py must not import {sorted(_FORBIDDEN_ROOTS)}; "
        f"found {sorted(leaked)}"
    )
