"""Pin the temporary installation evidence contract to the existing 24 gates."""

from __future__ import annotations

import ast
import shlex
from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def test_installation_collector_omits_only_the_not_yet_installed_app_gate() -> None:
    """Reject missing, duplicate or arbitrary contexts while keeping defaults25."""
    tree = ast.parse(
        (PROJECT_ROOT / "scripts/_github_repository_controls.py").read_text()
    )
    assignments = {
        target.id: node.value
        for node in tree.body
        if isinstance(node, ast.Assign)
        for target in node.targets
        if isinstance(target, ast.Name)
    }
    defaults = assignments["REQUIRED_STATUS_CHECKS"]
    assert isinstance(defaults, ast.Tuple)
    assert isinstance(defaults.elts[0], ast.Name)
    assert defaults.elts[0].id == "GOVERNANCE_PROMOTION_CONTEXT"
    assert ast.literal_eval(assignments["GOVERNANCE_PROMOTION_CONTEXT"]) == (
        "Governance Promotion"
    )
    existing = [ast.literal_eval(value) for value in defaults.elts[1:]]
    assert len(existing) == len(set(existing)) == 24

    workflow = yaml.safe_load(
        (PROJECT_ROOT / ".github/workflows/well-architected-evidence.yml").read_text()
    )
    triggers = workflow.get("on", workflow.get(True))
    assert triggers["workflow_dispatch"] is None
    collector = next(
        step
        for step in workflow["jobs"]["test_account_evidence"]["steps"]
        if step.get("name") == "Collect Well-Architected evidence"
    )
    script = collector["run"]
    invocation = script.split('"${HOME}/.local/bin/uv" run python', 1)[1]
    invocation = invocation.split("collector_status=$?", 1)[0]
    arguments = shlex.split(invocation.replace("\\\n", " "))
    assert arguments[:5] == [
        "./scripts/collect_well_architected_evidence.py",
        "--output",
        ".artifacts/well-architected/evidence.json",
        "--markdown-output",
        ".artifacts/well-architected/evidence.md",
    ]
    assert arguments[5::2] == ["--required-status-check"] * 24
    assert arguments[6::2] == existing
    assert "collector_status=$?\nset -e" in script
    assert 'echo "exit_code=${collector_status}" >> "${GITHUB_OUTPUT}"' in script
    assert "make verify-well-architected-questions" in script
    assert "make report-well-architected-closeout" in script
