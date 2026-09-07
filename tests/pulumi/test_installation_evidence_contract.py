"""Keep the required evidence authority separate from advisory PR data checks."""

from __future__ import annotations

import ast
from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def test_advisory_retirement_preserves_required_app_evidence_contract() -> None:
    """The schema-only replacement cannot remove or emit the required context."""
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
    contexts = [ast.literal_eval(value) for value in defaults.elts[1:]]
    assert len(contexts) == len(set(contexts)) == 24
    assert "Test Account Evidence" in contexts
    legacy = yaml.safe_load(
        (PROJECT_ROOT / ".github/workflows/well-architected-evidence.yml").read_text()
    )
    assert "Test Account Evidence" not in {
        job["name"] for job in legacy["jobs"].values()
    }
    trusted = yaml.safe_load(
        (PROJECT_ROOT / ".github/workflows/trusted-well-architected.yml").read_text()
    )
    triggers = trusted.get("on", trusted.get(True))
    assert set(triggers) == {"workflow_dispatch"}
    for job in trusted["jobs"].values():
        assert job["if"] == "github.ref == 'refs/heads/main' && github.run_attempt == 1"
    collector = next(
        step
        for step in trusted["jobs"]["collect"]["steps"]
        if step.get("name") == "Execute the complete trusted collector"
    )
    assert "scripts/publish_well_architected.py collect" in collector["run"]
    assert "--required-status-check" not in collector["run"]
