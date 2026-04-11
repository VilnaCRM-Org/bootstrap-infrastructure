"""Tests for the Pulumi project manifest."""

from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[2]
PULUMI_MANIFEST = PROJECT_ROOT / "pulumi" / "Pulumi.yaml"
POLICY_MANIFEST = PROJECT_ROOT / "policy" / "PulumiPolicy.yaml"
POLICY_REQUIREMENTS = PROJECT_ROOT / "policy" / "requirements.txt"
POLICY_CONFIG = PROJECT_ROOT / "policy" / "vilnacrm_guardrails.yaml"


def test_manifest_declares_python_runtime() -> None:
    """Ensure the Pulumi manifest declares the expected runtime and project name."""
    manifest = yaml.safe_load(PULUMI_MANIFEST.read_text(encoding="utf-8"))

    assert manifest["runtime"]["name"] == "python"
    assert manifest["name"] == "bootstrap-infrastructure"


def test_policy_pack_manifest_declares_python_runtime() -> None:
    """Ensure the policy pack advertises the expected Python runtime contract."""
    manifest = yaml.safe_load(POLICY_MANIFEST.read_text(encoding="utf-8"))
    content = POLICY_REQUIREMENTS.read_text(encoding="utf-8")
    lines = {line.strip() for line in content.splitlines() if line.strip()}
    config = yaml.safe_load(POLICY_CONFIG.read_text(encoding="utf-8"))

    assert manifest["runtime"]["name"] == "python"
    assert manifest["runtime"]["options"]["virtualenv"] == ".venv"
    assert "guardrails" in manifest["description"]
    assert "pulumi>=3.200.0,<4" in lines
    assert "pulumi-policy>=1.20.0,<2" in lines
    assert config["required_tags"] == [
        "Project",
        "Environment",
        "Owner",
        "CostCenter",
    ]
    assert "eu-central-1" in config["allowed_regions"]
