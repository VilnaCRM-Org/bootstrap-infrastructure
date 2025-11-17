from pathlib import Path

import yaml


PROJECT_ROOT = Path(__file__).resolve().parents[2]
PULUMI_MANIFEST = PROJECT_ROOT / "pulumi" / "Pulumi.yaml"


def test_manifest_declares_python_runtime() -> None:
    manifest = yaml.safe_load(PULUMI_MANIFEST.read_text(encoding="utf-8"))

    assert manifest["runtime"]["name"] == "python"
    assert manifest["name"] == "infrastructure-template"
