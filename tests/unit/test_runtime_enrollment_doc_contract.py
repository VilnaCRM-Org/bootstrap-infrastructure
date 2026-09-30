"""Documentation lists must equal the renderer's credential trigger tuple."""

from __future__ import annotations

import importlib
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

renderer = importlib.import_module("render_runtime_seed_policies")

DOCS = (
    ROOT / "specs/219-test-workload-capability/runtime-enrollment.md",
    ROOT / "docs/testing.md",
)


def test_documented_credential_triggers_match_renderer():
    """Every trigger variable is named, and no undocumented AWS trigger is."""
    compose = (ROOT / "docker-compose.yml").read_text()
    assert "env_file:" in compose and "path: .env" in compose
    for doc in DOCS:
        text = doc.read_text()
        assert ".env" in text
        for name in renderer.CREDENTIAL_VARIABLES:
            assert f"`{name}`" in text, (doc, name)
    section = DOCS[0].read_text().split("`CREDENTIAL_VARIABLES`")[1]
    listed = re.findall(r"`(AWS_[A-Z_]+)`", section.split("`docker-compose.yml`")[0])
    assert listed == list(renderer.CREDENTIAL_VARIABLES)


def test_documented_forwarded_variables_match_compose_environment():
    """The documented compose forwarding list equals the pulumi service keys."""
    compose = (ROOT / "docker-compose.yml").read_text()
    block = compose.split("  pulumi:")[1].split("    environment:\n")[1]
    keys = []
    for line in block.splitlines():
        match = re.match(r" {6}- ([A-Z_]+)(?:=.*)?$", line)
        if not match:
            break
        keys.append(match.group(1))
    forwarded = [k for k in keys if k != "PYTHONPATH"]
    text = DOCS[0].read_text()
    sentence = text.split("`docker-compose.yml` forwards only")[1].split(
        "from the host"
    )[0]
    assert re.findall(r"`([A-Z_]+)`", sentence) == forwarded
