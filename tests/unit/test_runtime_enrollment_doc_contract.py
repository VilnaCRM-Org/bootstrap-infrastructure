"""Documentation lists must equal the renderer's credential trigger tuple."""

from __future__ import annotations

import re
from pathlib import Path

import render_runtime_seed_policies as renderer

ROOT = Path(__file__).resolve().parents[2]
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
