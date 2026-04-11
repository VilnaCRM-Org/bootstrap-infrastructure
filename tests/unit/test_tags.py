from infra.config import settings
from infra.utils.tags import base_tags

import pulumi


def test_base_tags_with_app(monkeypatch):
    monkeypatch.setattr(pulumi, "get_project", lambda: "bootstrap-infrastructure")
    monkeypatch.setattr(settings, "environment", "test")
    monkeypatch.setattr(settings, "owner", "owner")
    monkeypatch.setattr(settings, "cost_center", "cost")
    monkeypatch.setattr(settings, "repo", "app")

    tags = base_tags({"Extra": "value"})
    assert tags["Project"] == "bootstrap-infrastructure"  # nosec B101
    assert tags["Environment"] == "test"  # nosec B101
    assert tags["Owner"] == "owner"  # nosec B101
    assert tags["CostCenter"] == "cost"  # nosec B101
    assert tags["App"] == "app"  # nosec B101
    assert tags["Extra"] == "value"  # nosec B101


def test_base_tags_without_app(monkeypatch):
    monkeypatch.setattr(pulumi, "get_project", lambda: "bootstrap-infrastructure")
    monkeypatch.setattr(settings, "environment", "prod")
    monkeypatch.setattr(settings, "owner", "owner")
    monkeypatch.setattr(settings, "cost_center", "cost")
    monkeypatch.setattr(settings, "repo", None)

    tags = base_tags()
    assert tags["Project"] == "bootstrap-infrastructure"  # nosec B101
    assert "App" not in tags  # nosec B101
