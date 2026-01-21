from infra.config import settings
from infra.utils.tags import base_tags


def test_base_tags_with_app(monkeypatch):
  monkeypatch.setattr(settings, "environment", "test")
  monkeypatch.setattr(settings, "owner", "owner")
  monkeypatch.setattr(settings, "cost_center", "cost")
  monkeypatch.setattr(settings, "repo", "app")

  tags = base_tags({"Extra": "value"})
  assert tags["Environment"] == "test"
  assert tags["Owner"] == "owner"
  assert tags["CostCenter"] == "cost"
  assert tags["App"] == "app"
  assert tags["Extra"] == "value"


def test_base_tags_without_app(monkeypatch):
  monkeypatch.setattr(settings, "environment", "prod")
  monkeypatch.setattr(settings, "owner", "owner")
  monkeypatch.setattr(settings, "cost_center", "cost")
  monkeypatch.setattr(settings, "repo", None)

  tags = base_tags()
  assert "App" not in tags
