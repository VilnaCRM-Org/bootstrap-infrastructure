import os
import sys
from pathlib import Path

import pytest

os.environ.setdefault("PULUMI_ALLOW_TEST_DEFAULTS", "1")

sys.path.append(str(Path(__file__).resolve().parents[2] / "pulumi"))

from infra.config import _sanitize_bucket_component, central_logging_bucket_name, settings, state_bucket_name_for_repo  # noqa: E402


def test_sanitize_bucket_component_normalizes_case_and_invalid_chars():
  assert _sanitize_bucket_component("My_App.repo", "repoSlug") == "my-app.repo"


def test_sanitize_bucket_component_collapses_sequences_and_trims():
  dirty = "..My--Repo__Name.."
  assert _sanitize_bucket_component(dirty, "repoSlug") == "my-repo-name"


def test_sanitize_bucket_component_rejects_empty_result():
  with pytest.raises(ValueError):
    _sanitize_bucket_component("???", "repoSlug")


def test_sanitize_bucket_component_length_constraints():
  with pytest.raises(ValueError):
    _sanitize_bucket_component("aa", "repoSlug")


def test_sanitize_bucket_component_rejects_ipv4():
  with pytest.raises(ValueError):
    _sanitize_bucket_component("192.168.0.1", "repoSlug")


def test_sanitize_bucket_component_rejects_ipv6():
  with pytest.raises(ValueError):
    _sanitize_bucket_component("2001:0db8:85a3:0000:0000:8a2e:0370:7334", "repoSlug")


def test_state_bucket_name_length_guard(monkeypatch):
  monkeypatch.setattr(settings, "environment", "e" * 40)
  with pytest.raises(ValueError):
    state_bucket_name_for_repo("r" * 40)


def test_central_logging_bucket_length_guard(monkeypatch):
  monkeypatch.setattr(settings, "logging_prefix", "x" * 50)
  monkeypatch.setattr(settings, "environment", "e" * 40)
  with pytest.raises(ValueError):
    central_logging_bucket_name("regionname")
