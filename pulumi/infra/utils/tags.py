"""Tagging helpers for infrastructure resources."""

from __future__ import annotations

from ..bootstrap_settings import BootstrapSettings
from ..config import settings as default_settings


def base_tags(
    extra: dict[str, str] | None = None,
    *,
    settings: BootstrapSettings | None = None,
    app_name: str | None = None,
) -> dict[str, str]:
    """Return the standard tag set merged with optional extra tags."""
    active_settings = settings or default_settings
    return active_settings.base_tags(extra, app_name=app_name)
