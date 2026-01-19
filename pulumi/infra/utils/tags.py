"""Tagging helpers for infrastructure resources."""

from typing import Dict

from ..config import settings


def base_tags(extra: Dict[str, str] | None = None) -> Dict[str, str]:
  """Return the standard tag set merged with optional extra tags."""
  tags = {
    "Environment": settings.environment,
    "Owner": settings.owner,
    "CostCenter": settings.cost_center,
  }
  if settings.repo:
    tags["App"] = settings.repo
  if extra:
    tags.update(extra)
  return tags
