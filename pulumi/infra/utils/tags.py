from typing import Dict

from ..config import settings


def base_tags(extra: Dict[str, str] | None = None) -> Dict[str, str]:
  tags = {
    "Environment": settings.environment,
    "Owner": settings.owner,
    "CostCenter": settings.cost_center,
    "App": settings.repo,
  }
  if extra:
    tags.update(extra)
  return tags
