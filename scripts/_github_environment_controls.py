from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def environment_prevents_self_review(environment: Mapping[str, Any]) -> bool:
    """Return whether a GitHub required-reviewer rule prevents self-review."""
    if environment.get("prevent_self_review") is True:
        return True
    protection_rules = environment.get("protection_rules")
    if not isinstance(protection_rules, list):
        return False
    return any(
        isinstance(rule, Mapping)
        and rule.get("type") == "required_reviewers"
        and rule.get("prevent_self_review") is True
        for rule in protection_rules
    )
