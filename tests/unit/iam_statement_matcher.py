"""Strict test-only IAM action/resource matching; conditions are not evaluated."""

from collections.abc import Mapping
from fnmatch import fnmatchcase
from typing import cast


def _patterns(value: object, field: str) -> list[str]:
    """Reject malformed IAM JSON instead of letting negative assertions pass."""
    values = [value] if isinstance(value, str) else value
    if not isinstance(values, list) or not values:
        raise ValueError(f"IAM {field} must be a nonempty string or list")
    if any(not isinstance(item, str) or not item.strip() for item in values):
        raise ValueError(f"IAM {field} patterns must be nonempty strings")
    return cast(list[str], values)


def iam_statement_matches(
    statement: Mapping[str, object], action: str, resource: str
) -> bool:
    """Match scope for an Allow or Deny; never claim effective AWS authorization."""
    if statement.get("Effect") not in ("Allow", "Deny"):
        raise ValueError("IAM statement requires an Allow or Deny Effect")
    if "NotAction" in statement:
        raise ValueError("NotAction is outside this test matcher's contract")
    actions = _patterns(statement.get("Action"), "Action")
    if ("Resource" in statement) == ("NotResource" in statement):
        raise ValueError("IAM statement requires exactly one Resource or NotResource")
    field = "NotResource" if "NotResource" in statement else "Resource"
    resources = _patterns(statement[field], field)
    resource_matches = any(fnmatchcase(resource, pattern) for pattern in resources)
    return any(
        fnmatchcase(action.lower(), pattern.lower()) for pattern in actions
    ) and (not resource_matches if field == "NotResource" else resource_matches)
