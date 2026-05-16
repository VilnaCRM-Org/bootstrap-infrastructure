from __future__ import annotations

import argparse
import os
from collections.abc import Mapping
from pathlib import Path


def environment_value(name: str) -> str | None:
    """Return a non-empty environment variable value."""
    value = os.environ.get(name)
    return value if value else None


def apply_environment_defaults(
    args: argparse.Namespace,
    string_defaults: Mapping[str, str],
    path_defaults: Mapping[str, str],
) -> argparse.Namespace:
    """Populate omitted evidence flags from environment variables."""
    if args.pr is None:
        pr_number = environment_value("PR_NUMBER")
        if pr_number is not None:
            args.pr = int(pr_number)
    for attribute, variable in string_defaults.items():
        if getattr(args, attribute) is None:
            value = environment_value(variable)
            if value is not None:
                setattr(args, attribute, value)
    for attribute, variable in path_defaults.items():
        if getattr(args, attribute) is None:
            value = environment_value(variable)
            if value is not None:
                setattr(args, attribute, Path(value))
    return args
