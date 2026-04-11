"""Typed adapters around Pulumi Output helpers for static analyzers."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any, TypeVar, cast

import pulumi

T = TypeVar("T")
U = TypeVar("U")


def apply_output(
    output: pulumi.Output[T], func: Callable[[T], pulumi.Input[U]]
) -> pulumi.Output[U]:
    """Wrap Output.apply so stricter type checkers can follow Pulumi values."""
    return cast("pulumi.Output[U]", cast(Any, output).apply(func))


def future_output(output: pulumi.Output[T]) -> Awaitable[T | None]:
    """Return the eventual value for a Pulumi output in tests."""
    return cast(Awaitable[T | None], cast(Any, output).future())
