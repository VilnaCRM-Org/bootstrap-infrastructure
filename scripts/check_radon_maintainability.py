#!/usr/bin/env python3
"""Fail when repository maintainability drops below the agreed Radon baseline."""

from __future__ import annotations

import argparse
import json
import subprocess  # nosec B404 - this guardrail intentionally shells out.
import sys
from typing import TypedDict

MIN_RANK_ORDER = {"A": 3, "B": 2, "C": 1}
DEFAULT_PATHS = ("pulumi/infra", "policy_pack", "scripts")
DEFAULT_EXCLUDES = ("pulumi/venv/*", "**/__pycache__/*")


class MaintainabilityResult(TypedDict):
    """Typed Radon maintainability result for one module."""

    mi: float
    rank: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate Radon maintainability index thresholds.",
    )
    parser.add_argument(
        "paths",
        nargs="*",
        default=list(DEFAULT_PATHS),
        help="Repository paths to inspect.",
    )
    parser.add_argument(
        "--minimum-rank",
        choices=tuple(MIN_RANK_ORDER),
        default="B",
        help="Lowest maintainability rank allowed in CI.",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=list(DEFAULT_EXCLUDES),
        help="Glob pattern to exclude from Radon analysis.",
    )
    return parser.parse_args()


def radon_mi(
    paths: list[str],
    excludes: list[str],
) -> dict[str, MaintainabilityResult]:
    command = [
        "radon",
        "mi",
        *paths,
        "-j",
        "-s",
        "-e",
        ",".join(excludes),
    ]
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
    )  # nosec B603
    if result.returncode != 0:
        raise RuntimeError(f"radon mi failed: {result.stderr.strip()}")
    payload = json.loads(result.stdout)
    if not isinstance(payload, dict):
        raise ValueError("radon mi returned an unexpected payload.")
    typed_payload: dict[str, MaintainabilityResult] = {}
    for path, result in payload.items():
        if not isinstance(path, str) or not isinstance(result, dict):
            raise ValueError("radon mi returned an unexpected payload.")
        rank = result.get("rank")
        score = result.get("mi")
        if not isinstance(rank, str) or not isinstance(score, (int, float)):
            raise ValueError(f"radon mi returned invalid data for {path}.")
        typed_payload[path] = {"rank": rank, "mi": float(score)}
    return typed_payload


def failing_modules(
    payload: dict[str, MaintainabilityResult],
    minimum_rank: str,
) -> list[tuple[str, str, float]]:
    minimum_order = MIN_RANK_ORDER[minimum_rank]
    failures: list[tuple[str, str, float]] = []
    for path, result in sorted(payload.items()):
        rank = result["rank"]
        score = result["mi"]
        if MIN_RANK_ORDER[rank] < minimum_order:
            failures.append((path, rank, score))
    return failures


def main() -> int:
    args = parse_args()
    payload = radon_mi(args.paths, args.exclude)
    failures = failing_modules(payload, args.minimum_rank)

    if failures:
        for path, rank, score in failures:
            print(
                f"[fail] {path}: maintainability rank {rank} ({score:.2f}) "
                f"is below required rank {args.minimum_rank}.",
                file=sys.stderr,
            )
        return 1

    for path, result in sorted(payload.items()):
        rank = result["rank"]
        score = float(result["mi"])
        print(f"[ok] {path}: {rank} ({score:.2f})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
