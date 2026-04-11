#!/usr/bin/env python3
from __future__ import annotations

import os

from _script_support import find_uv_binary, repo_root, run, split_values


def main() -> int:
    root_dir = repo_root(__file__)
    default_targets = [
        "tests/unit/test_environment_component.py",
        "tests/unit/test_guardrails.py",
    ]

    uv_bin = find_uv_binary()
    mutation_paths = split_values(os.environ.get("MUTATION_PATHS", "pulumi/app"))
    mutation_test_targets = (
        split_values(os.environ.get("MUTATION_TEST_TARGETS")) or default_targets
    )
    mutation_tests_dir = os.environ.get("MUTATION_TESTS_DIR", "tests/unit")
    mutation_coverage_targets = (
        split_values(os.environ.get("MUTATION_COVERAGE_TARGETS"))
        or mutation_test_targets
    )
    mutation_time_multiplier = os.environ.get("MUTATION_TEST_TIME_MULTIPLIER", "3")
    mutation_runner = os.environ.get(
        "MUTATION_RUNNER",
        f"{uv_bin} run pytest -q {' '.join(mutation_test_targets)}",
    )

    for coverage_file in root_dir.glob(".coverage*"):
        if coverage_file.name == ".coveragerc":
            continue
        if coverage_file.is_file():
            coverage_file.unlink()

    coverage_flags = [f"--cov={mutation_path}" for mutation_path in mutation_paths]
    run(
        [
            uv_bin,
            "run",
            "pytest",
            "-q",
            *coverage_flags,
            "--cov-branch",
            "--cov-report=",
            *mutation_coverage_targets,
        ],
        cwd=root_dir,
    )

    run(
        [
            uv_bin,
            "run",
            "mutmut",
            "run",
            "--paths-to-mutate",
            " ".join(mutation_paths),
            "--runner",
            mutation_runner,
            "--tests-dir",
            mutation_tests_dir,
            "--test-time-multiplier",
            mutation_time_multiplier,
            "--use-coverage",
        ],
        cwd=root_dir,
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
