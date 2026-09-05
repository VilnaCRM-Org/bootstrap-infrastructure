#!/usr/bin/env python3
"""Require every enumerated semantic security-boundary mutant to be killed.

This supplements ordinary mutmut; it is not exhaustive module mutation coverage.
Each mutant removes one real rejection or permission ceiling in an isolated copy.
Only a pytest test failure kills it; setup/collection errors and timeouts fail.
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import shutil
import subprocess  # nosec B404
import sys
import tempfile
import xml.etree.ElementTree as ET  # nosec B405
from dataclasses import asdict, dataclass
from pathlib import Path

from _script_support import repo_root

TARGETS = (
    "tests/unit/test_github_identity.py",
    "tests/unit/test_pulumi_command_preflight.py",
    "tests/unit/test_governance_promotion.py",
    "tests/unit/test_platform_entrypoint_boundary.py",
    "tests/unit/test_security_boundary_regressions.py",
    "tests/unit/test_main_only_environments.py",
    "tests/unit/test_reviewed_script_boundaries.py",
)
GUARDS = {
    "pulumi/infra/github_identity.py": {
        "normalize_identity",
        "identity_conditions",
        "expand_subjects",
    },
    "pulumi/infra/iam/account.py": {"assert_bootstrap_account"},
}
REQUIREMENTS = {
    "scripts/pulumi_command_preflight.py": {
        "validate_request",
        "read_request",
        "claim_request",
        "verify_environments",
        "main",
    },
    "scripts/governance_promotion.py": {
        "report_scope",
        "build_proof",
        "publish_proof",
        "main",
    },
}


@dataclass(frozen=True)
class Mutant:
    """One semantic edit with a stable source location and explicit operator."""

    path: str
    function: str
    line: int
    column: int
    kind: str
    replacement: str
    operator: str


def candidates(path: str, function: ast.FunctionDef):
    """Enumerate guard bypasses and individual proof/permission weakenings."""
    for node in ast.walk(function):
        if (
            isinstance(node, ast.If)
            and function.name in GUARDS.get(path, set())
            and (isinstance(node.body[0], ast.Raise) or function.name == "_allow")
        ):
            yield node.test, "False", "bypass-rejection-or-condition"
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "require"
            and function.name in REQUIREMENTS.get(path, set())
        ):
            yield node.args[0], "True", "bypass-required-evidence"
        yield from semantic_candidates(function.name, node)


def _identity_pin_candidates(node):
    """Remove each immutable claim independently, retaining source order."""
    if isinstance(node, ast.Dict) and node.keys:
        for index in range(len(node.keys)):
            reduced = ast.Dict(
                keys=node.keys[:index] + node.keys[index + 1 :],
                values=node.values[:index] + node.values[index + 1 :],
            )
            yield node, ast.unparse(reduced), "remove-immutable-identity-pin"


def semantic_candidates(function: str, node: ast.AST):
    """Dispatch the unchanged semantic operators for each security boundary."""
    if function == "verified_promotion_status" and isinstance(node, ast.Compare):
        yield node, "True", "drop-promotion-status-predicate"
    if function == "identity_conditions":
        yield from _identity_pin_candidates(node)


def inventory(root: Path) -> list[Mutant]:
    """Build the complete configured semantic inventory; absent functions fail."""
    mutants = []
    for path in sorted(GUARDS.keys() | REQUIREMENTS.keys()):
        tree = ast.parse((root / path).read_text())
        functions = [node for node in tree.body if isinstance(node, ast.FunctionDef)]
        expected = GUARDS.get(path, set()) | REQUIREMENTS.get(path, set())
        if not expected <= {node.name for node in functions}:
            raise ValueError(f"Mutation target function disappeared: {path}")
        for function in functions:
            for node, replacement, operator in candidates(path, function):
                mutants.append(
                    Mutant(
                        path,
                        function.name,
                        node.lineno,
                        node.col_offset,
                        type(node).__name__,
                        replacement,
                        operator,
                    )
                )
    if not mutants:
        raise ValueError("Security mutation inventory is empty")
    return mutants


def _matches_expression(child, mutant):
    """Match the complete recorded AST location and expression type."""
    return (
        isinstance(child, ast.expr)
        and child.lineno == mutant.line
        and child.col_offset == mutant.column
        and type(child).__name__ == mutant.kind
    )


def _expression_locations(tree, mutant):
    """Find all matching parent slots so ambiguity fails before replacement."""
    for parent in ast.walk(tree):
        for field, value in ast.iter_fields(parent):
            values = enumerate(value) if isinstance(value, list) else [(None, value)]
            for index, child in values:
                if _matches_expression(child, mutant):
                    yield parent, field, index


def mutate(source: str, mutant: Mutant) -> str:
    """Replace exactly one AST expression; never modify the shared checkout."""
    tree = ast.parse(source)
    matches = list(_expression_locations(tree, mutant))
    if len(matches) != 1:
        raise ValueError("Mutation location must identify exactly one expression")
    parent, field, index = matches[0]
    replacement = ast.parse(mutant.replacement, mode="eval").body
    if index is None:
        setattr(parent, field, replacement)
    else:
        getattr(parent, field)[index] = replacement
    return ast.unparse(ast.fix_missing_locations(tree)) + "\n"


def _junit_cases(report: Path):
    """Require a complete JUnit report without collection or setup errors."""
    if not report.exists():
        return None
    try:
        tree = ET.parse(report)  # nosec B314 - local pytest-generated XML only
    except ET.ParseError:
        return None
    cases = list(tree.iter("testcase"))
    if not cases or any(case.find("error") is not None for case in cases):
        return None
    return cases


def classify(returncode: int, report: Path) -> str:
    """Distinguish killed mutants from infrastructure/collection failures."""
    cases = _junit_cases(report)
    if cases is None:
        return "error"
    failures = [failure for case in cases for failure in case.findall("failure")]
    if returncode == 0 and not failures:
        return "survived"
    if returncode == 1 and failures:
        return "killed"
    return "error"


def execute(root: Path, report: Path) -> str:
    """Run the existing behavioral tests with independent reports and no cache."""
    environment = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    environment.pop("PYTEST_ADDOPTS", None)
    report.unlink(missing_ok=True)
    report.with_suffix(".log").unlink(missing_ok=True)
    try:
        result = subprocess.run(  # nosec B603
            [
                sys.executable,
                "-m",
                "pytest",
                "-q",
                "--tb=short",
                "-p",
                "no:cacheprovider",
                "-p",
                "tests.security_mutation_guard",
                f"--junitxml={report}",
                *TARGETS,
            ],
            cwd=root,
            env=environment,
            capture_output=True,
            text=True,
            timeout=90,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return "timeout"
    report.with_suffix(".log").write_text(result.stdout + result.stderr)
    return classify(result.returncode, report)


def run_campaign(root: Path, output: Path) -> int:
    """Require passing baseline and zero survivors, errors, or timed-out mutants."""
    output.mkdir(parents=True, exist_ok=True)
    (output / "results.json").unlink(missing_ok=True)
    results = []
    with tempfile.TemporaryDirectory(prefix="security-mutation-") as temporary:
        isolated = Path(temporary) / "repo"
        shutil.copytree(
            root,
            isolated,
            ignore=shutil.ignore_patterns(
                ".git",
                ".venv",
                "__pycache__",
                ".artifacts",
                ".pytest_cache",
                ".mypy_cache",
                ".ruff_cache",
                ".coverage*",
                ".mutmut-cache",
                ".pulumi-backend",
                "node_modules",
            ),
        )
        baseline = execute(isolated, output / "baseline.xml")
        (output / "baseline-status.json").write_text(json.dumps({"baseline": baseline}))
        if baseline != "survived":
            raise ValueError(f"Security mutation baseline failed: {baseline}")
        for index, mutant in enumerate(inventory(isolated), start=1):
            path = isolated / mutant.path
            original = path.read_text()
            try:
                path.write_text(mutate(original, mutant))
                outcome = execute(isolated, output / f"mutant-{index:03d}.xml")
            finally:
                path.write_text(original)
            results.append(
                {
                    **asdict(mutant),
                    "outcome": outcome,
                    "source_sha256": hashlib.sha256(original.encode()).hexdigest(),
                }
            )
            print(
                f"{index}: {outcome}: {mutant.path}:{mutant.line} {mutant.operator}",
                flush=True,
            )
    (output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    failures = sum(result["outcome"] != "killed" for result in results)
    print(
        f"Security semantic mutation: {len(results) - failures}/{len(results)} killed"
    )
    return int(failures != 0)


def main() -> int:
    """Run the mandatory semantic supplement and retain an auditable ledger."""
    root = repo_root(__file__)
    return run_campaign(root, root / ".artifacts/security-mutation")


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
