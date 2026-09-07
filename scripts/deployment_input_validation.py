"""Prepare authenticated input checks, then run them in a separate token-free step.

The expected plan digest must come from the trusted prepare step output. A public
hash is not provenance. Run checks untrusted repository code and must execute on
an ephemeral runner with no stored credentials; this is not an OS sandbox.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess  # nosec B404
import sys
import tempfile
from pathlib import Path
from typing import Any

# Subprocess use is limited to the two reviewed fixed-argv call sites below.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from deployment_worker_runtime import load_verified_admission  # noqa: E402

MAX_PLAN_BYTES = 16 * 1024
FLAGS = ("catalog_validation", "scaffold_validation", "execution_validation")
STACKS = ("operator", "governance", "platform")
PLAN_KEYS = {
    "schema_version",
    "head_sha",
    "base_sha",
    "command",
    "target_environment",
    "stacks",
    "source",
    "commands",
    *FLAGS,
}
CREDENTIAL_KEYS = (
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "PULUMI_ACCESS_TOKEN",
    "ACTIONS_RUNTIME_TOKEN",
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _commands(plan: dict[str, Any]) -> list[list[str]]:
    """Use actual Make target bodies and existing offline test suites."""
    uv = ["uv", "run", "--frozen"]
    commands = [
        ["git", "diff", "--check", plan["base_sha"], plan["head_sha"], "--"],
        [*uv, "pytest", "-q", "tests/pulumi/test_manifest.py"],
    ]
    if plan["catalog_validation"]:
        catalog = [*uv, "python", "scripts/validate_repository_catalogs.py"]
        commands.extend([catalog, [*catalog, "--fanout-report"]])
    if plan["scaffold_validation"]:
        commands.append(
            [
                *uv,
                "pytest",
                "-q",
                "tests/unit/test_service_scaffold_generation.py",
                "tests/pulumi/test_user_service_scaffold.py",
            ]
        )
    if plan["execution_validation"]:
        commands.append([*uv, "pytest", "-q", "tests/pulumi"])
        commands.append(
            [
                *uv,
                "pytest",
                "-q",
                "tests/unit/test_ci_guardrails.py",
                "tests/unit/test_script_entrypoints.py",
            ]
        )
    return commands


def _environment(directory: str) -> dict[str, str]:
    """An allowlist, fresh home and fresh venv exclude local credential discovery."""
    return {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": directory,
        "LANG": "C.UTF-8",
        "CI": "true",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "XDG_CONFIG_HOME": directory,
        "XDG_CACHE_HOME": directory,
        "AWS_CONFIG_FILE": os.devnull,
        "AWS_SHARED_CREDENTIALS_FILE": os.devnull,
        "AWS_EC2_METADATA_DISABLED": "true",
        "UV_NO_CONFIG": "1",
        "UV_PYTHON_DOWNLOADS": "never",
        "UV_PYTHON": sys.executable,
        "UV_PROJECT_ENVIRONMENT": str(Path(directory) / "venv"),
    }


def _tool(name: str, source: Path) -> str:
    executable = shutil.which(name)
    _require(executable is not None, f"Required validation tool missing: {name}")
    resolved = Path(str(executable)).resolve()
    _require(not resolved.is_relative_to(source), "Validation tool is in PR checkout")
    return str(resolved)


def _verify_head(source: Path, head_sha: str, environment: dict[str, str]) -> None:
    # Absolute git outside the PR checkout, literal read-only arguments, no shell.
    result = subprocess.run(  # nosec B603
        [_tool("git", source), "-C", str(source), "rev-parse", "--verify", "HEAD"],
        check=True,
        shell=False,
        capture_output=True,
        text=True,
        env=environment,
        timeout=30,
    )
    _require(result.stdout.strip() == head_sha, "Checkout HEAD differs from admission")


def _canonical(plan: dict[str, Any]) -> bytes:
    return (json.dumps(plan, sort_keys=True, separators=(",", ":")) + "\n").encode()


def prepare(
    *,
    artifact_id: str,
    artifact_sha256: str,
    contract_sha256: str,
    source: str,
    plan_path: str,
    output: str,
) -> None:
    """Authenticate before writing a plan; never execute PR Python with a token."""
    contract = load_verified_admission(
        artifact_id=artifact_id,
        artifact_sha256=artifact_sha256,
        contract_sha256=contract_sha256,
    )
    checkout = Path(source).resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="deployment-prepare-") as directory:
        _verify_head(checkout, contract.identity.head_sha, _environment(directory))
    plan = {
        "schema_version": 1,
        "head_sha": contract.identity.head_sha,
        "base_sha": contract.identity.base_sha,
        "command": contract.identity.command,
        "target_environment": contract.identity.target_environment,
        "stacks": list(contract.selection.stacks),
        "source": str(checkout),
        **{flag: getattr(contract.selection, flag) for flag in FLAGS},
    }
    plan["commands"] = _commands(plan)
    payload = _canonical(plan)
    _require(len(payload) <= MAX_PLAN_BYTES, "Validation plan exceeds size limit")
    destination = Path(plan_path)
    _require(
        not destination.resolve().is_relative_to(checkout), "Plan is in PR checkout"
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("xb") as stream:
        stream.write(payload)
    with Path(output).open("a", encoding="utf-8") as stream:
        stream.write(f"plan_sha256={hashlib.sha256(payload).hexdigest()}\n")


def _read_plan(plan_path: str, expected_sha256: str) -> dict[str, Any]:
    _require(
        bool(re.fullmatch(r"[0-9a-f]{64}", expected_sha256)), "Invalid plan SHA256"
    )
    with Path(plan_path).open("rb") as stream:
        payload = stream.read(MAX_PLAN_BYTES + 1)
    _require(len(payload) <= MAX_PLAN_BYTES, "Validation plan exceeds size limit")
    _require(
        hashlib.sha256(payload).hexdigest() == expected_sha256, "Plan SHA256 differs"
    )
    plan = json.loads(payload)
    _require(
        type(plan) is dict and set(plan) == PLAN_KEYS, "Invalid validation plan fields"
    )
    _require(
        type(plan["schema_version"]) is int and plan["schema_version"] == 1,
        "Invalid validation plan version",
    )
    for field in ("head_sha", "base_sha"):
        _require(
            type(plan[field]) is str
            and bool(re.fullmatch(r"[0-9a-f]{40}", plan[field])),
            "Invalid validation revision",
        )
    for flag in FLAGS:
        _require(type(plan[flag]) is bool, "Invalid validation flag")
    _require(plan["command"] in ("plan", "up"), "Invalid deployment command")
    _require(plan["target_environment"] in ("test", "prod"), "Invalid account")
    scopes = plan["stacks"]
    _require(
        type(scopes) is list
        and scopes == [scope for scope in STACKS if scope in scopes],
        "Invalid validation scopes",
    )
    _require(
        type(plan["source"]) is str and Path(plan["source"]).is_absolute(),
        "Invalid checkout path",
    )
    _require(plan["commands"] == _commands(plan), "Validation commands differ")
    _require(payload == _canonical(plan), "Validation plan is not canonical")
    return plan


def run(*, plan_path: str, plan_sha256: str) -> None:
    """Execute fixed checks without output authority or an authenticated parent."""
    _require(
        not any(os.environ.get(key) for key in CREDENTIAL_KEYS),
        "Run must execute in a separate credential-free workflow step",
    )
    plan = _read_plan(plan_path, plan_sha256)
    source = Path(plan["source"]).resolve(strict=True)
    _require(str(source) == plan["source"], "Checkout path changed")
    with tempfile.TemporaryDirectory(prefix="deployment-validation-") as directory:
        environment = _environment(directory)
        _verify_head(source, plan["head_sha"], environment)
        commands = [
            [_tool(command[0], source), *command[1:]] for command in plan["commands"]
        ]
        # _read_plan requires the authenticated digest and exact fixed registry.
        # Tools resolve outside PR source before it executes; children get no auth
        # environment. PR code is intentionally tested on a credential-free runner.
        for command in commands:
            subprocess.run(  # nosec B603
                command,
                cwd=source,
                env=environment,
                check=True,
                shell=False,
                timeout=1200,
            )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="mode", required=True)
    admission = commands.add_parser("prepare")
    for name in (
        "artifact-id",
        "artifact-sha256",
        "contract-sha256",
        "source",
        "plan-path",
        "output",
    ):
        admission.add_argument(f"--{name}", required=True)
    execute = commands.add_parser("run")
    for name in ("plan-path", "plan-sha256"):
        execute.add_argument(f"--{name}", required=True)
    arguments = vars(parser.parse_args(argv))
    mode = arguments.pop("mode")
    if mode == "prepare":
        prepare(**arguments)
    else:
        run(**arguments)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
