"""Authenticate input checks, then execute PR code in a fresh offline container.

The expected plan digest comes from trusted prepare output; a hash is not
provenance. Docker provides the filesystem/PID boundary, not environment clearing.
PR-authored checks remain PR code, not independent acceptance evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess  # nosec B404
import sys
import tempfile
from pathlib import Path
from typing import Any

# Subprocess use is limited to the reviewed fixed-argv call sites below.
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
    uv = ["uv", "run", "--frozen", "--no-sync", "--offline"]
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
    """Fresh host-tool settings; container execution supplies its frozen venv."""
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


def _verify_base(source: Path, base_sha: str, environment: dict[str, str]) -> None:
    try:
        _execute(
            [
                _tool("git", source),
                "-C",
                str(source),
                "cat-file",
                "-e",
                base_sha + "^{commit}",
            ],
            environment,
        )
    except subprocess.CalledProcessError as error:
        raise ValueError(
            "Checkout is missing admitted base commit; fetch full history"
        ) from error


def _execute(command: list[str], environment: dict[str, str]) -> str:
    # Fixed trusted argv, absolute executable outside PR checkout, never a shell.
    result = subprocess.run(  # nosec B603
        command,
        env=environment,
        check=True,
        shell=False,
        capture_output=True,
        text=True,
        timeout=1200,
    )
    return result.stdout


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
        _verify_base(checkout, contract.identity.base_sha, _environment(directory))
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


def _image_id(path: Path) -> str:
    value = path.read_text().strip()
    _require(
        bool(re.fullmatch(r"sha256:[0-9a-f]{64}", value)), "Invalid built image ID"
    )
    return value


def _build_image(source: Path, directory: Path, environment: dict[str, str]) -> str:
    """Only the trusted Dockerfile and two committed dependency files enter builds."""
    docker = _tool("docker", source)
    context = directory / "dependencies"
    context.mkdir()
    for name in ("pyproject.toml", "uv.lock"):
        content = _execute(
            [
                _tool("git", source),
                "-C",
                str(source),
                "show",
                "HEAD:" + name,
            ],
            environment,
        )
        (context / name).write_text(content)
    recipe = context / "Dockerfile"
    trusted = (Path(__file__).resolve().parents[1] / "Dockerfile").read_text()
    boundary = "FROM runtime-base AS dev"
    _require(trusted.count(boundary) == 1, "Trusted runtime-base stage is unavailable")
    recipe.write_text(
        trusted.split(boundary)[0] + "FROM runtime-base AS validation\n"
        "USER root\n"
        "RUN mkdir -p /deps /home/dev/.venvs/bootstrap-infrastructure "
        "/home/dev/.cache/uv "
        "&& chown -R dev:dev /deps /home/dev/.venvs /home/dev/.cache\n"
        "COPY --chown=dev:dev pyproject.toml uv.lock /deps/\n"
        "USER dev\nWORKDIR /deps\n"
        "RUN uv sync --frozen --all-groups --no-install-project\n"
    )
    image_id = directory / "dependencies.iid"
    _execute(
        [
            docker,
            "build",
            "--iidfile",
            str(image_id),
            "--file",
            str(recipe),
            str(context),
        ],
        environment,
    )
    return _image_id(image_id)


def _mount(source: Path, destination: str) -> list[str]:
    _require(
        not any(char in str(source) for char in (",", "\n", "\r")), "Invalid mount path"
    )
    return ["--mount", f"type=bind,src={source},dst={destination},readonly"]


def _container_command(
    source: Path, plan: Path, digest: str, image_id: str
) -> list[str]:
    runtime = Path(__file__).resolve().parent
    entry = (
        "import sys; sys.path.insert(0, '/trusted'); "
        "from deployment_input_validation import _inside; _inside(sys.argv[1])"
    )
    # Private container tmpfs, never a shared host temporary path.
    temporary_mount = "/tmp:rw,noexec,nosuid,mode=1777"  # nosec B108
    return [
        _tool("docker", source),
        "run",
        "--rm",
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--user=1000:1000",
        "--tmpfs",
        "/work:rw,exec,uid=1000,gid=1000,mode=0700",
        "--tmpfs",
        temporary_mount,
        *_mount(source, "/source"),
        *_mount(runtime, "/trusted"),
        *_mount(plan, "/validation-plan.json"),
        image_id,
        "python3",
        "-I",
        "-c",
        entry,
        digest,
    ]


def _inside(digest: str) -> None:
    """Fixed container entry; never dispatched by the host CLI."""
    plan = _read_plan("/validation-plan.json", digest)
    source = Path("/work/source")
    shutil.copytree("/source", source, symlinks=True)
    environment = _environment("/work/home")
    environment["UV_PROJECT_ENVIRONMENT"] = "/home/dev/.venvs/bootstrap-infrastructure"
    Path(environment["HOME"]).mkdir()
    environment["TMPDIR"] = "/work/tmp"
    Path(environment["TMPDIR"]).mkdir()
    _verify_head(source, plan["head_sha"], environment)
    _verify_base(source, plan["base_sha"], environment)
    for command in plan["commands"]:
        # PR execution happens only here, inside the fresh container. Fixed registry
        # uses preinstalled dependencies; network is disabled by the host launcher.
        subprocess.run(  # nosec B603
            [_tool(command[0], source), *command[1:]],
            cwd=source,
            env=environment,
            check=True,
            shell=False,
            timeout=1200,
        )


def run(*, plan_path: str, plan_sha256: str) -> None:
    """Build without credentials, then run solely inside the offline container."""
    _require(
        not any(os.environ.get(key) for key in CREDENTIAL_KEYS),
        "Run must execute in a separate credential-free workflow step",
    )
    plan = _read_plan(plan_path, plan_sha256)
    source = Path(plan["source"]).resolve(strict=True)
    _require(str(source) == plan["source"], "Checkout path changed")
    _require(
        (source / ".git").is_dir() and not (source / ".git").is_symlink(),
        "Validation requires a self-contained Git checkout",
    )
    with tempfile.TemporaryDirectory(prefix="deployment-validation-") as directory:
        environment = _environment(directory)
        _verify_head(source, plan["head_sha"], environment)
        _verify_base(source, plan["base_sha"], environment)
        snapshot = Path(directory) / "plan.json"
        snapshot.write_bytes(_canonical(plan))
        # Disable runner workflow command interpretation before any untrusted
        # dependency/build/test output. The random resume token never enters Docker.
        token = secrets.token_hex(32)
        print(f"::stop-commands::{token}", flush=True)
        try:
            image_id = _build_image(source, Path(directory), environment)
            result = _execute(
                _container_command(source, snapshot, plan_sha256, image_id), environment
            )
            print(result, end="", flush=True)
        finally:
            print(f"::{token}::", flush=True)


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
