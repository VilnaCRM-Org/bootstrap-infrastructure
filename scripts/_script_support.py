from __future__ import annotations

import os
import shlex
import shutil
import subprocess  # nosec B404
import sys
from pathlib import Path
from typing import TextIO
from urllib.parse import unquote, urlparse


def repo_root(script_path: str) -> Path:
    """Return the repository root for a script stored under scripts/."""
    return Path(script_path).resolve().parents[1]


def split_values(value: str | None) -> list[str]:
    """Split comma- or space-delimited configuration values."""
    if not value:
        return []
    return [item for item in shlex.split(value.replace(",", " ")) if item]


def run(
    command: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    check: bool = True,
    capture_output: bool = False,
    stdout: TextIO | None = None,
) -> subprocess.CompletedProcess[str]:
    """Execute a subprocess with consistent text-mode defaults."""
    return subprocess.run(  # nosec B603
        command,
        cwd=str(cwd) if cwd is not None else None,
        env=env,
        check=check,
        capture_output=capture_output,
        stdout=stdout,
        text=True,
    )


def discover_stacks(pulumi_dir: Path, configured_stacks: str | None) -> list[str]:
    """Return explicit stack names or discover them from committed stack files."""
    if configured_stacks:
        return split_values(configured_stacks)

    return sorted(
        path.name.removeprefix("Pulumi.").removesuffix(".yaml")
        for path in pulumi_dir.glob("Pulumi.*.yaml")
        if path.name not in {"Pulumi.yaml", "Pulumi.example.yaml"}
    )


def ensure_file_backend_directory(backend_url: str) -> None:
    """Create the local Pulumi backend directory when a file:// backend is used."""
    parsed = urlparse(backend_url)
    if parsed.scheme != "file":
        return

    backend_dir = Path(unquote(parsed.path)).resolve()
    backend_dir.mkdir(parents=True, exist_ok=True)


def find_uv_binary() -> str:
    """Locate the uv executable inside or outside the container image."""
    configured_uv = os.environ.get("UV_BIN")
    if configured_uv:
        configured_path = Path(configured_uv)
        if configured_path.is_file() and os.access(configured_path, os.X_OK):
            return str(configured_path)

    uv_bin = shutil.which("uv")
    if uv_bin:
        return uv_bin

    fallback = Path("/usr/local/bin/uv")
    if fallback.is_file() and os.access(fallback, os.X_OK):
        return str(fallback)

    print("uv executable not found. Set UV_BIN or install uv.", file=sys.stderr)
    raise SystemExit(127)


def policy_import_probe(root_dir: Path) -> list[str]:
    """Build a small import probe for the policy-pack environment."""
    probe = (
        "import sys\n"
        f"sys.path.insert(0, {root_dir.as_posix()!r})\n"
        "import pulumi\n"
        "import pulumi_policy\n"
        "import policy.config\n"
        "import policy.guardrails\n"
        "import policy.pack\n"
    )
    return ["-c", probe]
