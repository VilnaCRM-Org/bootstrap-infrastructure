#!/usr/bin/env python3
from __future__ import annotations

import os
import shutil
import subprocess  # nosec B404
import sys
from pathlib import Path


def _version(command: list[str]) -> str:
    result = subprocess.run(  # nosec B603
        command,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def main() -> int:
    compose_env_file = os.environ.get("COMPOSE_ENV_FILE", ".env.empty")
    compose_service = os.environ.get("COMPOSE_SERVICE", "pulumi")
    pulumi_dir = Path(os.environ.get("PULUMI_DIR", "pulumi"))

    if shutil.which("docker") is None:
        print("docker: missing", file=sys.stderr)
        return 1

    try:
        docker_version = _version(["docker", "--version"])
        compose_version = _version(["docker", "compose", "version", "--short"])
    except subprocess.CalledProcessError:
        print("docker compose: missing", file=sys.stderr)
        return 1

    print(f"docker: {docker_version}")
    print(f"docker compose: {compose_version}")
    print(f"effective env file: {compose_env_file}")
    print(f"compose service: {compose_service}")
    print(f"pulumi directory: {pulumi_dir}")

    if not pulumi_dir.is_dir():
        print(f"pulumi directory missing: {pulumi_dir}", file=sys.stderr)
        return 1

    if Path(compose_env_file).is_file():
        print("env file present: yes")
        return 0

    print("env file present: no", file=sys.stderr)
    return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
