#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path

from _script_support import (
    discover_stacks,
    ensure_file_backend_directory,
    repo_root,
    run,
)


def _uses_file_backend(backend_url: str) -> bool:
    """Return whether Pulumi preview should treat the backend as ephemeral."""
    return backend_url.startswith("file://")


def _emit_stderr(stderr: str) -> None:
    """Print Pulumi stderr only when the command actually produced it."""
    if stderr:
        print(stderr, file=sys.stderr, end="")


def _shared_backend_select_failure(stack: str, stderr: str, returncode: int) -> int:
    """Reject missing stacks in shared backends without creating them implicitly."""
    print(
        "error: shared-backend previews will not create missing stacks. "
        f"Create `{stack}` explicitly or fix PULUMI_PREVIEW_STACKS.",
        file=sys.stderr,
    )
    _emit_stderr(stderr)
    return returncode or 1


def _missing_secrets_provider_failure(stderr: str, returncode: int) -> int:
    """Require an explicit AWS KMS provider before creating local scratch stacks."""
    print(
        "error: file-backed previews require PULUMI_SECRETS_PROVIDER to "
        "create missing stacks with AWS KMS.",
        file=sys.stderr,
    )
    _emit_stderr(stderr)
    return returncode or 1


def _init_file_backend_stack(
    pulumi_dir: Path,
    stack: str,
    *,
    env: dict[str, str],
    secrets_provider: str,
) -> int | None:
    """Create the stack with the configured AWS KMS provider when needed."""
    init_result = run(
        [
            "pulumi",
            "-C",
            str(pulumi_dir),
            "stack",
            "init",
            stack,
            "--non-interactive",
            "--secrets-provider",
            secrets_provider,
        ],
        check=False,
        capture_output=True,
        env=env,
    )
    if init_result.returncode == 0:
        return None

    _emit_stderr(init_result.stderr)
    return init_result.returncode or 1


def _select_stack_for_preview(
    pulumi_dir: Path,
    stack: str,
    *,
    env: dict[str, str],
    uses_file_backend: bool,
    secrets_provider: str,
) -> int | None:
    """Select the target stack and fail fast on shared-backend typos."""
    select_command = [
        "pulumi",
        "-C",
        str(pulumi_dir),
        "stack",
        "select",
        stack,
        "--non-interactive",
    ]

    select_result = run(
        select_command,
        check=False,
        capture_output=True,
        env=env,
    )
    if select_result.returncode == 0:
        return None

    if not uses_file_backend:
        return _shared_backend_select_failure(
            stack, select_result.stderr, select_result.returncode
        )

    if not secrets_provider:
        return _missing_secrets_provider_failure(
            select_result.stderr, select_result.returncode
        )

    return _init_file_backend_stack(
        pulumi_dir,
        stack,
        env=env,
        secrets_provider=secrets_provider,
    )


def _safe_preview_artifact_stem(stack: str) -> str:
    """Build a filesystem-safe preview artifact stem without name collisions."""
    sanitized = "".join(
        character if character.isalnum() or character in "._-" else "_"
        for character in stack
    )
    digest = hashlib.sha256(stack.encode("utf-8")).hexdigest()[:8]
    return f"{sanitized or 'stack'}-{digest}"


def main() -> int:
    root_dir = repo_root(__file__)
    pulumi_dir = Path(os.environ.get("PULUMI_DIR", root_dir / "pulumi"))
    policy_pack_dir = Path(os.environ.get("POLICY_PACK_DIR", root_dir / "policy"))
    preview_artifact_dir = Path(
        os.environ.get(
            "PREVIEW_ARTIFACT_DIR", root_dir / ".artifacts" / "pulumi-preview"
        )
    )
    summary_file = preview_artifact_dir / "summary.md"
    backend_url = os.environ.get(
        "PULUMI_BACKEND_URL",
        (root_dir / ".pulumi-backend").resolve().as_uri(),
    )

    preview_artifact_dir.mkdir(parents=True, exist_ok=True)
    for preview_file in preview_artifact_dir.glob("*.json"):
        preview_file.unlink()
    if summary_file.exists():
        summary_file.unlink()

    env = os.environ.copy()
    env.setdefault("PULUMI_BACKEND_URL", backend_url)
    ensure_file_backend_directory(backend_url)
    secrets_provider = env.get("PULUMI_SECRETS_PROVIDER", "")
    run(
        [sys.executable, str(root_dir / "scripts" / "prepare_policy_pack.py")],
        cwd=root_dir,
        env=env,
    )

    stacks = discover_stacks(pulumi_dir, env.get("PULUMI_PREVIEW_STACKS"))
    if not stacks:
        print(
            f"error: no Pulumi stack configs found under {pulumi_dir}", file=sys.stderr
        )
        return 1

    run(
        ["pulumi", "-C", str(pulumi_dir), "login", "--non-interactive", backend_url],
        env=env,
    )
    uses_file_backend = _uses_file_backend(backend_url)

    for stack in stacks:
        preview_file = preview_artifact_dir / (
            f"{_safe_preview_artifact_stem(stack)}.json"
        )

        select_failure = _select_stack_for_preview(
            pulumi_dir,
            stack,
            env=env,
            uses_file_backend=uses_file_backend,
            secrets_provider=secrets_provider,
        )
        if select_failure is not None:
            return select_failure

        with preview_file.open("w", encoding="utf-8") as handle:
            run(
                [
                    "pulumi",
                    "-C",
                    str(pulumi_dir),
                    "preview",
                    "--stack",
                    stack,
                    "--non-interactive",
                    "--json",
                    "--policy-pack",
                    str(policy_pack_dir),
                ],
                env=env,
                stdout=handle,
            )

        summary = run(
            [
                "uv",
                "--project",
                str(root_dir),
                "run",
                "python",
                str(root_dir / "scripts" / "pulumi_ci_guardrails.py"),
                "summarize",
                str(preview_file),
            ],
            capture_output=True,
            env=env,
        )
        with summary_file.open("a", encoding="utf-8") as handle:
            handle.write(summary.stdout)

    print(summary_file.read_text(encoding="utf-8"), end="")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
