#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from _pulumi_command_support import (
    CommandContext,
    StackCommand,
    _emit_stderr,
    _plan_file,
    _preview_file,
    _pulumi_command,
    _run_stack_command,
    _safe_artifact_stem,
    _select_or_init_stack,
    _uses_file_backend,
)
from _script_support import (
    discover_stacks,
    ensure_file_backend_directory,
    repo_root,
    run,
)

__all__ = [
    "CommandContext",
    "StackCommand",
    "_emit_stderr",
    "_plan_file",
    "_preview_file",
    "_pulumi_command",
    "_run_stack_command",
    "_safe_artifact_stem",
    "_select_or_init_stack",
    "_uses_file_backend",
]

COMMANDS_WITH_POLICY_PACK = {"preview", "plan", "up", "drift"}
SUPPORTED_COMMANDS = {
    "preview",
    "plan",
    "up",
    "up-plan",
    "refresh",
    "drift",
    "destroy",
}


def _resolve_path(root_dir: Path, raw_path: str) -> Path:
    path = Path(raw_path)
    if path.is_absolute():
        return path
    return root_dir / path


def _configured_stack_names(
    command: str, pulumi_dir: Path, env: dict[str, str]
) -> list[str]:
    if env.get("PULUMI_STACK"):
        return [env["PULUMI_STACK"]]

    if command == "drift":
        configured_stacks = env.get("PULUMI_DRIFT_STACKS")
    else:
        configured_stacks = env.get("PULUMI_PREVIEW_STACKS")
    return discover_stacks(pulumi_dir, configured_stacks)


def _validate_secrets_provider(secrets_provider: str) -> int | None:
    if not secrets_provider:
        print(
            "error: PULUMI_SECRETS_PROVIDER must be set to an awskms:// URI.",
            file=sys.stderr,
        )
        return 1
    if not secrets_provider.startswith("awskms://"):
        print(
            "error: PULUMI_SECRETS_PROVIDER must be an awskms:// URI.",
            file=sys.stderr,
        )
        return 1
    return None


def _prepare_policy_pack(root_dir: Path, env: dict[str, str]) -> None:
    run(
        [sys.executable, str(root_dir / "scripts" / "prepare_policy_pack.py")],
        cwd=root_dir,
        env=env,
    )


def _write_preview_summary(
    root_dir: Path,
    preview_file: Path,
    summary_file: Path,
    *,
    env: dict[str, str],
) -> None:
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


def _write_plan_outputs(
    output_file: str, plan_files: list[Path], plan_dir: Path
) -> None:
    with Path(output_file).open("a", encoding="utf-8") as handle:
        handle.write(f"plan_dir={plan_dir}\n")
        if len(plan_files) == 1:
            handle.write(f"plan_file={plan_files[0]}\n")
        handle.write("plan_files<<EOF\n")
        for plan_path in plan_files:
            handle.write(f"{plan_path}\n")
        handle.write("EOF\n")


def _context_from_environment() -> CommandContext:
    root_dir = repo_root(__file__)
    env = os.environ.copy()
    return CommandContext(
        root_dir=root_dir,
        env=env,
        pulumi_dir=_resolve_path(root_dir, env.get("PULUMI_DIR", "pulumi")),
        policy_pack_dir=_resolve_path(root_dir, env.get("POLICY_PACK_DIR", "policy")),
        plan_dir=_resolve_path(
            root_dir, env.get("PULUMI_PLAN_DIR", ".artifacts/pulumi-plan")
        ),
        preview_artifact_dir=_resolve_path(
            root_dir, env.get("PREVIEW_ARTIFACT_DIR", ".artifacts/pulumi-preview")
        ),
        backend_url=env.get(
            "PULUMI_BACKEND_URL", (root_dir / ".pulumi-backend").resolve().as_uri()
        ),
        secrets_provider=env.get("PULUMI_SECRETS_PROVIDER", ""),
        runner=run,
    )


def _login_and_prepare(command: str, context: CommandContext) -> None:
    ensure_file_backend_directory(context.backend_url)
    context.env.setdefault("PULUMI_BACKEND_URL", context.backend_url)
    run(
        [
            "pulumi",
            "-C",
            str(context.pulumi_dir),
            "login",
            "--non-interactive",
            context.backend_url,
        ],
        env=context.env,
    )

    if command in COMMANDS_WITH_POLICY_PACK:
        _prepare_policy_pack(context.root_dir, context.env)


def _prepare_plan_artifacts(context: CommandContext) -> Path:
    context.plan_dir.mkdir(parents=True, exist_ok=True)
    context.preview_artifact_dir.mkdir(parents=True, exist_ok=True)
    for preview_file in context.preview_artifact_dir.glob("*.json"):
        preview_file.unlink()
    summary_file = context.preview_artifact_dir / "summary.md"
    if summary_file.exists():
        summary_file.unlink()
    return summary_file


def _run_plan_command(context: CommandContext, stacks: list[str]) -> int:
    summary_file = _prepare_plan_artifacts(context)
    plan_files: list[Path] = []

    for stack in stacks:
        select_failure = _select_or_init_stack(context, stack)
        if select_failure is not None:
            return select_failure

        plan_path = _plan_file(context.plan_dir, stack)
        plan_files.append(plan_path)
        preview_file = _preview_file(context.preview_artifact_dir, stack)
        with preview_file.open("w", encoding="utf-8") as handle:
            _run_stack_command(
                context,
                StackCommand("plan", stack, plan_path=plan_path, stdout=handle),
            )
        _write_preview_summary(
            context.root_dir,
            preview_file,
            summary_file,
            env=context.env,
        )

    if output_file := context.env.get("GITHUB_OUTPUT"):
        _write_plan_outputs(output_file, plan_files, context.plan_dir)
    print(summary_file.read_text(encoding="utf-8"), end="")
    return 0


def _selected_plan_path(
    context: CommandContext, selected_plan_file: str | None, stack: str
) -> Path:
    if selected_plan_file:
        return _resolve_path(context.root_dir, selected_plan_file)
    return _plan_file(context.plan_dir, stack)


def _run_up_plan_command(context: CommandContext, stacks: list[str]) -> int:
    selected_plan_file = context.env.get("PULUMI_PLAN_FILE")
    if selected_plan_file and len(stacks) > 1:
        print(
            "error: PULUMI_PLAN_FILE can only be used with a single selected stack.",
            file=sys.stderr,
        )
        return 1

    for stack in stacks:
        select_failure = _select_or_init_stack(context, stack)
        if select_failure is not None:
            return select_failure

        plan_path = _selected_plan_path(context, selected_plan_file, stack)
        if not plan_path.is_file():
            print(f"error: Pulumi plan file not found: {plan_path}", file=sys.stderr)
            return 1
        _run_stack_command(
            context,
            StackCommand("up-plan", stack, plan_path=plan_path),
        )
    return 0


def _run_regular_command(
    command: str, context: CommandContext, stacks: list[str]
) -> int:
    for stack in stacks:
        select_failure = _select_or_init_stack(context, stack)
        if select_failure is not None:
            return select_failure
        _run_stack_command(context, StackCommand(command, stack))
    return 0


def _dispatch_command(command: str, context: CommandContext, stacks: list[str]) -> int:
    _login_and_prepare(command, context)
    if command == "plan":
        return _run_plan_command(context, stacks)
    if command == "up-plan":
        return _run_up_plan_command(context, stacks)
    return _run_regular_command(command, context, stacks)


def _run_command(command: str) -> int:
    context = _context_from_environment()
    provider_failure = _validate_secrets_provider(context.secrets_provider)
    stacks = _configured_stack_names(command, context.pulumi_dir, context.env)
    status = provider_failure

    if status is None and not stacks:
        print(
            f"error: set PULUMI_STACK or commit "
            f"{context.pulumi_dir}/Pulumi.<stack>.yaml",
            file=sys.stderr,
        )
        status = 1

    if status is None:
        status = _dispatch_command(command, context, stacks)
    return status


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run repository Pulumi commands with stack safety checks."
    )
    parser.add_argument("command", choices=sorted(SUPPORTED_COMMANDS))
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    return _run_command(args.command)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
