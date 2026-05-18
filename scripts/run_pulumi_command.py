#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess  # nosec B404
import sys
import time
from pathlib import Path
from typing import Any

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

DEFAULT_RUNNER = run

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
COMMAND_STACK_LIST_ENV = {
    "preview": "PULUMI_PREVIEW_STACKS",
    "plan": "PULUMI_PREVIEW_STACKS",
    "up-plan": "PULUMI_PREVIEW_STACKS",
    "drift": "PULUMI_DRIFT_STACKS",
}
SUPPORTED_COMMANDS = {
    "preview",
    "plan",
    "up",
    "up-plan",
    "refresh",
    "drift",
    "destroy",
}
PLAN_MANIFEST_NAME = "manifest.json"
PLAN_MANIFEST_SCHEMA_VERSION = 1
DEFAULT_PLAN_MAX_AGE_SECONDS = 24 * 60 * 60
PLAN_DECRYPT_ERROR = "decrypting secret value: cipher: message authentication failed"
STACK_LOCK_ERROR = "the stack is currently locked"
FALSEY_ENV_VALUES = {"0", "false", "no", "off"}


def _resolve_path(root_dir: Path, raw_path: str) -> Path:
    path = Path(raw_path)
    if path.is_absolute():
        return path
    return root_dir / path


def _configured_stack_names(
    command: str, pulumi_dir: Path, env: dict[str, str]
) -> list[str]:
    stack_list_env = COMMAND_STACK_LIST_ENV.get(command)
    if stack_list_env and env.get(stack_list_env):
        return discover_stacks(pulumi_dir, env[stack_list_env])

    if env.get("PULUMI_STACK"):
        return [env["PULUMI_STACK"]]

    configured_stacks = env.get(stack_list_env) if stack_list_env else None
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
    output_file: str, plan_files: list[Path], plan_dir: Path, manifest_file: Path
) -> None:
    with Path(output_file).open("a", encoding="utf-8") as handle:
        handle.write(f"plan_dir={plan_dir}\n")
        handle.write(f"plan_manifest={manifest_file}\n")
        if len(plan_files) == 1:
            handle.write(f"plan_file={plan_files[0]}\n")
        handle.write("plan_files<<EOF\n")
        for plan_path in plan_files:
            handle.write(f"{plan_path}\n")
        handle.write("EOF\n")


def _plan_manifest_file(context: CommandContext) -> Path:
    return context.plan_dir / PLAN_MANIFEST_NAME


def _artifact_path(context: CommandContext, path: Path) -> str:
    return str(path.relative_to(context.root_dir))


def _manifest_path(context: CommandContext, value: str) -> Path:
    return context.root_dir / value


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _commit_sha(context: CommandContext) -> str:
    return (
        context.env.get("PULUMI_COMMIT_SHA")
        or context.env.get("PULUMI_EXPECTED_SHA")
        or context.env.get("GITHUB_SHA")
        or ""
    )


def _plan_now_epoch(context: CommandContext) -> int:
    if value := context.env.get("PULUMI_PLAN_NOW_EPOCH"):
        return int(value)
    return int(time.time())


def _plan_max_age_seconds(context: CommandContext) -> int:
    return int(
        context.env.get(
            "PULUMI_PLAN_MAX_AGE_SECONDS", str(DEFAULT_PLAN_MAX_AGE_SECONDS)
        )
    )


def _plan_manifest_entry(
    context: CommandContext, stack: str, plan_file: Path, preview_file: Path
) -> dict[str, str]:
    return {
        "stack": stack,
        "planFile": _artifact_path(context, plan_file),
        "planSha256": _file_sha256(plan_file),
        "previewFile": _artifact_path(context, preview_file),
        "previewSha256": _file_sha256(preview_file),
    }


def _write_plan_manifest(
    context: CommandContext, stack_entries: list[dict[str, str]]
) -> Path:
    manifest_file = _plan_manifest_file(context)
    manifest = {
        "schemaVersion": PLAN_MANIFEST_SCHEMA_VERSION,
        "createdAtEpoch": _plan_now_epoch(context),
        "commitSha": _commit_sha(context),
        "backendUrl": context.backend_url,
        "pulumiDir": _artifact_path(context, context.pulumi_dir),
        "policyPackDir": _artifact_path(context, context.policy_pack_dir),
        "stacks": stack_entries,
    }
    manifest_file.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest_file


def _load_plan_manifest(context: CommandContext) -> dict[str, Any] | None:
    manifest_file = _plan_manifest_file(context)
    if not manifest_file.is_file():
        print(
            f"error: Pulumi plan manifest not found: {manifest_file}", file=sys.stderr
        )
        return None
    return json.loads(manifest_file.read_text(encoding="utf-8"))


def _manifest_stack_entry(
    manifest: dict[str, Any], stack: str
) -> dict[str, Any] | None:
    for entry in manifest.get("stacks", []):
        if entry.get("stack") == stack:
            return entry
    print(
        f"error: Pulumi plan manifest has no entry for stack {stack}", file=sys.stderr
    )
    return None


def _validate_plan_manifest(
    context: CommandContext,
    manifest: dict[str, Any],
    stack: str,
    plan_file: Path,
) -> int | None:
    if manifest.get("schemaVersion") != PLAN_MANIFEST_SCHEMA_VERSION:
        print("error: unsupported Pulumi plan manifest schema.", file=sys.stderr)
        return 1

    plan_age = _plan_now_epoch(context) - int(manifest.get("createdAtEpoch", 0))
    if plan_age > _plan_max_age_seconds(context):
        print("error: Pulumi plan manifest is stale.", file=sys.stderr)
        return 1

    expected_sha = _commit_sha(context)
    manifest_sha = manifest.get("commitSha", "")
    if expected_sha and manifest_sha and expected_sha != manifest_sha:
        print("error: Pulumi plan commit SHA does not match checkout.", file=sys.stderr)
        return 1

    if manifest.get("backendUrl") != context.backend_url:
        print(
            "error: Pulumi plan backend URL does not match apply backend.",
            file=sys.stderr,
        )
        return 1

    entry = _manifest_stack_entry(manifest, stack)
    if entry is None:
        return 1

    recorded_plan = _manifest_path(context, entry["planFile"])
    if recorded_plan.resolve() != plan_file.resolve():
        print("error: Pulumi plan file does not match manifest entry.", file=sys.stderr)
        return 1

    if _file_sha256(plan_file) != entry.get("planSha256"):
        print("error: Pulumi plan file hash does not match manifest.", file=sys.stderr)
        return 1
    return None


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
    manifest_entries: list[dict[str, str]] = []

    for stack in stacks:
        select_failure = _select_or_init_stack(context, stack)
        if select_failure is not None:
            return select_failure

        _cancel_stale_stack_lock(context, stack)
        plan_path = _plan_file(context.plan_dir, stack)
        plan_files.append(plan_path)
        preview_file = _preview_file(context.preview_artifact_dir, stack)
        with preview_file.open("w", encoding="utf-8") as handle:
            _run_stack_command(
                context,
                StackCommand("plan", stack, plan_path=plan_path, stdout=handle),
            )
        if not plan_path.is_file():
            print(f"error: Pulumi plan file not created: {plan_path}", file=sys.stderr)
            return 1
        _write_preview_summary(
            context.root_dir,
            preview_file,
            summary_file,
            env=context.env,
        )
        manifest_entries.append(
            _plan_manifest_entry(context, stack, plan_path, preview_file)
        )

    manifest_file = _write_plan_manifest(context, manifest_entries)
    if output_file := context.env.get("GITHUB_OUTPUT"):
        _write_plan_outputs(output_file, plan_files, context.plan_dir, manifest_file)
    print(summary_file.read_text(encoding="utf-8"), end="")
    return 0


def _selected_plan_path(
    context: CommandContext, selected_plan_file: str | None, stack: str
) -> Path:
    if selected_plan_file:
        return _resolve_path(context.root_dir, selected_plan_file)
    return _plan_file(context.plan_dir, stack)


def _emit_completed_output(result: subprocess.CompletedProcess[str]) -> None:
    if result.stdout:
        print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, file=sys.stderr, end="")


def _run_with_observable_output(
    context: CommandContext, command: list[str]
) -> subprocess.CompletedProcess[str]:
    if context.runner is not DEFAULT_RUNNER:
        result = context.runner(
            command,
            env=context.env,
            check=False,
            capture_output=True,
        )
        _emit_completed_output(result)
        return result

    process = subprocess.Popen(  # nosec B603
        command,
        env=context.env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    output_parts: list[str] = []
    if process.stdout is not None:
        for line in process.stdout:
            output_parts.append(line)
            print(line, end="")
    returncode = process.wait()
    return subprocess.CompletedProcess(
        command,
        returncode,
        stdout="".join(output_parts),
        stderr="",
    )


def _plan_decrypt_fallback_enabled(context: CommandContext) -> bool:
    return context.env.get("GITHUB_ACTIONS") == "true" and bool(
        context.env.get("PULUMI_EXPECTED_SHA")
    )


def _ci_stack_lock_recovery_enabled(context: CommandContext) -> bool:
    return context.env.get("GITHUB_ACTIONS") == "true" and bool(_commit_sha(context))


def _prod_direct_apply_after_gates_enabled(context: CommandContext) -> bool:
    configured = context.env.get("PULUMI_PROD_DIRECT_APPLY_AFTER_GATES", "true")
    return (
        _plan_decrypt_fallback_enabled(context)
        and configured.strip().lower() not in FALSEY_ENV_VALUES
    )


def _run_direct_prod_apply_after_gates(
    context: CommandContext, stack: str
) -> int | None:
    print(
        "warning: applying production with guarded direct Pulumi up after "
        "the workflow preview, destructive diff, IAM validation, and "
        "environment approval gates; saved production plan replay is "
        "bypassed in CI to avoid provider-secret replay hangs; the direct "
        "apply reuses the policy-backed preview gate and skips policy-pack "
        "loading during the final apply.",
        file=sys.stderr,
    )
    return _run_up_stack(context, stack, include_policy_pack=False)


def _saved_prod_plan_recovery_enabled(
    context: CommandContext, combined_output: str, error_signature: str
) -> bool:
    return error_signature in combined_output and _plan_decrypt_fallback_enabled(
        context
    )


def _recover_failed_saved_prod_plan(
    context: CommandContext,
    stack: str,
    result: subprocess.CompletedProcess[str],
) -> int | None:
    combined_output = f"{result.stdout or ''}{result.stderr or ''}"
    if _saved_prod_plan_recovery_enabled(context, combined_output, PLAN_DECRYPT_ERROR):
        print(
            "warning: saved Pulumi plan failed with the known KMS plan-decrypt "
            "error; retrying guarded direct apply after the workflow gates.",
            file=sys.stderr,
        )
        return _run_up_stack(context, stack, include_policy_pack=False)

    if _saved_prod_plan_recovery_enabled(context, combined_output, STACK_LOCK_ERROR):
        print(
            "warning: Pulumi reported a stack lock while applying the saved "
            "production plan; running pulumi cancel for the selected stack "
            "and retrying with guarded direct apply.",
            file=sys.stderr,
        )
        context.runner(_pulumi_cancel_command(context, stack), env=context.env)
        return _run_up_stack(context, stack, include_policy_pack=False)

    return result.returncode or 1


def _run_up_plan_stack(
    context: CommandContext, stack: str, plan_path: Path
) -> int | None:
    if stack != "prod":
        _run_stack_command(
            context,
            StackCommand("up-plan", stack, plan_path=plan_path),
        )
        return None

    if _prod_direct_apply_after_gates_enabled(context):
        return _run_direct_prod_apply_after_gates(context, stack)

    result = _run_with_observable_output(
        context,
        _pulumi_command(context, StackCommand("up-plan", stack, plan_path=plan_path)),
    )
    if result.returncode == 0:
        return None

    return _recover_failed_saved_prod_plan(context, stack, result)


def _pulumi_cancel_command(context: CommandContext, stack: str) -> list[str]:
    return [
        "pulumi",
        "-C",
        str(context.pulumi_dir),
        "cancel",
        "--stack",
        stack,
        "--yes",
    ]


def _cancel_stale_stack_lock(context: CommandContext, stack: str) -> None:
    if not _ci_stack_lock_recovery_enabled(context):
        return

    result = context.runner(
        _pulumi_cancel_command(context, stack),
        env=context.env,
        check=False,
        capture_output=True,
    )
    if result.returncode == 0:
        print(
            f"warning: cleared a stale Pulumi lock for stack {stack} before "
            "running the next guarded CI operation.",
            file=sys.stderr,
        )


def _run_up_stack(
    context: CommandContext, stack: str, *, include_policy_pack: bool = True
) -> int | None:
    if not _plan_decrypt_fallback_enabled(context):
        _run_stack_command(
            context, StackCommand("up", stack, include_policy_pack=include_policy_pack)
        )
        return None

    result = _run_with_observable_output(
        context,
        _pulumi_command(
            context, StackCommand("up", stack, include_policy_pack=include_policy_pack)
        ),
    )
    if result.returncode == 0:
        return None

    combined_output = f"{result.stdout or ''}{result.stderr or ''}"
    if STACK_LOCK_ERROR in combined_output:
        print(
            "warning: Pulumi reported a stack lock during guarded direct apply; "
            "running pulumi cancel for the selected stack and retrying once.",
            file=sys.stderr,
        )
        context.runner(_pulumi_cancel_command(context, stack), env=context.env)
        _run_stack_command(
            context, StackCommand("up", stack, include_policy_pack=include_policy_pack)
        )
        return None

    return result.returncode or 1


def _run_up_plan_command(context: CommandContext, stacks: list[str]) -> int:
    selected_plan_file = context.env.get("PULUMI_PLAN_FILE")
    if selected_plan_file and len(stacks) > 1:
        print(
            "error: PULUMI_PLAN_FILE can only be used with a single selected stack.",
            file=sys.stderr,
        )
        return 1

    manifest: dict[str, Any] | None = None

    for stack in stacks:
        select_failure = _select_or_init_stack(context, stack)
        if select_failure is not None:
            return select_failure

        plan_path = _selected_plan_path(context, selected_plan_file, stack)
        if not plan_path.is_file():
            print(f"error: Pulumi plan file not found: {plan_path}", file=sys.stderr)
            return 1
        if manifest is None:
            manifest = _load_plan_manifest(context)
            if manifest is None:
                return 1
        manifest_failure = _validate_plan_manifest(context, manifest, stack, plan_path)
        if manifest_failure is not None:
            return manifest_failure
        up_plan_failure = _run_up_plan_stack(context, stack, plan_path)
        if up_plan_failure is not None:
            return up_plan_failure
    return 0


def _run_regular_command(
    command: str, context: CommandContext, stacks: list[str]
) -> int:
    for stack in stacks:
        select_failure = _select_or_init_stack(context, stack)
        if select_failure is not None:
            return select_failure
        if command == "up":
            up_failure = _run_up_stack(context, stack)
            if up_failure is not None:
                return up_failure
            continue
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
