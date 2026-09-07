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
from _pulumi_stack_config import (
    StackConfigError,
    prepared_stack_configuration,
    verify_provider_identity,
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

COMMANDS_WITH_POLICY_PACK = {"preview", "plan", "up", "up-plan", "drift"}
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


def _manifest_path(context: CommandContext, value: Any, field_name: str) -> Path | None:
    if not isinstance(value, str) or not value:
        print(
            f"error: Pulumi plan manifest {field_name} must be a relative path.",
            file=sys.stderr,
        )
        return None

    relative_path = Path(value)
    if relative_path.is_absolute() or ".." in relative_path.parts:
        print(
            f"error: Pulumi plan manifest {field_name} must stay under the repository.",
            file=sys.stderr,
        )
        return None

    manifest_path = (context.root_dir / relative_path).resolve()
    try:
        manifest_path.relative_to(context.root_dir.resolve())
    except ValueError:
        print(
            f"error: Pulumi plan manifest {field_name} must stay under the repository.",
            file=sys.stderr,
        )
        return None
    return manifest_path


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
) -> dict[str, Any]:
    return {
        "stack": stack,
        "planFile": _artifact_path(context, plan_file),
        "planSha256": _file_sha256(plan_file),
        "previewFile": _artifact_path(context, preview_file),
        "previewSha256": _file_sha256(preview_file),
        **(
            {"secretsProviderIdentity": context.provider_identity}
            if context.provider_identity is not None
            else {}
        ),
    }


def _write_plan_manifest(
    context: CommandContext, stack_entries: list[dict[str, Any]]
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
    try:
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        print("error: Pulumi plan manifest is not valid JSON.", file=sys.stderr)
        return None
    if not isinstance(manifest, dict):
        print("error: Pulumi plan manifest must be a JSON object.", file=sys.stderr)
        return None
    return manifest


def _manifest_stack_entry(
    manifest: dict[str, Any], stack: str
) -> dict[str, Any] | None:
    stacks = manifest.get("stacks")
    if not isinstance(stacks, list):
        print("error: Pulumi plan manifest stacks must be a list.", file=sys.stderr)
        return None

    for entry in stacks:
        if not isinstance(entry, dict):
            print(
                "error: Pulumi plan manifest stack entries must be objects.",
                file=sys.stderr,
            )
            return None
        if entry.get("stack") == stack:
            return entry
    print(
        f"error: Pulumi plan manifest has no entry for stack {stack}", file=sys.stderr
    )
    return None


def _validate_plan_manifest_age(
    context: CommandContext,
    manifest: dict[str, Any],
) -> int | None:
    try:
        plan_age = _plan_now_epoch(context) - int(manifest.get("createdAtEpoch", 0))
        max_plan_age = _plan_max_age_seconds(context)
    except (TypeError, ValueError):
        print(
            "error: Pulumi plan manifest timestamp or max age is invalid.",
            file=sys.stderr,
        )
        return 1
    if plan_age < 0:
        print("error: Pulumi plan manifest was created in the future.", file=sys.stderr)
        return 1
    if plan_age > max_plan_age:
        print("error: Pulumi plan manifest is stale.", file=sys.stderr)
        return 1
    return None


def _manifest_plan_sha(entry: dict[str, Any]) -> str | None:
    plan_sha = entry.get("planSha256")
    if not isinstance(plan_sha, str) or not plan_sha:
        print(
            "error: Pulumi plan manifest planSha256 must be a non-empty string.",
            file=sys.stderr,
        )
        return None
    return plan_sha


def _validate_plan_manifest_schema(manifest: dict[str, Any]) -> int | None:
    if manifest.get("schemaVersion") != PLAN_MANIFEST_SCHEMA_VERSION:
        print("error: unsupported Pulumi plan manifest schema.", file=sys.stderr)
        return 1
    return None


def _validate_plan_manifest_commit(
    context: CommandContext,
    manifest: dict[str, Any],
) -> int | None:
    expected_sha = _commit_sha(context)
    manifest_sha = manifest.get("commitSha", "")
    requested_sha = context.env.get("PULUMI_EXPECTED_SHA")
    if requested_sha and requested_sha != expected_sha:
        print("error: Pulumi checkout SHA differs from requested SHA.", file=sys.stderr)
        return 1
    if not expected_sha or not manifest_sha or expected_sha != manifest_sha:
        print("error: Pulumi plan commit SHA does not match checkout.", file=sys.stderr)
        return 1
    return None


def _validate_plan_manifest_backend(
    context: CommandContext,
    manifest: dict[str, Any],
) -> int | None:
    if manifest.get("backendUrl") != context.backend_url:
        print(
            "error: Pulumi plan backend URL does not match apply backend.",
            file=sys.stderr,
        )
        return 1
    return None


def _validate_plan_manifest_project(
    context: CommandContext,
    manifest: dict[str, Any],
) -> int | None:
    for field_name, expected_path in (
        ("pulumiDir", context.pulumi_dir),
        ("policyPackDir", context.policy_pack_dir),
    ):
        recorded_path = _manifest_path(context, manifest.get(field_name), field_name)
        if recorded_path is None:
            return 1
        if recorded_path.resolve() != expected_path.resolve():
            print(
                f"error: Pulumi plan {field_name} does not match apply project.",
                file=sys.stderr,
            )
            return 1
    return None


def _validate_plan_manifest_entry(
    context: CommandContext,
    entry: dict[str, Any],
    plan_file: Path,
) -> int | None:
    recorded_plan = _manifest_path(context, entry.get("planFile"), "planFile")
    if recorded_plan is None:
        return 1
    if recorded_plan.resolve() != plan_file.resolve():
        print("error: Pulumi plan file does not match manifest entry.", file=sys.stderr)
        return 1

    plan_sha = _manifest_plan_sha(entry)
    if plan_sha is None:
        return 1
    if _file_sha256(plan_file) != plan_sha:
        print("error: Pulumi plan file hash does not match manifest.", file=sys.stderr)
        return 1
    return None


def _validate_plan_manifest(
    context: CommandContext,
    manifest: dict[str, Any],
    stack: str,
    plan_file: Path,
) -> int | None:
    for validator in (
        lambda: _validate_plan_manifest_schema(manifest),
        lambda: _validate_plan_manifest_age(context, manifest),
        lambda: _validate_plan_manifest_commit(context, manifest),
        lambda: _validate_plan_manifest_backend(context, manifest),
        lambda: _validate_plan_manifest_project(context, manifest),
    ):
        status = validator()
        if status is not None:
            return status

    entry = _manifest_stack_entry(manifest, stack)
    if entry is None:
        return 1
    return _validate_plan_manifest_entry(context, entry, plan_file)


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
    manifest_entries: list[dict[str, Any]] = []

    for stack in stacks:
        select_failure = _select_or_init_stack(context, stack)
        if select_failure is not None:
            return select_failure

        plan_path = _plan_file(context.plan_dir, stack)
        plan_files.append(plan_path)
        preview_file = _preview_file(context.preview_artifact_dir, stack)
        with prepared_stack_configuration(context, stack) as prepared:
            with preview_file.open("w", encoding="utf-8") as handle:
                _run_stack_command(
                    prepared,
                    StackCommand("plan", stack, plan_path=plan_path, stdout=handle),
                )
            if plan_path.is_file():
                manifest_entries.append(
                    _plan_manifest_entry(prepared, stack, plan_path, preview_file)
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


def _run_up_plan_stack(
    context: CommandContext, stack: str, plan_path: Path
) -> int | None:
    result = _run_with_observable_output(
        context,
        _pulumi_command(context, StackCommand("up-plan", stack, plan_path=plan_path)),
    )
    # A failed saved plan never authorizes a different apply or cancellation of
    # another update. Resolve the failure and generate a fresh reviewed plan.
    return None if result.returncode == 0 else result.returncode


def _direct_ci_up_forbidden(context: CommandContext, command: str = "up") -> bool:
    if context.env.get("GITHUB_ACTIONS") == "true":
        guidance = (
            "destroy is available only through a separately authorized local operation."
            if command == "destroy"
            else "generate and apply a reviewed saved plan with pulumi-plan and "
            "pulumi-up-plan."
        )
        print(
            f"error: direct Pulumi {command} is disabled in GitHub Actions; {guidance}",
            file=sys.stderr,
        )
        return True
    return False


def _run_up_stack(
    context: CommandContext, stack: str, *, include_policy_pack: bool = True
) -> int | None:
    if _direct_ci_up_forbidden(context):
        return 1
    result = _run_with_observable_output(
        context,
        _pulumi_command(
            context, StackCommand("up", stack, include_policy_pack=include_policy_pack)
        ),
    )
    if result.returncode == 0:
        return None

    return result.returncode or 1


def _run_up_plan_command(context: CommandContext, stacks: list[str]) -> int:
    selected_plan_file = context.env.get("PULUMI_PLAN_FILE")
    status = _validate_up_plan_selection(selected_plan_file, stacks)
    manifest: dict[str, Any] | None = None

    for stack in stacks:
        if status is None:
            manifest, status = _run_validated_up_plan_stack(
                context,
                selected_plan_file,
                manifest,
                stack,
            )
    return 0 if status is None else status


def _validate_up_plan_selection(
    selected_plan_file: str | None, stacks: list[str]
) -> int | None:
    if not (selected_plan_file and len(stacks) > 1):
        return None

    print(
        "error: PULUMI_PLAN_FILE can only be used with a single selected stack.",
        file=sys.stderr,
    )
    return 1


def _validate_plan_file_exists(plan_path: Path) -> int | None:
    if plan_path.is_file():
        return None

    print(f"error: Pulumi plan file not found: {plan_path}", file=sys.stderr)
    return 1


def _run_validated_up_plan_stack(
    context: CommandContext,
    selected_plan_file: str | None,
    manifest: dict[str, Any] | None,
    stack: str,
) -> tuple[dict[str, Any] | None, int | None]:
    plan_path = _selected_plan_path(context, selected_plan_file, stack)
    status = _validate_plan_file_exists(plan_path)

    if status is None and manifest is None:
        manifest = _load_plan_manifest(context)
        if manifest is None:
            status = 1
    if status is None and manifest is not None:
        status = _validate_plan_manifest(context, manifest, stack, plan_path)
    if status is None:
        status = _select_or_init_stack(context, stack)
    if status is None:
        with prepared_stack_configuration(context, stack) as prepared:
            entry = _manifest_stack_entry(manifest or {}, stack)
            verify_provider_identity(prepared, entry or {})
            status = _run_up_plan_stack(prepared, stack, plan_path)
    return manifest, status


def _run_regular_command(
    command: str, context: CommandContext, stacks: list[str]
) -> int:
    for stack in stacks:
        select_failure = _select_or_init_stack(context, stack)
        if select_failure is not None:
            return select_failure
        with prepared_stack_configuration(context, stack) as prepared:
            if command == "up":
                up_failure = _run_up_stack(prepared, stack)
                if up_failure is not None:
                    return up_failure
                continue
            _run_stack_command(prepared, StackCommand(command, stack))
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
    if command in {"up", "destroy"} and _direct_ci_up_forbidden(context, command):
        return 1
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
        try:
            status = _dispatch_command(command, context, stacks)
        except StackConfigError as error:
            print(f"error: {error}", file=sys.stderr)
            status = 1
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
