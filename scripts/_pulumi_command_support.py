from __future__ import annotations

import hashlib
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, TextIO

from _script_support import run


@dataclass(frozen=True)
class CommandContext:
    root_dir: Path
    env: dict[str, str]
    pulumi_dir: Path
    policy_pack_dir: Path
    plan_dir: Path
    preview_artifact_dir: Path
    backend_url: str
    secrets_provider: str
    runner: Callable[..., Any] = run
    config_file: Path | None = None
    provider_identity: dict[str, Any] | None = None


@dataclass(frozen=True)
class PulumiInvocation:
    action: str
    static_args: tuple[str, ...] = ()
    include_policy_pack: bool = False
    plan_flag: str | None = None


@dataclass(frozen=True)
class StackCommand:
    command: str
    stack: str
    plan_path: Path | None = None
    stdout: TextIO | None = None
    include_policy_pack: bool | None = None


# A refreshed preview does not persist its observations. Refresh again on replay
# so a saved plan cannot silently skip drift against stale checkpoint inputs.
PULUMI_INVOCATIONS = {
    "preview": PulumiInvocation("preview", include_policy_pack=True),
    "plan": PulumiInvocation(
        "preview",
        static_args=("--json", "--refresh"),
        include_policy_pack=True,
        plan_flag="--save-plan",
    ),
    "up": PulumiInvocation("up", static_args=("--yes",), include_policy_pack=True),
    "up-plan": PulumiInvocation(
        "up",
        static_args=("--yes", "--refresh"),
        include_policy_pack=True,
        plan_flag="--plan",
    ),
    "refresh": PulumiInvocation("refresh", static_args=("--yes",)),
    "drift": PulumiInvocation(
        "preview",
        static_args=("--refresh", "--expect-no-changes"),
        include_policy_pack=True,
    ),
    "destroy": PulumiInvocation("destroy", static_args=("--yes",)),
}


def _emit_stderr(stderr: str) -> None:
    if stderr:
        print(stderr, file=sys.stderr, end="")


def _uses_file_backend(backend_url: str) -> bool:
    return backend_url.startswith("file://")


def _safe_artifact_stem(stack: str) -> str:
    sanitized = "".join(
        character if character.isalnum() or character in "._-" else "_"
        for character in stack
    )
    digest = hashlib.sha256(stack.encode("utf-8")).hexdigest()[:8]
    return f"{sanitized or 'stack'}-{digest}"


def _preview_file(preview_artifact_dir: Path, stack: str) -> Path:
    return preview_artifact_dir / f"{_safe_artifact_stem(stack)}.json"


def _plan_file(plan_dir: Path, stack: str) -> Path:
    return plan_dir / f"{_safe_artifact_stem(stack)}.plan"


def _select_or_init_stack(context: CommandContext, stack: str) -> int | None:
    select_result = context.runner(
        [
            "pulumi",
            "-C",
            str(context.pulumi_dir),
            "stack",
            "select",
            stack,
            "--non-interactive",
        ],
        check=False,
        capture_output=True,
        env=context.env,
    )
    if select_result.returncode == 0:
        return None

    if not _uses_file_backend(context.backend_url):
        print(
            f"error: shared backend stack {stack} does not exist; "
            "create it explicitly.",
            file=sys.stderr,
        )
        _emit_stderr(select_result.stderr)
        return select_result.returncode or 1

    if not context.secrets_provider:
        print(
            f"error: file backend stack {stack} does not exist; "
            "set PULUMI_SECRETS_PROVIDER.",
            file=sys.stderr,
        )
        _emit_stderr(select_result.stderr)
        return select_result.returncode or 1

    init_result = context.runner(
        [
            "pulumi",
            "-C",
            str(context.pulumi_dir),
            "stack",
            "init",
            stack,
            "--non-interactive",
            "--secrets-provider",
            context.secrets_provider,
        ],
        check=False,
        capture_output=True,
        env=context.env,
    )
    if init_result.returncode == 0:
        return None
    _emit_stderr(init_result.stderr)
    return init_result.returncode or 1


def _required_plan_path(request: StackCommand) -> Path:
    if request.plan_path is None:
        raise ValueError(f"{request.command} command requires plan_path")
    return request.plan_path


def _pulumi_command(context: CommandContext, request: StackCommand) -> list[str]:
    invocation = PULUMI_INVOCATIONS.get(request.command)
    if invocation is None:
        raise ValueError(f"unsupported Pulumi command: {request.command}")

    command = [
        "pulumi",
        "-C",
        str(context.pulumi_dir),
        invocation.action,
        "--stack",
        request.stack,
        "--non-interactive",
        *invocation.static_args,
    ]
    include_policy_pack = (
        invocation.include_policy_pack
        if request.include_policy_pack is None
        else request.include_policy_pack
    )
    if include_policy_pack:
        command.extend(["--policy-pack", str(context.policy_pack_dir)])
    if invocation.plan_flag:
        command.extend([invocation.plan_flag, str(_required_plan_path(request))])
    if context.config_file is not None:
        command.extend(["--config-file", str(context.config_file)])
    return command


def _run_stack_command(context: CommandContext, request: StackCommand) -> None:
    context.runner(
        _pulumi_command(context, request),
        env=context.env,
        stdout=request.stdout,
    )
