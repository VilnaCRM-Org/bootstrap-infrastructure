#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
from dataclasses import dataclass
from pathlib import Path

AUTHORIZED_ASSOCIATIONS = frozenset({"OWNER", "MEMBER", "COLLABORATOR"})
PULUMI_ACTIONS = frozenset({"plan", "up"})
PULUMI_ENVIRONMENTS = frozenset({"test", "prod"})


@dataclass(frozen=True)
class PulumiPrCommand:
    target_environment: str
    action: str

    @property
    def display_command(self) -> str:
        return f"/pulumi {self.target_environment} {self.action}"


def parse_command(body: str) -> PulumiPrCommand | None:
    tokens = body.strip().lower().split()
    if not tokens or tokens[0] not in {"/pulumi", "pulumi"}:
        return None

    args = tokens[1:]
    if len(args) == 1 and args[0] in PULUMI_ACTIONS:
        return PulumiPrCommand(target_environment="test", action=args[0])

    if len(args) == 2:
        first, second = args
        if first in PULUMI_ENVIRONMENTS and second in PULUMI_ACTIONS:
            return PulumiPrCommand(target_environment=first, action=second)
        if first in PULUMI_ACTIONS and second in PULUMI_ENVIRONMENTS:
            return PulumiPrCommand(target_environment=second, action=first)

    return None


def author_is_authorized(author_association: str) -> bool:
    return author_association.strip().upper() in AUTHORIZED_ASSOCIATIONS


def build_outputs(
    command: PulumiPrCommand | None, author_association: str
) -> dict[str, str]:
    outputs = {
        "authorized": "true" if author_is_authorized(author_association) else "false"
    }
    if command is None:
        return {**outputs, "skip": "true"}

    return {
        **outputs,
        "skip": "false",
        "target_environment": command.target_environment,
        "command": command.action,
        "display_command": command.display_command,
    }


def render_outputs(outputs: dict[str, str]) -> str:
    return "".join(f"{key}={value}\n" for key, value in outputs.items())


def write_outputs(outputs: dict[str, str], output_path: str | None) -> None:
    rendered = render_outputs(outputs)
    print(rendered, end="")
    if output_path:
        with Path(output_path).open("a", encoding="utf-8") as handle:
            handle.write(rendered)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Parse trusted Pulumi pull-request comment commands."
    )
    parser.add_argument("body")
    parser.add_argument("--author-association", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    outputs = build_outputs(parse_command(args.body), args.author_association)
    write_outputs(outputs, os.environ.get("GITHUB_OUTPUT"))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
