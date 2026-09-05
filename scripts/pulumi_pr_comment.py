#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
from dataclasses import dataclass
from pathlib import Path

AUTHORIZED_ASSOCIATIONS = frozenset({"OWNER", "MEMBER", "COLLABORATOR"})
PULUMI_ACTIONS = frozenset({"plan", "up"})
PULUMI_ENVIRONMENTS = frozenset({"test", "prod"})

# Sole approver of governance applies (FR13, D6). Login compare is
# case-insensitive. This intake gate is defense-in-depth; the governance
# runner's server-side re-auth (E1.S8) is the hard control.
KRAVALG_LOGIN = "Kravalg"


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


def author_is_authorized(
    author_association: str,
    *,
    author_login: str = "",
    governance_touched: bool = False,
    action: str = "",
) -> bool:
    if action == "up":
        login = author_login.strip().lower()
        if not login or login == KRAVALG_LOGIN.lower():
            return False
    return author_association.strip().upper() in AUTHORIZED_ASSOCIATIONS


def build_outputs(
    command: PulumiPrCommand | None,
    author_association: str,
    *,
    author_login: str = "",
    governance_touched: bool = False,
) -> dict[str, str]:
    authorized = author_is_authorized(
        author_association,
        author_login=author_login,
        governance_touched=governance_touched,
        action=command.action if command is not None else "",
    )
    outputs = {"authorized": "true" if authorized else "false"}
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
    parser.add_argument("--author-login", default="")
    parser.add_argument(
        "--governance-touched",
        choices=("true", "false"),
        default="false",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    outputs = build_outputs(
        parse_command(args.body),
        args.author_association,
        author_login=args.author_login,
        governance_touched=args.governance_touched == "true",
    )
    write_outputs(outputs, os.environ.get("GITHUB_OUTPUT"))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
