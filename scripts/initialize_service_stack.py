#!/usr/bin/env python3
"""Create only an absent backend stack, using trusted main and gated apply access."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess  # nosec B404
from pathlib import Path

from pulumi_command_preflight import gh, require, verify_environments

CLI_VERSION = "v3.223.0"


def execute(*args: str) -> str:
    """Run an exact argument vector; failures never become evidence of absence."""
    return subprocess.run(  # nosec B603
        list(args), check=True, capture_output=True, text=True
    ).stdout


def trusted_context() -> tuple[str, str]:
    """Accept only a fixed stack choice on the trusted default-branch workflow."""
    require(os.environ.get("GITHUB_REF") == "refs/heads/main", "Main required")
    require(
        os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch",
        "Manual initialization workflow required",
    )
    environment = os.environ.get("INIT_ENVIRONMENT", "")
    require(environment in {"test", "prod"}, "Invalid initialization environment")
    account = os.environ.get("INIT_ACCOUNT_ID", "")
    require(re.fullmatch(r"[0-9]{12}", account) is not None, "Invalid account pin")
    return environment, account


def verify_requester() -> None:
    """Require a fresh current-write requester distinct from the sole reviewer."""
    require(
        os.environ.get("GITHUB_RUN_ATTEMPT") == "1",
        "Re-run initialization rejected; dispatch again",
    )
    actor = os.environ.get("GITHUB_ACTOR", "")
    require(
        re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}", actor) is not None,
        "Invalid initialization requester",
    )
    require(
        actor.lower() != "kravalg",
        "Initialization requester must differ from sole approver Kravalg",
    )
    require(
        os.environ.get("GITHUB_TRIGGERING_ACTOR") == actor,
        "Initialization triggering actor differs",
    )
    permission = gh(
        f"repos/{os.environ['GITHUB_REPOSITORY']}/collaborators/{actor}/permission"
    )
    require(
        permission.get("permission") in {"write", "maintain", "admin"},
        "Current write access required for initialization",
    )


def contract(root: Path, environment: str, account: str) -> tuple[str, str, str]:
    """Bind project, account, backend and KMS provider to committed service metadata."""
    import yaml

    project = os.environ["GITHUB_REPOSITORY"].split("/")[-1]
    require(
        re.fullmatch(r"[a-z][a-z0-9-]*-infrastructure", project) is not None,
        "Invalid service repository",
    )
    manifest = yaml.safe_load((root / "pulumi/Pulumi.yaml").read_text())
    require(manifest["name"] == project, "Pulumi project mismatch")
    require(manifest["runtime"] == {"name": "python"}, "Unexpected Pulumi runtime")
    stack = yaml.safe_load((root / f"pulumi/Pulumi.{environment}.yaml").read_text())
    config = stack["config"]
    backend = f"s3://pulumi-{project}-{environment}-state"
    provider = (
        f"awskms://alias/pulumi-{project}-{environment}-secrets?region=eu-central-1"
    )
    expected = {
        "awsAccountId": account,
        "environment": environment,
        "repoSlug": project,
        "pulumiBackendUrl": backend,
        "pulumiSecretsProvider": provider,
    }
    require(
        all(config.get(f"{project}:{key}") == value for key, value in expected.items()),
        "Committed stack configuration differs from initialization contract",
    )
    require(stack.get("secretsprovider") == provider, "Stack KMS provider mismatch")
    require(config.get("aws:region") == "eu-central-1", "Unexpected AWS region")
    return project, backend, provider


def _verify_checkpoint(
    root: Path, environment: str, account: str, backend: str, provider: str
) -> None:
    """Verify remote state/provider continuity without replacing a configured key."""
    from _pulumi_command_support import CommandContext
    from _pulumi_stack_config import prepared_stack_configuration

    context = CommandContext(
        root_dir=root,
        env={**os.environ, "AWS_ACCOUNT_ID": account, "PULUMI_BACKEND_URL": backend},
        pulumi_dir=root / "pulumi",
        policy_pack_dir=root / "policy",
        plan_dir=root / ".artifacts/pulumi-plan",
        preview_artifact_dir=root / ".artifacts/pulumi-preview",
        backend_url=backend,
        secrets_provider=provider,
    )
    with prepared_stack_configuration(context, environment):
        pass


def initialize(root: Path) -> dict:
    """List the exact project successfully before initializing an absent stack."""
    environment, account = trusted_context()
    project, backend, provider = contract(root, environment, account)
    require(execute("pulumi", "version").strip() == CLI_VERSION, "CLI pin mismatch")
    caller = json.loads(
        execute("aws", "sts", "get-caller-identity", "--output", "json")
    )
    require(caller["Account"] == account, "AWS caller account mismatch")
    prefix = ("pulumi", "-C", str(root / "pulumi"))
    execute(*prefix, "login", "--non-interactive", backend)
    stacks = json.loads(execute(*prefix, "stack", "ls", "--json", "--project", project))
    require(isinstance(stacks, list), "Malformed stack listing")
    require(
        all(
            isinstance(item, dict) and isinstance(item.get("name"), str)
            for item in stacks
        ),
        "Malformed stack metadata",
    )
    names = {item["name"] for item in stacks}
    # Project-scoped DIY backends report short names or fully qualified names.
    identities = {environment, f"organization/{project}/{environment}"}
    ambiguous = {name for name in names if name.endswith(f"/{environment}")}
    require(ambiguous <= identities, "Ambiguous stack identity")
    exists = bool(names & identities)
    if exists:
        execute(*prefix, "stack", "select", environment, "--non-interactive")
    else:
        execute(
            *prefix,
            "stack",
            "init",
            environment,
            "--non-interactive",
            "--secrets-provider",
            provider,
        )
    _verify_checkpoint(root, environment, account, backend, provider)
    return {
        "schemaVersion": 1,
        "project": project,
        "stack": environment,
        "accountId": account,
        "backend": backend,
        "secretsProvider": provider,
        "headSha": os.environ["GITHUB_SHA"],
        "created": not exists,
        "resourceUpdateExecuted": False,
    }


def main(argv: list[str] | None = None) -> int:
    """Verify protection before credentials or initialize backend metadata."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("verify", "initialize"))
    args = parser.parse_args(argv)
    environment, _ = trusted_context()
    if args.command == "verify":
        verify_requester()
        verify_environments(
            {"command": "up", "target_environment": environment}, governance=False
        )
        repository = gh(f"repos/{os.environ['GITHUB_REPOSITORY']}")
        require(repository["default_branch"] == "main", "Default branch mismatch")
    else:
        root = Path(__file__).resolve().parents[1]
        receipt = initialize(root)
        output = root / ".artifacts/stack-initialization.json"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(receipt, indent=2) + "\n")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
