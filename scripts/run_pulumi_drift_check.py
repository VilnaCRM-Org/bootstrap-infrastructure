#!/usr/bin/env python3
from __future__ import annotations

import os
import sys
from pathlib import Path

from _script_support import discover_stacks, repo_root, run


def main() -> int:
    root_dir = repo_root(__file__)
    pulumi_dir = Path(os.environ.get("PULUMI_DIR", root_dir / "pulumi"))
    policy_pack_dir = Path(os.environ.get("POLICY_PACK_DIR", root_dir / "policy"))
    backend_url = os.environ.get("PULUMI_BACKEND_URL", "")

    if not pulumi_dir.is_dir():
        print(f"error: PULUMI_DIR '{pulumi_dir}' does not exist", file=sys.stderr)
        return 1

    if not backend_url or backend_url.startswith("file://"):
        print(
            "Skipping drift detection because PULUMI_BACKEND_URL is not configured "
            "for a shared backend."
        )
        return 0

    env = os.environ.copy()
    stacks = discover_stacks(pulumi_dir, env.get("PULUMI_DRIFT_STACKS"))
    if not stacks:
        print("error: no Pulumi stacks configured for drift detection", file=sys.stderr)
        return 1

    run(
        [sys.executable, str(root_dir / "scripts" / "prepare_policy_pack.py")],
        cwd=root_dir,
        env=env,
    )

    run(
        ["pulumi", "--cwd", str(pulumi_dir), "login", "--non-interactive", backend_url],
        env=env,
    )

    for stack in stacks:
        print(f"Checking drift for stack {stack}")
        run(
            [
                "pulumi",
                "--cwd",
                str(pulumi_dir),
                "stack",
                "select",
                stack,
                "--non-interactive",
            ],
            env=env,
        )
        run(
            [
                "pulumi",
                "--cwd",
                str(pulumi_dir),
                "preview",
                "--stack",
                stack,
                "--non-interactive",
                "--refresh",
                "--expect-no-changes",
                "--policy-pack",
                str(policy_pack_dir),
            ],
            env=env,
        )

    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
