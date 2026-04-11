#!/usr/bin/env python3
from __future__ import annotations

import os
import sys
from pathlib import Path

from _script_support import repo_root, run


def main() -> int:
    root_dir = repo_root(__file__)
    env = os.environ.copy()
    require_shared_backend = env.get("PULUMI_REQUIRE_SHARED_BACKEND") == "true"
    backend_url = env.get("PULUMI_BACKEND_URL", "")

    if require_shared_backend:
        if not backend_url or backend_url.startswith("file://"):
            print(
                "error: privileged previews require a non-file PULUMI_BACKEND_URL.",
                file=sys.stderr,
            )
            return 1
    else:
        env.setdefault("PULUMI_BACKEND_URL", "file:///workspace/.pulumi-backend")

    run(
        ["make", "test-preview"],
        check=True,
        cwd=root_dir,
        env=env,
    )

    summary_path = env.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return 0

    preview_summary = root_dir / ".artifacts" / "pulumi-preview" / "summary.md"
    destination = Path(summary_path)
    if preview_summary.is_file():
        existing = (
            destination.read_text(encoding="utf-8") if destination.exists() else ""
        )
        destination.write_text(
            existing + preview_summary.read_text(encoding="utf-8"),
            encoding="utf-8",
        )
    else:
        existing = (
            destination.read_text(encoding="utf-8") if destination.exists() else ""
        )
        destination.write_text(
            existing
            + "Pulumi preview completed without a rendered summary artifact.\n",
            encoding="utf-8",
        )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
