import os
import subprocess  # nosec B404 - the e2e suite intentionally drives the Pulumi CLI.
from pathlib import Path

import pytest

HAS_E2E_PROVIDER = bool(os.getenv("PULUMI_E2E_SECRETS_PROVIDER"))


def _run(
    cmd: list[str], *, cwd: Path, env: dict[str, str]
) -> subprocess.CompletedProcess[str]:
    # The command list is assembled from fixed literals and pytest temp paths.
    return subprocess.run(
        cmd, cwd=cwd, env=env, text=True, capture_output=True, check=False
    )  # nosec B603


@pytest.mark.skipif(
    not HAS_E2E_PROVIDER, reason="PULUMI_E2E_SECRETS_PROVIDER is not set."
)
def test_pulumi_cli_smoke_with_awskms(tmp_path: Path):
    provider = os.environ["PULUMI_E2E_SECRETS_PROVIDER"]

    backend_dir = tmp_path / "backend"
    project_dir = tmp_path / "project"
    pulumi_home = tmp_path / "pulumi-home"
    backend_dir.mkdir()
    project_dir.mkdir()
    pulumi_home.mkdir()

    (project_dir / "Pulumi.yaml").write_text(
        "name: pulumi-e2e-smoke\nruntime:\n  name: python\n",
        encoding="utf-8",
    )
    (project_dir / "__main__.py").write_text(
        "import pulumi\npulumi.export('status', 'ok')\n",
        encoding="utf-8",
    )

    env = os.environ.copy()
    env["PULUMI_HOME"] = str(pulumi_home)
    env["PULUMI_SKIP_UPDATE_CHECK"] = "true"

    backend_url = f"file://{backend_dir}"
    stack = "e2e"

    commands = [
        ["pulumi", "login", backend_url],
        [
            "pulumi",
            "-C",
            str(project_dir),
            "stack",
            "init",
            stack,
            "--non-interactive",
            "--secrets-provider",
            provider,
        ],
        [
            "pulumi",
            "-C",
            str(project_dir),
            "preview",
            "--stack",
            stack,
            "--non-interactive",
            "--suppress-outputs",
        ],
        [
            "pulumi",
            "-C",
            str(project_dir),
            "up",
            "--stack",
            stack,
            "--yes",
            "--skip-preview",
        ],
        [
            "pulumi",
            "-C",
            str(project_dir),
            "stack",
            "output",
            "status",
            "--stack",
            stack,
        ],
    ]

    try:
        for command in commands[:-1]:
            result = _run(command, cwd=project_dir, env=env)
            assert result.returncode == 0, result.stdout + result.stderr  # nosec B101

        output = _run(commands[-1], cwd=project_dir, env=env)
        assert output.returncode == 0, output.stdout + output.stderr  # nosec B101
        assert output.stdout.strip() == "ok"  # nosec B101
    finally:
        _run(
            [
                "pulumi",
                "-C",
                str(project_dir),
                "destroy",
                "--stack",
                stack,
                "--yes",
                "--skip-preview",
            ],
            cwd=project_dir,
            env=env,
        )
        _run(
            ["pulumi", "-C", str(project_dir), "stack", "rm", stack, "--yes"],
            cwd=project_dir,
            env=env,
        )
