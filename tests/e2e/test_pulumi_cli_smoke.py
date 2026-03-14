import os
import subprocess  # nosec B404 - the e2e suite intentionally drives the Pulumi CLI.
from pathlib import Path

import pytest

HAS_E2E_PROVIDER = bool(os.getenv("PULUMI_E2E_SECRETS_PROVIDER"))
ROOT = Path(__file__).resolve().parents[2]


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


@pytest.mark.skipif(
    not HAS_E2E_PROVIDER, reason="PULUMI_E2E_SECRETS_PROVIDER is not set."
)
def test_pulumi_command_script_handles_plan_and_up(tmp_path: Path):
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
    env["PULUMI_STACK"] = "script-e2e"
    env["PULUMI_BACKEND_URL"] = f"file://{backend_dir}"
    env["PULUMI_SECRETS_PROVIDER"] = provider
    env["PULUMI_DIR"] = str(project_dir)
    env["PULUMI_PREVIEW_JSON_PATH"] = str(tmp_path / "preview.json")

    script = ROOT / "scripts" / "run_pulumi_command.sh"

    try:
        for command_name in ("plan", "up"):
            result = _run(
                ["bash", str(script), command_name],
                cwd=ROOT,
                env=env,
            )
            assert result.returncode == 0, result.stdout + result.stderr  # nosec B101
        assert Path(env["PULUMI_PREVIEW_JSON_PATH"]).exists()  # nosec B101

        output = _run(
            [
                "pulumi",
                "-C",
                str(project_dir),
                "stack",
                "output",
                "status",
                "--stack",
                env["PULUMI_STACK"],
            ],
            cwd=project_dir,
            env=env,
        )
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
                env["PULUMI_STACK"],
                "--yes",
                "--skip-preview",
            ],
            cwd=project_dir,
            env=env,
        )


@pytest.mark.skipif(
    not HAS_E2E_PROVIDER, reason="PULUMI_E2E_SECRETS_PROVIDER is not set."
)
def test_policy_pack_blocks_disallowed_resource_types(tmp_path: Path):
    provider = os.environ["PULUMI_E2E_SECRETS_PROVIDER"]

    backend_dir = tmp_path / "backend"
    project_dir = tmp_path / "project"
    pulumi_home = tmp_path / "pulumi-home"
    backend_dir.mkdir()
    project_dir.mkdir()
    pulumi_home.mkdir()

    (project_dir / "Pulumi.yaml").write_text(
        "name: pulumi-e2e-policy\nruntime:\n  name: python\n",
        encoding="utf-8",
    )
    (project_dir / "__main__.py").write_text(
        "import pulumi_aws as aws\n"
        "aws.ec2.Vpc('blocked-vpc', cidr_block='10.0.0.0/16')\n",
        encoding="utf-8",
    )

    env = os.environ.copy()
    env["PULUMI_HOME"] = str(pulumi_home)
    env["PULUMI_SKIP_UPDATE_CHECK"] = "true"
    env["AWS_REGION"] = env.get("AWS_REGION", "eu-central-1")
    env["AWS_DEFAULT_REGION"] = env["AWS_REGION"]

    backend_url = f"file://{backend_dir}"
    stack = "policy-e2e"

    try:
        init = _run(
            [
                "pulumi",
                "login",
                backend_url,
            ],
            cwd=project_dir,
            env=env,
        )
        assert init.returncode == 0, init.stdout + init.stderr  # nosec B101

        stack_init = _run(
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
            cwd=project_dir,
            env=env,
        )
        assert stack_init.returncode == 0, stack_init.stdout + stack_init.stderr  # nosec B101

        preview = _run(
            [
                "pulumi",
                "-C",
                str(project_dir),
                "preview",
                "--stack",
                stack,
                "--non-interactive",
                "--policy-pack",
                str(ROOT / "policy_pack"),
            ],
            cwd=project_dir,
            env=env,
        )
        assert preview.returncode != 0  # nosec B101
        assert "approved-bootstrap-resource-types" in (preview.stdout + preview.stderr)  # nosec B101
        assert "aws:ec2/vpc:Vpc" in (preview.stdout + preview.stderr)  # nosec B101
    finally:
        _run(
            [
                "pulumi",
                "-C",
                str(project_dir),
                "stack",
                "rm",
                stack,
                "--yes",
            ],
            cwd=project_dir,
            env=env,
        )
