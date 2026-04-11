"""Unit tests for repo-local Python script entrypoints."""

from __future__ import annotations

import importlib
import os
import subprocess
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS_DIR = PROJECT_ROOT / "scripts"


def load_script_module(monkeypatch: pytest.MonkeyPatch, module_name: str):
    """Import a script module from the repo-local scripts directory."""
    monkeypatch.syspath_prepend(str(SCRIPTS_DIR))
    importlib.invalidate_caches()
    sys.modules.pop(module_name, None)
    return importlib.import_module(module_name)


def test_script_support_helpers_cover_local_script_utilities(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Exercise the shared helper functions used by the new Python scripts."""
    module = load_script_module(monkeypatch, "_script_support")
    pulumi_dir = tmp_path / "pulumi"
    pulumi_dir.mkdir()
    (pulumi_dir / "Pulumi.dev.yaml").write_text("", encoding="utf-8")
    (pulumi_dir / "Pulumi.example.yaml").write_text("", encoding="utf-8")
    (pulumi_dir / "Pulumi.yaml").write_text("name: template\n", encoding="utf-8")

    command_result = module.run(
        [sys.executable, "-c", "print('ok')"],
        capture_output=True,
    )

    backend_dir = (tmp_path / "backend").resolve()
    module.ensure_file_backend_directory(backend_dir.as_uri())
    module.ensure_file_backend_directory("https://example.com/backend")

    assert module.repo_root("/tmp/repo/scripts/tool.py") == Path("/tmp/repo")
    assert module.split_values(None) == []
    assert module.split_values('dev, "qa env"') == ["dev", "qa env"]
    assert module.discover_stacks(pulumi_dir, None) == ["dev", "example"]
    assert module.discover_stacks(pulumi_dir, "prod staging") == ["prod", "staging"]
    assert backend_dir.is_dir()
    assert command_result.stdout == "ok\n"
    assert "import policy.pack" in "".join(module.policy_import_probe(tmp_path))


def test_find_uv_binary_prefers_env_and_supports_fallbacks(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Find uv from env, PATH, fallback, and surface a helpful error when absent."""
    module = load_script_module(monkeypatch, "_script_support")
    env_uv = tmp_path / "uv-env"
    env_uv.write_text("", encoding="utf-8")
    os.chmod(env_uv, 0o755)
    path_uv = tmp_path / "uv-path"
    path_uv.write_text("", encoding="utf-8")
    os.chmod(path_uv, 0o755)

    monkeypatch.setenv("UV_BIN", str(env_uv))
    assert module.find_uv_binary() == str(env_uv)

    missing_env_uv = tmp_path / "missing-uv"
    monkeypatch.setenv("UV_BIN", str(missing_env_uv))
    monkeypatch.setattr(module.shutil, "which", lambda name: str(path_uv))
    assert module.find_uv_binary() == str(path_uv)

    monkeypatch.delenv("UV_BIN", raising=False)
    monkeypatch.setattr(module.shutil, "which", lambda name: str(path_uv))
    assert module.find_uv_binary() == str(path_uv)

    monkeypatch.setattr(module.shutil, "which", lambda name: None)
    monkeypatch.setattr(
        module.Path, "is_file", lambda self: str(self) == "/usr/local/bin/uv"
    )
    monkeypatch.setattr(
        module.os, "access", lambda path, mode: str(path) == "/usr/local/bin/uv"
    )
    assert module.find_uv_binary() == "/usr/local/bin/uv"

    monkeypatch.setattr(module.Path, "is_file", lambda self: False)
    monkeypatch.setattr(module.os, "access", lambda path, mode: False)
    with pytest.raises(SystemExit, match="127"):
        module.find_uv_binary()
    assert "uv executable not found" in capsys.readouterr().err


def test_doctor_main_reports_missing_and_ready_states(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Cover prerequisite detection for the repo doctor command."""
    module = load_script_module(monkeypatch, "doctor")
    assert module._version([sys.executable, "-c", "print('version')"]) == "version"

    monkeypatch.setattr(module.shutil, "which", lambda name: None)
    assert module.main() == 1
    assert "docker: missing" in capsys.readouterr().err

    monkeypatch.setattr(module.shutil, "which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr(
        module,
        "_version",
        lambda command: (_ for _ in ()).throw(
            subprocess.CalledProcessError(1, command)
        ),
    )
    assert module.main() == 1
    assert "docker compose: missing" in capsys.readouterr().err

    env_file = tmp_path / ".env"
    env_file.write_text("KEY=value\n", encoding="utf-8")
    monkeypatch.setenv("COMPOSE_ENV_FILE", str(env_file))
    monkeypatch.setenv("COMPOSE_SERVICE", "pulumi")
    monkeypatch.setenv("PULUMI_DIR", str(tmp_path / "missing"))
    monkeypatch.setattr(
        module,
        "_version",
        lambda command: "2.0.0" if "--short" in command else "Docker version 1.0.0",
    )
    assert module.main() == 1
    assert "pulumi directory missing" in capsys.readouterr().err

    pulumi_dir = tmp_path / "pulumi"
    pulumi_dir.mkdir()
    monkeypatch.setenv("PULUMI_DIR", str(pulumi_dir))
    assert module.main() == 0
    output = capsys.readouterr().out
    assert "effective env file:" in output
    assert "env file present: yes" in output

    monkeypatch.setenv("COMPOSE_ENV_FILE", str(tmp_path / "absent.env"))
    assert module.main() == 1
    assert "env file present: no" in capsys.readouterr().err


def test_prepare_docker_context_main_bootstraps_and_rejects_invalid_env(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Create the local Docker context safely and reject invalid .env paths."""
    module = load_script_module(monkeypatch, "prepare_docker_context")
    home_dir = tmp_path / "home"
    repo_dir = tmp_path / "repo"
    home_dir.mkdir()
    repo_dir.mkdir()
    monkeypatch.setenv("HOME", str(home_dir))
    monkeypatch.chdir(repo_dir)

    aws_marker = home_dir / ".aws"
    aws_target = tmp_path / "aws-target"
    aws_target.mkdir()
    aws_marker.symlink_to(aws_target, target_is_directory=True)
    assert module.main() == 1
    assert "~/.aws must be a regular directory" in capsys.readouterr().err
    aws_marker.unlink()

    aws_marker.write_text("not-a-directory\n", encoding="utf-8")
    assert module.main() == 1
    assert "~/.aws must be a regular directory" in capsys.readouterr().err
    aws_marker.unlink()

    assert module.main() == 1
    assert ".env.empty not found" in capsys.readouterr().err

    (repo_dir / ".env.empty").write_text("KEY=value\n", encoding="utf-8")
    target_env = tmp_path / "target.env"
    target_env.write_text("TARGET=value\n", encoding="utf-8")
    (repo_dir / ".env").symlink_to(target_env)
    assert module.main() == 1
    assert ".env must be a regular file" in capsys.readouterr().err
    (repo_dir / ".env").unlink()

    missing_env_target = tmp_path / "missing.env"
    (repo_dir / ".env").symlink_to(missing_env_target)
    assert module.main() == 1
    assert ".env must be a regular file" in capsys.readouterr().err
    (repo_dir / ".env").unlink()

    backend_target = tmp_path / "backend-target"
    backend_target.mkdir()
    (repo_dir / ".pulumi-backend").symlink_to(backend_target, target_is_directory=True)
    assert module.main() == 1
    assert ".pulumi-backend must be a regular directory" in capsys.readouterr().err
    (repo_dir / ".pulumi-backend").unlink()

    assert module.main() == 0
    assert (home_dir / ".aws").is_dir()
    assert (repo_dir / ".env").read_text(encoding="utf-8") == "KEY=value\n"
    assert (repo_dir / ".pulumi-backend").is_dir()
    (repo_dir / ".env").write_text("LOCAL=value\n", encoding="utf-8")
    assert module.main() == 0
    assert (repo_dir / ".env").read_text(encoding="utf-8") == "LOCAL=value\n"


def test_prepare_docker_context_helpers_reject_non_directories(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Exercise helper guards that reject symlinks and non-directory paths."""
    module = load_script_module(monkeypatch, "prepare_docker_context")
    regular_dir = tmp_path / "regular-dir"
    regular_dir.mkdir()
    symlink_dir = tmp_path / "symlink-dir"
    symlink_dir.symlink_to(regular_dir, target_is_directory=True)
    plain_file = tmp_path / "plain-file"
    plain_file.write_text("x\n", encoding="utf-8")

    assert module._is_regular_directory_path(regular_dir, "regular-dir") is True
    assert module._is_regular_directory_path(symlink_dir, "symlink-dir") is False

    with pytest.raises(NotADirectoryError):
        module._ensure_dir(symlink_dir, 0o700)
    with pytest.raises(NotADirectoryError):
        module._ensure_dir(plain_file, 0o700)


def test_prepare_policy_pack_helpers_and_main_paths(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Cover policy-pack bootstrap success and failure paths."""
    module = load_script_module(monkeypatch, "prepare_policy_pack")
    policy_dir = tmp_path / "policy"
    policy_dir.mkdir()
    policy_link = policy_dir / ".venv"
    policy_link.mkdir()
    with pytest.raises(SystemExit, match="1"):
        module._link_policy_venv(tmp_path / "shared-venv", policy_link)
    assert "must be a symlink" in capsys.readouterr().err
    policy_link.rmdir()

    monkeypatch.setattr(
        module.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0),
    )
    assert module._imports_available(tmp_path / "python", tmp_path) is True
    monkeypatch.setattr(
        module.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 1),
    )
    assert module._imports_available(tmp_path / "python", tmp_path) is False

    repo_dir = tmp_path / "repo"
    repo_policy_dir = repo_dir / "policy"
    repo_policy_dir.mkdir(parents=True)
    policy_venv = tmp_path / "policy-venv"
    policy_python = policy_venv / "bin" / "python"
    policy_python.parent.mkdir(parents=True)
    policy_python.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
    os.chmod(policy_python, 0o755)
    monkeypatch.setattr(module, "repo_root", lambda _: repo_dir)
    monkeypatch.setenv("POLICY_VENV", str(policy_venv))

    assert module.main() == 1
    assert "policy requirements file not found" in capsys.readouterr().err

    requirements_file = repo_policy_dir / "requirements.txt"
    requirements_file.write_text("pulumi-policy\n", encoding="utf-8")
    policy_python.unlink()
    assert module.main() == 1
    assert "policy interpreter not found" in capsys.readouterr().err

    policy_python.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
    os.chmod(policy_python, 0o755)
    run_calls: list[list[str]] = []
    availability = iter([False, True])
    monkeypatch.setattr(module, "_imports_available", lambda *args: next(availability))
    monkeypatch.setattr(
        module,
        "run",
        lambda command, **kwargs: (
            run_calls.append(command) or subprocess.CompletedProcess(command, 0)
        ),
    )
    assert module.main() == 0
    assert run_calls == [["uv", "sync", "--frozen", "--all-groups"]]
    assert (repo_policy_dir / ".venv").is_symlink()

    run_calls.clear()
    monkeypatch.setattr(module, "_imports_available", lambda *args: True)
    assert module.main() == 0
    assert run_calls == []

    monkeypatch.setattr(module, "_imports_available", lambda *args: False)
    assert module.main() == 1
    assert "shared policy interpreter is missing" in capsys.readouterr().err


def test_publish_pulumi_preview_summary_main_handles_backend_and_summary_paths(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Run the preview summary wrapper across its guarded execution paths."""
    module = load_script_module(monkeypatch, "publish_pulumi_preview_summary")
    repo_dir = tmp_path / "repo"
    preview_dir = repo_dir / ".artifacts" / "pulumi-preview"
    preview_dir.mkdir(parents=True)
    monkeypatch.setattr(module, "repo_root", lambda _: repo_dir)

    monkeypatch.setenv("PULUMI_REQUIRE_SHARED_BACKEND", "true")
    monkeypatch.delenv("PULUMI_BACKEND_URL", raising=False)
    assert module.main() == 1
    assert "privileged previews require a non-file" in capsys.readouterr().err

    run_calls: list[tuple[list[str], Path | None, dict[str, str]]] = []

    def fake_run(command, **kwargs):
        run_calls.append((command, kwargs.get("cwd"), kwargs["env"]))
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(module, "run", fake_run)
    monkeypatch.setenv("PULUMI_REQUIRE_SHARED_BACKEND", "false")
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    assert module.main() == 0
    assert run_calls[-1][0] == ["make", "test-preview"]
    assert run_calls[-1][1] == repo_dir
    assert run_calls[-1][2]["PULUMI_BACKEND_URL"] == "file:///workspace/.pulumi-backend"

    monkeypatch.setenv("PULUMI_REQUIRE_SHARED_BACKEND", "true")
    monkeypatch.setenv("PULUMI_BACKEND_URL", "s3://shared-backend")
    assert module.main() == 0
    assert run_calls[-1][2]["PULUMI_BACKEND_URL"] == "s3://shared-backend"

    preview_summary = preview_dir / "summary.md"
    preview_summary.write_text("preview summary\n", encoding="utf-8")
    github_summary = tmp_path / "github-summary.md"
    github_summary.write_text("existing\n", encoding="utf-8")
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(github_summary))
    assert module.main() == 0
    assert github_summary.read_text(encoding="utf-8") == "existing\npreview summary\n"

    preview_summary.unlink()
    assert module.main() == 0
    assert "without a rendered summary artifact" in github_summary.read_text(
        encoding="utf-8"
    )


def test_report_maintainability_trends_main_handles_git_and_wily_paths(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Cover skipped and successful maintainability-report generation."""
    module = load_script_module(monkeypatch, "report_maintainability_trends")
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    monkeypatch.setattr(module, "repo_root", lambda _: repo_dir)
    monkeypatch.setenv("ROOT_DIR", str(repo_dir))
    monkeypatch.setenv("QUALITY_ARTIFACT_DIR", "reports")
    monkeypatch.setenv("WILY_TARGETS", "pulumi,policy")

    skip_results = iter(
        [
            subprocess.CompletedProcess(["git"], 1),
            subprocess.CompletedProcess(["git"], 1),
        ]
    )
    monkeypatch.setattr(module, "run", lambda *args, **kwargs: next(skip_results))
    assert module.main() == 0
    skip_report = repo_dir / "reports" / "wily-rank.txt"
    assert "Wily maintainability report skipped" in skip_report.read_text(
        encoding="utf-8"
    )

    calls: list[list[str]] = []
    rank_stdout = "ranked output\n"
    cache_dir = repo_dir / "reports" / "wily-cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    (cache_dir / "stale.txt").write_text("stale\n", encoding="utf-8")

    def fake_run(command, **kwargs):
        calls.append(command)
        if command[:3] == ["git", "rev-parse", "--is-inside-work-tree"]:
            return subprocess.CompletedProcess(command, 0)
        if command[:3] == ["git", "rev-parse", "--verify"]:
            return subprocess.CompletedProcess(command, 0)
        if "rank" in command:
            return subprocess.CompletedProcess(command, 0, stdout=rank_stdout)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(module, "run", fake_run)
    assert module.main() == 0
    monkeypatch.setenv("QUALITY_ARTIFACT_DIR", str(tmp_path / "absolute-reports"))
    assert module.main() == 0
    assert not cache_dir.joinpath("stale.txt").exists()
    assert (repo_dir / "reports" / "wily-rank.txt").read_text(
        encoding="utf-8"
    ) == rank_stdout
    assert any(
        command[:3] == ["uv", "run", "wily"] and "build" in command for command in calls
    )
    assert any(
        command[:3] == ["uv", "run", "wily"] and "rank" in command for command in calls
    )

    symlink_reports_dir = repo_dir / "symlink-reports"
    symlink_reports_dir.mkdir(parents=True, exist_ok=True)
    symlink_cache_target = tmp_path / "symlink-target"
    symlink_cache_target.write_text("stale\n", encoding="utf-8")
    symlink_cache_dir = symlink_reports_dir / "wily-cache"
    symlink_cache_dir.symlink_to(symlink_cache_target)
    monkeypatch.setenv("QUALITY_ARTIFACT_DIR", str(symlink_reports_dir))
    calls.clear()
    assert module.main() == 0
    assert not symlink_cache_dir.exists()


def test_run_mutation_tests_main_uses_configurable_paths_and_runner(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Build the coverage and mutmut commands from the configured environment."""
    module = load_script_module(monkeypatch, "run_mutation_tests")
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    coverage_file = repo_dir / ".coverage.old"
    coverage_file.write_text("stale\n", encoding="utf-8")
    coverage_config = repo_dir / ".coveragerc"
    coverage_config.write_text("[run]\nbranch = True\n", encoding="utf-8")
    (repo_dir / ".coverage-dir").mkdir()
    monkeypatch.setattr(module, "repo_root", lambda _: repo_dir)
    monkeypatch.setattr(module, "find_uv_binary", lambda: "uv")
    monkeypatch.setenv("MUTATION_PATHS", "pulumi/app,scripts")
    monkeypatch.setenv(
        "MUTATION_TEST_TARGETS",
        "tests/unit/test_environment_component.py tests/unit/test_guardrails.py",
    )
    monkeypatch.setenv("MUTATION_TESTS_DIR", "tests/unit")
    monkeypatch.setenv("MUTATION_COVERAGE_TARGETS", "tests/unit/test_guardrails.py")
    monkeypatch.setenv("MUTATION_TEST_TIME_MULTIPLIER", "4")
    monkeypatch.setenv(
        "MUTATION_RUNNER", "uv run pytest -q tests/unit/test_guardrails.py"
    )

    calls: list[list[str]] = []
    monkeypatch.setattr(
        module,
        "run",
        lambda command, **kwargs: (
            calls.append(command) or subprocess.CompletedProcess(command, 0)
        ),
    )

    assert module.main() == 0
    assert not coverage_file.exists()
    assert coverage_config.exists()
    assert calls[0] == [
        "uv",
        "run",
        "pytest",
        "-q",
        "--cov=pulumi/app",
        "--cov=scripts",
        "--cov-branch",
        "--cov-report=",
        "tests/unit/test_guardrails.py",
    ]
    assert calls[1] == [
        "uv",
        "run",
        "mutmut",
        "run",
        "--paths-to-mutate",
        "pulumi/app scripts",
        "--runner",
        "uv run pytest -q tests/unit/test_guardrails.py",
        "--tests-dir",
        "tests/unit",
        "--test-time-multiplier",
        "4",
        "--use-coverage",
    ]


def test_run_pulumi_drift_check_main_handles_skip_and_success_paths(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Validate shared-backend drift orchestration without touching real cloud state."""
    module = load_script_module(monkeypatch, "run_pulumi_drift_check")
    repo_dir = tmp_path / "repo"
    monkeypatch.setattr(module, "repo_root", lambda _: repo_dir)

    assert module.main() == 1
    assert "does not exist" in capsys.readouterr().err

    pulumi_dir = repo_dir / "pulumi"
    pulumi_dir.mkdir(parents=True)
    policy_dir = repo_dir / "policy"
    policy_dir.mkdir()
    monkeypatch.setenv("PULUMI_BACKEND_URL", "file:///workspace/.pulumi-backend")
    assert module.main() == 0
    assert "Skipping drift detection" in capsys.readouterr().out

    calls: list[list[str]] = []
    monkeypatch.setattr(
        module,
        "run",
        lambda command, **kwargs: (
            calls.append(command) or subprocess.CompletedProcess(command, 0)
        ),
    )
    monkeypatch.setenv("PULUMI_BACKEND_URL", "s3://shared-backend")
    monkeypatch.setattr(module, "discover_stacks", lambda *args: [])
    assert module.main() == 1
    assert "no Pulumi stacks configured for drift detection" in capsys.readouterr().err
    assert calls == []

    calls.clear()
    monkeypatch.setattr(module, "discover_stacks", lambda *args: ["dev"])
    assert module.main() == 0
    assert calls[0][0] == sys.executable
    assert calls[1][:5] == [
        "pulumi",
        "--cwd",
        str(pulumi_dir),
        "login",
        "--non-interactive",
    ]
    assert calls[2][3:6] == ["stack", "select", "dev"]
    assert "--expect-no-changes" in calls[3]


def test_run_pulumi_preview_main_handles_empty_and_successful_runs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Validate preview orchestration and summary generation for file backends."""
    module = load_script_module(monkeypatch, "run_pulumi_preview")
    repo_dir = tmp_path / "repo"
    pulumi_dir = repo_dir / "pulumi"
    policy_dir = repo_dir / "policy"
    preview_dir = repo_dir / ".artifacts" / "pulumi-preview"
    preview_dir.mkdir(parents=True)
    pulumi_dir.mkdir()
    policy_dir.mkdir()
    (preview_dir / "stale.json").write_text("{}", encoding="utf-8")
    (preview_dir / "summary.md").write_text("old summary\n", encoding="utf-8")
    monkeypatch.setattr(module, "repo_root", lambda _: repo_dir)
    monkeypatch.delenv("PULUMI_BACKEND_URL", raising=False)
    monkeypatch.setenv(
        "PULUMI_SECRETS_PROVIDER",
        "awskms://alias/bootstrap-preview?region=eu-central-1",
    )

    precheck_calls: list[list[str]] = []
    monkeypatch.setattr(
        module,
        "run",
        lambda command, **kwargs: (
            precheck_calls.append(command)
            or subprocess.CompletedProcess(command, 0, stdout="")
        ),
    )
    monkeypatch.setattr(module, "discover_stacks", lambda *args: [])
    assert module.main() == 1
    assert "no Pulumi stack configs found" in capsys.readouterr().err

    run_calls: list[tuple[list[str], dict[str, str], object | None]] = []

    def fake_run(command, **kwargs):
        env = kwargs.get("env", {})
        stdout = kwargs.get("stdout")
        run_calls.append((command, env, stdout))
        if command[0] == "pulumi" and command[3:6] == ["stack", "select", "dev"]:
            return subprocess.CompletedProcess(command, 1, stderr="missing stack\n")
        if command[0] == "pulumi" and command[3:6] == ["stack", "select", "qa/staging"]:
            return subprocess.CompletedProcess(command, 1, stderr="missing stack\n")
        if command[0] == "pulumi" and "preview" in command and stdout is not None:
            stdout.write('{"changeSummary": {"create": 1}, "steps": []}')
            stdout.flush()
            return subprocess.CompletedProcess(command, 0)
        if command[:3] == ["uv", "--project", str(repo_dir)]:
            preview_path = Path(command[-1])
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=f"### Pulumi Preview: {preview_path.stem}\n\n",
            )
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(module, "discover_stacks", lambda *args: ["dev", "qa/staging"])
    monkeypatch.setattr(module, "run", fake_run)
    assert module.main() == 0

    dev_stem = module._safe_preview_artifact_stem("dev")
    staging_stem = module._safe_preview_artifact_stem("qa/staging")
    output = capsys.readouterr().out
    assert f"Pulumi Preview: {dev_stem}" in output
    assert f"Pulumi Preview: {staging_stem}" in output
    assert not (preview_dir / "stale.json").exists()
    assert (preview_dir / f"{dev_stem}.json").is_file()
    assert (preview_dir / f"{staging_stem}.json").is_file()
    assert (repo_dir / ".pulumi-backend").is_dir()
    backend_url = (repo_dir / ".pulumi-backend").resolve().as_uri()
    assert any(
        env.get("PULUMI_BACKEND_URL") == backend_url
        and env.get("PULUMI_SECRETS_PROVIDER")
        == "awskms://alias/bootstrap-preview?region=eu-central-1"
        for _, env, _ in run_calls
    )
    assert any(
        len(command) > 1 and "prepare_policy_pack.py" in str(command[1])
        for command, _, _ in run_calls
    )
    assert any(
        command[:5]
        == ["pulumi", "--cwd", str(pulumi_dir), "login", "--non-interactive"]
        for command, _, _ in run_calls
    )
    assert any(
        command[3:10]
        == [
            "stack",
            "init",
            "dev",
            "--non-interactive",
            "--secrets-provider",
            "awskms://alias/bootstrap-preview?region=eu-central-1",
        ]
        for command, _, _ in run_calls
    )


def test_run_pulumi_preview_artifact_stems_add_a_hash_to_avoid_collisions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Different raw stack names must not collapse into the same artifact stem."""
    module = load_script_module(monkeypatch, "run_pulumi_preview")

    slash_stack = module._safe_preview_artifact_stem("org/prod")
    underscore_stack = module._safe_preview_artifact_stem("org_prod")

    assert slash_stack.startswith("org_prod-")
    assert underscore_stack.startswith("org_prod-")
    assert slash_stack != underscore_stack


def test_select_stack_for_preview_returns_none_for_existing_stack(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Existing stacks should bypass the create-with-provider flow entirely."""
    module = load_script_module(monkeypatch, "run_pulumi_preview")
    pulumi_dir = tmp_path / "pulumi"
    pulumi_dir.mkdir()
    calls: list[list[str]] = []

    def fake_run(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, stdout="")

    monkeypatch.setattr(module, "run", fake_run)
    result = module._select_stack_for_preview(
        pulumi_dir,
        "dev",
        env={"PULUMI_BACKEND_URL": "file:///tmp/backend"},
        uses_file_backend=True,
        secrets_provider="awskms://alias/example?region=eu-central-1",
    )

    assert result is None
    assert calls == [
        [
            "pulumi",
            "--cwd",
            str(pulumi_dir),
            "stack",
            "select",
            "dev",
            "--non-interactive",
        ]
    ]


def test_run_pulumi_preview_main_keeps_shared_backends_read_only(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Fail fast instead of creating typo stacks in shared preview backends."""
    module = load_script_module(monkeypatch, "run_pulumi_preview")
    repo_dir = tmp_path / "repo"
    pulumi_dir = repo_dir / "pulumi"
    policy_dir = repo_dir / "policy"
    preview_dir = repo_dir / ".artifacts" / "pulumi-preview"
    preview_dir.mkdir(parents=True)
    pulumi_dir.mkdir()
    policy_dir.mkdir()
    monkeypatch.setattr(module, "repo_root", lambda _: repo_dir)
    monkeypatch.setenv("PULUMI_BACKEND_URL", "s3://shared-backend")
    monkeypatch.setattr(module, "discover_stacks", lambda *args: ["missing-stack"])

    run_calls: list[tuple[list[str], dict[str, str]]] = []

    def fake_run(command, **kwargs):
        env = kwargs.get("env", {})
        run_calls.append((command, env))
        if command[0] == "pulumi" and command[3:6] == [
            "stack",
            "select",
            "missing-stack",
        ]:
            return subprocess.CompletedProcess(
                command,
                255,
                stderr="error: no stack named missing-stack found\n",
            )
        return subprocess.CompletedProcess(command, 0, stdout="")

    monkeypatch.setattr(module, "run", fake_run)
    assert module.main() == 255

    error_output = capsys.readouterr().err
    assert "shared-backend previews will not create missing stacks" in error_output
    assert "no stack named missing-stack found" in error_output
    assert any(
        command[3:7] == ["stack", "select", "missing-stack", "--non-interactive"]
        for command, _ in run_calls
    )
    assert not any("--create" in command for command, _ in run_calls)


def test_run_pulumi_preview_main_returns_file_backend_select_failures(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Require an explicit KMS secrets provider before creating file-backed stacks."""
    module = load_script_module(monkeypatch, "run_pulumi_preview")
    repo_dir = tmp_path / "repo"
    pulumi_dir = repo_dir / "pulumi"
    policy_dir = repo_dir / "policy"
    preview_dir = repo_dir / ".artifacts" / "pulumi-preview"
    preview_dir.mkdir(parents=True)
    pulumi_dir.mkdir()
    policy_dir.mkdir()
    monkeypatch.setattr(module, "repo_root", lambda _: repo_dir)
    monkeypatch.delenv("PULUMI_BACKEND_URL", raising=False)
    monkeypatch.delenv("PULUMI_SECRETS_PROVIDER", raising=False)
    monkeypatch.setattr(module, "discover_stacks", lambda *args: ["dev"])

    run_calls: list[list[str]] = []

    def fake_run(command, **kwargs):
        run_calls.append(command)
        if command[0] == "pulumi" and command[3:6] == ["stack", "select", "dev"]:
            return subprocess.CompletedProcess(
                command,
                1,
                stderr="error: no stack named dev found\n",
            )
        return subprocess.CompletedProcess(command, 0, stdout="")

    monkeypatch.setattr(module, "run", fake_run)
    assert module.main() == 1

    error_output = capsys.readouterr().err
    assert "file-backed previews require PULUMI_SECRETS_PROVIDER" in error_output
    assert "shared-backend previews will not create missing stacks" not in error_output
    assert any(
        command[3:7] == ["stack", "select", "dev", "--non-interactive"]
        for command in run_calls
    )


def test_select_stack_for_preview_surfaces_stack_init_failures(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Propagate init failures after a missing file-backed stack selection."""
    module = load_script_module(monkeypatch, "run_pulumi_preview")
    pulumi_dir = tmp_path / "pulumi"
    pulumi_dir.mkdir()

    def fake_run(command, **kwargs):
        if command[0] == "pulumi" and command[3:6] == ["stack", "select", "dev"]:
            return subprocess.CompletedProcess(
                command,
                1,
                stderr="error: no stack named dev found\n",
            )
        if command[0] == "pulumi" and command[3:6] == ["stack", "init", "dev"]:
            return subprocess.CompletedProcess(
                command,
                255,
                stderr="error: access denied to KMS key\n",
            )
        return subprocess.CompletedProcess(command, 0, stdout="")

    monkeypatch.setattr(module, "run", fake_run)
    result = module._select_stack_for_preview(
        pulumi_dir,
        "dev",
        env={"PULUMI_BACKEND_URL": "file:///tmp/backend"},
        uses_file_backend=True,
        secrets_provider="awskms://alias/example?region=eu-central-1",
    )

    assert result == 255
    assert "access denied to KMS key" in capsys.readouterr().err


def test_select_stack_for_preview_handles_empty_stderr_error_paths(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Cover the stderr-free branches for shared, missing-provider, and init errors."""
    module = load_script_module(monkeypatch, "run_pulumi_preview")
    pulumi_dir = tmp_path / "pulumi"
    pulumi_dir.mkdir()

    def shared_run(command, **kwargs):
        if command[0] == "pulumi" and command[3:6] == ["stack", "select", "dev"]:
            return subprocess.CompletedProcess(command, 1, stderr="")
        return subprocess.CompletedProcess(command, 0, stdout="")

    monkeypatch.setattr(module, "run", shared_run)
    assert (
        module._select_stack_for_preview(
            pulumi_dir,
            "dev",
            env={"PULUMI_BACKEND_URL": "s3://shared-backend"},
            uses_file_backend=False,
            secrets_provider="awskms://alias/example?region=eu-central-1",
        )
        == 1
    )

    def missing_provider_run(command, **kwargs):
        if command[0] == "pulumi" and command[3:6] == ["stack", "select", "dev"]:
            return subprocess.CompletedProcess(command, 1, stderr="")
        return subprocess.CompletedProcess(command, 0, stdout="")

    monkeypatch.setattr(module, "run", missing_provider_run)
    assert (
        module._select_stack_for_preview(
            pulumi_dir,
            "dev",
            env={"PULUMI_BACKEND_URL": "file:///tmp/backend"},
            uses_file_backend=True,
            secrets_provider="",
        )
        == 1
    )

    def init_failure_run(command, **kwargs):
        if command[0] == "pulumi" and command[3:6] == ["stack", "select", "dev"]:
            return subprocess.CompletedProcess(command, 1, stderr="")
        if command[0] == "pulumi" and command[3:6] == ["stack", "init", "dev"]:
            return subprocess.CompletedProcess(command, 1, stderr="")
        return subprocess.CompletedProcess(command, 0, stdout="")

    monkeypatch.setattr(module, "run", init_failure_run)
    assert (
        module._select_stack_for_preview(
            pulumi_dir,
            "dev",
            env={"PULUMI_BACKEND_URL": "file:///tmp/backend"},
            uses_file_backend=True,
            secrets_provider="awskms://alias/example?region=eu-central-1",
        )
        == 1
    )
