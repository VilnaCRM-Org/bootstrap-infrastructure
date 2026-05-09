"""Unit tests for repo-local Python script entrypoints."""

from __future__ import annotations

import hashlib
import importlib
import json
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
    assert module.discover_stacks(pulumi_dir, None) == ["dev"]  # nosec B101
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
    assert "docker: missing or not installed" in capsys.readouterr().err

    env_file = tmp_path / ".env"
    env_file.write_text("KEY=value\n", encoding="utf-8")
    monkeypatch.setenv("COMPOSE_ENV_FILE", str(env_file))
    monkeypatch.setenv("COMPOSE_SERVICE", "pulumi")
    monkeypatch.setenv("PULUMI_DIR", str(tmp_path / "missing"))
    monkeypatch.setattr(
        module,
        "_version",
        lambda command: (
            (_ for _ in ()).throw(subprocess.CalledProcessError(1, command))
            if "--short" in command
            else "Docker version 1.0.0"
        ),
    )
    assert module.main() == 1
    assert "docker compose: missing" in capsys.readouterr().err

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


def test_configure_github_repository_controls_payloads(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Build the GitHub admin-control payloads without applying them."""
    module = load_script_module(monkeypatch, "configure_github_repository_controls")
    existing_pull_request_rule = {
        "type": "pull_request",
        "parameters": {"required_approving_review_count": 2},
    }
    existing_code_quality_rule = {
        "type": "code_quality",
        "parameters": {"severity": "errors"},
    }

    payload = module.ruleset_payload(
        [
            existing_pull_request_rule,
            existing_code_quality_rule,
            {"type": "ignored_rule"},
        ]
    )
    rules = {rule["type"]: rule for rule in payload["rules"]}
    contexts = [
        check["context"]
        for check in rules["required_status_checks"]["parameters"][
            "required_status_checks"
        ]
    ]

    assert contexts == list(module.REQUIRED_STATUS_CHECKS)  # nosec B101
    assert rules["pull_request"] == existing_pull_request_rule  # nosec B101
    assert rules["code_quality"] == existing_code_quality_rule  # nosec B101
    assert module.prod_environment_payload(9444106) == {  # nosec B101
        "wait_timer": 0,
        "prevent_self_review": True,
        "reviewers": [{"type": "User", "id": 9444106}],
        "deployment_branch_policy": {
            "protected_branches": True,
            "custom_branch_policies": False,
        },
    }

    monkeypatch.setattr(module, "_main_ruleset", lambda _repo: None)
    assert (  # nosec B101
        module.main(["--repo", "VilnaCRM-Org/bootstrap-infrastructure"]) == 0
    )
    rendered = json.loads(capsys.readouterr().out)
    assert rendered["prodEnvironment"]["reviewers"][0]["id"] == 0  # nosec B101
    assert rendered["prodEnvironmentReviewerLogin"] == "Kravalg"  # nosec B101


def test_configure_github_repository_controls_api_helpers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cover gh api parsing, ruleset lookup, and reviewer resolution paths."""
    module = load_script_module(monkeypatch, "configure_github_repository_controls")
    calls: list[tuple[list[str], str | None]] = []
    responses = [
        '{"ok": true}',
        "",
        '"scalar"',
        '[{"name":"other"},{"name":"main","target":"branch","id":123}]',
        '{"id":123,"rules":[{"type":"deletion"}]}',
        '{"not":"a-list"}',
        '["invalid", {"name":"main","target":"branch","id":"not-int"}]',
        '{"id":9444106}',
        "{}",
        "[]",
        '{"permissions":{"admin":true}}',
        '{"permissions":{"admin":false}}',
        '{"permissions":{}}',
    ]

    def fake_run(command, input=None, check=None, capture_output=None, text=None):
        calls.append((command, input))
        return subprocess.CompletedProcess(command, 0, stdout=responses.pop(0))

    monkeypatch.setattr(module.subprocess, "run", fake_run)

    assert module._run_gh_api(["repos/example/repo"]) == {"ok": True}  # nosec B101
    assert (  # nosec B101
        module._run_gh_api(["repos/example/repo"], input_payload={"x": 1}) == {}
    )
    assert module._run_gh_api(["repos/example/repo"]) == {}  # nosec B101
    assert module._main_ruleset("example/repo") == {  # nosec B101
        "id": 123,
        "rules": [{"type": "deletion"}],
    }
    assert module._main_ruleset("example/repo") is None  # nosec B101
    assert module._main_ruleset("example/repo") is None  # nosec B101
    assert module._github_user_id("Kravalg") == 9444106  # nosec B101
    with pytest.raises(ValueError, match="Could not resolve"):
        module._github_user_id("missing")
    assert module._repo_admin_allowed("example/repo") is False  # nosec B101  # noqa: SLF001
    assert module._repo_admin_allowed("example/repo") is True  # nosec B101  # noqa: SLF001
    assert module._repo_admin_allowed("example/repo") is False  # nosec B101  # noqa: SLF001
    assert module._repo_admin_allowed("example/repo") is False  # nosec B101  # noqa: SLF001
    assert calls[1][1] == '{"x": 1}'  # nosec B101

    def failing_run(command, input=None, check=None, capture_output=None, text=None):
        return subprocess.CompletedProcess(command, 1, stdout="", stderr="denied")

    monkeypatch.setattr(module.subprocess, "run", failing_run)
    with pytest.raises(RuntimeError, match="denied"):
        module._run_gh_api(["repos/example/repo"])


def test_configure_github_repository_controls_apply_paths(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Apply existing and new ruleset paths through gh api wrappers."""
    module = load_script_module(monkeypatch, "configure_github_repository_controls")
    calls: list[tuple[list[str], dict]] = []
    existing = {"id": 123, "rules": "invalid"}

    monkeypatch.setattr(module, "_repo_admin_allowed", lambda _repo: True)
    monkeypatch.setattr(module, "_github_user_id", lambda _reviewer: 9444106)

    def fake_run_gh_api(args, *, input_payload=None):
        calls.append((list(args), dict(input_payload or {})))
        return {}

    monkeypatch.setattr(module, "_run_gh_api", fake_run_gh_api)
    monkeypatch.setattr(module, "_main_ruleset", lambda _repo: existing)

    assert module.configure("example/repo", "Kravalg", apply=True) == 0  # nosec B101
    assert calls[0][0] == [  # nosec B101
        "repos/example/repo/rulesets/123",
        "--method",
        "PUT",
    ]
    assert calls[1][0] == [  # nosec B101
        "repos/example/repo/environments/prod",
        "--method",
        "PUT",
    ]
    rendered = json.loads(capsys.readouterr().out)
    assert rendered["prodEnvironment"]["reviewers"][0]["id"] == 9444106  # nosec B101

    calls.clear()
    monkeypatch.setattr(module, "_main_ruleset", lambda _repo: None)
    assert module.configure("example/repo", "Kravalg", apply=True) == 0  # nosec B101
    assert calls[0][0] == ["repos/example/repo/rulesets", "--method", "POST"]  # nosec B101


def test_configure_github_repository_controls_apply_requires_admin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fail before mutating repository controls when the token is not an admin."""
    module = load_script_module(monkeypatch, "configure_github_repository_controls")
    calls: list[list[str]] = []

    monkeypatch.setattr(module, "_main_ruleset", lambda _repo: {"id": 123, "rules": []})
    monkeypatch.setattr(module, "_repo_admin_allowed", lambda _repo: False)
    monkeypatch.setattr(module, "_github_user_id", lambda _reviewer: 9444106)

    def fake_run_gh_api(args, *, input_payload=None):
        calls.append(list(args))
        return {}

    monkeypatch.setattr(module, "_run_gh_api", fake_run_gh_api)

    with pytest.raises(RuntimeError, match="repository admin rights"):
        module.configure("example/repo", "Kravalg", apply=True)
    assert calls == []  # nosec B101


def test_configure_github_repository_controls_main_reports_errors(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Return a non-zero exit when GitHub rejects the admin update."""
    module = load_script_module(monkeypatch, "configure_github_repository_controls")

    def fail_configure(*_args, **_kwargs):
        raise RuntimeError("admin required")

    monkeypatch.setattr(module, "configure", fail_configure)

    assert module.main(["--repo", "example/repo", "--apply"]) == 1  # nosec B101
    assert "error:" in capsys.readouterr().err  # nosec B101


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


def test_validate_repository_catalogs_main_validates_default_catalogs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Validate committed repository catalog files against schema and loader rules."""
    module = load_script_module(monkeypatch, "validate_repository_catalogs")
    repo_dir = tmp_path / "repo"
    pulumi_dir = repo_dir / "pulumi"
    pulumi_dir.mkdir(parents=True)
    schema_path = pulumi_dir / "repositories.schema.json"
    schema_path.write_text(
        (PROJECT_ROOT / "pulumi" / "repositories.schema.json").read_text(
            encoding="utf-8"
        ),
        encoding="utf-8",
    )
    catalog_path = pulumi_dir / "repositories.example.json"
    catalog_path.write_text(
        json.dumps(
            {
                "$schema": "./repositories.schema.json",
                "repositories": [
                    {
                        "name": "user-service-infrastructure",
                        "defaultBranch": "main",
                        "project": "user-service",
                        "owner": "team-user-service",
                        "lifecycleState": "active",
                        "lastReviewed": "2026-04-27",
                        "expectedEnvironments": 2,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(module, "ROOT_DIR", repo_dir)

    assert module.repository_catalog_paths(repo_dir) == [catalog_path]  # nosec B101
    assert module.validate_catalogs(  # nosec B101
        [catalog_path], schema_path
    ) == [catalog_path]
    assert module.catalog_fanout_report(catalog_path, schema_path) == {  # nosec B101
        "backupPlans": 1,
        "backupSelections": 2,
        "backupVaults": 1,
        "budgets": 1,
        "cloudTrailTrails": 1,
        "configDeliveryChannels": 1,
        "configRecorders": 1,
        "costAllocationTags": 0,
        "costAnomalyMonitors": 1,
        "costAnomalySubscriptions": 1,
        "ecrRepositories": 1,
        "environmentInstances": 2,
        "eventRules": 4,
        "guardDutyDetectors": 1,
        "iamRoles": 7,
        "kmsKeys": 3,
        "oidcProviders": 1,
        "repositories": 1,
        "s3Buckets": 8,
        "securityHubAccounts": 1,
        "snsSubscriptions": 1,
        "snsTopics": 1,
        "sqsQueues": 1,
    }
    assert module._fanout_threshold_report(  # nosec B101
        {"s3Buckets": 6, "kmsKeys": 3},
        {"s3Buckets": 10, "kmsKeys": 2},
    ) == {
        "kmsKeys": {
            "current": 3,
            "max": 2,
            "overBy": 1,
            "remaining": 0,
            "status": "exceeded",
        },
        "s3Buckets": {
            "current": 6,
            "max": 10,
            "overBy": 0,
            "remaining": 4,
            "status": "ok",
        },
    }
    assert module.main([]) == 0  # nosec B101
    assert module.main(["--fanout-report"]) == 0  # nosec B101
    assert module.main(["--fanout-report", "--max-s3-buckets", "1"]) == 1  # nosec B101
    assert module.main(["--fanout-report", "--max-budgets", "0"]) == 1  # nosec B101

    captured = capsys.readouterr()
    output = captured.out
    assert f"validated repository catalog: {catalog_path}" in output  # nosec B101
    assert "repository fanout estimate" in output  # nosec B101
    assert "repository fanout thresholds" in output  # nosec B101
    assert '"current": 8' in output  # nosec B101
    assert '"remaining": 192' in output  # nosec B101
    assert "s3Buckets fanout" in captured.err  # nosec B101
    assert "budgets fanout" in captured.err  # nosec B101
    assert "cloudTrailTrails" in output  # nosec B101
    assert "guardDutyDetectors" in output  # nosec B101


def test_validate_repository_catalogs_reports_schema_errors(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Schema failures should identify the invalid catalog path."""
    module = load_script_module(monkeypatch, "validate_repository_catalogs")
    catalog_path = tmp_path / "repositories.json"
    catalog_path.write_text(
        json.dumps({"repositories": [{"name": 123}]}),
        encoding="utf-8",
    )
    schema_path = PROJECT_ROOT / "pulumi" / "repositories.schema.json"

    assert module._json_pointer(["repositories", 0, "name"]) == (  # nosec B101
        "$.repositories[0].name"
    )
    assert module.main(["--schema", str(schema_path), str(catalog_path)]) == 1  # nosec B101

    error_output = capsys.readouterr().err
    assert str(catalog_path) in error_output  # nosec B101
    assert "$.repositories[0]" in error_output  # nosec B101


def test_validate_repository_catalogs_reports_semantic_errors(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Loader-level checks should still catch schema-valid duplicate names."""
    module = load_script_module(monkeypatch, "validate_repository_catalogs")
    catalog_path = tmp_path / "repositories.json"
    catalog_path.write_text(
        json.dumps({"repositories": ["Repo", "repo"]}),
        encoding="utf-8",
    )
    schema_path = PROJECT_ROOT / "pulumi" / "repositories.schema.json"

    with pytest.raises(ValueError, match="must be unique"):
        module.validate_catalog(catalog_path, schema_path)

    catalog_path.write_text(
        json.dumps(
            {
                "repositories": [
                    {
                        "name": "repo",
                        "lifecycleState": "unknown",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="lifecycleState"):
        module.validate_catalog(catalog_path, schema_path)


def test_validate_repository_catalogs_semantic_helpers_reject_bad_inputs(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Cover semantic guardrails that usually sit behind schema validation."""
    module = load_script_module(monkeypatch, "validate_repository_catalogs")

    assert module._repository_name({"name": " repo "}) == "repo"  # nosec B101
    module._validate_repository_mapping({"name": "repo"})

    with pytest.raises(ValueError, match="blank value"):
        module._required_non_blank_string(" ", "blank value")
    with pytest.raises(ValueError, match="string or an object"):
        module._repository_name(123)
    with pytest.raises(ValueError, match="must be a list"):
        module._validate_loader_semantics({"repositories": "repo"})
    with pytest.raises(ValueError, match="lastReviewed"):
        module._validate_repository_mapping(
            {"name": "repo", "lastReviewed": "27-04-2026"}
        )
    with pytest.raises(ValueError, match="lastReviewed"):
        module._validate_repository_mapping(
            {"name": "repo", "lastReviewed": "20260427"}
        )
    with pytest.raises(ValueError, match="lastReviewed"):
        module._validate_repository_mapping(
            {"name": "repo", "lastReviewed": "2026-02-30"}
        )
    with pytest.raises(ValueError, match="lifecycleState"):
        module._validate_repository_mapping(
            {"name": "repo", "lifecycleState": "unknown"}
        )
    with pytest.raises(ValueError, match="expectedEnvironments"):
        module._validate_repository_mapping({"name": "repo", "expectedEnvironments": 0})
    with pytest.raises(ValueError, match="expectedEnvironments"):
        module._validate_repository_mapping(
            {"name": "repo", "expectedEnvironments": True}
        )
    with pytest.raises(ValueError, match="must be a list"):
        module.estimate_fanout({"repositories": "repo"})
    assert (  # nosec B101
        module.estimate_fanout({"repositories": ["repo"]})["environmentInstances"] == 2
    )
    assert (  # nosec B101
        module.estimate_fanout(
            {"repositories": [{"name": "repo", "expectedEnvironments": "2"}]}
        )["environmentInstances"]
        == 2
    )

    monkeypatch.setattr(module, "validate_catalog", lambda *_args: None)
    monkeypatch.setattr(module, "_load_json", lambda _path: [])
    with pytest.raises(ValueError, match="must be an object"):
        module.catalog_fanout_report(
            tmp_path / "repositories.json",
            tmp_path / "schema.json",
        )


def test_validate_repository_catalogs_handles_empty_and_invalid_inputs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The CLI should fail clearly when no catalogs or malformed JSON are present."""
    module = load_script_module(monkeypatch, "validate_repository_catalogs")
    repo_dir = tmp_path / "repo"
    (repo_dir / "pulumi").mkdir(parents=True)
    monkeypatch.setattr(module, "ROOT_DIR", repo_dir)

    assert module.main([]) == 1  # nosec B101
    assert "no repository catalog JSON files found" in capsys.readouterr().err  # nosec B101

    schema_path = PROJECT_ROOT / "pulumi" / "repositories.schema.json"
    bad_catalog = tmp_path / "repositories.bad.json"
    bad_catalog.write_text("{not-json", encoding="utf-8")

    assert module.main(["--schema", str(schema_path), str(bad_catalog)]) == 1  # nosec B101
    assert "Expecting property name" in capsys.readouterr().err  # nosec B101

    invalid_schema = tmp_path / "repositories.schema.json"
    invalid_schema.write_text(json.dumps({"type": 123}), encoding="utf-8")
    valid_catalog = tmp_path / "repositories.json"
    valid_catalog.write_text(
        json.dumps({"repositories": ["user-service-infrastructure"]}),
        encoding="utf-8",
    )

    assert module.main(["--schema", str(invalid_schema), str(valid_catalog)]) == 1  # nosec B101
    error_output = capsys.readouterr().err
    assert str(invalid_schema) in error_output  # nosec B101
    assert "invalid repository catalog schema" in error_output  # nosec B101


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

    monkeypatch.setenv("PULUMI_BACKEND_URL", "")
    assert module.main() == 0
    assert run_calls[-1][2]["PULUMI_BACKEND_URL"] == "file:///workspace/.pulumi-backend"

    monkeypatch.setenv("PULUMI_BACKEND_URL", "s3://configured-backend")
    assert module.main() == 0
    assert run_calls[-1][2]["PULUMI_BACKEND_URL"] == "s3://configured-backend"

    monkeypatch.setenv("PULUMI_REQUIRE_SHARED_BACKEND", "true")
    monkeypatch.setenv("PULUMI_BACKEND_URL", "s3://shared-backend")
    monkeypatch.delenv("PULUMI_SECRETS_PROVIDER", raising=False)
    assert module.main() == 1  # nosec B101
    assert "privileged previews require an awskms://" in capsys.readouterr().err  # nosec B101

    monkeypatch.setenv(
        "PULUMI_SECRETS_PROVIDER",
        "awskms://alias/bootstrap-preview?region=eu-central-1",
    )
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
    assert module.main() == 0  # nosec B101
    assert calls[0][0] == sys.executable  # nosec B101
    expected_login_command = [
        "pulumi",
        "-C",
        str(pulumi_dir),
        "login",
        "--non-interactive",
    ]
    assert calls[1][:5] == expected_login_command  # nosec B101
    assert calls[2][3:6] == ["stack", "select", "dev"]  # nosec B101
    assert "--expect-no-changes" in calls[3]  # nosec B101

    calls.clear()
    relative_repo_dir = repo_dir / "nested"
    relative_repo_dir.mkdir()
    monkeypatch.setattr(module, "repo_root", lambda _: relative_repo_dir)
    (relative_repo_dir / "relative-pulumi").mkdir()
    (relative_repo_dir / "relative-policy").mkdir()
    monkeypatch.setenv("PULUMI_DIR", "relative-pulumi")
    monkeypatch.setenv("POLICY_PACK_DIR", "relative-policy")
    assert module.main() == 0  # nosec B101
    relative_login_command = [
        "pulumi",
        "-C",
        str((relative_repo_dir / "relative-pulumi").resolve()),
        "login",
        "--non-interactive",
    ]
    assert calls[1][:5] == relative_login_command  # nosec B101
    assert calls[3][-1] == str((relative_repo_dir / "relative-policy").resolve())  # nosec B101


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
    login_called = any(
        command[:5] == ["pulumi", "-C", str(pulumi_dir), "login", "--non-interactive"]
        for command, _, _ in run_calls
    )
    assert login_called  # nosec B101
    initialized_dev = any(
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
    assert initialized_dev  # nosec B101


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


def test_run_pulumi_command_builds_expected_pulumi_invocations(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Keep the generic Pulumi command helper explicit and argument-safe."""
    module = load_script_module(monkeypatch, "run_pulumi_command")
    pulumi_dir = tmp_path / "pulumi"
    policy_dir = tmp_path / "policy"
    plan_path = tmp_path / "plan"
    context = module.CommandContext(
        root_dir=tmp_path,
        env={},
        pulumi_dir=pulumi_dir,
        policy_pack_dir=policy_dir,
        plan_dir=tmp_path / "plans",
        preview_artifact_dir=tmp_path / "previews",
        backend_url="file:///tmp/backend",
        secrets_provider="awskms://alias/example?region=eu-central-1",
    )

    configured_stacks = module._configured_stack_names(
        "preview", pulumi_dir, {"PULUMI_STACK": "test"}
    )
    assert configured_stacks == ["test"]  # nosec B101
    drift_stacks = module._configured_stack_names(
        "drift", pulumi_dir, {"PULUMI_DRIFT_STACKS": "prod"}
    )
    assert drift_stacks == ["prod"]  # nosec B101
    assert module._validate_secrets_provider("not-kms") == 1  # nosec B101
    assert module._validate_secrets_provider("") == 1  # nosec B101
    assert (  # nosec B101
        module._validate_secrets_provider("awskms://alias/example") is None
    )
    assert module._uses_file_backend("file:///tmp/backend") is True  # nosec B101
    assert module._uses_file_backend("s3://bucket/state") is False  # nosec B101

    expected_preview_command = [
        "pulumi",
        "-C",
        str(pulumi_dir),
        "preview",
        "--stack",
        "test",
        "--non-interactive",
        "--policy-pack",
        str(policy_dir),
    ]
    preview_command = module._pulumi_command(
        context, module.StackCommand("preview", "test")
    )
    assert preview_command == expected_preview_command  # nosec B101
    assert "--save-plan" in module._pulumi_command(  # nosec B101
        context, module.StackCommand("plan", "test", plan_path=plan_path)
    )
    assert "--plan" in module._pulumi_command(  # nosec B101
        context, module.StackCommand("up-plan", "test", plan_path=plan_path)
    )
    drift_command = module._pulumi_command(
        context, module.StackCommand("drift", "test")
    )
    up_command = module._pulumi_command(context, module.StackCommand("up", "test"))
    refresh_command = module._pulumi_command(
        context, module.StackCommand("refresh", "test")
    )
    destroy_command = module._pulumi_command(
        context, module.StackCommand("destroy", "test")
    )
    assert "--yes" in up_command  # nosec B101
    assert "--yes" in refresh_command  # nosec B101
    assert "--expect-no-changes" in drift_command  # nosec B101
    assert "--yes" in destroy_command  # nosec B101

    with pytest.raises(ValueError, match="plan command requires"):
        module._pulumi_command(context, module.StackCommand("plan", "test"))
    with pytest.raises(ValueError, match="up-plan command requires"):
        module._pulumi_command(context, module.StackCommand("up-plan", "test"))
    with pytest.raises(ValueError, match="unsupported"):
        module._pulumi_command(context, module.StackCommand("unknown", "test"))


def test_run_pulumi_command_prefers_configured_stack_lists(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Multi-stack commands should not be masked by Make's default PULUMI_STACK."""
    module = load_script_module(monkeypatch, "run_pulumi_command")
    pulumi_dir = tmp_path / "pulumi"
    pulumi_dir.mkdir()

    preview_stacks = module._configured_stack_names(
        "preview",
        pulumi_dir,
        {"PULUMI_STACK": "default", "PULUMI_PREVIEW_STACKS": "test prod/eu"},
    )
    drift_stacks = module._configured_stack_names(
        "drift",
        pulumi_dir,
        {"PULUMI_STACK": "default", "PULUMI_DRIFT_STACKS": "prod"},
    )
    up_plan_stacks = module._configured_stack_names(
        "up-plan",
        pulumi_dir,
        {"PULUMI_STACK": "default", "PULUMI_PREVIEW_STACKS": "test prod/eu"},
    )

    assert preview_stacks == ["test", "prod/eu"]  # nosec B101
    assert drift_stacks == ["prod"]  # nosec B101
    assert up_plan_stacks == ["test", "prod/eu"]  # nosec B101


def test_run_pulumi_command_safe_artifact_stem_handles_empty_sanitized_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Artifact names should still be stable when no stack characters are safe."""
    module = load_script_module(monkeypatch, "run_pulumi_command")

    stem = module._safe_artifact_stem("")

    assert stem.startswith("stack-")  # nosec B101
    assert len(stem) == len("stack-") + 8  # nosec B101


def test_collect_well_architected_evidence_success_path(  # noqa: C901
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Metadata evidence collector should score proven controls without secrets."""
    module = load_script_module(monkeypatch, "collect_well_architected_evidence")
    reviewed_at = module.dt.datetime.now(module.dt.timezone.utc).isoformat()
    restore_evidence = tmp_path / "restore-drill.json"
    restore_evidence.write_text(
        json.dumps(
            {
                "workload": "bootstrap-infrastructure",
                "environment": "test",
                "completedAt": "2026-04-27T10:00:00Z",
                "sourceRecoveryPointArn": (
                    "arn:aws:backup:us-east-1:123456789012:recovery-point:test"
                ),
                "targetRestoreLocation": "s3://awsbackup-restore-test-bootstrap-123456789012-drill",
                "validationResult": "passed",
                "cleanupConfirmed": True,
            }
        ),
        encoding="utf-8",
    )
    question_matrix_evidence = tmp_path / "question-matrix.json"
    question_matrix_evidence.write_text(
        json.dumps(
            {
                "workload": "bootstrap-infrastructure",
                "owner": "platform",
                "reviewedAt": reviewed_at,
                "questionCount": 57,
                "unresolvedQuestionCount": 0,
                "unresolvedQuestionIds": [],
                "questionScoreAverages": {
                    "Operational Excellence": 5.0,
                    "Security": 5.0,
                },
                "pillarUnresolvedQuestionCounts": {
                    "Operational Excellence": 0,
                    "Security": 0,
                },
                "evidenceLocation": (
                    "specs/issue-17-well-architected-5-of-5/question-matrix.md"
                ),
            }
        ),
        encoding="utf-8",
    )
    external_control_evidence = tmp_path / "external-controls.json"
    external_control_evidence.write_text(
        json.dumps(
            {
                "workload": "bootstrap-infrastructure",
                "owner": "platform",
                "reviewedAt": reviewed_at,
                "controlCount": 8,
                "unresolvedControlCount": 0,
                "controls": [
                    {"id": "alert_route", "status": "passed"},
                    {"id": "backup_restore", "status": "passed"},
                    {"id": "branch_protection", "status": "passed"},
                    {"id": "finops", "status": "passed"},
                    {"id": "production_approval", "status": "passed"},
                    {"id": "quota_headroom", "status": "passed"},
                    {"id": "security_account_controls", "status": "passed"},
                    {"id": "sustainability_governance", "status": "passed"},
                ],
                "evidenceLocation": "internal-control-ledger",
                "fallbackPlan": "Block final score claims until evidence is refreshed.",
            }
        ),
        encoding="utf-8",
    )

    def runner(command, **_kwargs):  # noqa: C901
        command_text = " ".join(command)
        payload: object
        if command[:4] == ["git", "-C", str(PROJECT_ROOT), "rev-parse"]:
            return subprocess.CompletedProcess(command, 0, "abc123\n", "")
        if command[:4] == ["git", "-C", str(PROJECT_ROOT), "status"]:
            return subprocess.CompletedProcess(command, 0, "", "")
        if command[:3] == ["gh", "pr", "view"]:
            payload = {
                "mergeStateStatus": "CLEAN",
                "reviewDecision": "APPROVED",
                "headRefOid": "abc123",
                "headRefName": "feature",
                "statusCheckRollup": [
                    {
                        "__typename": "CheckRun",
                        "name": "Unit",
                        "status": "COMPLETED",
                        "conclusion": "SUCCESS",
                    },
                    {
                        "__typename": "CheckRun",
                        "name": "Preview (Unprivileged)",
                        "status": "COMPLETED",
                        "conclusion": "SKIPPED",
                    },
                    {
                        "__typename": "StatusContext",
                        "context": "qlty check",
                        "state": "SUCCESS",
                    },
                ],
            }
        elif command[:3] == ["gh", "api", "graphql"]:
            payload = {
                "data": {
                    "repository": {
                        "pullRequest": {
                            "reviewThreads": {
                                "nodes": [{"isResolved": True}, {"isResolved": True}]
                            }
                        }
                    }
                }
            }
        elif command[:2] == ["gh", "api"]:
            payload = {
                "required_status_checks": {"contexts": ["Unit"]},
                "required_pull_request_reviews": {"required_approving_review_count": 1},
                "enforce_admins": {"enabled": True},
            }
        elif command[:3] == ["aws", "sts", "get-caller-identity"]:
            payload = {"Account": "123456789012", "Arn": "arn:aws:iam::123:user/test"}
        elif command[:3] == ["aws", "budgets", "describe-budgets"]:
            payload = 1
        elif command[:3] == ["aws", "ce", "get-anomaly-monitors"]:
            payload = 1
        elif command[:3] == ["aws", "sns", "get-topic-attributes"]:
            payload = "arn:aws:kms:us-east-1:123456789012:key/topic"
        elif command[:3] == ["aws", "sns", "list-subscriptions-by-topic"]:
            payload = ["sqs"]
        elif command[:3] == ["aws", "cloudtrail", "get-trail"]:
            payload = {
                "Name": "bootstrap-test-management-events",
                "IsMultiRegionTrail": True,
                "IncludeGlobalServiceEvents": True,
                "LogFileValidationEnabled": True,
                "KmsKeyId": "arn:aws:kms:us-east-1:123456789012:key/cloudtrail",
            }
        elif command[:3] == ["aws", "cloudtrail", "get-trail-status"]:
            payload = {
                "IsLogging": True,
                "LatestDeliveryTime": "2026-04-27T10:00:00Z",
            }
        elif command[:3] == ["aws", "cloudtrail", "get-event-selectors"]:
            payload = [{"IncludeManagementEvents": True, "ReadWriteType": "All"}]
        elif command[:3] == ["aws", "backup", "list-restore-jobs"]:
            payload = ["COMPLETED"]
        else:  # pragma: no cover - fail fast if the command contract changes.
            raise AssertionError(command_text)
        return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")

    args = module.build_parser().parse_args(
        [
            "--repo",
            "VilnaCRM-Org/bootstrap-infrastructure",
            "--pr",
            "22",
            "--aws-account-id",
            "123456789012",
            "--operations-topic-arn",
            "arn:aws:sns:us-east-1:123456789012:bootstrap-test-operations",
            "--operations-cloudtrail-name",
            "bootstrap-test-management-events",
            "--restore-drill-evidence",
            str(restore_evidence),
            "--question-matrix-evidence",
            str(question_matrix_evidence),
            "--external-control-evidence",
            str(external_control_evidence),
            "--required-status-check",
            "Unit",
            "--root-dir",
            str(PROJECT_ROOT),
        ]
    )
    report = module.collect_evidence(args, runner=runner)

    assert report["blockers"] == []  # nosec B101
    assert report["scoreBlockers"] == []  # nosec B101
    assert report["proxyPillarScores"] == report["pillarScores"]  # nosec B101
    assert all(score == 5 for score in report["pillarScores"].values())  # nosec B101
    assert {check["status"] for check in report["checks"]} == {"passed"}  # nosec B101
    checks = {check["name"]: check for check in report["checks"]}
    question_evidence = checks["question_matrix_evidence"]["evidence"]
    assert question_evidence["unresolvedQuestionIds"] == []  # nosec B101
    assert question_evidence["questionScoreAverages"]["Security"] == 5.0  # nosec B101
    assert (  # nosec B101
        question_evidence["pillarUnresolvedQuestionCounts"]["Security"] == 0
    )
    assert (  # nosec B101
        checks["external_control_evidence"]["evidence"].get("unresolvedControlIds")
        is None
    )


def test_collect_well_architected_evidence_reports_failed_controls(  # noqa: C901
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Collector should keep blockers explicit when metadata is insufficient."""
    module = load_script_module(monkeypatch, "collect_well_architected_evidence")

    def runner(command, **_kwargs):  # noqa: C901
        if command[0] == "git" and command[3:5] == ["rev-parse", "HEAD"]:
            return subprocess.CompletedProcess(command, 0, "local123\n", "")
        if command[0] == "git" and command[3] == "status":
            return subprocess.CompletedProcess(command, 0, " M file.py\n", "")
        if command[:3] == ["gh", "pr", "view"]:
            payload = {
                "mergeStateStatus": "DIRTY",
                "reviewDecision": "REVIEW_REQUIRED",
                "headRefOid": "abc123",
                "headRefName": "feature",
                "statusCheckRollup": [
                    {
                        "__typename": "CheckRun",
                        "name": "Unit",
                        "status": "IN_PROGRESS",
                        "conclusion": "",
                    },
                    {
                        "__typename": "StatusContext",
                        "context": "qlty check",
                        "state": "ERROR",
                    },
                    {"__typename": "Unknown", "name": "mystery"},
                ],
            }
        elif command[:3] == ["gh", "api", "graphql"]:
            payload = {
                "data": {
                    "repository": {
                        "pullRequest": {
                            "reviewThreads": {
                                "nodes": [{"isResolved": False}, {"isResolved": True}]
                            }
                        }
                    }
                }
            }
        elif command[:2] == ["gh", "api"]:
            payload = {
                "required_status_checks": {"contexts": []},
                "enforce_admins": {"enabled": False},
            }
        elif command[:3] == ["aws", "sts", "get-caller-identity"]:
            payload = {"Account": "123456789012", "Arn": "arn:aws:iam::123:user/test"}
        elif command[:3] == ["aws", "budgets", "describe-budgets"]:
            payload = 0
        elif command[:3] == ["aws", "ce", "get-anomaly-monitors"]:
            payload = 0
        elif command[:3] == ["aws", "sns", "get-topic-attributes"]:
            payload = None
        elif command[:3] == ["aws", "sns", "list-subscriptions-by-topic"]:
            payload = []
        elif command[:3] == ["aws", "cloudtrail", "get-trail"]:
            payload = {
                "Name": "bootstrap-test-management-events",
                "IsMultiRegionTrail": False,
                "IncludeGlobalServiceEvents": False,
                "LogFileValidationEnabled": False,
                "KmsKeyId": None,
            }
        elif command[:3] == ["aws", "cloudtrail", "get-trail-status"]:
            payload = {"IsLogging": False}
        elif command[:3] == ["aws", "cloudtrail", "get-event-selectors"]:
            payload = []
        elif command[:3] == ["aws", "backup", "list-restore-jobs"]:
            payload = []
        else:  # pragma: no cover - fail fast if the command contract changes.
            raise AssertionError(command)
        return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")

    args = module.build_parser().parse_args(
        [
            "--repo",
            "VilnaCRM-Org/bootstrap-infrastructure",
            "--pr",
            "22",
            "--operations-topic-arn",
            "arn:aws:sns:us-east-1:123456789012:bootstrap-test-operations",
            "--operations-cloudtrail-name",
            "bootstrap-test-management-events",
            "--root-dir",
            str(PROJECT_ROOT),
        ]
    )
    report = module.collect_evidence(args, runner=runner)
    statuses = {check["name"]: check["status"] for check in report["checks"]}

    assert statuses["github_pr_checks"] == "failed"  # nosec B101
    assert statuses["github_pr_local_state"] == "failed"  # nosec B101
    assert statuses["github_review_threads"] == "failed"  # nosec B101
    assert statuses["github_branch_protection"] == "failed"  # nosec B101
    assert statuses["aws_cost_controls"] == "failed"  # nosec B101
    assert statuses["aws_sns_alert_route"] == "failed"  # nosec B101
    assert statuses["aws_cloudtrail_management_events"] == "failed"  # nosec B101
    assert statuses["aws_restore_jobs"] == "failed"  # nosec B101
    assert statuses["restore_drill_evidence"] == "missing"  # nosec B101
    assert report["scoreBlockers"]  # nosec B101
    assert max(report["pillarScores"].values()) <= 4  # nosec B101
    assert report["blockers"]  # nosec B101


def test_collect_well_architected_evidence_unknown_and_missing_paths(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Unknown command results and missing inputs should be represented safely."""
    module = load_script_module(monkeypatch, "collect_well_architected_evidence")

    def failing_runner(command, **_kwargs):
        return subprocess.CompletedProcess(command, 1, "", "not available")

    invalid_ok, invalid_payload, invalid_error = module._run_json(  # noqa: SLF001
        ["tool"],
        runner=lambda command, **_kwargs: subprocess.CompletedProcess(
            command, 0, "not-json", ""
        ),
    )
    missing_fanout_args = module.build_parser().parse_args(
        ["--root-dir", str(tmp_path)]
    )
    (tmp_path / "pulumi").mkdir()
    low_threshold_args = module.build_parser().parse_args(
        ["--root-dir", str(PROJECT_ROOT), "--max-s3-buckets", "0"]
    )

    assert invalid_ok is False  # nosec B101
    assert invalid_payload is None  # nosec B101
    assert "invalid JSON output" in invalid_error  # nosec B101
    assert module._account_id_from_identity({"evidence": "unknown"}) == ""  # noqa: SLF001
    assert module._all_blockers([{"blockers": "unknown"}]) == []  # noqa: SLF001
    assert module._pr_head_oid([]) == ""  # noqa: SLF001
    assert module.github_pr_checks("org/repo", None)["status"] == "missing"
    assert (
        module.github_pr_local_state("org/repo", None, tmp_path)["status"] == "missing"
    )
    assert module.github_review_threads("org/repo", None)["status"] == "missing"
    assert module.aws_sns_alert_route(None)["status"] == "missing"
    assert module.aws_cloudtrail_management_events(None)["status"] == "missing"
    assert module.github_pr_checks("org/repo", 1, runner=failing_runner)["status"] == (
        "unknown"
    )
    assert (
        module.github_pr_local_state("org/repo", 1, tmp_path, runner=failing_runner)[
            "status"
        ]
        == "failed"
    )
    assert (
        module.github_review_threads("org/repo", 1, runner=failing_runner)["status"]
        == "unknown"
    )
    assert (
        module.github_branch_protection("org/repo", "main", runner=failing_runner)[
            "status"
        ]
        == "unknown"
    )
    assert module.aws_identity(runner=failing_runner)["status"] == "unknown"
    assert module.aws_cost_controls(None, runner=failing_runner)["status"] == "unknown"
    assert (
        module.aws_cost_controls("123456789012", runner=failing_runner)["status"]
        == "failed"
    )
    assert module.aws_sns_alert_route("arn:topic", runner=failing_runner)["status"] == (
        "failed"
    )
    null_subscription_result = module.aws_sns_alert_route(
        "arn:topic",
        runner=lambda command, **_kwargs: subprocess.CompletedProcess(
            command,
            0,
            json.dumps(
                {"KmsMasterKeyId": "alias/bootstrap"}
                if command[:3] == ["aws", "sns", "get-topic-attributes"]
                else None
            ),
            "",
        ),
    )
    assert null_subscription_result["status"] == "failed"  # nosec B101
    assert null_subscription_result["evidence"]["subscriptionProtocols"] == []  # nosec B101
    assert (
        module.aws_cloudtrail_management_events(
            "bootstrap-test-management-events", runner=failing_runner
        )["status"]
        == "failed"
    )
    assert module.aws_restore_jobs(90, runner=failing_runner)["status"] == "unknown"
    assert module.restore_drill_evidence(None)["status"] == "missing"
    assert module.restore_drill_evidence(tmp_path / "missing.json")["status"] == (
        "failed"
    )
    malformed_restore_evidence = tmp_path / "malformed-restore.json"
    malformed_restore_evidence.write_text("{", encoding="utf-8")
    assert module.restore_drill_evidence(malformed_restore_evidence)["status"] == (
        "failed"
    )
    list_restore_evidence = tmp_path / "list-restore.json"
    list_restore_evidence.write_text("[]", encoding="utf-8")
    assert module.restore_drill_evidence(list_restore_evidence)["status"] == "failed"
    invalid_restore_evidence = tmp_path / "restore.json"
    invalid_restore_evidence.write_text(
        json.dumps({"workload": "other", "cleanupConfirmed": False}),
        encoding="utf-8",
    )
    invalid_restore = module.restore_drill_evidence(invalid_restore_evidence)
    assert invalid_restore["status"] == "failed"  # nosec B101
    assert "bootstrap-infrastructure" in " ".join(invalid_restore["blockers"])  # nosec B101
    legacy_args = module.build_parser().parse_args(
        [
            "--question-matrix-evidence-confirmed",
            "--external-control-evidence-confirmed",
        ]
    )
    assert module.question_matrix_evidence(legacy_args)["status"] == "missing"
    legacy_blockers = module.question_matrix_evidence(legacy_args)["blockers"]
    assert "boolean" in " ".join(legacy_blockers)
    malformed_structured = tmp_path / "malformed-structured.json"
    malformed_structured.write_text("{", encoding="utf-8")
    malformed_args = module.build_parser().parse_args(
        ["--question-matrix-evidence", str(malformed_structured)]
    )
    assert module.question_matrix_evidence(malformed_args)["status"] == "failed"
    missing_structured_args = module.build_parser().parse_args(
        ["--external-control-evidence", str(tmp_path / "missing-structured.json")]
    )
    assert module.external_control_evidence(missing_structured_args)["status"] == (
        "failed"
    )
    list_structured = tmp_path / "list-structured.json"
    list_structured.write_text("[]", encoding="utf-8")
    list_args = module.build_parser().parse_args(
        ["--external-control-evidence", str(list_structured)]
    )
    assert module.external_control_evidence(list_args)["status"] == "failed"
    incomplete_external = tmp_path / "incomplete-external.json"
    incomplete_external.write_text(
        json.dumps(
            {
                "workload": "bootstrap-infrastructure",
                "owner": "platform",
                "reviewedAt": module.dt.datetime.now(
                    module.dt.timezone.utc
                ).isoformat(),
                "controlCount": 8,
                "unresolvedControlCount": 0,
                "controls": [{"id": "alert_route", "status": "passed"}],
                "evidenceLocation": "ledger",
                "fallbackPlan": "block",
            }
        ),
        encoding="utf-8",
    )
    incomplete_external_args = module.build_parser().parse_args(
        ["--external-control-evidence", str(incomplete_external)]
    )
    incomplete_external_check = module.external_control_evidence(
        incomplete_external_args
    )
    assert incomplete_external_check["status"] == "failed"  # nosec B101
    assert "branch_protection" in " ".join(  # nosec B101
        incomplete_external_check["blockers"]
    )
    stale_structured = tmp_path / "stale-structured.json"
    stale_structured.write_text(
        json.dumps(
            {
                "workload": "bootstrap-infrastructure",
                "owner": "platform",
                "reviewedAt": "2025-01-01",
                "questionCount": 1,
                "unresolvedQuestionCount": 2,
                "evidenceLocation": "spec",
            }
        ),
        encoding="utf-8",
    )
    stale_args = module.build_parser().parse_args(
        ["--question-matrix-evidence", str(stale_structured)]
    )
    stale_question_matrix = module.question_matrix_evidence(stale_args)
    assert stale_question_matrix["status"] == "failed"  # nosec B101
    assert "older than" in " ".join(stale_question_matrix["blockers"])  # nosec B101
    future_blockers = module._structured_evidence_freshness_blockers(  # noqa: SLF001
        {
            "reviewedAt": (
                module.dt.datetime.now(module.dt.timezone.utc)
                + module.dt.timedelta(days=1)
            ).isoformat()
        },
        "Future evidence",
    )
    assert "future" in future_blockers[0]  # nosec B101
    invalid_blockers = module._structured_evidence_freshness_blockers(  # noqa: SLF001
        {"reviewedAt": 123},
        "Invalid evidence",
    )
    assert "ISO-8601" in invalid_blockers[0]  # nosec B101
    unresolved_payload = module._structured_evidence_payload(  # noqa: SLF001
        {
            "workload": "bootstrap-infrastructure",
            "owner": "platform",
            "reviewedAt": "2026-04-27T10:00:00Z",
            "controlCount": 2,
            "unresolvedControlCount": 1,
            "controls": [
                {"id": "alert_route", "status": "passed"},
                {"id": "branch_protection", "status": "unresolved"},
            ],
            "evidenceLocation": "ledger",
        },
        "controlCount",
        "unresolvedControlCount",
    )
    assert unresolved_payload["unresolvedControlIds"] == [  # nosec B101
        "branch_protection"
    ]
    assert module._string_list(["OPS1", 2]) is None  # noqa: SLF001  # nosec B101
    assert (  # noqa: SLF001  # nosec B101
        module._string_key_number_map({"Security": True}) is None
    )
    assert module._string_key_number_map({"Security": "5"}) is None  # noqa: SLF001  # nosec B101
    assert module._string_key_int_map({"Security": False}) is None  # noqa: SLF001  # nosec B101
    assert module._string_key_int_map({"Security": 5.0}) is None  # noqa: SLF001  # nosec B101
    assert module._parse_reviewed_at("not-a-date") is None  # noqa: SLF001
    assert (  # nosec B101
        module._parse_reviewed_at("2026-04-27T10:00:00").tzinfo  # noqa: SLF001
        is not None
    )
    assert (
        module.repository_fanout_evidence(tmp_path, missing_fanout_args)["status"]
        == "missing"
    )
    evidence_catalog_paths = module._evidence_repository_catalog_paths(PROJECT_ROOT)  # noqa: SLF001
    assert [path.name for path in evidence_catalog_paths] == [  # nosec B101
        "repositories.bootstrap.json"
    ]
    assert (
        module.repository_fanout_evidence(
            PROJECT_ROOT,
            module.build_parser().parse_args(["--root-dir", str(PROJECT_ROOT)]),
        )["status"]
        == "passed"
    )
    assert (
        module.repository_fanout_evidence(PROJECT_ROOT, low_threshold_args)["status"]
        == "failed"
    )
    monkeypatch.setattr(
        module,
        "_evidence_repository_catalog_paths",
        lambda root_dir: [root_dir / "pulumi" / "repositories.example.json"],
    )
    monkeypatch.setattr(
        module,
        "catalog_fanout_report",
        lambda *_args: (_ for _ in ()).throw(ValueError("invalid catalog")),
    )
    invalid_fanout = module.repository_fanout_evidence(
        PROJECT_ROOT,
        module.build_parser().parse_args(["--root-dir", str(PROJECT_ROOT)]),
    )
    assert invalid_fanout["status"] == "failed"  # nosec B101
    assert invalid_fanout["evidence"]["reports"][0]["error"] == "invalid catalog"  # nosec B101


def test_collect_well_architected_evidence_reads_ruleset_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Rulesets should provide branch evidence when classic protection is absent."""
    module = load_script_module(monkeypatch, "collect_well_architected_evidence")

    def runner(command, **_kwargs):
        command_path = command[-1]
        if command_path.endswith("/protection"):
            return subprocess.CompletedProcess(command, 1, "", "not found")
        if command_path.endswith("/rulesets"):
            payload = [
                {"id": 1},
                {"id": 2},
                {"id": 3},
                {"name": "missing id"},
                "malformed",
            ]
            return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")
        if command_path.endswith("/rulesets/1"):
            payload = {
                "name": "main",
                "target": "branch",
                "enforcement": "active",
                "rules": [
                    {
                        "type": "required_status_checks",
                        "parameters": {
                            "required_status_checks": [
                                {"context": "Unit"},
                                {"context": "Policy"},
                            ]
                        },
                    },
                    {"type": "pull_request", "parameters": {}},
                ],
            }
            return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")
        if command_path.endswith("/rulesets/2"):
            return subprocess.CompletedProcess(command, 1, "", "denied")
        if command_path.endswith("/rulesets/3"):
            payload = {
                "name": "tag rules",
                "target": "tag",
                "enforcement": "active",
                "rules": [{"type": "pull_request", "parameters": {}}],
            }
            return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")
        raise AssertionError(command)  # pragma: no cover

    evidence = module.github_branch_protection(
        "VilnaCRM-Org/bootstrap-infrastructure",
        "main",
        expected_required_status_checks=("Unit", "Policy"),
        runner=runner,
    )

    assert evidence["status"] == "passed"  # nosec B101
    assert evidence["evidence"]["classicProtectionReadable"] is False  # nosec B101
    assert evidence["evidence"]["activeRulesetCount"] == 1  # nosec B101
    assert evidence["evidence"]["requiredStatusCheckCount"] == 2  # nosec B101
    assert evidence["evidence"]["requiresPullRequestReviews"] is True  # nosec B101
    assert (  # nosec B101
        module._ruleset_has_pull_request_reviews(  # noqa: SLF001
            [
                {
                    "target": "branch",
                    "enforcement": "active",
                    "rules": [{"type": "required_status_checks"}],
                },
                {
                    "target": "tag",
                    "enforcement": "active",
                    "rules": [{"type": "pull_request"}],
                },
                {
                    "target": "branch",
                    "enforcement": "evaluate",
                    "rules": [{"type": "pull_request"}],
                },
            ]
        )
        is False
    )


def test_collect_well_architected_evidence_paginates_review_threads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Review thread collection should follow cursors and surface bad pagination."""
    module = load_script_module(monkeypatch, "collect_well_architected_evidence")
    calls: list[list[str]] = []

    def runner(command, **_kwargs):
        calls.append(command)
        after_arg = next(
            (argument for argument in command if argument.startswith("after=")),
            None,
        )
        payload = {
            "data": {
                "repository": {
                    "pullRequest": {
                        "reviewThreads": {
                            "nodes": [{"isResolved": after_arg is None}],
                            "pageInfo": {
                                "hasNextPage": after_arg is None,
                                "endCursor": "cursor-1",
                            },
                        }
                    }
                }
            }
        }
        return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")

    evidence = module.github_review_threads(
        "VilnaCRM-Org/bootstrap-infrastructure",
        22,
        runner=runner,
    )

    assert evidence["status"] == "failed"  # nosec B101
    assert evidence["evidence"]["threadCount"] == 2  # nosec B101
    assert evidence["evidence"]["unresolvedThreadCount"] == 1  # nosec B101
    assert evidence["evidence"]["blockingThreadCount"] == 1  # nosec B101
    assert any("after=cursor-1" in command for command in calls)  # nosec B101

    def outdated_thread_runner(command, **_kwargs):
        payload = {
            "data": {
                "repository": {
                    "pullRequest": {
                        "reviewThreads": {
                            "nodes": [
                                {"isResolved": False, "isOutdated": True},
                                {"isResolved": True, "isOutdated": False},
                            ],
                            "pageInfo": {"hasNextPage": False, "endCursor": None},
                        }
                    }
                }
            }
        }
        return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")

    outdated_evidence = module.github_review_threads(
        "VilnaCRM-Org/bootstrap-infrastructure",
        22,
        runner=outdated_thread_runner,
    )

    assert outdated_evidence["status"] == "passed"  # nosec B101
    assert outdated_evidence["evidence"]["unresolvedThreadCount"] == 1  # nosec B101
    assert outdated_evidence["evidence"]["outdatedUnresolvedThreadCount"] == 1  # nosec B101
    assert outdated_evidence["evidence"]["blockingThreadCount"] == 0  # nosec B101

    def missing_cursor_runner(command, **_kwargs):
        payload = {
            "data": {
                "repository": {
                    "pullRequest": {
                        "reviewThreads": {
                            "nodes": [],
                            "pageInfo": {"hasNextPage": True},
                        }
                    }
                }
            }
        }
        return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")

    missing_cursor = module.github_review_threads(
        "VilnaCRM-Org/bootstrap-infrastructure",
        22,
        runner=missing_cursor_runner,
    )

    assert missing_cursor["status"] == "unknown"  # nosec B101
    assert "pagination did not return a cursor" in missing_cursor["blockers"][0]  # nosec B101

    def endless_runner(command, **_kwargs):
        payload = {
            "data": {
                "repository": {
                    "pullRequest": {
                        "reviewThreads": {
                            "nodes": [],
                            "pageInfo": {
                                "hasNextPage": True,
                                "endCursor": "cursor-loop",
                            },
                        }
                    }
                }
            }
        }
        return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")

    endless = module.github_review_threads(
        "VilnaCRM-Org/bootstrap-infrastructure",
        22,
        runner=endless_runner,
    )

    assert endless["status"] == "unknown"  # nosec B101
    assert "exceeded 20 pages" in endless["blockers"][0]  # nosec B101


@pytest.mark.parametrize(
    "payload",
    [
        {"data": None},
        {"data": {"repository": None}},
        {"data": {"repository": {"pullRequest": None}}},
        {"data": {"repository": {"pullRequest": {"reviewThreads": None}}}},
        {
            "data": {
                "repository": {
                    "pullRequest": {"reviewThreads": {"nodes": None, "pageInfo": None}}
                }
            }
        },
    ],
)
def test_collect_well_architected_evidence_handles_null_review_thread_leaves(
    monkeypatch: pytest.MonkeyPatch,
    payload: dict[str, object],
) -> None:
    """Review thread parsing should tolerate nullable GraphQL leaves."""
    module = load_script_module(monkeypatch, "collect_well_architected_evidence")

    assert module._review_threads_page(payload) == ([], {})  # nosec B101  # noqa: SLF001


def test_collect_well_architected_evidence_reports_missing_required_checks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Branch evidence should name required contexts absent from protection."""
    module = load_script_module(monkeypatch, "collect_well_architected_evidence")

    def runner(command, **_kwargs):
        command_path = command[-1]
        if command_path.endswith("/protection"):
            payload = {
                "required_status_checks": {"contexts": ["Preview"]},
                "required_pull_request_reviews": {"required_approving_review_count": 1},
                "enforce_admins": {"enabled": True},
            }
            return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")
        if command_path.endswith("/rulesets"):
            return subprocess.CompletedProcess(command, 0, "[]", "")
        raise AssertionError(command)  # pragma: no cover

    evidence = module.github_branch_protection(
        "VilnaCRM-Org/bootstrap-infrastructure",
        "main",
        expected_required_status_checks=("Preview", "IAM Validation"),
        runner=runner,
    )

    assert evidence["status"] == "failed"  # nosec B101
    assert evidence["evidence"]["requiredStatusChecks"] == ["Preview"]  # nosec B101
    assert evidence["evidence"]["missingRequiredStatusChecks"] == [  # nosec B101
        "IAM Validation"
    ]
    assert "IAM Validation" in evidence["blockers"][0]  # nosec B101


def test_collect_well_architected_evidence_main_writes_report(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """CLI wrapper should write evidence reports and signal blockers."""
    module = load_script_module(monkeypatch, "collect_well_architected_evidence")
    output_path = tmp_path / "evidence.json"

    monkeypatch.setattr(
        module,
        "collect_evidence",
        lambda _args: {
            "checks": [],
            "pillarScores": {},
            "blockers": [],
        },
    )
    assert module.main(["--output", str(output_path)]) == 0
    assert json.loads(output_path.read_text(encoding="utf-8"))["blockers"] == []
    assert '"blockers": []' in capsys.readouterr().out

    monkeypatch.setattr(
        module,
        "collect_evidence",
        lambda _args: {
            "checks": [],
            "pillarScores": {},
            "blockers": ["missing evidence"],
        },
    )
    assert module.main([]) == 1
    assert "missing evidence" in capsys.readouterr().out


def test_run_pulumi_command_branch_helpers_return_select_failures(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Cover helper branches that short-circuit before invoking Pulumi."""
    module = load_script_module(monkeypatch, "run_pulumi_command")
    repo_dir = tmp_path / "repo"
    pulumi_dir = repo_dir / "pulumi"
    policy_dir = repo_dir / "policy"
    plan_dir = repo_dir / ".artifacts" / "pulumi-plan"
    preview_dir = repo_dir / ".artifacts" / "pulumi-preview"
    pulumi_dir.mkdir(parents=True)
    policy_dir.mkdir()
    plan_dir.mkdir(parents=True)
    preview_dir.mkdir(parents=True)
    context = module.CommandContext(
        root_dir=repo_dir,
        env={},
        pulumi_dir=pulumi_dir,
        policy_pack_dir=policy_dir,
        plan_dir=plan_dir,
        preview_artifact_dir=preview_dir,
        backend_url="file:///tmp/backend",
        secrets_provider="awskms://alias/example?region=eu-central-1",
    )

    default_plan = module._selected_plan_path(context, None, "test")
    assert default_plan == module._plan_file(plan_dir, "test")  # nosec B101

    monkeypatch.setattr(module, "_select_or_init_stack", lambda *args: 7)
    assert module._run_plan_command(context, ["test"]) == 7  # nosec B101

    monkeypatch.setattr(module, "_select_or_init_stack", lambda *args: 9)
    assert module._run_up_plan_command(context, ["test"]) == 9  # nosec B101


def test_run_pulumi_command_validates_plan_manifest_error_paths(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Reject saved plans with stale or mismatched manifest evidence."""
    module = load_script_module(monkeypatch, "run_pulumi_command")
    repo_dir = tmp_path / "repo"
    pulumi_dir = repo_dir / "pulumi"
    policy_dir = repo_dir / "policy"
    plan_dir = repo_dir / ".artifacts" / "pulumi-plan"
    preview_dir = repo_dir / ".artifacts" / "pulumi-preview"
    pulumi_dir.mkdir(parents=True)
    policy_dir.mkdir()
    plan_dir.mkdir(parents=True)
    preview_dir.mkdir(parents=True)
    plan_file = plan_dir / "test.plan"
    other_plan = plan_dir / "other.plan"
    plan_file.write_text("plan", encoding="utf-8")
    other_plan.write_text("other", encoding="utf-8")
    context = module.CommandContext(
        root_dir=repo_dir,
        env={"PULUMI_PLAN_NOW_EPOCH": "1000", "PULUMI_EXPECTED_SHA": "sha-a"},
        pulumi_dir=pulumi_dir,
        policy_pack_dir=policy_dir,
        plan_dir=plan_dir,
        preview_artifact_dir=preview_dir,
        backend_url="file:///tmp/backend",
        secrets_provider="awskms://alias/example?region=eu-central-1",
    )

    assert module._load_plan_manifest(context) is None  # nosec B101
    assert "manifest not found" in capsys.readouterr().err  # nosec B101

    valid_entry = {
        "stack": "test",
        "planFile": ".artifacts/pulumi-plan/test.plan",
        "planSha256": hashlib.sha256(b"plan").hexdigest(),
    }
    valid_manifest = {
        "schemaVersion": 1,
        "createdAtEpoch": 1000,
        "commitSha": "sha-a",
        "backendUrl": "file:///tmp/backend",
        "stacks": [
            {"stack": "skip", "planFile": "unused", "planSha256": "unused"},
            valid_entry,
        ],
    }
    assert (  # nosec B101
        module._validate_plan_manifest(context, valid_manifest, "test", plan_file)
        is None
    )

    bad_schema = {**valid_manifest, "schemaVersion": 2}
    assert module._validate_plan_manifest(context, bad_schema, "test", plan_file) == 1
    context.env["PULUMI_PLAN_MAX_AGE_SECONDS"] = "10"
    stale = {**valid_manifest, "createdAtEpoch": 0}
    assert module._validate_plan_manifest(context, stale, "test", plan_file) == 1
    context.env.pop("PULUMI_PLAN_MAX_AGE_SECONDS")
    wrong_sha = {**valid_manifest, "commitSha": "sha-b"}
    assert module._validate_plan_manifest(context, wrong_sha, "test", plan_file) == 1
    wrong_backend = {**valid_manifest, "backendUrl": "s3://other"}
    assert (  # nosec B101
        module._validate_plan_manifest(context, wrong_backend, "test", plan_file) == 1
    )
    missing_stack = {**valid_manifest, "stacks": []}
    assert (  # nosec B101
        module._validate_plan_manifest(context, missing_stack, "test", plan_file) == 1
    )
    wrong_plan_path = {
        **valid_manifest,
        "stacks": [{**valid_entry, "planFile": ".artifacts/pulumi-plan/other.plan"}],
    }
    assert (  # nosec B101
        module._validate_plan_manifest(context, wrong_plan_path, "test", plan_file) == 1
    )
    wrong_hash = {
        **valid_manifest,
        "stacks": [{**valid_entry, "planSha256": hashlib.sha256(b"bad").hexdigest()}],
    }
    assert module._validate_plan_manifest(context, wrong_hash, "test", plan_file) == 1
    assert "hash does not match" in capsys.readouterr().err  # nosec B101


def test_run_pulumi_command_requires_manifest_before_saved_plan_apply(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A saved plan cannot be applied without its manifest."""
    module = load_script_module(monkeypatch, "run_pulumi_command")
    repo_dir = tmp_path / "repo"
    plan_dir = repo_dir / ".artifacts" / "pulumi-plan"
    plan_dir.mkdir(parents=True)
    plan_file = plan_dir / f"{module._safe_artifact_stem('test')}.plan"
    plan_file.write_text("plan", encoding="utf-8")
    context = module.CommandContext(
        root_dir=repo_dir,
        env={},
        pulumi_dir=repo_dir / "pulumi",
        policy_pack_dir=repo_dir / "policy",
        plan_dir=plan_dir,
        preview_artifact_dir=repo_dir / ".artifacts" / "pulumi-preview",
        backend_url="file:///tmp/backend",
        secrets_provider="awskms://alias/example?region=eu-central-1",
        runner=lambda command, **kwargs: subprocess.CompletedProcess(command, 0),
    )

    assert module._run_up_plan_command(context, ["test"]) == 1  # nosec B101
    assert "manifest not found" in capsys.readouterr().err  # nosec B101

    (plan_dir / "manifest.json").write_text(
        json.dumps({"schemaVersion": 2, "stacks": []}),
        encoding="utf-8",
    )
    assert module._run_up_plan_command(context, ["test"]) == 1  # nosec B101
    assert "unsupported" in capsys.readouterr().err  # nosec B101


def test_run_pulumi_command_reuses_manifest_for_multiple_plan_applications(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Multi-stack apply should load one manifest and validate every plan."""
    module = load_script_module(monkeypatch, "run_pulumi_command")
    repo_dir = tmp_path / "repo"
    plan_dir = repo_dir / ".artifacts" / "pulumi-plan"
    plan_dir.mkdir(parents=True)
    context = module.CommandContext(
        root_dir=repo_dir,
        env={"PULUMI_PLAN_NOW_EPOCH": "1000"},
        pulumi_dir=repo_dir / "pulumi",
        policy_pack_dir=repo_dir / "policy",
        plan_dir=plan_dir,
        preview_artifact_dir=repo_dir / ".artifacts" / "pulumi-preview",
        backend_url="file:///tmp/backend",
        secrets_provider="awskms://alias/example?region=eu-central-1",
        runner=lambda command, **kwargs: subprocess.CompletedProcess(command, 0),
    )
    stacks = ["test", "prod"]
    entries = []
    for stack in stacks:
        plan_file = module._plan_file(plan_dir, stack)
        plan_file.write_text(f"plan-{stack}", encoding="utf-8")
        entries.append(
            {
                "stack": stack,
                "planFile": f".artifacts/pulumi-plan/{plan_file.name}",
                "planSha256": hashlib.sha256(f"plan-{stack}".encode()).hexdigest(),
            }
        )
    (plan_dir / "manifest.json").write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "createdAtEpoch": 1000,
                "commitSha": "",
                "backendUrl": "file:///tmp/backend",
                "stacks": entries,
            }
        ),
        encoding="utf-8",
    )

    assert module._run_up_plan_command(context, stacks) == 0  # nosec B101


def test_run_pulumi_command_plan_fails_when_saved_plan_is_missing(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The plan command must not publish a manifest without a real saved plan."""
    module = load_script_module(monkeypatch, "run_pulumi_command")
    repo_dir = tmp_path / "repo"
    pulumi_dir = repo_dir / "pulumi"
    policy_dir = repo_dir / "policy"
    pulumi_dir.mkdir(parents=True)
    policy_dir.mkdir()
    context = module.CommandContext(
        root_dir=repo_dir,
        env={},
        pulumi_dir=pulumi_dir,
        policy_pack_dir=policy_dir,
        plan_dir=repo_dir / ".artifacts" / "pulumi-plan",
        preview_artifact_dir=repo_dir / ".artifacts" / "pulumi-preview",
        backend_url="file:///tmp/backend",
        secrets_provider="awskms://alias/example?region=eu-central-1",
        runner=lambda command, **kwargs: subprocess.CompletedProcess(command, 0),
    )

    assert module._run_plan_command(context, ["test"]) == 1  # nosec B101
    assert "plan file not created" in capsys.readouterr().err  # nosec B101


def test_select_or_init_stack_requires_file_backend_secrets_provider(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """File-backed stack initialization should fail before init without a provider."""
    module = load_script_module(monkeypatch, "run_pulumi_command")
    repo_dir = tmp_path / "repo"
    pulumi_dir = repo_dir / "pulumi"
    pulumi_dir.mkdir(parents=True)

    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(command, 1, stderr="missing stack\n")

    context = module.CommandContext(
        root_dir=repo_dir,
        env={},
        pulumi_dir=pulumi_dir,
        policy_pack_dir=repo_dir / "policy",
        plan_dir=repo_dir / ".artifacts" / "pulumi-plan",
        preview_artifact_dir=repo_dir / ".artifacts" / "pulumi-preview",
        backend_url="file:///tmp/backend",
        secrets_provider="",
        runner=fake_run,
    )

    assert module._select_or_init_stack(context, "test") == 1  # nosec B101
    assert "set PULUMI_SECRETS_PROVIDER" in capsys.readouterr().err  # nosec B101


def test_run_pulumi_command_plan_handles_multiple_configured_stacks(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A configured stack list should create one saved plan per stack."""
    module = load_script_module(monkeypatch, "run_pulumi_command")
    repo_dir = tmp_path / "repo"
    pulumi_dir = repo_dir / "pulumi"
    policy_dir = repo_dir / "policy"
    output_file = repo_dir / "github-output.txt"
    preview_dir = repo_dir / ".artifacts" / "pulumi-preview"
    pulumi_dir.mkdir(parents=True)
    policy_dir.mkdir()
    preview_dir.mkdir(parents=True)
    (preview_dir / "stale.json").write_text("{}", encoding="utf-8")
    (preview_dir / "summary.md").write_text("old summary\n", encoding="utf-8")
    monkeypatch.setattr(module, "repo_root", lambda _: repo_dir)
    monkeypatch.setenv("PULUMI_STACK", "default")
    monkeypatch.setenv("PULUMI_PREVIEW_STACKS", "test prod/eu")
    monkeypatch.setenv(
        "PULUMI_SECRETS_PROVIDER",
        "awskms://alias/bootstrap-preview?region=eu-central-1",
    )
    monkeypatch.setenv("GITHUB_OUTPUT", str(output_file))

    calls: list[list[str]] = []

    def fake_run(command, **kwargs):
        calls.append(command)
        if command[0] == "pulumi" and command[3:6] == ["stack", "select", "test"]:
            return subprocess.CompletedProcess(command, 1, stderr="missing test\n")
        if command[0] == "pulumi" and command[3:6] == [
            "stack",
            "select",
            "prod/eu",
        ]:
            return subprocess.CompletedProcess(command, 1, stderr="missing prod\n")
        if command[0] == "pulumi" and command[3] == "preview":
            stdout = kwargs.get("stdout")
            if stdout is not None:
                stdout.write('{"changeSummary": {"create": 1}, "steps": []}')
            if "--save-plan" in command:
                plan_path = Path(command[command.index("--save-plan") + 1])
                plan_path.write_text(
                    f"plan for {command[command.index('--stack') + 1]}",
                    encoding="utf-8",
                )
            return subprocess.CompletedProcess(command, 0)
        if command[:3] == ["uv", "--project", str(repo_dir)]:
            return subprocess.CompletedProcess(
                command, 0, stdout=f"summary for {Path(command[-1]).stem}\n"
            )
        return subprocess.CompletedProcess(command, 0, stdout="")

    monkeypatch.setattr(module, "run", fake_run)
    assert module.main(["plan"]) == 0  # nosec B101

    test_stem = module._safe_artifact_stem("test")
    prod_stem = module._safe_artifact_stem("prod/eu")
    output = capsys.readouterr().out
    output_values = output_file.read_text(encoding="utf-8")
    assert f"summary for {test_stem}" in output  # nosec B101
    assert f"summary for {prod_stem}" in output  # nosec B101
    assert f"{test_stem}.plan" in output_values  # nosec B101
    assert f"{prod_stem}.plan" in output_values  # nosec B101
    assert "plan_manifest=" in output_values  # nosec B101
    assert "old summary" not in output  # nosec B101
    assert not (preview_dir / "stale.json").exists()  # nosec B101
    manifest = json.loads(
        (repo_dir / ".artifacts/pulumi-plan/manifest.json").read_text()
    )
    assert manifest["schemaVersion"] == 1  # nosec B101
    assert manifest["backendUrl"].startswith("file://")  # nosec B101
    assert [entry["stack"] for entry in manifest["stacks"]] == [  # nosec B101
        "test",
        "prod/eu",
    ]
    initialized_prod = any(
        command[3:10]
        == [
            "stack",
            "init",
            "prod/eu",
            "--non-interactive",
            "--secrets-provider",
            "awskms://alias/bootstrap-preview?region=eu-central-1",
        ]
        for command in calls
    )
    assert initialized_prod  # nosec B101


def test_run_pulumi_command_handles_error_paths_and_plan_application(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Cover stack-safety failures and saved-plan application."""
    module = load_script_module(monkeypatch, "run_pulumi_command")
    repo_dir = tmp_path / "repo"
    pulumi_dir = repo_dir / "pulumi"
    policy_dir = repo_dir / "policy"
    plan_dir = repo_dir / ".artifacts" / "pulumi-plan"
    pulumi_dir.mkdir(parents=True)
    policy_dir.mkdir()
    plan_dir.mkdir(parents=True)
    monkeypatch.setattr(module, "repo_root", lambda _: repo_dir)

    monkeypatch.setenv("PULUMI_SECRETS_PROVIDER", "local")
    assert module.main(["preview"]) == 1  # nosec B101
    assert "awskms://" in capsys.readouterr().err  # nosec B101

    monkeypatch.setenv(
        "PULUMI_SECRETS_PROVIDER", "awskms://alias/example?region=eu-central-1"
    )
    monkeypatch.setattr(module, "discover_stacks", lambda *args: [])
    assert module.main(["preview"]) == 1  # nosec B101
    assert "set PULUMI_STACK" in capsys.readouterr().err  # nosec B101

    def shared_run(command, **kwargs):
        if command[0] == "pulumi" and command[3:6] == ["stack", "select", "test"]:
            return subprocess.CompletedProcess(command, 255, stderr="missing\n")
        return subprocess.CompletedProcess(command, 0, stdout="")

    monkeypatch.setattr(module, "discover_stacks", lambda *args: ["test"])
    monkeypatch.setattr(module, "run", shared_run)
    monkeypatch.setenv("PULUMI_BACKEND_URL", "s3://shared-state")
    assert module.main(["refresh"]) == 255  # nosec B101
    assert "shared backend stack test does not exist" in capsys.readouterr().err  # nosec B101

    def missing_provider_run(command, **kwargs):
        if command[0] == "pulumi" and command[3:6] == ["stack", "select", "test"]:
            return subprocess.CompletedProcess(command, 1, stderr="")
        return subprocess.CompletedProcess(command, 0, stdout="")

    monkeypatch.setattr(module, "run", missing_provider_run)
    monkeypatch.setenv("PULUMI_BACKEND_URL", "file:///tmp/backend")
    monkeypatch.delenv("PULUMI_SECRETS_PROVIDER", raising=False)
    module._emit_stderr("")
    assert module.main(["refresh"]) == 1  # nosec B101
    assert "PULUMI_SECRETS_PROVIDER must be set" in capsys.readouterr().err  # nosec B101

    def init_failure_run(command, **kwargs):
        if command[0] == "pulumi" and command[3:6] == ["stack", "select", "test"]:
            return subprocess.CompletedProcess(command, 1, stderr="")
        if command[0] == "pulumi" and command[3:6] == ["stack", "init", "test"]:
            return subprocess.CompletedProcess(command, 42, stderr="kms denied\n")
        return subprocess.CompletedProcess(command, 0, stdout="")

    monkeypatch.setattr(module, "run", init_failure_run)
    monkeypatch.setenv(
        "PULUMI_SECRETS_PROVIDER", "awskms://alias/example?region=eu-central-1"
    )
    assert module.main(["refresh"]) == 42  # nosec B101
    assert "kms denied" in capsys.readouterr().err  # nosec B101

    def ok_run(command, **kwargs):
        return subprocess.CompletedProcess(command, 0, stdout="")

    monkeypatch.setattr(module, "run", ok_run)
    monkeypatch.setenv("PULUMI_BACKEND_URL", "file:///tmp/backend")
    monkeypatch.setenv("PULUMI_PLAN_FILE", str(plan_dir / "single.plan"))
    monkeypatch.setattr(module, "discover_stacks", lambda *args: ["test", "prod"])
    assert module.main(["up-plan"]) == 1  # nosec B101
    assert "single selected stack" in capsys.readouterr().err  # nosec B101

    monkeypatch.setattr(module, "discover_stacks", lambda *args: ["test"])
    assert module.main(["up-plan"]) == 1  # nosec B101
    assert "Pulumi plan file not found" in capsys.readouterr().err  # nosec B101

    selected_plan = plan_dir / "single.plan"
    selected_plan.write_text("plan", encoding="utf-8")
    monkeypatch.setenv("PULUMI_PLAN_NOW_EPOCH", "1000")
    (plan_dir / "manifest.json").write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "createdAtEpoch": 1000,
                "commitSha": "",
                "backendUrl": "file:///tmp/backend",
                "stacks": [
                    {
                        "stack": "test",
                        "planFile": ".artifacts/pulumi-plan/single.plan",
                        "planSha256": hashlib.sha256(b"plan").hexdigest(),
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    applied: list[list[str]] = []

    def apply_run(command, **kwargs):
        applied.append(command)
        return subprocess.CompletedProcess(command, 0, stdout="")

    monkeypatch.setattr(module, "run", apply_run)
    assert module.main(["up-plan"]) == 0  # nosec B101
    applied_selected_plan = any(
        "--plan" in command and str(selected_plan) in command for command in applied
    )
    assert applied_selected_plan  # nosec B101

    single_output = repo_dir / "single-output.txt"
    module._write_plan_outputs(
        str(single_output), [selected_plan], plan_dir, plan_dir / "manifest.json"
    )
    assert f"plan_file={selected_plan}" in single_output.read_text(encoding="utf-8")  # nosec B101


def test_run_pulumi_command_runs_generic_and_plan_without_github_output(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Cover non-plan command dispatch and plan summaries without GitHub outputs."""
    module = load_script_module(monkeypatch, "run_pulumi_command")
    repo_dir = tmp_path / "repo"
    pulumi_dir = repo_dir / "pulumi"
    policy_dir = repo_dir / "policy"
    pulumi_dir.mkdir(parents=True)
    policy_dir.mkdir()
    monkeypatch.setattr(module, "repo_root", lambda _: repo_dir)
    monkeypatch.setenv("PULUMI_STACK", "test")
    monkeypatch.setenv(
        "PULUMI_SECRETS_PROVIDER", "awskms://alias/example?region=eu-central-1"
    )
    monkeypatch.delenv("GITHUB_OUTPUT", raising=False)

    calls: list[list[str]] = []

    def fake_run(command, **kwargs):
        calls.append(command)
        if command[0] == "pulumi" and command[3] == "preview":
            stdout = kwargs.get("stdout")
            if stdout is not None:
                stdout.write('{"changeSummary": {}, "steps": []}')
            if "--save-plan" in command:
                plan_path = Path(command[command.index("--save-plan") + 1])
                plan_path.write_text("plan", encoding="utf-8")
            return subprocess.CompletedProcess(command, 0)
        if command[:3] == ["uv", "--project", str(repo_dir)]:
            return subprocess.CompletedProcess(command, 0, stdout="summary\n")
        return subprocess.CompletedProcess(command, 0, stdout="")

    monkeypatch.setattr(module, "run", fake_run)
    assert module.main(["preview"]) == 0  # nosec B101
    preview_called = any(
        len(command) > 3 and command[3] == "preview" for command in calls
    )
    assert preview_called  # nosec B101

    calls.clear()
    assert module.main(["plan"]) == 0  # nosec B101
    assert "summary" in capsys.readouterr().out  # nosec B101
    assert all("plan_files<<EOF" not in str(command) for command in calls)  # nosec B101


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

    assert result is None, (  # nosec B101
        f"expected existing stack select to return None, got {result}"
    )
    expected_calls = [
        [
            "pulumi",
            "-C",
            str(pulumi_dir),
            "stack",
            "select",
            "dev",
            "--non-interactive",
        ]
    ]
    assert calls == expected_calls, f"unexpected stack select calls: {calls!r}"  # nosec B101


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
    assert module.main() == 255  # nosec B101

    error_output = capsys.readouterr().err
    assert "shared-backend previews will not create missing stacks" in error_output  # nosec B101
    assert "no stack named missing-stack found" in error_output  # nosec B101
    selected_missing_stack = any(
        command[3:7] == ["stack", "select", "missing-stack", "--non-interactive"]
        for command, _ in run_calls
    )
    created_stack = any("--create" in command for command, _ in run_calls)
    assert selected_missing_stack  # nosec B101
    assert not created_stack  # nosec B101


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
    assert module.main() == 1  # nosec B101

    error_output = capsys.readouterr().err
    assert "file-backed previews require PULUMI_SECRETS_PROVIDER" in error_output  # nosec B101
    assert "shared-backend previews will not create missing stacks" not in error_output  # nosec B101
    selected_dev_stack = any(
        command[3:7] == ["stack", "select", "dev", "--non-interactive"]
        for command in run_calls
    )
    assert selected_dev_stack  # nosec B101


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
