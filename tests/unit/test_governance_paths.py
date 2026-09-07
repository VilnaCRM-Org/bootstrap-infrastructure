from __future__ import annotations

import importlib
import io
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

governance_paths = importlib.import_module("governance_paths")


def test_governance_path_globs_cover_expanded_credential_surface() -> None:
    globs = governance_paths.GOVERNANCE_PATH_GLOBS
    # The §7.1 expanded set: every credential-bearing / trust-altering path.
    for required in (
        "/pulumi/governance/",
        "/pulumi/infra/governance.py",
        "/pulumi/infra/iam/",
        "/pulumi/infra/ci_bootstrap.py",
        "/pulumi/infra/ci_config.py",
        "/pulumi/infra/automation.py",
        "/pulumi/infra/bootstrap_settings.py",
        "/pulumi/infra/pulumi_state.py",
        "/pulumi/infra/pulumi_secrets.py",
        "/pulumi/repositories.governance.json",
        "/policy/",
        "/scripts/governance_paths.py",
        "/scripts/run_pulumi_command.py",
        "/scripts/_pulumi_command_support.py",
        "/scripts/_script_support.py",
        "/scripts/prepare_policy_pack.py",
        "/scripts/pulumi_pr_comment.py",
        "/scripts/_github_repository_controls.py",
        "/scripts/configure_github_repository_controls.py",
        "/.github/CODEOWNERS",
        "/.github/workflows/pulumi-governance.yml",
        "/.github/workflows/pulumi-pr-command-runner.yml",
        "/.github/workflows/pulumi-pr-commands.yml",
    ):
        assert required in globs, f"missing governance glob: {required}"
    # No duplicates, deterministic ordering of a tuple.
    assert len(set(globs)) == len(globs)
    assert isinstance(globs, tuple)


def test_paths_touch_governance_positive_directory_and_file() -> None:
    # positive: governance project directory.
    assert governance_paths.paths_touch_governance(["pulumi/governance/x"]) is True
    assert (
        governance_paths.paths_touch_governance(["pulumi/governance/__main__.py"])
        is True
    )
    # positive: expanded set member bootstrap_settings.py.
    assert (
        governance_paths.paths_touch_governance(["pulumi/infra/bootstrap_settings.py"])
        is True
    )
    # positive: nested file under an iam/ directory glob.
    assert (
        governance_paths.paths_touch_governance(["pulumi/infra/iam/github_oidc.py"])
        is True
    )
    # positive: an exact file glob (governance.py).
    assert (
        governance_paths.paths_touch_governance(["pulumi/infra/governance.py"]) is True
    )
    # positive: the catalog file itself.
    assert (
        governance_paths.paths_touch_governance(["pulumi/repositories.governance.json"])
        is True
    )


def test_paths_touch_governance_closes_apply_context_support_holes() -> None:
    # Red-team hole closure: the support modules + policy-pack builder that run
    # inside the gated governance apply with AWS creds are now in scope, so a
    # non-@Kravalg approval can no longer slip past CODEOWNERS / governance_touched.
    assert (
        governance_paths.paths_touch_governance(["scripts/_pulumi_command_support.py"])
        is True
    )
    assert (
        governance_paths.paths_touch_governance(["scripts/_script_support.py"]) is True
    )
    assert (
        governance_paths.paths_touch_governance(["scripts/prepare_policy_pack.py"])
        is True
    )


def test_paths_touch_governance_normalizes_dotdot_traversal() -> None:
    # Defensive (FIX C): a ".."-containing path resolves to its true target
    # before fnmatch. "pulumi/governance/../infra/x.py" is really
    # "pulumi/infra/x.py" (NOT a governance path) and must NOT spuriously match
    # the "pulumi/governance/*" glob it traverses through.
    assert (
        governance_paths.paths_touch_governance(
            ["pulumi/governance/../infra/managed_repository.py"]
        )
        is False
    )
    # And a traversal that genuinely lands on a governance file still matches.
    assert (
        governance_paths.paths_touch_governance(
            ["pulumi/infra/../governance/__main__.py"]
        )
        is True
    )


def test_paths_touch_governance_normpath_collapses_to_dot_is_false() -> None:
    # Defensive: a path that survives the strip but whose normpath collapses to
    # "" or "." (a pure "." or a traversal that cancels itself out, e.g.
    # "a/..") resolves to the current directory and never matches a glob.
    assert governance_paths.paths_touch_governance(["."]) is False
    assert governance_paths.paths_touch_governance(["a/.."]) is False
    assert governance_paths.paths_touch_governance(["./."]) is False


def test_paths_touch_governance_negative_docs_and_tests() -> None:
    # negative: docs and tests never trip the gate.
    assert (
        governance_paths.paths_touch_governance(["docs/readme.md", "tests/x.py"])
        is False
    )
    # negative: a sibling file that is NOT in the set.
    assert (
        governance_paths.paths_touch_governance(["pulumi/infra/managed_repository.py"])
        is False
    )
    # negative: a non-governance pulumi catalog.
    assert (
        governance_paths.paths_touch_governance(["pulumi/repositories.bootstrap.json"])
        is False
    )


def test_paths_touch_governance_mixed_list_short_circuits_true() -> None:
    # Any single governance path in a mixed list flips the result to True.
    assert (
        governance_paths.paths_touch_governance(
            ["docs/readme.md", "pulumi/infra/ci_config.py", "tests/x.py"]
        )
        is True
    )


def test_paths_touch_governance_empty_is_false() -> None:
    # edge: empty file list is never governance-touching.
    assert governance_paths.paths_touch_governance([]) is False


def test_paths_touch_governance_ignores_blank_lines() -> None:
    # Defensive: blank / whitespace-only entries (from a stdin split) are ignored.
    assert governance_paths.paths_touch_governance(["", "   "]) is False
    assert (
        governance_paths.paths_touch_governance(["", "pulumi/governance/x", "  "])
        is True
    )


def test_files_stdin_cli_prints_true(capsys, monkeypatch) -> None:
    files = "pulumi/governance/x\ndocs/readme.md\n"
    monkeypatch.setattr(sys, "stdin", io.StringIO(files))
    exit_code = governance_paths.main(["--files-stdin"])
    assert exit_code == 0
    assert capsys.readouterr().out == "governance_touched=true\n"


def test_files_stdin_cli_prints_false(capsys, monkeypatch) -> None:
    files = "docs/readme.md\ntests/x.py\n"
    monkeypatch.setattr(sys, "stdin", io.StringIO(files))
    exit_code = governance_paths.main(["--files-stdin"])
    assert exit_code == 0
    assert capsys.readouterr().out == "governance_touched=false\n"


def test_files_stdin_cli_empty_prints_false(capsys, monkeypatch) -> None:
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))
    exit_code = governance_paths.main(["--files-stdin"])
    assert exit_code == 0
    assert capsys.readouterr().out == "governance_touched=false\n"


def test_root_file_glob_does_not_cross_directory_separators() -> None:
    assert governance_paths.paths_touch_governance(["docker-compose.prod.yml"])
    assert not governance_paths.paths_touch_governance(
        ["docker-compose.extra/nested.yml"]
    )
    assert not governance_paths.paths_touch_governance(["nested/docker-compose.yml"])
    assert governance_paths.paths_touch_governance([".github/workflows/nested/job.yml"])
    assert governance_paths._matches_path_pattern("a/test.py", "a/*.py")
    assert not governance_paths._matches_path_pattern("a/nested/test.py", "a/*.py")


def test_cli_without_stdin_flag_fails_before_reading(monkeypatch) -> None:
    def unexpected_read():
        raise AssertionError("Missing flag must not block waiting on standard input")

    monkeypatch.setattr(governance_paths, "_read_stdin_files", unexpected_read)
    with pytest.raises(SystemExit) as error:
        governance_paths.main([])
    assert error.value.code == 2
