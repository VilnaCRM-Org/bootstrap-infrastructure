from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

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
        "/.github/workflows/governance-apply-status.yml",
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


def test_paths_touch_governance_status_workflow_in_scope() -> None:
    # The merge-gate status workflow controls the required-check semantics and
    # must itself be Kravalg-gated.
    assert (
        governance_paths.paths_touch_governance(
            [".github/workflows/governance-apply-status.yml"]
        )
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


def test_files_stdin_cli_prints_true(capsys) -> None:
    files = "pulumi/governance/x\ndocs/readme.md\n"
    import io

    sys.stdin = io.StringIO(files)
    try:
        exit_code = governance_paths.main(["--files-stdin"])
    finally:
        sys.stdin = sys.__stdin__
    assert exit_code == 0
    assert capsys.readouterr().out == "governance_touched=true\n"


def test_files_stdin_cli_prints_false(capsys) -> None:
    files = "docs/readme.md\ntests/x.py\n"
    import io

    sys.stdin = io.StringIO(files)
    try:
        exit_code = governance_paths.main(["--files-stdin"])
    finally:
        sys.stdin = sys.__stdin__
    assert exit_code == 0
    assert capsys.readouterr().out == "governance_touched=false\n"


def test_files_stdin_cli_empty_prints_false(capsys) -> None:
    import io

    sys.stdin = io.StringIO("")
    try:
        exit_code = governance_paths.main(["--files-stdin"])
    finally:
        sys.stdin = sys.__stdin__
    assert exit_code == 0
    assert capsys.readouterr().out == "governance_touched=false\n"


def test_governance_catalog_resolves_into_managed_repository_catalog() -> None:
    # positive: the new catalog resolves into ManagedRepositoryCatalog and
    # bootstrap-infrastructure is absent from it.
    pulumi_dir = REPO_ROOT / "pulumi"
    if str(pulumi_dir) not in sys.path:
        sys.path.insert(0, str(pulumi_dir))
    from infra.repository_catalog import ManagedRepositoryCatalog

    catalog_path = pulumi_dir / "repositories.governance.json"
    repositories = ManagedRepositoryCatalog.load_from_json_file(str(catalog_path))
    catalog = ManagedRepositoryCatalog(repositories)
    names = {repository.name for repository in catalog.repositories}
    assert names == {"user-service-infrastructure"}
    assert "bootstrap-infrastructure" not in names
    project_mapping = catalog.project_mapping()
    assert (
        project_mapping["user-service-infrastructure"] == "user-service-infrastructure"
    )


def test_governance_catalog_excludes_bootstrap_infrastructure() -> None:
    # negative: bootstrap-infrastructure is never present in the governance catalog.
    catalog_path = REPO_ROOT / "pulumi" / "repositories.governance.json"
    payload = json.loads(catalog_path.read_text(encoding="utf-8"))
    names = {entry["name"] for entry in payload["repositories"]}
    assert "bootstrap-infrastructure" not in names
    assert names == {"user-service-infrastructure"}
