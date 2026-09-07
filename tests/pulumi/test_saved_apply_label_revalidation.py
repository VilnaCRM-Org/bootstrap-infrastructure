"""Execute saved-apply workflow guards with real destructive-diff parsing."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = [
    path
    for path in (
        ROOT / ".github/workflows/self-deploy.yml",
        ROOT / ".github/workflows/pulumi-pr-command-runner.yml",
        ROOT / ".github/workflows/pulumi-governance.yml",
        ROOT / "pulumi/user-service-infrastructure/.github/workflows/self-deploy.yml",
    )
    if path.exists()
]


def _apply_steps(path: Path, environment: str) -> tuple[list[dict], dict]:
    workflow = yaml.safe_load(path.read_text())
    prefix = "governance_" if path.name == "pulumi-governance.yml" else ""
    steps = workflow["jobs"][f"{prefix}{environment}_apply"]["steps"]
    apply = next(
        step for step in steps if step.get("name", "").startswith("Apply saved")
    )
    return steps, apply


@pytest.mark.parametrize(
    "path", WORKFLOWS, ids=lambda path: str(path.relative_to(ROOT))
)
@pytest.mark.parametrize("environment", ["test", "prod"])
def test_apply_reuses_matching_same_run_preview(path: Path, environment: str) -> None:
    steps, apply = _apply_steps(path, environment)
    downloads = [
        step
        for step in steps
        if step.get("uses", "").startswith("actions/download-artifact@")
    ]
    preview = next(
        step
        for step in downloads
        if step["with"]["path"] == ".artifacts/pulumi-preview"
    )
    plan = next(
        step for step in downloads if step["with"]["path"] == ".artifacts/pulumi-plan"
    )
    assert (
        preview["with"]["name"] == plan["with"]["name"].removesuffix("plan") + "preview"
    )
    assert preview["with"]["name"].endswith(f"-{environment}-preview")
    assert "head_sha" in preview["with"]["name"]
    assert "pull_request_number" in preview["with"]["name"]
    assert set(preview["with"]) == {"name", "path"}  # Default transport is this run.
    assert steps.index(preview) < steps.index(apply)
    assert (
        apply["run"]
        .rstrip()
        .endswith("make test-destructive-diff\nmake pulumi-up-plan")
    )
    workflow = yaml.safe_load(path.read_text())
    uploads = [
        step
        for job in workflow["jobs"].values()
        for step in job["steps"]
        if step.get("uses", "").startswith("actions/upload-artifact@")
    ]
    producer = next(
        step for step in uploads if step["with"].get("name") == preview["with"]["name"]
    )
    assert producer["with"]["path"] == ".artifacts/pulumi-preview"


@pytest.mark.parametrize(
    "path", WORKFLOWS, ids=lambda path: str(path.relative_to(ROOT))
)
@pytest.mark.parametrize("environment", ["test", "prod"])
@pytest.mark.parametrize(
    ("case", "operation", "labels", "expected"),
    [
        ("removed", "delete", [], False),
        ("retained", "delete", [{"name": "allow-destructive-infra-change"}], True),
        ("nondestructive", "same", [], True),
        (
            "second-page",
            "delete",
            [{"name": "ordinary"}] * 30 + [{"name": "allow-destructive-infra-change"}],
            True,
        ),
        ("closed", "same", [], False),
        ("merged", "same", [], False),
        ("head-moved", "same", [], False),
        ("base-moved", "same", [], False),
        ("retargeted", "same", [], False),
        ("pr-unavailable", "same", [], False),
        ("labels-unavailable", "same", [], False),
        ("missing-preview", "same", [], False),
        ("empty-preview", "same", [], False),
    ],
)
def test_rendered_apply_rechecks_current_labels(
    path: Path,
    environment: str,
    case: str,
    operation: str,
    labels: list,
    expected: bool,
    tmp_path: Path,
) -> None:
    _, apply = _apply_steps(path, environment)
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "--allow-empty",
            "-qm",
            "fixture",
        ],
        cwd=tmp_path,
        check=True,
    )
    head = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=tmp_path, text=True
    ).strip()
    preview_dir = tmp_path / ".artifacts/pulumi-preview"
    preview_dir.mkdir(parents=True)
    event = preview_dir / "pull-request-event.json"
    event.write_text(
        json.dumps(
            {"pull_request": {"labels": [{"name": "allow-destructive-infra-change"}]}}
        )
    )
    preview = preview_dir / "original.json"
    if case != "missing-preview":
        preview.write_text(
            ""
            if case == "empty-preview"
            else json.dumps(
                {
                    "steps": [
                        {
                            "op": operation,
                            "urn": "urn:pulumi:test::fixture::aws:kms/key:Key::key",
                            "newState": {"type": "aws:kms/key:Key"},
                        }
                    ]
                }
            )
        )
    original = preview.read_bytes() if preview.exists() else None
    binaries = tmp_path / "bin"
    binaries.mkdir()
    gh = binaries / "gh"
    gh.write_text(
        f"#!{sys.executable}\n"
        "import json, os, subprocess, sys\n"
        "if sys.argv[2].endswith('/pulls/39'):\n"
        "    case = os.environ['CASE']\n"
        "    if case == 'pr-unavailable': sys.exit(1)\n"
        "    pr = {'state': 'closed' if case == 'closed' else 'open',\n"
        "          'merged': case == 'merged',\n"
        "          'head': {'sha': 'changed' if case == 'head-moved' "
        "else os.environ['EXPECTED_SHA']},\n"
        "          'base': {'ref': 'other' if case == 'retargeted' else 'main',\n"
        "                   'sha': 'changed' if case == 'base-moved' "
        "else os.environ['EXPECTED_BASE_SHA']}}\n"
        "    print(json.dumps(pr)); sys.exit(0)\n"
        "assert sys.argv[2].endswith('/issues/39/labels')\n"
        "if os.environ['CASE'] == 'labels-unavailable':\n"
        "    sys.exit(1)\n"
        "assert '--paginate' in sys.argv and '--slurp' in sys.argv\n"
        "labels = json.loads(os.environ['LABELS'])\n"
        "pages = [labels[:30], labels[30:]]\n"
        "assert '--jq' not in sys.argv\n"
        "print(json.dumps(pages))\n"
    )
    compose = binaries / "compose"
    compose.write_text(
        f"#!{sys.executable}\n"
        "import subprocess, sys\n"
        "assert sys.argv[-3:-1] == ['bash', '-lc']\n"
        "sys.exit(subprocess.run(['/bin/bash', '-c', sys.argv[-1]],\n"
        "                         check=False).returncode)\n"
    )
    uv = binaries / "uv"
    uv.write_text(
        f"#!{sys.executable}\n"
        "import pathlib, subprocess, sys\n"
        "args = [arg for arg in sys.argv[1:] if arg != '--frozen']\n"
        "assert args[:2] == ['run', 'python']\n"
        "assert args[2] == './scripts/pulumi_ci_guardrails.py'\n"
        f"args[2] = {str(ROOT / 'scripts/pulumi_ci_guardrails.py')!r}\n"
        "sys.exit(subprocess.run([sys.executable, *args[2:]],\n"
        "                         check=False).returncode)\n"
    )
    make = binaries / "make"
    make.write_text(
        f"#!{sys.executable}\n"
        "import pathlib, subprocess, sys\n"
        "if sys.argv[1] == 'test-destructive-diff':\n"
        f"    recipe = {str(ROOT / 'Makefile')!r}\n"
        f"    compose = {str(compose)!r}\n"
        "    command = ['/usr/bin/make', '-f', recipe, 'COMPOSE=' + compose,\n"
        "               'DEFAULT_PULUMI_STACK=dev', 'COMPOSE_SERVICE=fixture',\n"
        "               'test-destructive-diff']\n"
        "    sys.exit(subprocess.run(command, check=False).returncode)\n"
        "assert sys.argv[1] == 'pulumi-up-plan'\n"
        "pathlib.Path('applied').touch()\n"
    )
    for executable in (gh, compose, uv, make):
        executable.chmod(0o755)
    result = subprocess.run(
        [
            "/bin/bash",
            "--noprofile",
            "--norc",
            "-e",
            "-o",
            "pipefail",
            "-c",
            apply["run"],
        ],
        cwd=tmp_path,
        env={
            "PATH": f"{binaries}:/usr/bin:/bin",
            "CASE": case,
            "LABELS": json.dumps(labels),
            "GITHUB_REPOSITORY": "fixture/repository",
            "PR_NUMBER": "39",
            "EXPECTED_SHA": head,
            "EXPECTED_BASE_SHA": "b" * 40,
        },
        capture_output=True,
        text=True,
        check=False,
    )
    assert (result.returncode == 0) is expected, result.stderr
    assert (tmp_path / "applied").exists() is expected
    assert (preview.read_bytes() if preview.exists() else None) == original
