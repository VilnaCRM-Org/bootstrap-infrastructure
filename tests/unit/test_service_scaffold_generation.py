"""Offline checks for complete downstream artifacts and fail-closed initialization."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import scaffold_infrastructure_repository as scaffold  # noqa: E402

TEMPLATE = ROOT / "pulumi/user-service-infrastructure"
spec = importlib.util.spec_from_file_location(
    "initialize_service_stack", ROOT / "scripts/initialize_service_stack.py"
)
assert spec and spec.loader
initializer = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = initializer
spec.loader.exec_module(initializer)


def test_generation_is_complete_and_hashes_every_input(tmp_path):
    """A clean artifact contains executable runtime, workflow and policy closure."""
    destination = tmp_path / "service"
    manifest = scaffold.generate(ROOT, destination, "billing-infrastructure")
    assert manifest["pulumiProject"] == "billing-infrastructure"
    assert manifest == json.loads((destination / "scaffold-manifest.json").read_text())
    for relative, digest in manifest["files"].items():
        assert (
            hashlib.sha256((destination / relative).read_bytes()).hexdigest() == digest
        )
    assert set(scaffold.RUNTIME_FILES) <= set(manifest["files"])
    for relative in (
        "Makefile",
        "docker-compose.yml",
        "policy/pack.py",
        "policy/config.py",
        "policy/guardrails.py",
        "policy/requirements.txt",
        "policy/PulumiPolicy.yaml",
        "policy/vilnacrm_guardrails.yaml",
        "scripts/initialize_service_stack.py",
        ".github/workflows/pulumi-pr-commands.yml",
        ".github/workflows/self-deploy.yml",
        ".github/workflows/initialize-stack.yml",
        ".github/workflows/governance-promotion.yml",
        "scripts/governance_promotion.py",
        "scripts/_github_evidence_environment.py",
        ".github/CODEOWNERS",
    ):
        assert relative in manifest["files"]
    assert (
        "user-service-infrastructure"
        not in (destination / "pulumi/Pulumi.yaml").read_text()
    )
    assert (
        "billing-infrastructure:repoSlug"
        in (destination / "pulumi/Pulumi.test.yaml").read_text()
    )
    makefile = (destination / "Makefile").read_text()
    runner = yaml.safe_load(
        (destination / ".github/workflows/self-deploy.yml").read_text()
    )
    for job in runner["jobs"].values():
        for step in job["steps"]:
            for line in step.get("run", "").splitlines():
                if line.startswith("make "):
                    assert f"{line.split()[1]}:" in makefile
    assert "iam_validation" not in str(runner)
    assert "--service" in str(runner)
    publisher = runner["jobs"]["platform_promotion"]
    assert publisher["environment"] == "governance-evidence"
    assert publisher["env"]["PROMOTION_KIND"] == "service"
    assert set(publisher["needs"]) == {
        "preflight",
        "test_apply",
        "test_post_apply_drift",
        "prod_apply",
        "prod_post_apply_drift",
    }
    assert publisher["permissions"] == {"contents": "read", "pull-requests": "read"}
    assert publisher["steps"][0]["with"]["ref"] == "${{ github.sha }}"
    assert "platform_promotion" in runner["jobs"]["comment_result"]["needs"]
    for key in ("base_sha", "source_run_id", "comment_id"):
        assert runner["jobs"]["preflight"]["outputs"][key] == (
            "${{ steps.resolve.outputs." + key + " }}"
        )
    scope = yaml.safe_load(
        (destination / ".github/workflows/governance-promotion.yml").read_text()
    )
    assert scope["jobs"]["scope"]["steps"][0]["with"]["ref"] == (
        "${{ github.event.repository.default_branch }}"
    )


@pytest.mark.parametrize("existing", ["directory", "file", "symlink"])
def test_generator_never_overwrites_existing_destination(tmp_path, existing):
    """Existing files, repositories and symlinks all retain their contents."""
    destination = tmp_path / "existing"
    if existing == "directory":
        destination.mkdir()
    elif existing == "file":
        destination.write_text("keep")
    else:
        destination.symlink_to(tmp_path / "missing")
    with pytest.raises(FileExistsError):
        scaffold.generate(ROOT, destination, "billing-infrastructure")


@pytest.mark.parametrize(
    "slug", ["../escape-infrastructure", "UPPER-infrastructure", "app"]
)
def test_generator_rejects_untrusted_repository_names(tmp_path, slug):
    with pytest.raises(ValueError):
        scaffold.generate(ROOT, tmp_path / "new", slug)


@pytest.mark.parametrize("prefix_length,accepted", [(17, True), (18, False)])
def test_generator_enforces_iam_role_name_limit_before_creating_files(
    tmp_path, prefix_length, accepted
):
    """A 64-character role is valid; a 65-character role leaves no artifact."""
    repository = "a" * prefix_length + "-infrastructure"
    destination = tmp_path / "new-parent" / "service"
    if accepted:
        manifest = scaffold.generate(ROOT, destination, repository)
        assert manifest["repository"] == repository
        assert (destination / "scaffold-manifest.json").is_file()
    else:
        with pytest.raises(ValueError, match="role longer than 64 characters"):
            scaffold.generate(ROOT, destination, repository)
        assert not destination.parent.exists()


@pytest.fixture
def initialization(monkeypatch):
    """Provide trusted workflow context and an observable fake CLI boundary."""
    values = {
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REPOSITORY": "VilnaCRM-Org/user-service-infrastructure",
        "GITHUB_SHA": "a" * 40,
        "INIT_ENVIRONMENT": "test",
        "INIT_ACCOUNT_ID": "891377212104",
    }
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    calls = []
    responses = {
        "version": "v3.223.0",
        "caller": '{"Account":"891377212104"}',
        "list": "[]",
    }

    def execute(*args):
        calls.append(args)
        if args[0] == "aws":
            return responses["caller"]
        if args[-1] == "version":
            return responses["version"]
        if "ls" in args:
            response = responses["list"]
            if isinstance(response, Exception):
                raise response
            return response
        return ""

    monkeypatch.setattr(initializer, "execute", execute)
    return calls, responses


@pytest.mark.parametrize(
    "names,created",
    [
        ([], True),
        ([{"name": "test"}], False),
        ([{"name": "organization/user-service-infrastructure/test"}], False),
    ],
)
def test_initialization_only_creates_after_successful_exact_project_listing(
    initialization, names, created
):
    calls, responses = initialization
    responses["list"] = json.dumps(names)
    receipt = initializer.initialize(TEMPLATE)
    assert receipt["created"] is created
    assert receipt["resourceUpdateExecuted"] is False
    assert ("init" in calls[-1]) is created
    assert "--project" in calls[-2]
    assert all("up" not in call and "preview" not in call for call in calls)


@pytest.mark.parametrize(
    "listing",
    [
        "{}",
        "[{}]",
        '[{"name":42}]',
        '[{"name":"other/project/test"}]',
        "invalid-json",
        subprocess.CalledProcessError(1, ["pulumi"], stderr="AccessDenied"),
    ],
)
def test_listing_errors_never_trigger_stack_initialization(initialization, listing):
    calls, responses = initialization
    responses["list"] = listing
    with pytest.raises((ValueError, subprocess.CalledProcessError)):
        initializer.initialize(TEMPLATE)
    assert all("init" not in call for call in calls)


def test_existing_stack_selection_failure_never_falls_back_to_init(
    initialization, monkeypatch
):
    calls, responses = initialization
    responses["list"] = '[{"name":"test"}]'
    execute = initializer.execute

    def denied_selection(*args):
        result = execute(*args)
        if "select" in args:
            raise subprocess.CalledProcessError(1, list(args), stderr="AccessDenied")
        return result

    monkeypatch.setattr(initializer, "execute", denied_selection)
    with pytest.raises(subprocess.CalledProcessError):
        initializer.initialize(TEMPLATE)
    assert all("init" not in call for call in calls)


@pytest.mark.parametrize(
    "key,value",
    [
        ("GITHUB_REF", "refs/heads/attacker"),
        ("GITHUB_EVENT_NAME", "repository_dispatch"),
        ("INIT_ENVIRONMENT", "other"),
        ("INIT_ACCOUNT_ID", ""),
        ("GITHUB_REPOSITORY", "org/wrong-infrastructure"),
        ("GITHUB_REPOSITORY", "org/../../escape"),
    ],
)
def test_initialization_rejects_untrusted_context_before_cloud_calls(
    initialization, monkeypatch, key, value
):
    calls, _ = initialization
    monkeypatch.setenv(key, value)
    with pytest.raises(ValueError):
        initializer.initialize(TEMPLATE)
    assert calls == []


@pytest.mark.parametrize(
    "key,value",
    [
        ("version", "v3.224.0"),
        ("caller", '{"Account":"933245420672"}'),
    ],
)
def test_wrong_cli_or_account_never_logs_into_backend(initialization, key, value):
    calls, responses = initialization
    responses[key] = value
    with pytest.raises(ValueError):
        initializer.initialize(TEMPLATE)
    assert all("login" not in call for call in calls)


def test_initializer_workflow_is_main_only_with_gated_account_pinned_credentials():
    workflow = yaml.safe_load(
        (TEMPLATE / ".github/workflows/initialize-stack.yml").read_text()
    )
    assert set(workflow[True]) == {"workflow_dispatch"}
    for job in workflow["jobs"].values():
        assert job["if"] == "github.ref == 'refs/heads/main'"
        for step in job["steps"]:
            if "checkout@" in step.get("uses", ""):
                assert step["with"]["ref"] == "${{ github.sha }}"
            if "configure-aws-credentials@" in step.get("uses", ""):
                assert (
                    step["with"]["allowed-account-ids"] == "${{ env.INIT_ACCOUNT_ID }}"
                )
    job = workflow["jobs"]["initialize"]
    assert job["environment"] == "${{ inputs.environment }}"
    assert job["needs"] == "preflight"
    assert "head_sha" not in str(workflow)


def test_generator_cli_creates_reviewable_artifact(tmp_path):
    destination = tmp_path / "new"
    assert scaffold.main(["--destination", str(destination)]) == 0
    assert (destination / "scaffold-manifest.json").is_file()


def test_cli_execution_preserves_argument_boundaries(monkeypatch):
    calls = []
    monkeypatch.setattr(
        initializer.subprocess,
        "run",
        lambda args, **kwargs: (
            calls.append((args, kwargs)) or SimpleNamespace(stdout="[]")
        ),
    )
    assert initializer.execute("pulumi", "stack", "ls") == "[]"
    assert calls == [
        (
            ["pulumi", "stack", "ls"],
            {
                "check": True,
                "capture_output": True,
                "text": True,
            },
        )
    ]


def test_verification_cli_checks_protection_and_default_branch(
    initialization, monkeypatch
):
    calls = []
    monkeypatch.setattr(
        initializer,
        "verify_environments",
        lambda request, **kwargs: calls.append(request),
    )
    monkeypatch.setattr(initializer, "gh", lambda _path: {"default_branch": "main"})
    assert initializer.main(["verify"]) == 0
    assert calls == [{"command": "up", "target_environment": "test"}]
    monkeypatch.setattr(initializer, "gh", lambda _path: {"default_branch": "develop"})
    with pytest.raises(ValueError, match="Default branch"):
        initializer.main(["verify"])


def test_initialization_cli_writes_metadata_receipt(
    initialization, monkeypatch, tmp_path
):
    monkeypatch.setattr(
        initializer, "__file__", str(tmp_path / "scripts/initialize.py")
    )
    receipt = {"resourceUpdateExecuted": False, "headSha": "a" * 40}
    monkeypatch.setattr(initializer, "initialize", lambda root: receipt)
    assert initializer.main(["initialize"]) == 0
    assert (
        json.loads((tmp_path / ".artifacts/stack-initialization.json").read_text())
        == receipt
    )
