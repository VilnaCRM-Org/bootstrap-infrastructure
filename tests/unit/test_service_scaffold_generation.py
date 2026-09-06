"""Offline checks for complete downstream artifacts and fail-closed initialization."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import runpy
import shlex
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import scaffold_infrastructure_repository as scaffold  # noqa: E402
from _pulumi_stack_config import _coordinates  # noqa: E402

TEMPLATE = ROOT / "pulumi/user-service-infrastructure"
spec = importlib.util.spec_from_file_location(
    "initialize_service_stack", ROOT / "scripts/initialize_service_stack.py"
)
assert spec and spec.loader
initializer = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = initializer
spec.loader.exec_module(initializer)


@pytest.mark.parametrize(
    "stack,environment,account,passes",
    [
        ("test", "test", "891377212104", True),
        ("prod", "prod", "933245420672", True),
        ("test", "test", "933245420672", False),
        ("prod", "prod", "891377212104", False),
        ("test", "dev", "891377212104", False),
        ("prod", "dev", "933245420672", False),
        ("dev", "test", "891377212104", False),
        ("dev", "dev", "", True),
    ],
)
def test_generated_entrypoint_pins_selected_stack_and_live_account(
    tmp_path, monkeypatch, stack, environment, account, passes
):
    destination = tmp_path / "generated"
    scaffold.generate(ROOT, destination, "billing-infrastructure")
    values = {
        "repoSlug": "billing-infrastructure",
        "environment": environment,
        "awsAccountId": "933245420672" if stack == "prod" else "891377212104",
        "pulumiBackendUrl": "s3://owned",
        "pulumiSecretsProvider": "awskms://owned",
    }
    exports = {}
    calls = []

    class Config:
        def require(self, name):
            return values[name]

    def caller():
        calls.append(account)
        return SimpleNamespace(account_id=account)

    monkeypatch.setitem(
        sys.modules,
        "pulumi",
        SimpleNamespace(
            Config=Config,
            get_stack=lambda: stack,
            export=lambda k, v: exports.__setitem__(k, v),
        ),
    )
    monkeypatch.setitem(
        sys.modules, "pulumi_aws", SimpleNamespace(get_caller_identity=caller)
    )
    if passes:
        runpy.run_path(str(destination / "pulumi/__main__.py"))
        assert exports["repoSlug"] == "billing-infrastructure"
    else:
        with pytest.raises(ValueError):
            runpy.run_path(str(destination / "pulumi/__main__.py"))
        assert exports == {}
    assert bool(calls) is (stack == environment and stack in {"test", "prod"})


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
    for relative in ("pyproject.toml", "uv.lock"):
        contents = (destination / relative).read_text()
        assert 'name = "billing-infrastructure"' in contents
        assert 'name = "bootstrap-infrastructure"' not in contents
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


def test_generator_never_overwrites_data_written_after_reservation(
    tmp_path, monkeypatch
):
    """A concurrent writer keeps its file; publication refuses a nonempty target."""
    destination = tmp_path / "service"
    rename = Path.rename

    def concurrent_write(staged, target):
        (target / "precious.txt").write_text("concurrent data")
        return rename(staged, target)

    monkeypatch.setattr(Path, "rename", concurrent_write)
    with pytest.raises(OSError):
        scaffold.generate(ROOT, destination, "billing-infrastructure")
    assert (destination / "precious.txt").read_text() == "concurrent data"
    assert list(destination.iterdir()) == [destination / "precious.txt"]


@pytest.mark.parametrize("invalid", ["pyproject.toml", "uv.lock"])
def test_generator_rejects_unexpected_python_project_identity(tmp_path, invalid):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "bootstrap-infrastructure"\n'
    )
    (tmp_path / "uv.lock").write_text(
        '[[package]]\nname = "bootstrap-infrastructure"\n'
    )
    (tmp_path / invalid).write_text('name = "different-project"\n')
    with pytest.raises(ValueError, match="exactly one bootstrap Python project"):
        scaffold._bind_python_project(tmp_path, "billing-infrastructure")


def test_generated_compose_forwards_account_to_checkpoint_binding(tmp_path):
    """A workflow's account pin survives Compose and reaches the shared guard."""
    destination = tmp_path / "service"
    scaffold.generate(ROOT, destination, "billing-infrastructure")
    compose = yaml.safe_load((destination / "docker-compose.yml").read_text())
    forwarded = compose["services"]["pulumi"]["environment"]
    host = {
        "AWS_ACCOUNT_ID": "891377212104",
        "PULUMI_BACKEND_URL": "s3://pulumi-billing-infrastructure-test-state",
    }
    context = SimpleNamespace(
        env={name: value for name, value in host.items() if name in forwarded},
        backend_url=host["PULUMI_BACKEND_URL"],
        pulumi_dir=destination / "pulumi",
    )
    target = _coordinates(context, "test")
    assert target["accountId"] == host["AWS_ACCOUNT_ID"]
    assert target["project"] == "billing-infrastructure"


@pytest.mark.parametrize(
    "target,command",
    [("pulumi-plan", "plan"), ("pulumi-up-plan", "up-plan"), ("test-drift", "drift")],
)
def test_generated_make_runs_checkpoint_helper_with_locked_dependencies(
    tmp_path, target, command
):
    """Each actual Make recipe selects the venv containing PyYAML and Pulumi."""
    destination = tmp_path / "service"
    scaffold.generate(ROOT, destination, "billing-infrastructure")
    result = subprocess.run(
        ["make", "--no-print-directory", "--dry-run", target],
        cwd=destination,
        check=True,
        capture_output=True,
        text=True,
    )
    assert shlex.split(result.stdout) == [
        "docker",
        "compose",
        "run",
        "--rm",
        "pulumi",
        "uv",
        "run",
        "--frozen",
        "python",
        "scripts/run_pulumi_command.py",
        command,
    ]


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
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_ACTOR": "dmytrocraft",
        "GITHUB_TRIGGERING_ACTOR": "dmytrocraft",
    }
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    calls = []
    responses = {
        "version": "v3.223.0\n",
        "caller": '{"Account":"891377212104"}',
        "list": "[]",
        "checkpoint_verifications": [],
    }

    def execute(*args):
        calls.append(args)
        if args == ("pulumi", "version"):
            return responses["version"]
        if args[0] == "aws":
            assert args == ("aws", "sts", "get-caller-identity", "--output", "json")
            return responses["caller"]
        assert args[:3] == ("pulumi", "-C", str(TEMPLATE / "pulumi"))
        environment = os.environ["INIT_ENVIRONMENT"]
        tail = args[3:]
        backend = f"s3://pulumi-user-service-infrastructure-{environment}-state"
        provider = f"awskms://alias/pulumi-user-service-infrastructure-{environment}-secrets?region=eu-central-1"
        if tail == (
            "stack",
            "ls",
            "--json",
            "--project",
            "user-service-infrastructure",
        ):
            response = responses["list"]
            if isinstance(response, Exception):
                raise response
            return response
        assert tail in {
            ("login", "--non-interactive", backend),
            ("stack", "select", environment, "--non-interactive"),
            (
                "stack",
                "init",
                environment,
                "--non-interactive",
                "--secrets-provider",
                provider,
            ),
        }, "Unexpected CLI operation or target"
        return ""

    monkeypatch.setattr(initializer, "execute", execute)
    monkeypatch.setattr(
        initializer,
        "_verify_checkpoint",
        lambda *args: responses["checkpoint_verifications"].append(args),
    )
    return calls, responses


@pytest.mark.parametrize(
    "names,created",
    [
        ([], True),
        ([{"name": "test"}], False),
        ([{"name": "organization/user-service-infrastructure/test"}], False),
        (
            [
                {"name": "test"},
                {"name": "organization/user-service-infrastructure/test"},
            ],
            False,
        ),
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
    assert responses["checkpoint_verifications"] == [
        (
            TEMPLATE,
            "test",
            "891377212104",
            "s3://pulumi-user-service-infrastructure-test-state",
            "awskms://alias/pulumi-user-service-infrastructure-test-secrets?region=eu-central-1",
        )
    ]


def test_existing_stack_provider_failure_never_falls_back_to_init(
    initialization, monkeypatch
):
    calls, responses = initialization
    responses["list"] = '[{"name":"test"}]'

    def invalid_provider(*args):
        raise ValueError("Checkpoint provider mismatch")

    monkeypatch.setattr(initializer, "_verify_checkpoint", invalid_provider)
    with pytest.raises(ValueError, match="Checkpoint provider mismatch"):
        initializer.initialize(TEMPLATE)
    assert all("init" not in call for call in calls)


def test_checkpoint_verification_uses_exact_shared_provider_guard(
    tmp_path, monkeypatch
):
    import _pulumi_stack_config

    seen = []

    @contextmanager
    def verified(context, stack):
        seen.append((context, stack))
        yield context

    monkeypatch.setattr(_pulumi_stack_config, "prepared_stack_configuration", verified)
    monkeypatch.setenv("AWS_REGION", "eu-central-1")
    initializer._verify_checkpoint(
        tmp_path, "test", "891377212104", "s3://owned-state", "awskms://alias/owned"
    )
    context, stack = seen[0]
    assert stack == "test"
    assert context.pulumi_dir == tmp_path / "pulumi"
    assert context.policy_pack_dir == tmp_path / "policy"
    assert context.plan_dir == tmp_path / ".artifacts/pulumi-plan"
    assert context.preview_artifact_dir == tmp_path / ".artifacts/pulumi-preview"
    assert context.env["AWS_ACCOUNT_ID"] == "891377212104"
    assert context.env["AWS_REGION"] == "eu-central-1"
    assert (
        context.backend_url == context.env["PULUMI_BACKEND_URL"] == "s3://owned-state"
    )
    assert context.secrets_provider == "awskms://alias/owned"


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
                    step["with"]["allowed-account-ids"]
                    == "${{ needs.preflight.outputs.account_id }}"
                )
    job = workflow["jobs"]["initialize"]
    assert job["environment"] == "${{ inputs.environment }}"
    assert job["needs"] == "preflight"
    assert "head_sha" not in str(workflow)
    assert job["env"]["INIT_ACCOUNT_ID"] == "${{ needs.preflight.outputs.account_id }}"
    assert workflow["jobs"]["preflight"]["outputs"] == {
        "account_id": "${{ steps.target.outputs.account_id }}",
        "config_role": "${{ steps.target.outputs.config_role }}",
    }


@pytest.mark.parametrize("environment", ["test", "prod"])
@pytest.mark.parametrize(
    "corruption",
    [
        None,
        "empty-account",
        "invalid-account",
        "empty-role",
        "wrong-role-account",
        "empty-role-name",
        "newline-role",
    ],
)
def test_initializer_target_resolution_never_falls_back(
    tmp_path, environment, corruption
):
    """Execute the real resolver; a valid opposite account never masks bad input."""
    workflow = yaml.safe_load(
        (TEMPLATE / ".github/workflows/initialize-stack.yml").read_text()
    )
    resolver = next(
        step
        for step in workflow["jobs"]["preflight"]["steps"]
        if step.get("id") == "target"
    )
    output = tmp_path / "outputs"
    env = {
        "PATH": os.defpath,
        "INIT_ENVIRONMENT": environment,
        "GITHUB_OUTPUT": str(output),
        "TEST_ACCOUNT_ID": "891377212104",
        "PROD_ACCOUNT_ID": "933245420672",
        "TEST_CONFIG_ROLE": "arn:aws:iam::891377212104:role/GitHubCiConfigRead-test",
        "PROD_CONFIG_ROLE": "arn:aws:iam::933245420672:role/GitHubCiConfigRead-prod",
    }
    selected = environment.upper()
    mutations = {
        "empty-account": ("ACCOUNT_ID", ""),
        "invalid-account": ("ACCOUNT_ID", "１２３４５６７８９０１２"),
        "empty-role": ("CONFIG_ROLE", ""),
        "wrong-role-account": ("CONFIG_ROLE", "arn:aws:iam::123456789012:role/wrong"),
        "empty-role-name": (
            "CONFIG_ROLE",
            f"arn:aws:iam::{env[selected + '_ACCOUNT_ID']}:role/",
        ),
        "newline-role": (
            "CONFIG_ROLE",
            env[selected + "_CONFIG_ROLE"] + "\ninjected=true",
        ),
    }
    if corruption:
        key, value = mutations[corruption]
        env[f"{selected}_{key}"] = value
    result = subprocess.run(
        ["bash", "-euo", "pipefail", "-c", resolver["run"]],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    if corruption:
        assert result.returncode != 0
        assert not output.exists()
    else:
        assert result.returncode == 0, result.stderr
        assert output.read_text() == (
            f"account_id={env[selected + '_ACCOUNT_ID']}\n"
            f"config_role={env[selected + '_CONFIG_ROLE']}\n"
        )


def test_template_build_preserves_runner_user_identity():
    """Container writes use the runner UID/GID for its mounted checkout."""
    makefile = (TEMPLATE / "Makefile").read_text()
    assert "UID ?= $(shell id -u)" in makefile
    assert "GID ?= $(shell id -g)" in makefile
    assert "export UID\nexport GID" in makefile
    compose = yaml.safe_load((TEMPLATE / "docker-compose.yml").read_text())
    assert compose["services"]["pulumi"]["build"]["args"] == {
        "UID": "${UID:-1000}",
        "GID": "${GID:-1000}",
        "USERNAME": "dev",
    }


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
        lambda request, **kwargs: calls.append((request, kwargs)),
    )
    monkeypatch.setattr(
        initializer,
        "gh",
        lambda path: (
            {"permission": "write"}
            if path.endswith("/collaborators/dmytrocraft/permission")
            else {
                "repos/VilnaCRM-Org/user-service-infrastructure": {
                    "default_branch": "main"
                }
            }[path]
        ),
    )
    assert initializer.main(["verify"]) == 0
    assert calls == [
        ({"command": "up", "target_environment": "test"}, {"governance": False})
    ]
    monkeypatch.setattr(
        initializer,
        "gh",
        lambda _path: {"default_branch": "develop", "permission": "write"},
    )
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
    assert initializer.main(["initialize"]) == 0
    assert (
        json.loads((tmp_path / ".artifacts/stack-initialization.json").read_text())
        == receipt
    )


@pytest.mark.parametrize("permission", ["write", "maintain", "admin"])
def test_initializer_requires_current_requester_permission(
    initialization, monkeypatch, permission
):
    requested = []
    monkeypatch.setattr(
        initializer,
        "gh",
        lambda path: requested.append(path) or {"permission": permission},
    )
    initializer.verify_requester()
    assert requested == [
        "repos/VilnaCRM-Org/user-service-infrastructure/collaborators/dmytrocraft/permission"
    ]


@pytest.mark.parametrize("permission", ["read", "triage", "none", "", None])
def test_initializer_rejects_insufficient_permission_before_environment_checks(
    initialization, monkeypatch, permission
):
    calls, _ = initialization
    monkeypatch.setattr(initializer, "gh", lambda _path: {"permission": permission})
    monkeypatch.setattr(
        initializer,
        "verify_environments",
        lambda *args, **kwargs: pytest.fail(
            "Unapproved requester reached environment verification"
        ),
    )
    with pytest.raises(ValueError, match="Current write access"):
        initializer.main(["verify"])
    assert calls == []


@pytest.mark.parametrize(
    "key,value",
    [
        ("GITHUB_ACTOR", "Kravalg"),
        ("GITHUB_ACTOR", "kravalg"),
        ("GITHUB_ACTOR", ""),
        ("GITHUB_ACTOR", "../other"),
        ("GITHUB_TRIGGERING_ACTOR", "other"),
        ("GITHUB_RUN_ATTEMPT", "2"),
        ("GITHUB_RUN_ATTEMPT", ""),
    ],
)
def test_initializer_rejects_self_review_forged_actor_and_rerun_before_api(
    initialization, monkeypatch, key, value
):
    calls, _ = initialization
    monkeypatch.setenv(key, value)
    if key == "GITHUB_ACTOR":
        monkeypatch.setenv("GITHUB_TRIGGERING_ACTOR", value)
    monkeypatch.setattr(
        initializer,
        "gh",
        lambda _path: pytest.fail("Invalid requester reached GitHub API"),
    )
    with pytest.raises(ValueError):
        initializer.main(["verify"])
    assert calls == []


def test_initializer_permission_read_failure_never_continues(
    initialization, monkeypatch
):
    calls, _ = initialization

    def denied(_path):
        raise subprocess.CalledProcessError(1, ["gh", "api"])

    monkeypatch.setattr(initializer, "gh", denied)
    monkeypatch.setattr(
        initializer,
        "verify_environments",
        lambda *args, **kwargs: pytest.fail(
            "Denied permission read reached environment verification"
        ),
    )
    with pytest.raises(subprocess.CalledProcessError):
        initializer.main(["verify"])
    assert calls == []


def test_prod_initialization_emits_exact_public_receipt(initialization, monkeypatch):
    """The PROD metadata receipt binds the same selected account and backend."""
    calls, responses = initialization
    monkeypatch.setenv("INIT_ENVIRONMENT", "prod")
    monkeypatch.setenv("INIT_ACCOUNT_ID", "933245420672")
    responses["caller"] = '{"Account":"933245420672"}'
    assert initializer.initialize(TEMPLATE) == {
        "schemaVersion": 1,
        "project": "user-service-infrastructure",
        "stack": "prod",
        "accountId": "933245420672",
        "backend": "s3://pulumi-user-service-infrastructure-prod-state",
        "secretsProvider": "awskms://alias/pulumi-user-service-infrastructure-prod-secrets?region=eu-central-1",
        "headSha": "a" * 40,
        "created": True,
        "resourceUpdateExecuted": False,
    }
    assert calls[-1][-5:] == (
        "init",
        "prod",
        "--non-interactive",
        "--secrets-provider",
        "awskms://alias/pulumi-user-service-infrastructure-prod-secrets?region=eu-central-1",
    )
    assert all("up" not in call and "preview" not in call for call in calls)


@pytest.mark.parametrize("job_name", ["preflight", "initialize"])
@pytest.mark.parametrize(
    "attempt,actor,triggering,permission,passes",
    [
        ("1", "dmytrocraft", "dmytrocraft", "write", True),
        ("1", "dmytrocraft", "dmytrocraft", "admin", True),
        ("2", "dmytrocraft", "dmytrocraft", "write", False),
        ("", "dmytrocraft", "dmytrocraft", "write", False),
        ("1", "Kravalg", "Kravalg", "admin", False),
        ("1", "dmytrocraft", "other", "write", False),
        ("1", "dmytrocraft", "dmytrocraft", "read", False),
        ("1", "dmytrocraft", "dmytrocraft", None, False),
    ],
)
def test_each_initialization_job_verifies_before_credentials(
    initialization,
    monkeypatch,
    job_name,
    attempt,
    actor,
    triggering,
    permission,
    passes,
):
    """A job-only rerun must hit the actual workflow command before either OIDC step."""
    workflow = yaml.safe_load(
        (TEMPLATE / ".github/workflows/initialize-stack.yml").read_text()
    )
    job = workflow["jobs"][job_name]
    steps = job["steps"]
    verification = [
        (index, step)
        for index, step in enumerate(steps)
        if step.get("run") == "python3 scripts/initialize_service_stack.py verify"
    ]
    assert len(verification) == 1
    index, step = verification[0]
    assert "if" not in step and "continue-on-error" not in step
    assert step["env"]["GH_TOKEN"] == "${{ github.token }}"
    assert job["permissions"]["actions"] == "read"
    credential_steps = [
        offset
        for offset, candidate in enumerate(steps)
        if "load-aws-ci-env" in candidate.get("uses", "")
        or "configure-aws-credentials" in candidate.get("uses", "")
    ]
    if job_name == "initialize":
        assert len(credential_steps) == 2
        assert all(index < offset for offset in credential_steps)
        assert job["env"]["INIT_ACCOUNT_ID"] == (
            "${{ needs.preflight.outputs.account_id }}"
        )
    else:
        assert credential_steps == []
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", attempt)
    monkeypatch.setenv("GITHUB_ACTOR", actor)
    monkeypatch.setenv("GITHUB_TRIGGERING_ACTOR", triggering)
    monkeypatch.setattr(
        initializer,
        "gh",
        lambda path: (
            {"permission": permission}
            if "/collaborators/" in path
            else {"default_branch": "main"}
        ),
    )
    protected = []
    monkeypatch.setattr(
        initializer, "verify_environments", lambda *a, **k: protected.append(True)
    )
    arguments = shlex.split(step["run"])[2:]
    if passes:
        assert initializer.main(arguments) == 0
        assert protected == [True]
    else:
        with pytest.raises(ValueError):
            initializer.main(arguments)
        assert protected == []
    assert initialization[0] == []
