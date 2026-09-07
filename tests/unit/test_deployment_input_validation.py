"""Offline input plan authentication, tampering and process separation checks."""

from __future__ import annotations

import hashlib
import io
import json
import os
import runpy
import shutil
import subprocess
import sys
import tarfile
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import deployment_input_validation as runtime  # noqa: E402
from test_deployment_controller import build  # noqa: E402

PROCESS = subprocess.run


@pytest.fixture
def prepared(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    (source / ".git").mkdir()
    state = SimpleNamespace(
        contract=build(()),
        calls=[],
        authenticated=[],
        source=source,
        plan=tmp_path / "plan.json",
        output=tmp_path / "outputs",
        metadata={
            name: (Path(runtime.__file__).resolve().parents[1] / name).read_text()
            for name in ("pyproject.toml", "uv.lock")
        },
    )

    def authenticate(**kwargs):
        state.authenticated.append(kwargs)
        return state.contract

    def execute(command, **kwargs):
        state.calls.append((command, kwargs))
        if "--iidfile" in command:
            Path(command[command.index("--iidfile") + 1]).write_text(
                "sha256:" + "d" * 64
            )
        return subprocess.CompletedProcess(
            command,
            0,
            state.metadata[command[-1].removeprefix("HEAD:")]
            if "show" in command
            else state.contract.identity.head_sha + "\n",
        )

    monkeypatch.setattr(runtime, "load_verified_admission", authenticate)
    monkeypatch.setattr(runtime.subprocess, "run", execute)
    # Orchestration uses fake commands; real bounded pipe tests below exercise
    # _execute itself without GitHub, AWS, Docker or untrusted code.
    monkeypatch.setattr(
        runtime,
        "_execute",
        lambda command, environment: (
            runtime.subprocess.run(
                command,
                env=environment,
                check=True,
                shell=False,
                capture_output=True,
                text=True,
                timeout=1200,
            ).stdout
        ),
    )
    monkeypatch.setattr(runtime.shutil, "which", lambda name: "/usr/bin/" + name)
    for key in runtime.CREDENTIAL_KEYS:
        monkeypatch.delenv(key, raising=False)
    state.args = dict(
        artifact_id="123",
        artifact_sha256="a" * 64,
        contract_sha256="b" * 64,
        source=str(source),
        plan_path=str(state.plan),
        output=str(state.output),
    )
    return state


def prepare(state):
    runtime.prepare(**state.args)
    return state.output.read_text().strip().split("=", 1)[1]


def rewrite(state, change):
    plan = json.loads(state.plan.read_bytes())
    change(plan)
    payload = runtime._canonical(plan)
    state.plan.write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()


@pytest.mark.parametrize(
    "flags",
    [
        (False, False, False),
        (True, False, False),
        (False, True, False),
        (False, False, True),
        (True, True, True),
    ],
)
def test_selected_fixed_checks_only_after_authentication(prepared, flags):
    prepared.contract = replace(
        prepared.contract,
        selection=replace(
            prepared.contract.selection, **dict(zip(runtime.FLAGS, flags, strict=True))
        ),
    )
    digest = prepare(prepared)
    assert len(prepared.authenticated) == 1
    assert (
        len(prepared.calls) == 2
    )  # Only trusted git HEAD/base reads during auth step.
    plan = runtime._read_plan(str(prepared.plan), digest)
    runtime.run(plan_path=str(prepared.plan), plan_sha256=digest)
    assert len(plan["commands"]) == 2 + 2 * flags[0] + flags[1] + 2 * flags[2]
    assert prepared.calls[-1][0][1:3] == ["run", "--rm"]
    assert not any("pytest" in call[0] for call in prepared.calls)
    assert prepared.output.read_text() == f"plan_sha256={digest}\n"
    assert "contract_digest" not in prepared.plan.read_text()


@pytest.mark.parametrize("key", runtime.CREDENTIAL_KEYS)
def test_run_rejects_authenticated_parent(prepared, monkeypatch, key):
    digest = prepare(prepared)
    monkeypatch.setenv(key, "fake-test-credential")
    with pytest.raises(ValueError, match="separate credential-free"):
        runtime.run(plan_path=str(prepared.plan), plan_sha256=digest)
    assert len(prepared.calls) == 2


def test_prepare_failure_has_no_plan_or_output(prepared, monkeypatch):
    def reject(**_kwargs):
        raise ValueError("unauthenticated")

    monkeypatch.setattr(runtime, "load_verified_admission", reject)
    with pytest.raises(ValueError, match="unauthenticated"):
        prepare(prepared)
    assert not prepared.plan.exists() and not prepared.output.exists()
    assert not prepared.calls


@pytest.mark.parametrize("phase", ["prepare", "run"])
def test_changed_head_rejected(prepared, monkeypatch, phase):
    digest = prepare(prepared) if phase == "run" else ""
    monkeypatch.setattr(
        runtime.subprocess, "run", lambda *a, **k: SimpleNamespace(stdout="f" * 40)
    )
    with pytest.raises(ValueError, match="HEAD differs"):
        if phase == "run":
            runtime.run(plan_path=str(prepared.plan), plan_sha256=digest)
        else:
            prepare(prepared)


def test_exclusive_plan_refuses_overwrite(prepared):
    prepare(prepared)
    with pytest.raises(FileExistsError):
        prepare(prepared)


def test_plan_outside_source_required(prepared):
    prepared.args["plan_path"] = str(prepared.source / "plan.json")
    with pytest.raises(ValueError, match="Plan is in PR"):
        prepare(prepared)
    assert not prepared.output.exists()


def test_prepare_bound_before_write(prepared, monkeypatch):
    monkeypatch.setattr(runtime, "MAX_PLAN_BYTES", 1)
    with pytest.raises(ValueError, match="size limit"):
        prepare(prepared)
    assert not prepared.plan.exists()


@pytest.mark.parametrize("digest", ["", "A" * 64, "a" * 63])
def test_invalid_expected_hash(prepared, digest):
    prepare(prepared)
    with pytest.raises(ValueError, match="Invalid plan SHA"):
        runtime.run(plan_path=str(prepared.plan), plan_sha256=digest)


def test_tampering_cannot_rehash_trusted_output(prepared):
    digest = prepare(prepared)
    rewrite(prepared, lambda plan: plan.update(execution_validation=True))
    with pytest.raises(ValueError, match="SHA256 differs"):
        runtime.run(plan_path=str(prepared.plan), plan_sha256=digest)


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema_version", True),
        ("schema_version", 2),
        ("head_sha", 123),
        ("base_sha", "bad"),
        ("catalog_validation", 1),
        ("scaffold_validation", "false"),
        ("execution_validation", None),
        ("command", "destroy"),
        ("target_environment", "dev"),
        ("stacks", ["foreign"]),
        ("stacks", ["operator", "operator"]),
        ("stacks", ["platform", "operator"]),
        ("stacks", None),
        ("source", 1),
        ("source", "relative"),
        ("commands", [["bash", "-c", "bad"]]),
        ("unknown", "value"),
    ],
)
def test_rehashed_malformed_plan_rejected(prepared, field, value):
    prepare(prepared)
    digest = rewrite(prepared, lambda plan: plan.update({field: value}))
    with pytest.raises(ValueError):
        runtime.run(plan_path=str(prepared.plan), plan_sha256=digest)
    assert len(prepared.calls) == 2


@pytest.mark.parametrize("payload", [b"[]", b"null", b"{}", b"invalid"])
def test_invalid_json_shape(prepared, payload):
    prepared.plan.write_bytes(payload)
    with pytest.raises(ValueError):
        runtime._read_plan(str(prepared.plan), hashlib.sha256(payload).hexdigest())


def test_bounded_read(prepared):
    payload = b"x" * (runtime.MAX_PLAN_BYTES + 1)
    prepared.plan.write_bytes(payload)
    with pytest.raises(ValueError, match="size limit"):
        runtime._read_plan(str(prepared.plan), hashlib.sha256(payload).hexdigest())


@pytest.mark.parametrize("kind", ["whitespace", "duplicate"])
def test_noncanonical_json_rejected(prepared, kind):
    prepare(prepared)
    payload = prepared.plan.read_bytes()
    payload = (
        b" " + payload
        if kind == "whitespace"
        else payload.replace(b"{", b'{"schema_version":1,', 1)
    )
    prepared.plan.write_bytes(payload)
    with pytest.raises(ValueError, match="not canonical"):
        runtime._read_plan(str(prepared.plan), hashlib.sha256(payload).hexdigest())


def test_changed_checkout_symlink_rejected(prepared):
    digest = prepare(prepared)
    other = prepared.source.with_name("other")
    prepared.source.rename(other)
    prepared.source.symlink_to(other, target_is_directory=True)
    with pytest.raises(ValueError, match="Checkout path changed"):
        runtime.run(plan_path=str(prepared.plan), plan_sha256=digest)


@pytest.mark.parametrize("tool", [None, "source"])
def test_missing_or_source_tool_rejected(prepared, monkeypatch, tool):
    monkeypatch.setattr(
        runtime.shutil,
        "which",
        lambda _: None if tool is None else str(prepared.source / "git"),
    )
    with pytest.raises(ValueError):
        prepare(prepared)


def test_first_failure_stops_remaining_checks(prepared, monkeypatch, capsys):
    digest = prepare(prepared)
    calls = []

    def execute(command, **_kwargs):
        calls.append(command)
        if "rev-parse" in command:
            return SimpleNamespace(stdout=prepared.contract.identity.head_sha)
        if "cat-file" in command:
            return SimpleNamespace(stdout="")
        raise subprocess.CalledProcessError(1, command)

    monkeypatch.setattr(runtime.subprocess, "run", execute)
    with pytest.raises(subprocess.CalledProcessError):
        runtime.run(plan_path=str(prepared.plan), plan_sha256=digest)
    assert len(calls) == 3
    lines = capsys.readouterr().out.splitlines()
    token = lines[0].removeprefix("::stop-commands::")
    assert lines[-1] == f"::{token}::"


def test_environment_is_allowlisted_fresh_and_has_no_output_authority(
    prepared, monkeypatch
):
    digest = prepare(prepared)
    for name in (
        "SSH_AUTH_SOCK",
        "GITHUB_OUTPUT",
        "GITHUB_ENV",
        "PYTHONPATH",
        "UV_INDEX_PASSWORD",
        "BASH_ENV",
    ):
        monkeypatch.setenv(name, "must-not-inherit")
    runtime.run(plan_path=str(prepared.plan), plan_sha256=digest)
    for _, kwargs in prepared.calls[1:]:
        env = kwargs["env"]
        assert "must-not-inherit" not in env.values()
        assert not set(runtime.CREDENTIAL_KEYS).intersection(env)
        assert (
            env["AWS_CONFIG_FILE"] == env["AWS_SHARED_CREDENTIALS_FILE"] == os.devnull
        )
        assert env["AWS_EC2_METADATA_DISABLED"] == "true"
        assert not Path(env["HOME"]).exists()  # Removed after child exits.
        assert Path(env["UV_PROJECT_ENVIRONMENT"]).parent == Path(env["HOME"])


@pytest.mark.parametrize("mode", ["prepare", "run"])
def test_cli_routes_exact_api(prepared, monkeypatch, mode):
    calls = []
    args = (
        prepared.args
        if mode == "prepare"
        else dict(plan_path="plan", plan_sha256="a" * 64)
    )
    monkeypatch.setattr(runtime, mode, lambda **kwargs: calls.append(kwargs))
    argv = [
        mode,
        *[
            part
            for name, value in args.items()
            for part in ("--" + name.replace("_", "-"), value)
        ],
    ]
    assert runtime.main(argv) == 0
    assert calls == [args]


def test_isolated_cli_ignores_hostile_imports(tmp_path):
    marker = tmp_path / "injected"
    payload = f"open({str(marker)!r}, 'w').write('bad')\n"
    for name in (
        "json.py",
        "re.py",
        "sitecustomize.py",
        "deployment_worker_runtime.py",
    ):
        (tmp_path / name).write_text(payload)
    env = {**os.environ, "PYTHONPATH": str(tmp_path)}
    result = PROCESS(
        [sys.executable, "-I", runtime.__file__, "--help"],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert not marker.exists()
    control = PROCESS(
        [sys.executable, "-c", "import json"],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        check=False,
    )
    assert control.returncode == 0 and marker.exists()


def test_real_child_gets_no_inherited_credentials(tmp_path, monkeypatch):
    monkeypatch.setenv("GH_TOKEN", "fake-not-inherited")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "fake-not-inherited")
    monkeypatch.setenv("GITHUB_OUTPUT", "fake-not-inherited")
    monkeypatch.setenv("PYTHONPATH", "fake-not-inherited")
    program = "import json,os; print(json.dumps(dict(os.environ)))"
    result = PROCESS(
        [sys.executable, "-I", "-c", program],
        env=runtime._environment(str(tmp_path)),
        capture_output=True,
        text=True,
        check=True,
    )
    child = json.loads(result.stdout)
    assert "fake-not-inherited" not in child.values()
    assert not {
        "GH_TOKEN",
        "AWS_ACCESS_KEY_ID",
        "GITHUB_OUTPUT",
        "PYTHONPATH",
    }.intersection(child)
    assert child["HOME"] == str(tmp_path)


def test_subprocess_boundary_uses_absolute_argv_without_shell(prepared):
    digest = prepare(prepared)
    runtime.run(plan_path=str(prepared.plan), plan_sha256=digest)
    for command, options in prepared.calls:
        assert isinstance(command, list)
        assert Path(command[0]).is_absolute()
        assert not Path(command[0]).is_relative_to(prepared.source)
        assert options["shell"] is False
        assert options["check"] is True
        assert not set(runtime.CREDENTIAL_KEYS).intersection(options["env"])
    assert prepared.calls[0][0][1:] == [
        "-C",
        str(prepared.source),
        "rev-parse",
        "--verify",
        "HEAD",
    ]


@pytest.mark.parametrize("phase", ["prepare", "run"])
def test_missing_base_is_explicit(prepared, monkeypatch, phase):
    digest = prepare(prepared) if phase == "run" else ""
    original = runtime.subprocess.run

    def execute(command, **kwargs):
        if "cat-file" in command:
            raise subprocess.CalledProcessError(1, command)
        return original(command, **kwargs)

    monkeypatch.setattr(runtime.subprocess, "run", execute)
    with pytest.raises(ValueError, match="missing admitted base commit"):
        if phase == "run":
            runtime.run(plan_path=str(prepared.plan), plan_sha256=digest)
        else:
            prepare(prepared)
    if phase == "prepare":
        assert not prepared.output.exists() and not prepared.plan.exists()


def test_real_missing_base_commit(tmp_path):
    origin = tmp_path / "origin"
    PROCESS(["git", "init", str(origin)], check=True, capture_output=True)
    for message in ("base", "head"):
        PROCESS(
            [
                "git",
                "-C",
                str(origin),
                "-c",
                "user.name=Sandbox Test",
                "-c",
                "user.email=sandbox@example.invalid",
                "commit",
                "--allow-empty",
                "-m",
                message,
            ],
            check=True,
            capture_output=True,
        )
    base = PROCESS(
        [
            "git",
            "-C",
            str(origin),
            "rev-parse",
            "HEAD^",
        ],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    shallow = tmp_path / "shallow"
    PROCESS(
        [
            "git",
            "clone",
            "--depth=1",
            origin.as_uri(),
            str(shallow),
        ],
        check=True,
        capture_output=True,
    )
    with pytest.raises(ValueError, match="missing admitted base commit"):
        runtime._verify_base(shallow, base, runtime._environment(str(tmp_path)))


@pytest.mark.parametrize("kind", ["file", "symlink"])
def test_external_git_metadata_rejected(prepared, kind):
    digest = prepare(prepared)
    git = prepared.source / ".git"
    git.rmdir()
    if kind == "file":
        git.write_text("gitdir: /host/private")
    else:
        git.symlink_to(prepared.source, target_is_directory=True)
    with pytest.raises(ValueError, match="self-contained"):
        runtime.run(plan_path=str(prepared.plan), plan_sha256=digest)


def test_bad_image_id_rejected(tmp_path):
    path = tmp_path / "image"
    path.write_text("mutable:latest")
    with pytest.raises(ValueError, match="Invalid built image"):
        runtime._image_id(path)


@pytest.mark.parametrize("path", ["/bad,path", "/bad\npath", "/bad\rpath"])
def test_mount_option_injection_rejected(path):
    with pytest.raises(ValueError, match="Invalid mount"):
        runtime._mount(Path(path), "/source")


def test_container_boundary_is_closed(prepared):
    digest = prepare(prepared)
    runtime.run(plan_path=str(prepared.plan), plan_sha256=digest)
    command = prepared.calls[-1][0]
    for flag in (
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--user=1000:1000",
    ):
        assert flag in command
    mounts = [
        command[index + 1] for index, value in enumerate(command) if value == "--mount"
    ]
    assert len(mounts) == 3 and all(value.endswith(",readonly") for value in mounts)
    assert not any(
        "docker.sock" in item or "--privileged" in item or "--pid" in item
        for item in command
    )
    assert "sha256:" + "d" * 64 in command
    assert command[-1] == digest
    assert not any(
        "--build-arg" in call[0] or "--secret" in call[0] for call in prepared.calls
    )


def test_dependency_context_is_only_committed_files(prepared, monkeypatch):
    original = runtime.subprocess.run
    contexts = []

    def execute(command, **kwargs):
        if "build" in command:
            context = Path(command[-1])
            contexts.append(
                {
                    str(path.relative_to(context)): path.read_text()
                    for path in context.rglob("*")
                    if path.is_file()
                }
            )
        return original(command, **kwargs)

    monkeypatch.setattr(runtime.subprocess, "run", execute)
    digest = prepare(prepared)
    runtime.run(plan_path=str(prepared.plan), plan_sha256=digest)
    assert len(contexts) == 1
    assert set(contexts[0]) == {
        "Dockerfile",
        "pyproject.toml",
        "uv.lock",
        "trusted/pyproject.toml",
        "trusted/uv.lock",
    }
    recipe = contexts[0]["Dockerfile"]
    assert "FROM runtime-base AS validation\n" in recipe
    assert "FROM runtime-base AS dev" not in recipe
    assert "@sha256:" in recipe
    assert (
        "USER dev\n" in recipe
        and "uv sync --frozen --all-groups --no-install-project --no-build" in recipe
    )
    installed = Path(runtime.__file__).resolve().parents[1]
    for name in ("pyproject.toml", "uv.lock"):
        assert contexts[0]["trusted/" + name] == (installed / name).read_text()
        assert contexts[0][name] == prepared.metadata[name]
    trusted_copy = recipe.index("COPY --chown=dev:dev trusted/pyproject.toml")
    trusted_sync = recipe.index(
        "RUN uv sync --frozen --all-groups --no-install-project\n"
    )
    pr_copy = recipe.index("COPY --chown=dev:dev pyproject.toml uv.lock")
    pr_sync = recipe.index(
        "RUN uv sync --frozen --all-groups --no-install-project --no-build"
    )
    assert trusted_copy < trusted_sync < pr_copy < pr_sync
    assert [call[0][-1] for call in prepared.calls if "show" in call[0]] == [
        "HEAD:pyproject.toml",
        "HEAD:uv.lock",
    ]


def test_workflow_commands_disabled_during_pr_output(prepared, capsys):
    digest = prepare(prepared)
    runtime.run(plan_path=str(prepared.plan), plan_sha256=digest)
    lines = capsys.readouterr().out.splitlines()
    token = lines[0].removeprefix("::stop-commands::")
    assert len(token) == 64 and lines[-1] == f"::{token}::"
    assert all(token not in str(call) for call in prepared.calls)


def test_inside_offline_registry(tmp_path, monkeypatch):
    source = tmp_path / "work" / "source"
    plan = {
        "head_sha": "a" * 40,
        "base_sha": "b" * 40,
        **dict.fromkeys(runtime.FLAGS, False),
    }
    plan["commands"] = runtime._commands(plan)
    calls = []
    original_path = Path
    monkeypatch.setattr(
        runtime,
        "Path",
        lambda value: original_path(
            str(value).replace("/work", str(tmp_path / "work"))
        ),
    )
    monkeypatch.setattr(runtime, "_read_plan", lambda *args: plan)
    monkeypatch.setattr(
        runtime.shutil, "copytree", lambda *args, **kwargs: source.mkdir(parents=True)
    )
    monkeypatch.setattr(runtime, "_verify_head", lambda *args: None)
    monkeypatch.setattr(runtime, "_verify_base", lambda *args: None)
    monkeypatch.setattr(runtime, "_tool", lambda name, _: "/usr/bin/" + name)
    monkeypatch.setattr(
        runtime.subprocess,
        "run",
        lambda command, **kwargs: calls.append((command, kwargs)),
    )
    runtime._inside("c" * 64)
    assert len(calls) == 2
    assert calls[1][0][1:5] == ["run", "--frozen", "--no-sync", "--offline"]
    assert all(call[1]["cwd"] == source for call in calls)
    assert (
        calls[1][1]["env"]["UV_PROJECT_ENVIRONMENT"]
        == "/home/dev/.venvs/bootstrap-infrastructure"
    )


@pytest.mark.skipif(
    os.environ.get("RUN_INPUT_SANDBOX_TEST") != "1",
    reason="Requires Docker daemon and pinned image dependency build",
)
@pytest.mark.parametrize("all_flags", [False, True])
def test_real_container_hides_host_files(tmp_path, monkeypatch, all_flags):
    """Explicit Docker rehearsal; normal unit CI has no daemon/socket mount."""
    source = tmp_path / "checkout"
    root = Path(runtime.__file__).resolve().parents[1]
    PROCESS(
        ["git", "clone", "--no-hardlinks", str(root), str(source)],
        check=True,
        capture_output=True,
    )
    canary = tmp_path / "host-secret-canary"
    output = tmp_path / "runner-command-file"
    canary.write_text("host-only-canary")
    output.write_text("original=true\n")
    # Reproduce the old environment-only boundary: a clean child can still read
    # and overwrite host files. The container must prevent the same operations.
    PROCESS(
        [
            sys.executable,
            "-I",
            "-c",
            "from pathlib import Path; "
            f"assert Path({str(canary)!r}).read_text() == 'host-only-canary'; "
            f"Path({str(output)!r}).write_text('forged=true')",
        ],
        check=True,
        env=runtime._environment(str(tmp_path)),
    )
    assert output.read_text() == "forged=true"
    output.write_text("original=true\n")
    attack = source / "tests/pulumi/test_manifest.py"
    attack.write_text(
        attack.read_text() + "\n"
        "from pathlib import Path\nimport os\n"
        "def test_container_boundary():\n"
        "    assert os.getuid() == 1000\n"
        "    from importlib.metadata import version\n"
        "    assert version('mutmut') == '2.5.1'\n"
        "    assert version('glob2') == '0.7'\n"
        "    assert 'GITHUB_OUTPUT' not in os.environ\n"
        f"    paths = [Path({str(canary)!r}), Path({str(output)!r})]\n"
        "    for path in paths:\n"
        "        assert not path.exists()\n"
        "        assert not Path('/proc/1/root' + str(path)).exists()\n"
        "        try:\n"
        "            path.write_text('forged=true')\n"
        "        except OSError:\n"
        "            pass\n"
        "        else:\n"
        "            raise AssertionError('host path writable')\n"
        "    assert not Path('/var/run/docker.sock').exists()\n"
        "    assert Path('/proc/1/comm').read_text().strip() == 'python3'\n"
        "    print('::set-output name=forged::true')\n"
    )
    PROCESS(
        ["git", "-C", str(source), "add", "tests/pulumi/test_manifest.py"], check=True
    )
    PROCESS(
        [
            "git",
            "-C",
            str(source),
            "-c",
            "user.name=Sandbox Test",
            "-c",
            "user.email=sandbox@example.invalid",
            "commit",
            "-m",
            "Local sandbox fixture",
        ],
        check=True,
        capture_output=True,
    )
    head = PROCESS(
        ["git", "-C", str(source), "rev-parse", "HEAD"],
        check=True,
        text=True,
        capture_output=True,
    ).stdout.strip()
    base = PROCESS(
        ["git", "-C", str(source), "rev-parse", "HEAD^"],
        check=True,
        text=True,
        capture_output=True,
    ).stdout.strip()
    plan = {
        "schema_version": 1,
        "head_sha": head,
        "base_sha": base,
        "command": "plan",
        "target_environment": "test",
        "stacks": [],
        "source": str(source),
        **dict.fromkeys(runtime.FLAGS, all_flags),
    }
    plan["commands"] = runtime._commands(plan)
    payload = runtime._canonical(plan)
    plan_path = tmp_path / "plan.json"
    plan_path.write_bytes(payload)
    for key in runtime.CREDENTIAL_KEYS:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    runtime.run(
        plan_path=str(plan_path), plan_sha256=hashlib.sha256(payload).hexdigest()
    )
    assert canary.read_text() == "host-only-canary"
    assert output.read_text() == "original=true\n"


def test_real_bounded_process_drains_both_streams(tmp_path):
    program = (
        "import os; [(os.write(1,b'a'*4096),os.write(2,b'b'*4096)) for _ in range(32)]"
    )
    value = runtime._execute(
        [sys.executable, "-I", "-c", program], runtime._environment(str(tmp_path))
    )
    assert value == "a" * (4096 * 32)


@pytest.mark.parametrize("stream", [1, 2])
def test_real_process_output_bound_kills_noisy_child(tmp_path, monkeypatch, stream):
    monkeypatch.setattr(runtime, "MAX_OUTPUT_BYTES", 8192)
    real_popen = subprocess.Popen
    children = []

    def popen(*args, **kwargs):
        child = real_popen(*args, **kwargs)
        children.append(child)
        return child

    monkeypatch.setattr(runtime.subprocess, "Popen", popen)
    with pytest.raises(ValueError, match="output exceeds bound"):
        runtime._execute(
            [
                sys.executable,
                "-I",
                "-c",
                f"import os; [os.write({stream}, b'x'*4096) for _ in range(10000)]",
            ],
            runtime._environment(str(tmp_path)),
        )
    assert len(children) == 1 and children[0].poll() is not None


def test_shared_output_bound_counts_stdout_and_stderr(tmp_path, monkeypatch):
    monkeypatch.setattr(runtime, "MAX_OUTPUT_BYTES", 100)
    with pytest.raises(ValueError, match="output exceeds bound"):
        runtime._execute(
            [
                sys.executable,
                "-I",
                "-c",
                "import os; os.write(1,b'a'*60); os.write(2,b'b'*60)",
            ],
            runtime._environment(str(tmp_path)),
        )


def test_failure_redacts_child_output(tmp_path):
    with pytest.raises(subprocess.CalledProcessError) as caught:
        runtime._execute(
            [
                sys.executable,
                "-I",
                "-c",
                (
                    "import os; os.write(1,b'private-output'); "
                    "os.write(2,b'private-error'); raise SystemExit(3)"
                ),
            ],
            runtime._environment(str(tmp_path)),
        )
    assert caught.value.returncode == 3
    assert caught.value.output is None and caught.value.stderr is None


@pytest.mark.parametrize("close_streams", [False, True])
def test_real_process_timeout_is_bounded(tmp_path, monkeypatch, close_streams):
    monkeypatch.setattr(runtime, "PROCESS_TIMEOUT", 0.1)
    program = "import os,time; "
    if close_streams:
        program += "os.close(1); os.close(2); "
    with pytest.raises(subprocess.TimeoutExpired):
        runtime._execute(
            [sys.executable, "-I", "-c", program + "time.sleep(60)"],
            runtime._environment(str(tmp_path)),
        )


def test_noisy_child_ignoring_term_is_killed(tmp_path, monkeypatch):
    monkeypatch.setattr(runtime, "MAX_OUTPUT_BYTES", 1)
    monkeypatch.setattr(runtime, "TERMINATE_TIMEOUT", 0.05)
    program = (
        "import os,signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); "
        "os.write(1,b'xx'); time.sleep(60)"
    )
    with pytest.raises(ValueError, match="output exceeds bound"):
        runtime._execute(
            [sys.executable, "-I", "-c", program], runtime._environment(str(tmp_path))
        )


def _hook_distribution(directory):
    marker = directory / "build-hook-ran"
    archive = directory / "hook-probe-1.0.0.tar.gz"
    files = {
        "pyproject.toml": (
            '[build-system]\nrequires=[]\nbuild-backend="backend"\nbackend-path=["."]\n'
            '[project]\nname="hook-probe"\nversion="1.0.0"\n'
        ),
        "backend.py": (
            "def build_wheel(*args, **kwargs):\n from pathlib import Path\n"
            f' Path({str(marker)!r}).write_text("ran")\n'
            ' raise RuntimeError("synthetic build probe")\n'
        ),
        "PKG-INFO": "Metadata-Version: 2.4\nName: hook-probe\nVersion: 1.0.0\n",
    }
    with tarfile.open(archive, "w:gz") as stream:
        for name, text in files.items():
            raw = text.encode()
            info = tarfile.TarInfo("hook-probe-1.0.0/" + name)
            info.size = len(raw)
            stream.addfile(info, io.BytesIO(raw))
    (directory / "pyproject.toml").write_text(
        '[project]\nname="host-probe"\nversion="0.1.0"\nrequires-python=">=3.11"\n'
        f'dependencies=["hook-probe @ {archive.as_uri()}"]\n'
    )
    return marker


def test_real_uv_refuses_pr_build_hook_before_execution(tmp_path):
    """Actual uv source-build negative control; no network or credentials needed."""
    marker = _hook_distribution(tmp_path)
    uv = shutil.which("uv")
    assert uv is not None
    common = [uv, "--directory", str(tmp_path), "--no-cache"]
    environment = runtime._environment(str(tmp_path))
    locked = PROCESS(
        [*common, "lock", "--offline", "--no-build"],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert locked.returncode == 0, locked.stderr
    assert not marker.exists()
    install = [*common, "sync", "--frozen", "--all-groups", "--no-install-project"]
    blocked = PROCESS(
        [*install, "--no-build"],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert blocked.returncode != 0 and "--no-build" in blocked.stderr
    assert not marker.exists()
    control = PROCESS(
        install,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert control.returncode != 0 and marker.read_text() == "ran"


def _source_lock(*, version="1", hash_value="sha256:aaa", dependencies="[]", extra=""):
    return (
        'version = 1\n[[package]]\nname = "source-probe"\n'
        f'version = "{version}"\nsource = {{ registry = "https://example.invalid" }}\n'
        f"dependencies = {dependencies}\n"
        'sdist = { url = "https://example.invalid/probe.tar.gz", '
        f'hash = "{hash_value}" }}\n' + extra
    )


def test_source_preservation_compares_complete_record_sets():
    trusted = _source_lock()
    assert runtime._preserved_sources(trusted, trusted) == ("source-probe",)
    with_wheel = trusted + (
        '\n[[package]]\nname="new-wheel"\nversion="2"\n'
        'source={registry="https://example.invalid"}\n'
        'wheels=[{url="https://example.invalid/a.whl",hash="sha256:bbb"}]\n'
    )
    assert runtime._preserved_sources(trusted, with_wheel) == ("source-probe",)


@pytest.mark.parametrize(
    "changed",
    [
        _source_lock(version="2"),
        _source_lock(hash_value="sha256:changed"),
        _source_lock(dependencies='[{name="other"}]'),
        _source_lock(extra="resolution-markers=[\"python_version < '3.11'\"]\n"),
        _source_lock().replace("https://example.invalid", "https://foreign.invalid"),
        _source_lock().replace("source-probe", "new-source"),
    ],
)
def test_source_record_changes_fail_before_build(changed):
    with pytest.raises(ValueError, match="dependency"):
        runtime._preserved_sources(_source_lock(), changed)


@pytest.mark.parametrize(
    "payload",
    [
        "",
        "package=[]",
        'package=["bad"]',
        _source_lock().replace("source-probe", "--bad-name"),
        _source_lock().replace(
            'source = { registry = "https://example.invalid" }', "source = {}"
        ),
        _source_lock() + _source_lock().split("version = 1\n", 1)[1],
    ],
)
def test_bad_lock_shape_and_duplicate_record_fail(payload):
    with pytest.raises(ValueError):
        runtime._preserved_sources(_source_lock(), payload)


def test_virtual_root_and_empty_source_exclusions():
    lock = '[[package]]\nname="root"\nversion="1"\nsource={virtual="."}\n'
    assert runtime._preserved_sources(lock, lock) == ()


def test_ambiguous_trusted_source_versions_fail():
    lock = _source_lock() + _source_lock(version="2").split("version = 1\n", 1)[1]
    with pytest.raises(ValueError, match="Ambiguous"):
        runtime._preserved_sources(lock, lock)


def test_python310_toml_compatibility(monkeypatch):
    monkeypatch.setattr(sys, "version_info", (3, 10, 0))
    loaded = runpy.run_path(runtime.__file__, run_name="compatibility_probe")
    assert loaded["tomllib"].__name__ == "tomli"
    assert loaded["_preserved_sources"](_source_lock(), _source_lock()) == (
        "source-probe",
    )
