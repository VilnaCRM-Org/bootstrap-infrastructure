"""Concrete transport commands tested offline against synthetic metadata/processes."""

import base64
import copy
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))

import operator_execution_transport as transport  # noqa: E402
from test_operator_plan_validation import fixture  # noqa: E402


@pytest.fixture
def installed(tmp_path, monkeypatch):
    """Model required container ownership without changing host users or AWS."""
    monkeypatch.setattr(transport.os, "geteuid", lambda: 0)
    monkeypatch.setattr(transport.os, "getpid", lambda: 1)
    monkeypatch.setattr(transport.os, "chown", lambda *_: None)
    monkeypatch.setattr(
        transport, "_session_environment", lambda: {"AWS_SESSION_TOKEN": "synthetic"}
    )
    area = tmp_path / "area"
    area.mkdir()
    source = tmp_path / "source"
    project = source / "pulumi/github-ci-bootstrap"
    project.mkdir(parents=True)
    (project / "Pulumi.yaml").write_text(
        "name: github-ci-bootstrap\nruntime:\n  name: python\n"
    )
    (project / "Pulumi.test.yaml").write_text("config: {}\n")
    return transport.OperatorTransport("test", area, source)


@pytest.fixture
def checkpoint(installed, monkeypatch):
    """Serve an exact S3 object version and a matching independently resolved key."""
    deployment = fixture()["checkpoint"]["deployment"]
    deployment["secrets_providers"] = {
        "type": "cloud",
        "state": {
            "url": installed.uri,
            "encryptedkey": base64.b64encode(b"synthetic-wrapped-key").decode(),
        },
    }
    raw = transport.encode({"version": 3, "checkpoint": {"latest": deployment}})
    calls = []
    head = {"VersionId": "version-1", "ETag": '"etag"', "ContentLength": len(raw)}
    key = {
        "Arn": installed.key,
        "KeyState": "Enabled",
        "KeyManager": "CUSTOMER",
        "KeyUsage": "ENCRYPT_DECRYPT",
    }

    def aws(service, operation, arguments, output=None):
        calls.append((service, operation, arguments))
        if service == "kms":
            return {"KeyMetadata": key}
        assert arguments["Bucket"] == installed.bucket
        assert arguments["Key"] == installed.object_key
        assert arguments["ExpectedBucketOwner"] == installed.account
        if output is not None:
            assert arguments["VersionId"] == "version-1"
            output.write_bytes(raw)
        return copy.deepcopy(head)

    monkeypatch.setattr(installed, "aws", aws)
    return calls, head, key, deployment


def test_snapshot_uses_exact_version_and_checks_current_pointer(installed, checkpoint):
    calls, _, _, deployment = checkpoint
    result = installed.snapshot()
    assert result.execution.checkpoint.version_id == "version-1"
    assert result.execution.provider.key_arn == installed.key
    assert result.checkpoint == transport.encode(
        {"version": 3, "deployment": deployment}
    )
    assert [operation for _, operation, _ in calls] == [
        "head-object",
        "get-object",
        "describe-key",
        "head-object",
    ]
    assert not list(installed.area.glob("checkpoint-*"))


@pytest.mark.parametrize(
    "field,value",
    [
        ("VersionId", "null"),
        ("VersionId", None),
        ("ETag", ""),
        ("ContentLength", True),
        ("ContentLength", 0),
        ("ContentLength", transport.MAX_BYTES + 1),
    ],
)
def test_missing_or_unbounded_checkpoint_never_downloads(
    installed, checkpoint, field, value
):
    calls, head, _, _ = checkpoint
    head[field] = value
    with pytest.raises(ValueError):
        installed.snapshot()
    assert [operation for _, operation, _ in calls] == ["head-object"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("Arn", "foreign"),
        ("KeyState", "Disabled"),
        ("KeyManager", "AWS"),
        ("KeyUsage", "SIGN_VERIFY"),
    ],
)
def test_provider_key_must_remain_exact(installed, checkpoint, field, value):
    checkpoint[2][field] = value
    with pytest.raises(ValueError, match="provider-key"):
        installed.snapshot()


def test_checkpoint_change_during_read_is_rejected(installed, checkpoint, monkeypatch):
    first = copy.deepcopy(checkpoint[1])
    second = {**first, "VersionId": "version-2"}
    versions = iter([first, second])
    monkeypatch.setattr(installed, "head", lambda: next(versions))
    with pytest.raises(ValueError, match="read-race"):
        installed.snapshot()


def test_kms_translates_native_bytes_without_printing_values(installed, monkeypatch):
    calls = []
    monkeypatch.setattr(
        installed,
        "aws",
        lambda *args: (
            calls.append(args)
            or {
                "KeyId": installed.key,
                "Plaintext": base64.b64encode(bytes(range(32))).decode(),
                "CiphertextBlob": "d3JhcHBlZA==",
            }
        ),
    )
    result = installed.kms(
        "decrypt",
        {
            "KeyId": installed.key,
            "CiphertextBlob": b"wrapped",
            "EncryptionContext": {"purpose": "operator-saved-plan-v1"},
        },
    )
    assert result["Plaintext"] == bytes(range(32))
    assert calls[0][2]["CiphertextBlob"] == "d3JhcHBlZA=="
    with pytest.raises(ValueError):
        installed.kms("encrypt", {"KeyId": installed.key})


@pytest.mark.parametrize("stage", ["preview", "apply", "drift"])
def test_pulumi_commands_use_private_full_plans_and_isolated_child(
    installed, checkpoint, monkeypatch, stage
):
    snapshot = installed.snapshot()
    calls = []

    def execute(command, **kwargs):
        calls.append((command, kwargs))
        config = Path(command[command.index("--config-file") + 1])
        assert config.stat().st_mode & 0o777 == 0o440
        assert config.parent == installed.inputs
        assert config.parent.stat().st_mode & 0o777 == 0o710
        if stage != "apply":
            Path(command[command.index("--save-plan") + 1]).write_bytes(
                b'{"plan":true}'
            )
        else:
            saved = Path(command[command.index("--plan") + 1])
            assert saved.parent == installed.inputs
            assert saved.stat().st_mode & 0o777 == 0o440
            assert (
                Path(command[command.index("--plan") + 1]).read_bytes()
                == b'{"saved":true}'
            )
        return b'{"steps":[]}'

    monkeypatch.setattr(transport, "run", execute)
    actual = installed.pulumi(
        stage, snapshot, b'{"saved":true}' if stage == "apply" else None
    )
    command, options = calls[0]
    assert command[0] == transport.PULUMI
    assert options["child"] is True
    assert "GH_TOKEN" not in options["env"]
    assert options["env"]["PULUMI_DISABLE_AUTOMATIC_PLUGIN_ACQUISITION"] == "true"
    if stage == "apply":
        assert "--plan" in command and "--yes" in command
        assert actual == (b"", b"")
    else:
        assert "--show-sames" in command and "--show-replacement-steps" in command
        assert actual[0] == b'{"plan":true}'
    if stage == "drift":
        assert "--refresh" in command and "--expect-no-changes" in command
    assert not list(installed.work.glob("*.plan"))
    assert not list(installed.work.glob("*.yaml"))
    assert not list(installed.inputs.iterdir())


@pytest.mark.parametrize("field", ["profile", "accessKey", "endpoints", "assumeRoles"])
def test_config_credentials_stop_before_child_execution(
    installed, checkpoint, monkeypatch, field
):
    snapshot = installed.snapshot()
    path = installed.source / "pulumi/github-ci-bootstrap/Pulumi.test.yaml"
    path.write_text(f"config:\n  aws:{field}: synthetic-denied\n")
    monkeypatch.setattr(transport, "run", lambda *_a, **_k: pytest.fail("child ran"))
    with pytest.raises(ValueError, match="credential-or-endpoint"):
        installed.pulumi("preview", snapshot)
    assert not list(installed.inputs.iterdir())


def test_external_config_environment_is_not_loaded(installed, checkpoint, monkeypatch):
    snapshot = installed.snapshot()
    path = installed.source / "pulumi/github-ci-bootstrap/Pulumi.test.yaml"
    path.write_text("environment: synthetic-external-config\nconfig: {}\n")
    monkeypatch.setattr(transport, "run", lambda *_a, **_k: pytest.fail("child ran"))
    with pytest.raises(ValueError, match="operator-config-source"):
        installed.pulumi("preview", snapshot)


def test_actual_subprocess_bounds_and_redacts(tmp_path, monkeypatch):
    safe = {"PATH": os.defpath}
    assert (
        transport.run(
            [sys.executable, "-I", "-c", "print('ok')"], env=safe, cwd=tmp_path
        ).strip()
        == b"ok"
    )
    with pytest.raises(ValueError, match="private-process-failed"):
        transport.run(
            [sys.executable, "-I", "-c", "raise RuntimeError('private-value')"],
            env=safe,
            cwd=tmp_path,
        )
    monkeypatch.setattr(transport, "MAX_BYTES", 10)
    with pytest.raises(ValueError, match="private-process-failed"):
        transport.run(
            [sys.executable, "-I", "-c", "print('x'*1000)"], env=safe, cwd=tmp_path
        )


def test_strict_private_json_and_files(tmp_path):
    with pytest.raises(ValueError):
        transport.decode(b'{"a":1,"a":2}')
    with pytest.raises(ValueError):
        transport.decode(b'{"a":NaN}')
    path = tmp_path / "private"
    transport.private_write(path, b"safe")
    assert transport.private_read(path) == b"safe"
    assert path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        transport.private_write(path, b"replace")
    alias = tmp_path / "link"
    alias.symlink_to(path)
    with pytest.raises(ValueError):
        transport.private_read(alias)


def test_child_output_ownership_remains_writable(tmp_path, monkeypatch):
    owners = []
    monkeypatch.setattr(transport.os, "chown", lambda *args: owners.append(args))
    path = tmp_path / "preview-output"
    transport.private_write(path, b"synthetic-output", child=True)
    assert owners == [(path, 2000, 2000)]
    assert path.stat().st_mode & 0o777 == 0o600


def test_tools_reject_substitution_and_pin_project_and_provider(installed, monkeypatch):
    plugin = installed.area / "plugins/resource-aws-v7.23.0/pulumi-resource-aws"
    plugin.parent.mkdir(parents=True)
    plugin.write_bytes(b"synthetic-public-binary")
    monkeypatch.setattr(transport, "PLUGIN", plugin)
    monkeypatch.setattr(
        transport, "PLUGIN_SHA256", hashlib.sha256(plugin.read_bytes()).hexdigest()
    )
    results = iter([b"a" * 40, b"v3.223.0", b"7.23.0", b"7.23.0"])
    monkeypatch.setattr(transport, "run", lambda *_args, **_kwargs: next(results))
    installed.tools("a" * 40)
    home = installed.area / "pulumi-home"
    assert (home / "plugins").is_symlink()
    assert home.stat().st_mode & 0o777 == 0o755
    assert installed.child_env["PULUMI_HOME"] == str(home)
    assert installed.child_env["PULUMI_CREDENTIALS_PATH"] == str(
        installed.work / "credentials"
    )
    monkeypatch.setattr(transport, "run", lambda *_args, **_kwargs: b"foreign")
    with pytest.raises(ValueError, match="source-head"):
        installed.tools("a" * 40)


@pytest.mark.parametrize("output", [None, "/private/checkpoint"])
def test_native_aws_fixed_json_and_private_dispatch(installed, monkeypatch, output):
    calls = []
    monkeypatch.setattr(
        transport, "run", lambda cmd, **kw: calls.append((cmd, kw)) or b'{"ok":true}'
    )
    assert installed.aws("kms", "describe-key", {"KeyId": installed.key}, output) == {
        "ok": True
    }
    command, options = calls[0]
    assert command[:3] == [transport.AWS, "kms", "describe-key"]
    assert json.loads(command[command.index("--cli-input-json") + 1]) == {
        "KeyId": installed.key
    }
    assert "--no-paginate" in command and "--no-cli-pager" in command
    assert options == {"env": installed.aws_env, "cwd": installed.area, "timeout": 90}
    if output:
        assert command[-1] == output


def test_process_scan_uses_uid_and_excludes_zombies(tmp_path, monkeypatch):
    paths = []
    for pid, uid, state in ((2, 2000, "R"), (3, 0, "R"), (4, 2000, "Z")):
        path = tmp_path / str(pid) / "status"
        path.parent.mkdir()
        path.write_text(f"Uid:\t{uid}\t{uid}\nState:\t{state}\n")
        paths.append(path)
    paths.append(tmp_path / "5" / "status")
    monkeypatch.setattr(transport.Path, "glob", lambda *_: iter(paths))
    assert transport._child_pids() == [2]


def test_cleanup_kills_even_detached_children_and_handles_disappearing_pid(monkeypatch):
    monkeypatch.setattr(transport.os, "getpid", lambda: 1)
    scans = iter([[2, 3], []])
    monkeypatch.setattr(transport, "_child_pids", lambda: next(scans))
    kills = []

    def kill(pid, sig):
        kills.append((pid, sig))
        if pid == 3:
            raise ProcessLookupError

    monkeypatch.setattr(transport.os, "kill", kill)
    monkeypatch.setattr(transport.time, "sleep", lambda _: None)
    transport._stop_children()
    assert [pid for pid, _ in kills] == [2, 3]


def test_child_cleanup_requires_private_namespace_and_has_deadline(monkeypatch):
    monkeypatch.setattr(transport.os, "getpid", lambda: 10)
    with pytest.raises(ValueError, match="private-pid-namespace"):
        transport._stop_children()
    monkeypatch.setattr(transport.os, "getpid", lambda: 1)
    monkeypatch.setattr(transport, "_child_pids", lambda: [2])
    clock = iter([0, 6])
    monkeypatch.setattr(transport.time, "monotonic", lambda: next(clock))
    with pytest.raises(ValueError, match="child-cleanup-timeout"):
        transport._stop_children()


def test_child_dispatch_always_cleans_descendants(monkeypatch, tmp_path):
    calls = []

    class Process:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def poll(self):
            return 0

    monkeypatch.setattr(transport.subprocess, "Popen", lambda *a, **k: Process())
    monkeypatch.setattr(transport, "_streams", lambda *_: b"done")
    monkeypatch.setattr(transport, "_stop_children", lambda: calls.append("cleanup"))
    assert (
        transport.run(["/trusted/binary"], env={}, cwd=tmp_path, child=True) == b"done"
    )
    assert calls == ["cleanup"]


@pytest.mark.skipif(
    not os.environ.get("OPERATOR_CONTAINER_SMOKE_IMAGE"),
    reason="Explicit locally built pinned worker image required; no AWS is used",
)
def test_actual_no_network_container_smoke(tmp_path):
    """Exercise the real image, private UID, SDK and CLI with synthetic state only."""
    project = tmp_path / "project"
    project.mkdir()
    (project / "Pulumi.yaml").write_text(
        "name: operator-offline-smoke\nruntime:\n  name: python\n"
    )
    (project / "__main__.py").write_text(
        "import os, pulumi, pulumi_aws\n"
        "from pathlib import Path\n"
        "assert os.geteuid() == 2000\n"
        "assert 'GH_TOKEN' not in os.environ\n"
        "for name in ('PROTECTED_PLAN', 'PROTECTED_CONFIG'):\n"
        "    if name not in os.environ: continue\n"
        "    path = Path(os.environ[name])\n"
        "    assert path.read_bytes()\n"
        "    attacker = Path(os.environ['HOME']) / 'replacement'\n"
        "    attacker.write_bytes(b'synthetic-not-a-plan')\n"
        "    for action in (lambda: path.write_bytes(b'changed'), path.unlink,\n"
        "                   lambda: path.chmod(0o600),\n"
        "                   lambda: os.replace(attacker, path),\n"
        "                   lambda: path.parent.chmod(0o777)):\n"
        "        try: action()\n"
        "        except PermissionError: pass\n"
        "        else: raise AssertionError('protected input was mutable')\n"
        "home = Path(os.environ['PULUMI_HOME'])\n"
        "plugins = home / 'plugins'\n"
        "assert plugins.is_symlink()\n"
        "assert plugins.resolve() == Path('/opt/operator-plugins/plugins')\n"
        "assert home.stat().st_uid == 0 and home.parent.stat().st_uid == 0\n"
        "for action in (plugins.unlink, lambda: home.chmod(0o777),\n"
        "               lambda: home.rename(home.with_name('hijacked')),\n"
        "               lambda: (home / 'plugins-override').symlink_to('/tmp'),\n"
        "               lambda: os.replace(Path(os.environ['HOME']), home)):\n"
        "    try: action()\n"
        "    except PermissionError: pass\n"
        "    else: raise AssertionError('trusted plugin path was mutable')\n"
        "pulumi.export('smoke', pulumi.Config().require('value'))\n"
    )
    code = r"""
import os, sys, tempfile, subprocess
from pathlib import Path
from importlib.metadata import version

sys.path[:0] = ["/source/scripts", "/source/pulumi"]
import operator_execution_transport as t
original_run = t.run
def diagnostic_run(command, **options):
    try:
        return original_run(command, **options)
    except ValueError:
        # This container has no network or real credentials; diagnostics are synthetic.
        child = options.pop("child", False)
        result = subprocess.run(command, capture_output=True, timeout=10,
                                user=2000 if child else None,
                                group=2000 if child else None, **options)
        raise AssertionError(result.stdout.decode() + result.stderr.decode())
t.run = diagnostic_run

assert version("cryptography") == "50.0.1"
for key in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"):
    os.environ[key] = "synthetic-offline-value"
os.environ["GH_TOKEN"] = "synthetic-root-only-value"
with tempfile.TemporaryDirectory() as directory:
    port = t.OperatorTransport("test", Path(directory), Path("/source"))
    head = (
        t.run(
            [
                "/usr/bin/git",
                "-c",
                "safe.directory=/source",
                "-C",
                "/source",
                "rev-parse",
                "HEAD",
            ],
            env={"PATH": os.defpath},
            cwd=directory,
        )
        .strip()
        .decode()
    )
    port.tools(head)
    t.run([t.AWS, "--version"], env=port.aws_env, cwd=directory)
    t.run(["/usr/bin/gh", "--version"], env={"PATH": os.defpath}, cwd=directory)
    t.run(
        [
            t.PYTHON,
            "-I",
            "-c",
            "import os,pulumi,pulumi_aws; assert os.getuid()==2000; "
            "assert 'GH_TOKEN' not in os.environ",
        ],
        env=port.child_env,
        cwd=port.work,
        child=True,
    )
    daemon = (
        "import os,time; pid=os.fork(); "
        "(os.setsid(),os.close(1),os.close(2),time.sleep(60)) "
        "if pid==0 else print(pid)"
    )
    t.run([t.PYTHON, "-I", "-c", daemon], env=port.child_env, cwd=port.work, child=True)
    assert not t._child_pids()
    config = port.inputs / "synthetic.yaml"
    t.protected_write(
        config, b"config:\n  operator-offline-smoke:value: synthetic-only\n"
    )
    (port.work / "backend").mkdir()
    os.chown(port.work / "backend", 2000, 2000)
    local = {
        **port.child_env,
        "PULUMI_BACKEND_URL": "file://" + str(port.work / "backend"),
        "PULUMI_CONFIG_PASSPHRASE": "synthetic-only",
        "PROTECTED_CONFIG": str(config),
    }
    base = [t.PULUMI, "-C", "/smoke"]
    initializer = port.work / "initializer"
    initializer.mkdir()
    os.chown(initializer, 2000, 2000)
    t.private_write(initializer / "Pulumi.yaml",
                    Path("/smoke/Pulumi.yaml").read_bytes(), child=True)
    t.run(
        [t.PULUMI, "-C", str(initializer)]
        + [
            "stack",
            "init",
            "smoke",
            "--secrets-provider",
            "passphrase",
            "--non-interactive",
        ],
        env=local,
        cwd=port.work,
        child=True,
    )
    # Bind the existing synthetic passphrase provider before making config read-only,
    # just as production _configuration supplies existing cloud provider state.
    initial_config = t.yaml.safe_load((initializer / "Pulumi.smoke.yaml").read_text())
    assert initial_config["encryptionsalt"]
    initial_config["config"] = {"operator-offline-smoke:value": "synthetic-only"}
    config.unlink()
    t.protected_write(config, t.yaml.safe_dump(initial_config).encode())
    plan = port.work / "smoke.plan"
    preview = t.run(
        base
        + [
            "preview",
            "--stack",
            "smoke",
            "--config-file",
            str(config),
            "--non-interactive",
            "--json",
            "--save-plan",
            str(plan),
            "--show-sames",
            "--show-replacement-steps",
        ],
        env=local,
        cwd=port.work,
        child=True,
    )
    assert t.private_read(plan) and b"synthetic-only" in preview
    reviewed = port.inputs / "reviewed.plan"
    expected = t.private_read(plan)
    t.protected_write(reviewed, expected)
    replay = t.run(
        base + ["up", "--stack", "smoke", "--config-file", str(config),
                "--non-interactive", "--json", "--yes", "--plan", str(reviewed)],
        env={**local, "PROTECTED_PLAN": str(reviewed)},
        cwd=port.work,
        child=True,
    )
    assert b"synthetic-only" in replay
    assert t.private_read(reviewed) == expected
    assert not t._child_pids()
print("PINNED-CONTAINER-SMOKE-PASS: no network, no AWS calls, synthetic local replay")
"""
    root = Path(__file__).resolve().parents[2]
    # The local checkout may be a worktree; hosted checkout has a normal .git.
    git_dir = subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "--git-common-dir"], text=True
    ).strip()
    common = (root / git_dir).resolve()
    command = [
        "docker",
        "run",
        "--rm",
        "-i",
        "--network",
        "none",
        "--user",
        "0:0",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,size=3g",
        "--cap-drop",
        "ALL",
        "--cap-add",
        "SETUID",
        "--cap-add",
        "SETGID",
        "--cap-add",
        "CHOWN",
        "--cap-add",
        "DAC_OVERRIDE",
        "--cap-add",
        "KILL",
        "--pids-limit",
        "512",
        "--security-opt",
        "no-new-privileges",
        "--mount",
        f"type=bind,src={root},dst=/source,readonly",
        "--mount",
        f"type=bind,src={common},dst={common},readonly",
        "--mount",
        f"type=bind,src={project},dst=/smoke,readonly",
        "--entrypoint",
        transport.PYTHON,
        os.environ["OPERATOR_CONTAINER_SMOKE_IMAGE"],
        "-I",
        "-",
    ]
    result = subprocess.run(
        command, input=code, text=True, capture_output=True, timeout=90
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "PINNED-CONTAINER-SMOKE-PASS" in result.stdout


@pytest.mark.parametrize("kind", ["symlink-device", "fifo", "oversize"])
def test_project_read_is_bounded_regular_input(installed, monkeypatch, kind):
    plugin = installed.area / "plugins/resource-aws-v7.23.0/pulumi-resource-aws"
    plugin.parent.mkdir(parents=True)
    plugin.write_bytes(b"synthetic-public-binary")
    monkeypatch.setattr(transport, "PLUGIN", plugin)
    monkeypatch.setattr(
        transport, "PLUGIN_SHA256", hashlib.sha256(plugin.read_bytes()).hexdigest()
    )
    results = iter([b"a" * 40, b"v3.223.0", b"7.23.0", b"7.23.0"])
    monkeypatch.setattr(transport, "run", lambda *_args, **_kwargs: next(results))
    monkeypatch.setattr(transport, "MAX_BYTES", 128)
    path = installed.source / "pulumi/github-ci-bootstrap/Pulumi.yaml"
    path.unlink()
    if kind == "symlink-device":
        path.symlink_to("/dev/zero")
    elif kind == "fifo":
        os.mkfifo(path)
    else:
        path.write_bytes(b"x" * 129)
    with pytest.raises(
        ValueError, match="private-file-required|private-document-bound"
    ):
        installed.tools("a" * 40)
    assert not (installed.area / "pulumi-home").exists()


@pytest.mark.parametrize(
    "extra",
    [
        {"plugins": {"providers": [{"name": "aws", "path": "./untrusted"}]}},
        {"packages": {"aws": {"source": "./untrusted"}}},
        {"config": {"aws:accessKey": {"value": "synthetic-only"}}},
        {"main": "./untrusted"},
        {"description": {}},
    ],
)
def test_project_discovery_overrides_fail(installed, monkeypatch, extra):
    project = {"name": "github-ci-bootstrap", "runtime": {"name": "python"}, **extra}
    _reject_project(installed, monkeypatch, project)


@pytest.mark.parametrize("project", [None, [], "not-an-object"])
def test_nonmapping_project_fails_cleanly(installed, monkeypatch, project):
    _reject_project(installed, monkeypatch, project)


def _reject_project(installed, monkeypatch, project):
    plugin = installed.area / "plugins/resource-aws-v7.23.0/pulumi-resource-aws"
    plugin.parent.mkdir(parents=True)
    plugin.write_bytes(b"synthetic-public-binary")
    monkeypatch.setattr(transport, "PLUGIN", plugin)
    monkeypatch.setattr(
        transport, "PLUGIN_SHA256", hashlib.sha256(plugin.read_bytes()).hexdigest()
    )
    results = iter([b"a" * 40, b"v3.223.0", b"7.23.0", b"7.23.0"])
    monkeypatch.setattr(transport, "run", lambda *_args, **_kwargs: next(results))
    path = installed.source / "pulumi/github-ci-bootstrap/Pulumi.yaml"
    path.write_text(transport.yaml.safe_dump(project))
    with pytest.raises(ValueError, match="operator-project-runtime"):
        installed.tools("a" * 40)
    assert not (installed.area / "pulumi-home").exists()
