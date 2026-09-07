"""Offline input plan authentication, tampering and process separation checks."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
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
    state = SimpleNamespace(
        contract=build(()),
        calls=[],
        authenticated=[],
        source=source,
        plan=tmp_path / "plan.json",
        output=tmp_path / "outputs",
    )

    def authenticate(**kwargs):
        state.authenticated.append(kwargs)
        return state.contract

    def execute(command, **kwargs):
        state.calls.append((command, kwargs))
        return subprocess.CompletedProcess(
            command, 0, state.contract.identity.head_sha + "\n"
        )

    monkeypatch.setattr(runtime, "load_verified_admission", authenticate)
    monkeypatch.setattr(runtime.subprocess, "run", execute)
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
    assert len(prepared.calls) == 1  # Only trusted git HEAD read during auth step.
    plan = runtime._read_plan(str(prepared.plan), digest)
    runtime.run(plan_path=str(prepared.plan), plan_sha256=digest)
    executed = prepared.calls[2:]
    assert len(executed) == 2 + 2 * flags[0] + flags[1] + 2 * flags[2]
    assert [call[0][1:] for call in executed] == [cmd[1:] for cmd in plan["commands"]]
    assert prepared.output.read_text() == f"plan_sha256={digest}\n"
    assert "contract_digest" not in prepared.plan.read_text()


@pytest.mark.parametrize("key", runtime.CREDENTIAL_KEYS)
def test_run_rejects_authenticated_parent(prepared, monkeypatch, key):
    digest = prepare(prepared)
    monkeypatch.setenv(key, "fake-test-credential")
    with pytest.raises(ValueError, match="separate credential-free"):
        runtime.run(plan_path=str(prepared.plan), plan_sha256=digest)
    assert len(prepared.calls) == 1


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
    assert len(prepared.calls) == 1


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


def test_first_failure_stops_remaining_checks(prepared, monkeypatch):
    digest = prepare(prepared)
    calls = []

    def execute(command, **_kwargs):
        calls.append(command)
        if "rev-parse" in command:
            return SimpleNamespace(stdout=prepared.contract.identity.head_sha)
        raise subprocess.CalledProcessError(1, command)

    monkeypatch.setattr(runtime.subprocess, "run", execute)
    with pytest.raises(subprocess.CalledProcessError):
        runtime.run(plan_path=str(prepared.plan), plan_sha256=digest)
    assert len(calls) == 2


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
