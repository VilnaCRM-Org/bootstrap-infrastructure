"""Authenticate worker artifacts using fake GitHub and bounded binary transport."""

from __future__ import annotations

import hashlib
import io
import json
import os
import stat
import struct
import subprocess
import sys
import zipfile
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))

import deployment_worker_runtime as runtime  # noqa: E402
from deployment_controller_runtime import required_environments  # noqa: E402
from test_deployment_controller_runtime import github as _github_fixture  # noqa: E402
from test_deployment_worker_recheck import admitted as _admitted_fixture  # noqa: E402

github = _github_fixture
admitted = _admitted_fixture

# The shared transport fixture patches subprocess.run. Retain the real function
# solely for the isolated-interpreter regression with an explicitly fake gh.
RUN_PROCESS = subprocess.run
ARTIFACT_ENDPOINT = f"repos/{runtime.REPOSITORY}/actions/artifacts/123"


def make_zip(entries):
    """Produce actual archives, including adversarial member metadata."""
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, payload in entries:
            archive.writestr(name, payload)
    return stream.getvalue()


@pytest.fixture
def artifact(admitted, github, monkeypatch, tmp_path):
    """Bind real admission bytes and the documented artifact metadata shape."""
    payload = github.contract.read_bytes()
    raw = make_zip([("contract.json", payload)])
    args = {
        "artifact_id": "123",
        "artifact_sha256": hashlib.sha256(raw).hexdigest(),
        "contract_sha256": hashlib.sha256(payload).hexdigest(),
        "scope": "platform",
        "environment": "test",
    }
    metadata = {
        "id": 123,
        "name": "deployment-selection-100-1",
        "size_in_bytes": len(raw),
        "expired": False,
        "digest": f"sha256:{args['artifact_sha256']}",
        "workflow_run": {
            "id": 100,
            "repository_id": runtime.REPOSITORY_ID,
            "head_repository_id": runtime.REPOSITORY_ID,
            "head_branch": "main",
            "head_sha": admitted.identity.controller.sha,
        },
    }
    github.overrides[ARTIFACT_ENDPOINT] = metadata
    state = SimpleNamespace(
        args=args,
        raw=raw,
        payload=payload,
        downloads=[],
        metadata=metadata,
        contract=admitted,
        output=tmp_path / "worker-output",
    )

    def download(artifact_id):
        assert github.calls[-1][0] == ARTIFACT_ENDPOINT
        assert artifact_id == "123"
        state.downloads.append(artifact_id)
        return state.raw

    monkeypatch.setattr(runtime, "_download_zip", download)
    return state


def cli_args(artifact):
    """Supply only the exact installed worker CLI fields."""
    return [
        part
        for name, value in {**artifact.args, "output": str(artifact.output)}.items()
        for part in (f"--{name.replace('_', '-')}", value)
    ]


def test_callable_verifies_transport_and_real_worker_without_outputs(artifact, github):
    assert runtime.load_verified_contract(**artifact.args) == artifact.contract
    assert artifact.downloads == ["123"]
    assert not artifact.output.exists()
    assert github.calls[0][0].endswith("/actions/runs/100")
    assert github.calls[1][0] == ARTIFACT_ENDPOINT
    assert sum(path.endswith("/actions/runs/100") for path, _ in github.calls) == 2


def test_root_loader_has_no_worker_outputs(artifact, github):
    args = {
        key: artifact.args[key]
        for key in ("artifact_id", "artifact_sha256", "contract_sha256")
    }
    assert runtime.load_verified_admission(**args) == artifact.contract
    assert artifact.downloads == ["123"]
    assert not artifact.output.exists()
    assert any("/environments/" in path for path, _ in github.calls)


def test_root_loader_rechecks_rights(artifact, github):
    github.evidence["permission"] = "read"
    args = {
        key: artifact.args[key]
        for key in ("artifact_id", "artifact_sha256", "contract_sha256")
    }
    with pytest.raises(ValueError):
        runtime.load_verified_admission(**args)
    assert not artifact.output.exists()


def test_receipt_name_is_exact(artifact):
    name = (
        "deployment-receipt-100-1-platform-test-" + artifact.contract.identity.head_sha
    )
    artifact.metadata["name"] = name
    runtime._verify_artifact(
        "123",
        artifact.args["artifact_sha256"],
        artifact.contract.identity.controller,
        expected_name=name,
    )
    with pytest.raises(ValueError, match="Artifact name differs"):
        runtime._verify_artifact(
            "123",
            artifact.args["artifact_sha256"],
            artifact.contract.identity.controller,
        )


def test_receipt_archive_has_one_exact_file():
    raw = make_zip([("receipt.json", b"{}\n")])
    assert runtime._contract_bytes(raw, member_name="receipt.json") == b"{}\n"
    with pytest.raises(ValueError, match="Artifact member must be contract.json"):
        runtime._contract_bytes(raw)
    with pytest.raises(ValueError, match="Artifact member must be receipt.json"):
        runtime._contract_bytes(
            make_zip([("contract.json", b"{}")]), member_name="receipt.json"
        )


@pytest.mark.parametrize("account", ["test", "prod"])
def test_barrier_zip_is_account_bound(account):
    name = f"{account}.json"
    raw = make_zip([(name, b"{}\n")])
    assert runtime._contract_bytes(raw, member_name=name) == b"{}\n"
    other = "prod" if account == "test" else "test"
    with pytest.raises(ValueError, match="Artifact member must be"):
        runtime._contract_bytes(raw, member_name=f"{other}.json")
    with pytest.raises(ValueError, match="Artifact member must be contract.json"):
        runtime._contract_bytes(raw)


@pytest.mark.parametrize("name", ["../receipt.json", "request.json", "", None])
def test_unknown_member_kind_is_rejected(name):
    with pytest.raises(ValueError, match="Unsupported artifact member"):
        runtime._contract_bytes(b"", member_name=name)


def test_cli_exposes_only_validated_fields_and_no_raw_evidence(
    artifact, monkeypatch, capsys
):
    monkeypatch.setenv("GH_TOKEN", "FAKE_SECRET_MUST_NOT_ESCAPE")
    assert runtime.main(cli_args(artifact)) == 0
    values = dict(
        line.split("=", 1) for line in artifact.output.read_text().splitlines()
    )
    assert values == {
        "head_sha": "a" * 40,
        "base_sha": "b" * 40,
        "command": "up",
        "pull_request_number": "78",
        "target_environment": "prod",
        "selection_digest": artifact.contract.selection_digest,
        "contract_digest": artifact.contract.contract_digest,
    }
    all_output = capsys.readouterr().out + artifact.output.read_text()
    assert "FAKE_SECRET_MUST_NOT_ESCAPE" not in all_output
    assert '"reasons"' not in all_output
    assert '"schema_version"' not in all_output


@pytest.mark.parametrize(
    "name,value",
    [
        ("artifact_id", "0"),
        ("artifact_id", "01"),
        ("artifact_id", "1/zip"),
        ("artifact_id", 123),
        ("artifact_sha256", "A" * 64),
        ("artifact_sha256", "a" * 63),
        ("artifact_sha256", None),
        ("contract_sha256", "sha256:" + "a" * 64),
        ("contract_sha256", "a" * 64 + "\n"),
        ("scope", "other"),
        ("environment", "stage"),
    ],
)
def test_malformed_caller_arguments_stop_before_api(artifact, github, name, value):
    artifact.args[name] = value
    with pytest.raises(ValueError):
        runtime.load_verified_contract(**artifact.args)
    assert not github.calls
    assert not artifact.downloads
    assert not artifact.output.exists()


@pytest.mark.parametrize(
    "path,value",
    [
        (("id",), 124),
        (("id",), "123"),
        (("id",), True),
        (("name",), "deployment-selection-100-2"),
        (("name",), "deployment-selection-101-1"),
        (("expired",), True),
        (("expired",), 0),
        (("digest",), None),
        (("digest",), "sha256:" + "d" * 64),
        (("workflow_run", "id"), 101),
        (("workflow_run", "id"), "100"),
        (("workflow_run", "repository_id"), 1),
        (("workflow_run", "head_repository_id"), 1),
        (("workflow_run", "head_branch"), "feature"),
        (("workflow_run", "head_sha"), "d" * 40),
        (("workflow_run",), None),
        (("size_in_bytes",), True),
        (("size_in_bytes",), 0),
        (("size_in_bytes",), runtime.MAX_ZIP_BYTES + 1),
    ],
)
def test_artifact_metadata_must_match_trusted_outputs(artifact, path, value):
    current = artifact.metadata
    for key in path[:-1]:
        current = current[key]
    current[path[-1]] = value
    with pytest.raises(ValueError):
        runtime.main(cli_args(artifact))
    assert not artifact.downloads
    assert not artifact.output.exists()


@pytest.mark.parametrize("response", [None, [], RuntimeError("artifact unavailable")])
def test_unreadable_artifact_fails_before_download(artifact, github, response):
    github.overrides[ARTIFACT_ENDPOINT] = response
    with pytest.raises((ValueError, RuntimeError)):
        runtime.main(cli_args(artifact))
    assert not artifact.downloads
    assert not artifact.output.exists()


def test_actual_root_run_failure_precedes_artifact_download(artifact, github):
    github.overrides[f"repos/{runtime.REPOSITORY}/actions/runs/100"]["path"] = (
        "foreign.yml"
    )
    with pytest.raises(ValueError, match="Controller run path"):
        runtime.main(cli_args(artifact))
    assert not artifact.downloads
    assert not artifact.output.exists()


@pytest.mark.parametrize("change", ["zip", "contract", "decode", "recheck"])
def test_transport_decode_or_live_recheck_failure_has_no_outputs(
    artifact, github, change
):
    if change == "zip":
        artifact.raw += b"changed archive"
    elif change == "contract":
        artifact.args["contract_sha256"] = "d" * 64
    elif change == "decode":
        artifact.payload = b'{"schema_version":2}'
        artifact.raw = make_zip([("contract.json", artifact.payload)])
        artifact.args["artifact_sha256"] = hashlib.sha256(artifact.raw).hexdigest()
        artifact.args["contract_sha256"] = hashlib.sha256(artifact.payload).hexdigest()
        artifact.metadata["digest"] = f"sha256:{artifact.args['artifact_sha256']}"
    else:
        github.evidence["permission"] = "read"
    with pytest.raises(ValueError):
        runtime.main(cli_args(artifact))
    assert not artifact.output.exists()


@pytest.mark.parametrize("args", [[], ["--skip-recheck"], ["accept"]])
def test_missing_arguments_and_bypass_flags_are_rejected(artifact, github, args):
    with pytest.raises(SystemExit) as exc:
        runtime.main(args)
    assert exc.value.code == 2
    assert not github.calls


@pytest.mark.parametrize(
    "name",
    [
        "../contract.json",
        "/contract.json",
        "nested/contract.json",
        "C:\\contract.json",
        "contract.json/",
        "other.json",
    ],
)
def test_zip_rejects_every_nonexact_member_path(name):
    with pytest.raises(ValueError, match="member must be contract.json"):
        runtime._contract_bytes(make_zip([(name, b"{}")]))


@pytest.mark.parametrize(
    "entries", [[], [("contract.json", b"{}"), ("extra", b"extra")]]
)
def test_zip_requires_exactly_one_member(entries):
    with pytest.raises(ValueError, match="exactly one"):
        runtime._contract_bytes(make_zip(entries))


def test_zip_rejects_duplicate_member():
    with pytest.warns(UserWarning, match="Duplicate name"):
        raw = make_zip([("contract.json", b"{}"), ("contract.json", b"{}")])
    with pytest.raises(ValueError, match="exactly one"):
        runtime._contract_bytes(raw)


@pytest.mark.parametrize("mode", [stat.S_IFLNK, stat.S_IFDIR, stat.S_IFIFO])
def test_zip_rejects_symlink_and_other_special_members(mode):
    member = zipfile.ZipInfo("contract.json")
    member.create_system = 3
    member.external_attr = (mode | 0o600) << 16
    with pytest.raises(ValueError, match="regular file"):
        runtime._contract_bytes(make_zip([(member, b"{}")]))


def test_zip_rejects_encrypted_member():
    raw = bytearray(make_zip([("contract.json", b"{}")]))
    struct.pack_into("<H", raw, 6, 1)
    central = raw.index(b"PK\x01\x02")
    struct.pack_into("<H", raw, central + 8, 1)
    with pytest.raises(ValueError, match="Encrypted"):
        runtime._contract_bytes(bytes(raw))


def test_zip_rejects_nul_alias():
    raw = make_zip([("contract.jsonX", b"{}")]).replace(
        b"contract.jsonX", b"contract.json\x00"
    )
    with pytest.raises(ValueError, match="member must be contract.json"):
        runtime._contract_bytes(raw)


def test_zip_compressed_and_expanded_bounds():
    with pytest.raises(ValueError, match="ZIP exceeds bound"):
        runtime._contract_bytes(b"x" * (runtime.MAX_ZIP_BYTES + 1))
    raw = make_zip([("contract.json", b"x" * (runtime.MAX_CONTRACT_BYTES + 1))])
    with pytest.raises(ValueError, match="Contract exceeds bound"):
        runtime._contract_bytes(raw)


def test_zip_rejects_corruption_and_truncation():
    raw = make_zip([("contract.json", b"{}")])
    with pytest.raises(zipfile.BadZipFile):
        runtime._contract_bytes(raw[:10])


@pytest.fixture
def transport(monkeypatch):
    """Model stdout readiness and a process lifecycle without invoking any tool."""
    state = SimpleNamespace(
        chunks=iter([b"zip", b""]),
        ready=iter([[], [1], [1]]),
        times=iter([0, 1, 2, 3]),
        running=True,
        killed=False,
        closed=False,
        code=0,
        reads=[],
        commands=[],
    )

    def close():
        state.closed = True

    def wait(timeout):
        assert timeout == 10
        state.running = False
        return state.code

    def kill():
        state.killed = True
        state.running = False

    process = SimpleNamespace(
        stdout=SimpleNamespace(fileno=lambda: 77, close=close),
        wait=wait,
        poll=lambda: None if state.running else state.code,
        kill=kill,
    )

    def popen(args, **kwargs):
        state.commands.append((args, kwargs))
        return process

    def read(fd, limit):
        assert fd == 77
        state.reads.append(limit)
        return next(state.chunks)

    selector = SimpleNamespace(
        register=lambda *args: None, select=lambda **kwargs: next(state.ready)
    )
    monkeypatch.setattr(runtime.subprocess, "Popen", popen)
    monkeypatch.setattr(
        runtime.selectors, "DefaultSelector", lambda: nullcontext(selector)
    )
    monkeypatch.setattr(runtime.time, "monotonic", lambda: next(state.times))
    monkeypatch.setattr(runtime.os, "read", read)
    state.process = process
    return state


def test_downloader_bounds_stream_and_closes_successful_process(transport):
    assert runtime._download_zip("123") == b"zip"
    assert transport.closed and not transport.killed
    assert transport.reads == [65536, 65536]
    assert transport.commands == [
        (
            ["gh", "api", f"{ARTIFACT_ENDPOINT}/zip"],
            {"stdout": subprocess.PIPE, "stderr": subprocess.DEVNULL},
        )
    ]


@pytest.mark.parametrize("failure", ["missing", "timeout", "oversize", "exit"])
def test_download_failure_cleans_up_without_unbounded_read(
    transport, monkeypatch, failure
):
    if failure == "missing":
        transport.process.stdout = None
    elif failure == "timeout":
        transport.times = iter([0, 121])
    elif failure == "oversize":
        monkeypatch.setattr(runtime, "MAX_ZIP_BYTES", 8)
        transport.chunks = iter([b"x" * 9])
    else:
        transport.code = 1
    with pytest.raises(ValueError):
        runtime._download_zip("123")
    assert transport.killed == (failure != "exit")
    assert transport.closed == (failure != "missing")
    if failure == "oversize":
        assert transport.reads == [9]


def test_isolated_process_ignores_hostile_cwd_and_pythonpath(
    artifact, github, tmp_path
):
    """A vulnerable startup executes the hook; the actual isolated CLI does not."""
    root = f"repos/{runtime.REPOSITORY}"
    backend = {
        **github.overrides,
        f"{root}/actions/runs/12": github.evidence["run"],
        f"{root}/issues/comments/9": github.evidence["comment"],
        f"{root}/pulls/78": github.evidence["pr"],
        f"{root}/collaborators/dmytrocraft/permission": {"permission": "write"},
        f"{root}/compare/{'b' * 40}...{'a' * 40}": {
            "files": github.evidence["changed_file_records"]
        },
        "users/Kravalg": {"id": 44},
        "request": github.artifact,
    }
    for name in required_environments(artifact.contract):
        backend[f"{root}/environments/{name}"] = github.protected
        backend[f"{root}/environments/{name}/deployment-branch-policies"] = (
            github.policies
        )
    backend_path = tmp_path / "backend.json"
    backend_path.write_text(json.dumps(backend))
    zip_path = tmp_path / "archive.zip"
    zip_path.write_bytes(artifact.raw)
    binary = tmp_path / "bin"
    binary.mkdir()
    gh = binary / "gh"
    gh.write_text(
        f"#!{sys.executable} -I\n"
        "import json, pathlib, sys\n"
        f"data = json.loads(pathlib.Path({str(backend_path)!r}).read_text())\n"
        "args = sys.argv[1:]\n"
        "if args[:2] == ['run', 'download']:\n"
        "    destination = pathlib.Path(args[args.index('--dir') + 1])\n"
        "    (destination / 'request.json').write_text(json.dumps(data['request']))\n"
        "elif args[0] == 'api' and args[1].endswith('/zip'):\n"
        f"    sys.stdout.buffer.write(pathlib.Path({str(zip_path)!r}).read_bytes())\n"
        "else:\n"
        "    print(json.dumps(data[args[1]]))\n"
    )
    gh.chmod(0o700)
    hostile = tmp_path / "hostile"
    hostile.mkdir()
    marker = tmp_path / "injected"
    for name in ("json.py", "re.py", "sitecustomize.py", "deployment_controller.py"):
        (hostile / name).write_text(
            f"open({str(marker)!r}, 'w').write('injected')\n"
            "raise RuntimeError('hostile import')\n"
        )
    environment = {
        **os.environ,
        "PYTHONPATH": str(hostile),
        "PATH": f"{binary}:{os.environ['PATH']}",
        "GH_TOKEN": "FAKE_SECRET_MUST_NOT_ESCAPE",
    }
    vulnerable = RUN_PROCESS(
        [sys.executable, "-c", "pass"],
        cwd=hostile,
        env=environment,
        capture_output=True,
        text=True,
    )
    assert marker.read_text() == "injected"
    assert "hostile import" in vulnerable.stderr
    marker.unlink()
    result = RUN_PROCESS(
        [
            sys.executable,
            "-I",
            str(Path(runtime.__file__).resolve()),
            *cli_args(artifact),
        ],
        cwd=hostile,
        env=environment,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == 0, result.stderr
    assert not marker.exists()
    assert "head_sha=" + "a" * 40 in artifact.output.read_text()
    assert (
        "FAKE_SECRET_MUST_NOT_ESCAPE"
        not in result.stdout + result.stderr + artifact.output.read_text()
    )
