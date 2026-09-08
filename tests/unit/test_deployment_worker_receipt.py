"""Receipts distinguish selected successful jobs from missing or skipped work."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from dataclasses import asdict
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))

import deployment_worker_receipt as worker  # noqa: E402
from deployment_controller import _receipt_digest  # noqa: E402
from test_deployment_controller import build  # noqa: E402


def results(command="up"):
    return {
        "plan": "success",
        "destructive": "success",
        "iam": "success",
        "apply": "success" if command == "up" else "skipped",
        "drift": "success" if command == "up" else "skipped",
    }


@pytest.mark.parametrize("command", ["plan", "up"])
@pytest.mark.parametrize("scope", ["operator", "governance", "platform"])
@pytest.mark.parametrize("environment", ["test", "prod"])
def test_receipt_matches_selected_schedule(command, scope, environment, tmp_path):
    contract = build(command=command)
    receipt = worker.build_worker_receipt(
        contract, scope=scope, environment=environment, results=results(command)
    )
    path = tmp_path / "receipt" / "receipt.json"
    outputs = worker.persist_receipt(receipt, path)
    assert json.loads(path.read_bytes()) == json.loads(json.dumps(asdict(receipt)))
    assert outputs["receipt_digest"] == _receipt_digest(
        contract, receipt, scope, environment
    )
    assert (
        outputs["receipt_file_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    )
    assert outputs["receipt_file_sha256"] != outputs["receipt_digest"]
    assert outputs["completion_kind"] == (
        "plan" if command == "plan" else "apply-drift"
    )
    with pytest.raises(FileExistsError):
        worker.persist_receipt(receipt, path)


@pytest.mark.parametrize("name", worker.RESULT_NAMES)
@pytest.mark.parametrize("state", ["failure", "cancelled", "skipped", "", None])
def test_apply_receipt_rejects_every_unsuccessful_gate(name, state):
    reported = results()
    reported[name] = state
    with pytest.raises(ValueError):
        worker.build_worker_receipt(
            build(), scope="platform", environment="test", results=reported
        )


@pytest.mark.parametrize("operation", ["apply", "drift"])
def test_plan_receipt_rejects_unrequested_apply_or_drift(operation):
    reported = results("plan")
    reported[operation] = "success"
    with pytest.raises(ValueError, match="requested command"):
        worker.build_worker_receipt(
            build(command="plan"),
            scope="platform",
            environment="test",
            results=reported,
        )


@pytest.mark.parametrize(
    "scope,environment", [("platform", "prod"), ("unknown", "test")]
)
def test_unselected_node_cannot_produce_receipt(scope, environment):
    with pytest.raises(ValueError, match="unselected"):
        worker.build_worker_receipt(
            build(target="test"),
            scope=scope,
            environment=environment,
            results=results(),
        )


@pytest.mark.parametrize("reported", [{}, {**results(), "extra": "success"}])
def test_results_require_exact_fields(reported):
    with pytest.raises(ValueError, match="Incomplete"):
        worker.build_worker_receipt(
            build(), scope="platform", environment="test", results=reported
        )


def arguments(tmp_path):
    args = [
        "--artifact-id",
        "10",
        "--artifact-sha256",
        "a" * 64,
        "--contract-sha256",
        "b" * 64,
        "--scope",
        "platform",
        "--environment",
        "test",
        "--receipt-path",
        str(tmp_path / "receipt.json"),
        "--output",
        str(tmp_path / "output"),
    ]
    for name, value in results().items():
        args.extend((f"--{name}-result", value))
    return args


def test_cli_authenticates_before_writing_receipt_or_outputs(monkeypatch, tmp_path):
    calls = []

    def load(**kwargs):
        assert not (tmp_path / "receipt.json").exists()
        assert not (tmp_path / "output").exists()
        calls.append(kwargs)
        return build()

    monkeypatch.setattr(worker, "load_verified_contract", load)
    assert worker.main(arguments(tmp_path)) == 0
    assert calls == [
        {
            "artifact_id": "10",
            "artifact_sha256": "a" * 64,
            "contract_sha256": "b" * 64,
            "scope": "platform",
            "environment": "test",
        }
    ]
    assert "completion_kind=apply-drift" in (tmp_path / "output").read_text()


def test_authentication_failure_leaves_no_receipt_or_outputs(monkeypatch, tmp_path):
    def fail(**kwargs):
        raise ValueError("Untrusted artifact")

    monkeypatch.setattr(worker, "load_verified_contract", fail)
    with pytest.raises(ValueError, match="Untrusted"):
        worker.main(arguments(tmp_path))
    assert not (tmp_path / "receipt.json").exists()
    assert not (tmp_path / "output").exists()


def test_cli_rejects_unknown_account_before_loading(monkeypatch, tmp_path):
    args = arguments(tmp_path)
    args[args.index("--environment") + 1] = "staging"
    with pytest.raises(SystemExit):
        worker.main(args)


@pytest.mark.parametrize("module", ["json", "re", "sitecustomize"])
def test_real_isolated_receipt_cli_ignores_hostile_imports(
    module, monkeypatch, tmp_path
):
    marker = tmp_path / "injected"
    (tmp_path / f"{module}.py").write_text(
        f"open({str(marker)!r}, 'w').write('injected')\n"
        "raise RuntimeError('hostile module')\n"
    )
    monkeypatch.setenv("PYTHONPATH", str(tmp_path))
    script = str(Path(worker.__file__).resolve())
    subprocess.run(
        [sys.executable, script, "--help"],
        cwd=tmp_path,
        capture_output=True,
        check=False,
    )
    assert marker.exists(), "Unisolated control must demonstrate injection"
    marker.unlink()
    result = subprocess.run(
        [sys.executable, "-I", script, "--help"],
        cwd=tmp_path,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr.decode()
    assert not marker.exists()
