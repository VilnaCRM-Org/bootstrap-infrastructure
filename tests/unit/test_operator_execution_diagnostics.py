"""Fixed failure attribution with hostile private output; all execution is offline."""

import json
import os
import signal
import subprocess
import sys

import operator_execution_runtime as runtime
import operator_execution_transport as transport
import pytest
from test_operator_execution_runtime import scenario  # noqa: F401
from test_seed_policy_registry import key_for

CANARY = "PRIVATE_CANARY::error title=forged::private-state-or-token"


@pytest.mark.parametrize(
    "program,category,exit_code,timeout,limit",
    [
        (
            "import sys; print(%r); sys.stderr.write(%r); sys.exit(23)"
            % (CANARY, CANARY),
            "process-exit",
            23,
            5,
            transport.MAX_BYTES,
        ),
        (
            "import os,signal; os.kill(os.getpid(), signal.SIGTERM)",
            "process-exit",
            -signal.SIGTERM,
            5,
            transport.MAX_BYTES,
        ),
        (
            "import time; time.sleep(10)",
            "process-timeout",
            None,
            0.03,
            transport.MAX_BYTES,
        ),
        ("print(%r * 1000)" % CANARY, "stdout-bound", None, 5, 10),
        (
            "import sys; sys.stderr.write(%r * 100000)" % CANARY,
            "stderr-bound",
            None,
            5,
            transport.MAX_BYTES,
        ),
    ],
)
def test_real_process_failures_never_publish_private_streams(
    tmp_path, monkeypatch, capsys, program, category, exit_code, timeout, limit
):
    monkeypatch.setattr(transport, "MAX_BYTES", limit)
    with pytest.raises(transport.ProcessFailure) as caught:
        transport.run(
            [sys.executable, "-I", "-c", program],
            env={"PATH": os.defpath},
            cwd=tmp_path,
            timeout=timeout,
        )
    assert caught.value.category == category
    assert caught.value.exit_code == exit_code
    assert str(caught.value) == "private-process-failed"
    assert capsys.readouterr() == ("", "")
    assert not list(tmp_path.iterdir())


def test_spawn_failure_is_distinct_and_redacted(tmp_path, capsys):
    with pytest.raises(transport.ProcessFailure) as caught:
        transport.run([str(tmp_path / CANARY)], env={}, cwd=tmp_path)
    assert caught.value.category == "spawn-failed"
    assert caught.value.exit_code is None
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize(
    "error,category",
    [
        (RuntimeError(CANARY), "unknown"),
        (
            subprocess.TimeoutExpired(CANARY, 1, output=CANARY, stderr=CANARY),
            "process-timeout",
        ),
    ],
)
def test_unexpected_dispatch_and_wait_exceptions_are_redacted(
    monkeypatch, tmp_path, error, category
):
    def reject(*_args, **_kwargs):
        raise error

    monkeypatch.setattr(transport.subprocess, "Popen", reject)
    with pytest.raises(transport.ProcessFailure) as caught:
        transport.run(["/trusted/program"], env={}, cwd=tmp_path)
    assert caught.value.category == category
    assert CANARY not in str(caught.value)


def test_cleanup_failure_still_fails_after_successful_child(monkeypatch, tmp_path):
    class Process:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def poll(self):
            return 0

    def reject():
        raise ValueError(CANARY)

    monkeypatch.setattr(transport.subprocess, "Popen", lambda *a, **kw: Process())
    monkeypatch.setattr(transport, "_streams", lambda *_: b"success")
    monkeypatch.setattr(transport, "_stop_children", reject)
    with pytest.raises(transport.ProcessFailure) as caught:
        transport.run(["/trusted/program"], env={}, cwd=tmp_path, child=True)
    assert caught.value.category == "child-cleanup-failed"


@pytest.mark.parametrize(
    "value,expected",
    [
        (-127, -127),
        (-15, -15),
        (1, 1),
        (255, 255),
        (-128, None),
        (256, None),
        (0, None),
        (True, None),
        (None, None),
        (CANARY, None),
        (1.0, None),
    ],
)
def test_exit_fields_reject_coercion_and_unbounded_values(value, expected):
    assert transport.safe_exit_code(value) == expected


class Hostile:
    def __str__(self):
        pytest.fail("Private object was stringified")


@pytest.mark.parametrize(
    "error,category,exit_code",
    [
        (ValueError("preview-error"), "validation-rejected", None),
        (ValueError(CANARY), "validation-rejected", None),
        (ValueError(Hostile()), "validation-rejected", None),
        (RuntimeError("preview-error"), "unknown", None),
        (transport.ProcessFailure("process-exit", 13), "process-exit", 13),
        (transport.ProcessFailure(CANARY, CANARY), "unknown", None),
    ],
)
def test_public_record_ignores_all_exception_text(error, category, exit_code):
    assert runtime._failure_record(error, "plan-validation") == {
        "stage": "plan-validation",
        "category": category,
        "exit_code": exit_code,
    }
    assert CANARY not in json.dumps(runtime._failure_record(error, "plan-validation"))


def test_public_record_revalidates_fields_and_unknown_exceptions():
    failure = transport.ProcessFailure("process-exit", 1)
    failure.category = Hostile()
    failure.exit_code = Hostile()
    expected = {"stage": "unknown", "category": "unknown", "exit_code": None}
    assert runtime._failure_record(failure, Hostile()) == expected
    assert runtime._failure_record(RuntimeError(Hostile()), CANARY) == expected


def _argv(tmp_path, account):
    return [
        "--stage",
        "preview",
        "--account",
        account,
        "--seed-key-arn",
        key_for(account).arn,
        "--artifact-id",
        "1",
        "--artifact-sha256",
        "a" * 64,
        "--contract-sha256",
        "b" * 64,
        "--output",
        str(tmp_path / "outputs"),
    ]


@pytest.mark.parametrize(
    "point,category",
    [
        ("pulumi", "process-exit"),
        ("validator", "validation-rejected"),
        ("unknown-validator", "validation-rejected"),
    ],
)
def test_main_reports_actual_preview_stage_without_output_or_success(
    scenario,  # noqa: F811
    monkeypatch,
    tmp_path,
    capsys,
    point,
    category,  # noqa: F811
):
    def reject(*_args, **_kwargs):
        if point == "pulumi":
            raise transport.ProcessFailure("process-exit", 23)
        raise ValueError("preview-error" if point == "validator" else CANARY)

    if point == "pulumi":
        monkeypatch.setattr(scenario.transport, "pulumi", reject)
    else:
        monkeypatch.setattr(runtime, "validate_operator_plan", reject)
    monkeypatch.setattr(runtime, "OperatorTransport", lambda *_: scenario.transport)
    result = runtime.main(_argv(tmp_path, scenario.args.account))
    assert result == 1
    output = capsys.readouterr()
    assert output.out == ""
    assert json.loads(output.err) == {
        "stage": "pulumi-preview" if point == "pulumi" else "plan-validation",
        "category": category,
        "exit_code": 23 if point == "pulumi" else None,
    }
    assert CANARY not in output.err
    assert not (tmp_path / "outputs").exists()
    assert not (scenario.args.public_dir / "saved-plan.encrypted.json").exists()
    assert "generate-data-key" not in scenario.events
    assert "apply" not in scenario.events
