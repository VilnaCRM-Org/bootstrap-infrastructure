"""Fixed failure attribution with hostile private output; all execution is offline."""

import base64
import json
import os
import signal
import subprocess
import sys
from pathlib import Path

import operator_execution_runtime as runtime
import operator_execution_transport as transport
import pytest
from test_operator_execution_runtime import scenario  # noqa: F401
from test_operator_plan_envelope import FakeKms
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


class PrivateValueError(ValueError):
    def __str__(self):
        pytest.fail("Custom exception was stringified")


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
        "--public-dir",
        str(tmp_path),
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
    }
    assert CANARY not in output.err
    assert not (tmp_path / "outputs").exists()
    assert not (scenario.args.public_dir / "saved-plan.encrypted.json").exists()
    assert "generate-data-key" not in scenario.events
    assert "apply" not in scenario.events


def test_prefix_capture_continues_draining_without_changing_success(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(transport, "MAX_DIAGNOSTIC_STDOUT_BYTES", 128)
    capture = transport.DiagnosticCapture()
    result = transport.run(
        [
            sys.executable,
            "-I",
            "-c",
            "import sys; print('x'*4096); sys.stderr.write('err')",
        ],
        env={"PATH": os.defpath},
        cwd=tmp_path,
        capture=capture,
    )
    assert len(result) == 4097
    assert capture.stdout == b"x" * 128 and capture.stdout_truncated is True
    assert capture.stderr == b"err" and capture.stderr_truncated is False
    assert "xxx" not in repr(capture)


def test_captured_stderr_total_limit_still_fails_closed(tmp_path):
    capture = transport.DiagnosticCapture()
    with pytest.raises(transport.ProcessFailure) as caught:
        transport.run(
            [sys.executable, "-I", "-c", "import sys; sys.stderr.write('x'*2000000)"],
            env={"PATH": os.defpath},
            cwd=tmp_path,
            capture=capture,
        )
    assert caught.value.category == "stderr-bound"
    assert len(capture.stderr) == transport.MAX_DIAGNOSTIC_STDERR_BYTES
    assert capture.stderr_truncated is True


@pytest.mark.parametrize("stdout,maximum", [(True, 32), (False, 8)])
def test_capture_split_exact_and_over_limit(monkeypatch, stdout, maximum):
    monkeypatch.setattr(transport, "MAX_DIAGNOSTIC_STDOUT_BYTES", 32)
    monkeypatch.setattr(transport, "MAX_DIAGNOSTIC_STDERR_BYTES", 8)
    capture = transport.DiagnosticCapture()
    field = "stdout" if stdout else "stderr"
    other = "stderr" if stdout else "stdout"
    capture.append(stdout, b"x" * maximum)
    capture.append(stdout, b"")
    assert getattr(capture, field) == b"x" * maximum
    assert getattr(capture, field + "_truncated") is False
    capture.append(stdout, b"y")
    capture.append(stdout, b"more")
    assert getattr(capture, field) == b"x" * maximum
    assert getattr(capture, field + "_truncated") is True
    assert getattr(capture, other) == b""
    assert getattr(capture, other + "_truncated") is False


def test_large_real_child_preview_failure_retains_complete_encrypted_stdout(
    scenario,  # noqa: F811
    monkeypatch,
    tmp_path,
    capsys,
):
    expected = json.dumps(
        {"padding": "x" * (1024 * 1024 + 128), "tail": CANARY}
    ).encode()
    original = scenario.transport.pulumi

    def pulumi(*args):
        plan, _ = original(*args)
        capture = transport.DiagnosticCapture()
        scenario.transport.diagnostic_capture = capture
        preview = transport.run(
            [
                sys.executable,
                "-I",
                "-c",
                "import json,sys; "
                "sys.stdout.write(json.dumps({'padding':'x'*(1024*1024+128),"
                f"'tail':{CANARY!r}}})); sys.stderr.write({CANARY!r})",
            ],
            env={"PATH": os.defpath},
            cwd=tmp_path,
            capture=capture,
        )
        assert preview == expected
        assert not list(tmp_path.iterdir())
        return plan, preview

    def reject(*_args, **_kwargs):
        raise ValueError("unsupported-input-change")

    monkeypatch.setattr(scenario.transport, "pulumi", pulumi)
    monkeypatch.setattr(runtime, "validate_operator_plan", reject)
    monkeypatch.setattr(runtime, "OperatorTransport", lambda *_: scenario.transport)
    assert runtime.main(_argv(tmp_path, scenario.args.account)) == 1
    public = capsys.readouterr()
    assert public.out == "" and CANARY not in public.err
    records = [json.loads(line) for line in public.err.splitlines()]
    assert len(records) == 2 and set(records[0]) == {"diagnostic_sha256"}
    assert records[1] == {"stage": "plan-validation", "category": "validation-rejected"}
    destination = tmp_path / "operator-diagnostic.encrypted.json"
    raw = destination.read_bytes()
    assert CANARY.encode() not in raw
    value = runtime.envelope.open_diagnostic(
        raw,
        contract=scenario.contract,
        execution=scenario.snapshot.execution,
        decrypt_key=FakeKms().decrypt,
    )
    assert base64.b64decode(value["stdout"]) == expected
    assert base64.b64decode(value["stderr"]) == CANARY.encode()
    assert value["stdout_truncated"] is False
    assert value["stderr_truncated"] is False
    assert value["validation_reason"] == "unsupported-input-change"
    assert value["exit_code"] is None
    assert set(tmp_path.iterdir()) == {destination}
    assert "apply" not in scenario.events


def _private_capture():
    capture = transport.DiagnosticCapture()
    capture.append(True, CANARY.encode())
    capture.append(False, (CANARY + "\n").encode())
    return capture


def _configure_diagnostic_failure(context, monkeypatch, destination, failure):
    if failure == "kms":

        def deny(*_args, **_kwargs):
            raise RuntimeError(CANARY)

        monkeypatch.setattr(context.transport, "kms", deny)
    if failure == "partial-write":

        def partial(path, _raw):
            path.write_bytes(b"partial ciphertext")
            raise OSError(CANARY)

        monkeypatch.setattr(runtime, "private_write", partial)
    if failure == "stale":
        destination.write_bytes(b"stale ciphertext")


@pytest.mark.parametrize(
    "failure", ["child", "validator", "kms", "partial-write", "stale"]
)
def test_failed_preview_preserves_original_error_and_only_recoverable_ciphertext(
    scenario,  # noqa: F811
    monkeypatch,
    tmp_path,
    capsys,
    failure,  # noqa: F811
):
    original = scenario.transport.pulumi

    def pulumi(*args):
        scenario.transport.diagnostic_capture = _private_capture()
        if failure == "child":
            raise transport.ProcessFailure("process-exit", 9)
        return original(*args)

    monkeypatch.setattr(scenario.transport, "pulumi", pulumi)
    if failure != "child":

        def reject(*_args, **_kwargs):
            raise ValueError(CANARY)

        monkeypatch.setattr(runtime, "validate_operator_plan", reject)
    destination = tmp_path / "operator-diagnostic.encrypted.json"
    _configure_diagnostic_failure(scenario, monkeypatch, destination, failure)
    monkeypatch.setattr(runtime, "OperatorTransport", lambda *_: scenario.transport)
    assert runtime.main(_argv(tmp_path, scenario.args.account)) == 1
    public = capsys.readouterr()
    assert CANARY not in public.err and public.out == ""
    records = [json.loads(line) for line in public.err.splitlines()]
    assert records[-1] == {
        "stage": "pulumi-preview" if failure == "child" else "plan-validation",
        "category": "process-exit" if failure == "child" else "validation-rejected",
    }
    if failure in {"child", "validator"}:
        raw = destination.read_bytes()
        assert CANARY.encode() not in raw
        payload = runtime.envelope.open_diagnostic(
            raw,
            contract=scenario.contract,
            execution=scenario.snapshot.execution,
            decrypt_key=FakeKms().decrypt,
        )
        assert payload["exit_code"] == (9 if failure == "child" else None)
        assert base64.b64decode(payload["stderr"]) == (CANARY + "\n").encode()
        assert payload["validation_reason"] == (
            CANARY if failure == "validator" else ""
        )
        assert len(records) == 2 and set(records[0]) == {"diagnostic_sha256"}
    else:
        assert not destination.exists() and len(records) == 1
    assert not (tmp_path / ".operator-diagnostic.pending").exists()
    assert not (tmp_path / "outputs").exists()
    assert not (tmp_path / "saved-plan.encrypted.json").exists()


def test_preview_input_failure_seals_only_allowlisted_comparison_metadata(
    scenario,  # noqa: F811
    monkeypatch,
    tmp_path,
    capsys,  # noqa: F811
):
    original = scenario.transport.pulumi
    urn = "urn:pulumi:test::github-ci-bootstrap::aws:iam/role:Role::role"

    def pulumi(*args):
        plan, preview = original(*args)
        scenario.transport.diagnostic_capture = _private_capture()
        return plan, preview

    def reject(*_args, mismatch=None, **_kwargs):
        mismatch.append(
            {
                "urn": urn,
                "type": "aws:iam/role:Role",
                "side": "new",
                "operation": "update",
                "fields": ["permissionsBoundary"],
            }
        )
        raise ValueError("preview-inputs")

    monkeypatch.setattr(scenario.transport, "pulumi", pulumi)
    monkeypatch.setattr(runtime, "validate_operator_plan", reject)
    monkeypatch.setattr(runtime, "OperatorTransport", lambda *_: scenario.transport)
    assert runtime.main(_argv(tmp_path, scenario.args.account)) == 1
    public = capsys.readouterr()
    assert public.out == "" and urn not in public.err
    assert json.loads(public.err.splitlines()[-1]) == {
        "stage": "plan-validation",
        "category": "validation-rejected",
    }
    raw = (tmp_path / "operator-diagnostic.encrypted.json").read_bytes()
    payload = runtime.envelope.open_diagnostic(
        raw,
        contract=scenario.contract,
        execution=scenario.snapshot.execution,
        decrypt_key=FakeKms().decrypt,
    )
    reason = json.loads(payload["validation_reason"])
    assert reason == {
        "schema": 1,
        "reason": "preview-inputs",
        "urn": urn,
        "type": "aws:iam/role:Role",
        "side": "new",
        "operation": "update",
        "fields": ["permissionsBoundary"],
    }
    assert set(payload) == runtime.envelope.DIAGNOSTIC_PAYLOAD_FIELDS
    assert "apply" not in scenario.events


def test_preview_mismatch_reason_omits_hostile_or_oversized_identity():
    assert runtime._mismatch_reason(None) == "preview-inputs"
    row = {
        "urn": "urn:pulumi:test::github-ci-bootstrap::aws:iam/role:Role::" + "x" * 1100,
        "type": "aws:iam/role:Role",
        "side": "old",
        "operation": "same",
        "fields": ["description"],
    }
    result = json.loads(runtime._mismatch_reason(row))
    assert result["identity_omitted"] is True
    assert "urn" not in result
    row["fields"] = ["arbitrary-secret-key"]
    assert runtime._mismatch_reason(row) == "preview-inputs"
    row["fields"] = ["description"]
    row["urn"] = "not-an-operator-urn"
    assert runtime._mismatch_reason(row) == "preview-inputs"


@pytest.mark.parametrize(
    "invalid",
    [
        {"urn": None},
        {"type": None},
        {"type": "aws:iam/unknown:Unknown"},
        {"side": "unexpected"},
        {"operation": "unexpected"},
    ],
)
def test_preview_mismatch_reason_rejects_invalid_coordinates(invalid):
    row = {
        "urn": "urn:pulumi:test::github-ci-bootstrap::aws:iam/role:Role::role",
        "type": "aws:iam/role:Role",
        "side": "new",
        "operation": "update",
        "fields": ["permissionsBoundary"],
    }
    row.update(invalid)
    assert runtime._mismatch_reason(row) == "preview-inputs"


@pytest.mark.parametrize(
    "error,expected",
    [
        (ValueError("界" * 10000), "界" * (4096 // 3)),
        (ValueError("\ud800"), "?"),
        (ValueError(Hostile()), ""),
        (PrivateValueError(CANARY), ""),
        (RuntimeError(CANARY), ""),
    ],
)
def test_private_validation_reason_is_bounded_without_custom_stringification(
    scenario,  # noqa: F811
    capsys,
    error,
    expected,  # noqa: F811
):
    scenario.args.diagnostic_binding = (scenario.contract, scenario.snapshot.execution)
    scenario.args.diagnostic_stage = "plan-validation"
    scenario.transport.diagnostic_capture = _private_capture()
    runtime._write_diagnostic(scenario.args, scenario.transport, error)
    raw = (scenario.args.public_dir / "operator-diagnostic.encrypted.json").read_bytes()
    payload = runtime.envelope.open_diagnostic(
        raw,
        contract=scenario.contract,
        execution=scenario.snapshot.execution,
        decrypt_key=FakeKms().decrypt,
    )
    assert payload["validation_reason"] == expected
    assert len(payload["validation_reason"].encode()) <= 4096
    assert CANARY not in capsys.readouterr().err


def test_early_or_nonpreview_failures_do_not_request_diagnostic_keys(scenario):  # noqa: F811
    scenario.transport.diagnostic_capture = _private_capture()
    runtime._write_diagnostic(scenario.args, scenario.transport, ValueError(CANARY))
    scenario.args.diagnostic_binding = (scenario.contract, scenario.snapshot.execution)
    scenario.args.stage = "apply"
    runtime._write_diagnostic(scenario.args, scenario.transport, ValueError(CANARY))
    assert "generate-data-key" not in scenario.events


def test_diagnostic_cleanup_error_does_not_replace_original_failure(
    scenario,  # noqa: F811
    monkeypatch,
    capsys,  # noqa: F811
):
    scenario.args.diagnostic_binding = (scenario.contract, scenario.snapshot.execution)
    scenario.args.diagnostic_stage = "plan-validation"
    scenario.transport.diagnostic_capture = _private_capture()

    def deny(*_args, **_kwargs):
        raise PermissionError(CANARY)

    monkeypatch.setattr(runtime.envelope, "seal_diagnostic", deny)
    monkeypatch.setattr(Path, "unlink", deny)
    runtime._write_diagnostic(scenario.args, scenario.transport, ValueError(CANARY))
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize("exit_code", [-127, -15, 1, 9, 23, 255])
def test_public_category_hides_distinct_process_exit_values(exit_code):
    failure = transport.ProcessFailure("process-exit", exit_code)
    assert runtime._public_record(failure, "pulumi-preview") == {
        "stage": "pulumi-preview",
        "category": "process-exit",
    }
    assert runtime._failure_record(failure, "pulumi-preview")["exit_code"] == exit_code
