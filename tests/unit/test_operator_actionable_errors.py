"""Public failure advice is finite data, never a sanitizer for private content."""

import json

import operator_execution_runtime as runtime
import operator_execution_transport as transport
import pytest
from test_operator_execution_diagnostics import (
    CANARY,
    Hostile,
    PrivateValueError,
    _argv,
)
from test_operator_execution_runtime import scenario  # noqa: F401


@pytest.mark.parametrize("stage,reason", runtime.VALIDATION_GUIDANCE)
def test_known_validation_reason_requires_exact_expected_stage(stage, reason):
    error = ValueError(reason)
    annotation = runtime._failure_annotation(error, stage)
    assert annotation == (
        "::error title=Operator execution failed::"
        f"Stage: {stage}. Category: validation-rejected. "
        + runtime.VALIDATION_GUIDANCE[(stage, reason)]
    )
    assert runtime.VALIDATION_GUIDANCE[
        (stage, reason)
    ] not in runtime._failure_annotation(error, "tools")
    assert runtime._failure_record(error, stage)["category"] == "validation-rejected"


@pytest.mark.parametrize("category", runtime.PROCESS_GUIDANCE)
def test_process_guidance_does_not_reveal_numeric_exit(category):
    outputs = {
        runtime._failure_annotation(
            transport.ProcessFailure(category, code), "pulumi-preview"
        )
        for code in (-127, -15, 1, 23, 255)
    }
    assert len(outputs) == 1
    assert next(iter(outputs)).endswith(runtime.PROCESS_GUIDANCE[category])


@pytest.mark.parametrize("stage", runtime.STAGE_GUIDANCE)
def test_stage_fallback_has_only_static_advice(stage):
    assert runtime._failure_annotation(ValueError(CANARY), stage).endswith(
        runtime.STAGE_GUIDANCE[stage]
    )


class HostileString(str):
    def __hash__(self):
        pytest.fail("Private string subclass was hashed")

    def __str__(self):
        pytest.fail("Private string subclass was formatted")


@pytest.mark.parametrize(
    "error",
    [
        ValueError(CANARY),
        ValueError("unsupported-goal-option\n::error title=forged::" + CANARY),
        ValueError("\x1b[2J\r%0A%0D%25" + CANARY),
        ValueError("x" * 100000),
        ValueError("界" * 4096),
        ValueError(Hostile()),
        ValueError(HostileString("unsupported-goal-option")),
        ValueError(),
        ValueError("unsupported-goal-option", CANARY),
        PrivateValueError("unsupported-goal-option"),
        RuntimeError("unsupported-goal-option"),
        transport.ProcessFailure(CANARY, CANARY),
    ],
)
def test_hostile_failures_do_not_expand_public_alphabet(error):
    annotation = runtime._failure_annotation(error, "tools")
    assert annotation.endswith(runtime.UNKNOWN_GUIDANCE)
    assert CANARY not in annotation
    assert annotation.count("::") == 2
    assert all(32 <= ord(character) <= 126 for character in annotation)
    assert "%" not in annotation
    assert "forged" not in annotation


@pytest.mark.parametrize("stage", [CANARY, Hostile(), HostileString("plan-validation")])
def test_untrusted_stage_and_mutated_process_fields_fall_back(stage):
    error = transport.ProcessFailure("process-exit", 1)
    error.category = Hostile()
    error.exit_code = Hostile()
    assert runtime._failure_annotation(error, stage) == (
        "::error title=Operator execution failed::Stage: unknown. Category: unknown. "
        + runtime.UNKNOWN_GUIDANCE
    )


def test_all_guidance_is_single_line_fixed_annotation_data():
    messages = (
        list(runtime.VALIDATION_GUIDANCE.values())
        + list(runtime.PROCESS_GUIDANCE.values())
        + list(runtime.STAGE_GUIDANCE.values())
        + [runtime.UNKNOWN_GUIDANCE]
    )
    for message in messages:
        assert 0 < len(message) < 512
        assert all(32 <= ord(character) <= 126 for character in message)
        assert "::" not in message and "%" not in message


def test_main_emits_known_advice_and_failure_without_private_output(
    scenario,  # noqa: F811
    monkeypatch,
    tmp_path,
    capsys,  # noqa: F811
):
    def reject(*_args, **_kwargs):
        raise ValueError("unsupported-goal-option")

    monkeypatch.setattr(runtime, "validate_operator_plan", reject)
    monkeypatch.setattr(runtime, "OperatorTransport", lambda *_: scenario.transport)
    assert runtime.main(_argv(tmp_path, scenario.args.account)) == 1
    public = capsys.readouterr()
    assert public.out == ""
    lines = public.err.splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0]) == {
        "stage": "plan-validation",
        "category": "validation-rejected",
    }
    assert lines[1] == runtime._failure_annotation(
        ValueError("unsupported-goal-option"), "plan-validation"
    )
    assert not (tmp_path / "outputs").exists()
    assert not (tmp_path / "saved-plan.encrypted.json").exists()
    assert "apply" not in scenario.events
