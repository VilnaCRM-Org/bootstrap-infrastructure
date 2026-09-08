"""Native-shaped provider compatibility never relaxes current execution settings."""

import copy
import json
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))

import operator_execution_transport as transport  # noqa: E402
import operator_plan_validation as validation  # noqa: E402
from test_operator_execution_transport import checkpoint as checkpoint  # noqa: E402
from test_operator_execution_transport import installed as installed  # noqa: E402
from test_operator_plan_validation import (  # noqa: E402
    fixture,
    reset_noop,
    resource,
    validate,
)


def legacy_inputs():
    return {
        "__internal": {},
        "region": "eu-central-1",
        "skipCredentialsValidation": "false",
        "skipRegionValidation": "true",
        "version": "7.23.0",
    }


def hardened_inputs(account):
    return {
        "__internal": {},
        "region": "eu-central-1",
        "version": "7.23.0",
        "allowedAccountIds": json.dumps([account]),
        "skipCredentialsValidation": "false",
        "skipRegionValidation": "false",
        "skipRequestingAccountId": "false",
    }


def transition(environment="test"):
    data = fixture(environment)
    provider = resource(data, validation.PROVIDER)
    provider["inputs"] = legacy_inputs()
    reset_noop(data)
    goal = data["plan"]["resourcePlans"][provider["urn"]]
    goal["steps"] = ["update"]
    desired = hardened_inputs(data["catalog"]["account_id"])
    goal["goal"]["inputDiff"] = {
        "adds": {
            key: item for key, item in desired.items() if key not in provider["inputs"]
        },
        "updates": {"skipRegionValidation": "false"},
    }
    return data


@pytest.mark.parametrize("environment", ["test", "prod"])
def test_exact_legacy_to_strict_transition_binds_original_bytes(environment):
    data = transition(environment)
    before = copy.deepcopy(data)

    result = validate(data)

    assert result.changed_urns == (resource(data, validation.PROVIDER)["urn"],)
    assert data == before


def test_strict_provider_supports_empty_internal_metadata_without_changes():
    data = fixture()
    provider = resource(data, validation.PROVIDER)
    provider["inputs"] = hardened_inputs(data["catalog"]["account_id"])
    reset_noop(data)

    assert validate(data).changed_urns == ()


def test_legacy_provider_cannot_remain_desired_execution_configuration():
    data = transition()
    reset_noop(data)

    with pytest.raises(ValueError, match="provider-validation-disabled"):
        validate(data)


@pytest.mark.parametrize(
    "extra",
    [
        {"accessKey": "synthetic"},
        {"endpoints": []},
        {"profile": "synthetic"},
        {"allowedAccountIds": ["933245420672"]},
        {"skipCredentialsValidation": "true"},
        {"__internal": {"endpoint": "synthetic"}},
    ],
)
def test_legacy_provider_requires_exact_observed_shape(extra):
    data = transition()
    resource(data, validation.PROVIDER)["inputs"].update(extra)

    with pytest.raises(ValueError):
        validate(data)


@pytest.mark.parametrize("key", list(legacy_inputs()))
def test_legacy_provider_missing_metadata_is_not_an_alias(key):
    data = transition()
    del resource(data, validation.PROVIDER)["inputs"][key]

    with pytest.raises(ValueError):
        validate(data)


@pytest.mark.parametrize(
    "extra",
    [
        {"region": "us-east-1"},
        {"version": "7.24.0"},
        {"allowedAccountIds": ["933245420672"]},
        {"skipCredentialsValidation": True},
        {"skipRegionValidation": "true"},
        {"skipRequestingAccountId": True},
        {"defaultTags": {"tags": {"Unreviewed": "change"}}},
        {"__internal": {"endpoint": "synthetic"}},
        {"endpoints": []},
    ],
)
def test_hardening_cannot_change_other_provider_inputs(extra):
    data = transition()
    provider = resource(data, validation.PROVIDER)
    goal = data["plan"]["resourcePlans"][provider["urn"]]["goal"]
    for key, item in extra.items():
        bucket = "updates" if key in provider["inputs"] else "adds"
        goal["inputDiff"][bucket][key] = item

    with pytest.raises(ValueError):
        validate(data)


@pytest.mark.parametrize("ops", [("create",), ("delete",), ("replace",), ("same",)])
def test_hardening_never_authorizes_other_lifecycles(ops):
    data = transition()
    old = resource(data, validation.PROVIDER)
    new = copy.deepcopy(old)
    new["inputs"] = hardened_inputs(data["catalog"]["account_id"])

    with pytest.raises(ValueError, match="provider-hardening-identity"):
        validation._provider_hardening(old, new, ops, data["catalog"])


@pytest.mark.parametrize("missing", ["old", "new"])
def test_hardening_requires_existing_and_desired_provider(missing):
    data = transition()
    row = resource(data, validation.PROVIDER)
    with pytest.raises(ValueError, match="provider-hardening-inventory"):
        validation._provider_hardening(
            None if missing == "old" else row,
            None if missing == "new" else row,
            ("update",),
            data["catalog"],
        )


@pytest.mark.parametrize("field", ["id", "urn"])
def test_hardening_preserves_provider_identity(field):
    data = transition()
    old = resource(data, validation.PROVIDER)
    new = copy.deepcopy(old)
    new[field] += "-other"
    new["inputs"] = hardened_inputs(data["catalog"]["account_id"])
    with pytest.raises(ValueError, match="provider-hardening-identity"):
        validation._provider_hardening(old, new, ("update",), data["catalog"])


def test_strict_provider_cannot_use_hardening_as_general_update_path():
    data = transition()
    old = resource(data, validation.PROVIDER)
    old["inputs"] = hardened_inputs(data["catalog"]["account_id"])
    with pytest.raises(ValueError, match="provider-hardening-origin"):
        validation._provider_hardening(old, old, ("update",), data["catalog"])


@pytest.mark.parametrize("flag", validation._PROVIDER_VALIDATION_FLAGS)
@pytest.mark.parametrize("value", [None, 0, "true", True])
def test_strict_provider_flags_are_present_false_booleans_or_strings(flag, value):
    data = fixture()
    inputs = hardened_inputs(data["catalog"]["account_id"])
    inputs.pop("__internal")
    inputs[flag] = value
    with pytest.raises(ValueError, match="provider-validation-disabled"):
        validation._provider_inputs(inputs, data["catalog"])


@pytest.mark.parametrize("environment", ["test", "prod"])
def test_actual_config_pins_are_materialized_without_mutating_pr_settings(environment):
    data = fixture(environment)
    original = {
        "github-ci-bootstrap:setting": "retained",
        "aws:config:region": "eu-central-1",
    }
    before = copy.deepcopy(original)
    result = validation.harden_operator_configuration(
        original, account_id=data["catalog"]["account_id"], region="eu-central-1"
    )
    assert result["aws:allowedAccountIds"] == [data["catalog"]["account_id"]]
    assert result["aws:region"] == "eu-central-1"
    assert all(
        result["aws:" + key] is False for key in validation._PROVIDER_VALIDATION_FLAGS
    )
    assert "aws:config:region" not in result
    assert result["github-ci-bootstrap:setting"] == "retained"
    assert original == before


@pytest.mark.parametrize(
    "settings",
    [
        {"aws:allowedAccountIds": ["933245420672"]},
        {"aws:skipRegionValidation": "true"},
        {"aws:region": "us-east-1"},
        {"aws:__internal": {}},
        {"aws:endpoints": []},
        {"aws:profile": "synthetic"},
        {"aws:region": "eu-central-1", "aws:config:region": "eu-central-1"},
    ],
)
def test_hardening_rejects_conflicting_or_unsafe_requested_settings(settings):
    with pytest.raises(ValueError):
        validation.harden_operator_configuration(
            settings, account_id="891377212104", region="eu-central-1"
        )


@pytest.mark.parametrize("stage", ["preview", "apply", "drift"])
def test_transport_writes_real_pins_before_child_execution(
    installed, checkpoint, monkeypatch, stage
):
    snapshot = installed.snapshot()
    observed = []

    def execute(command, **_kwargs):
        path = Path(command[command.index("--config-file") + 1])
        config = yaml.safe_load(path.read_text())["config"]
        observed.append(config)
        if stage != "apply":
            Path(command[command.index("--save-plan") + 1]).write_bytes(b"{}")
        return b"{}"

    monkeypatch.setattr(transport, "run", execute)
    installed.pulumi(stage, snapshot, b"{}" if stage == "apply" else None)
    assert observed[0]["aws:allowedAccountIds"] == [installed.account]
    assert observed[0]["aws:region"] == "eu-central-1"
    assert all(
        observed[0]["aws:" + key] is False
        for key in validation._PROVIDER_VALIDATION_FLAGS
    )
