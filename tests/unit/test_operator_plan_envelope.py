"""Real AES-GCM with in-memory fake KMS; no AWS or plaintext artifact writes."""

from __future__ import annotations

import base64
import json
import sys
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))

import operator_plan_envelope as envelope  # noqa: E402
from test_deployment_controller import build, input_facts  # noqa: E402


def execution(environment="test"):
    account, key = envelope.ACCOUNTS[environment]
    bucket = f"pulumi-bootstrap-infrastructure-{environment}-state"
    return envelope.ExecutionBinding(
        environment,
        account,
        "eu-central-1",
        "github-ci-bootstrap",
        "s3://" + bucket,
        key,
        envelope.CheckpointBinding(
            bucket,
            f".pulumi/stacks/github-ci-bootstrap/{environment}.json",
            "version-1",
            '"etag"',
        ),
        envelope.ProviderBinding(
            f"awskms://alias/pulumi-platform-bootstrap-{environment}?region=eu-central-1",
            key,
            "e" * 64,
        ),
    )


class FakeKms:
    """Model data-key wrapping/context binding, with actual AES-GCM in the module."""

    def __init__(self):
        self.key = bytes(range(32))
        self.wrapped = b"fake-wrapped-data-key"
        self.generated = []
        self.decrypted = []

    def generate(self, request):
        self.generated.append(request)
        return {
            "KeyId": request["KeyId"],
            "Plaintext": self.key,
            "CiphertextBlob": self.wrapped,
        }

    def decrypt(self, request):
        self.decrypted.append(request)
        return {"KeyId": request["KeyId"], "Plaintext": self.key}


def seal(kms, plan=b"{}", contract=None, context=None):
    return envelope.seal_plan(
        plan,
        contract=contract or build(("operator",)),
        execution=context or execution(),
        generate_key=kms.generate,
    )


def unseal(kms, raw, contract=None, context=None):
    return envelope.open_plan(
        raw,
        contract=contract or build(("operator",)),
        execution=context or execution(),
        decrypt_key=kms.decrypt,
    )


@pytest.mark.parametrize("environment", ["test", "prod"])
@pytest.mark.parametrize("command", ["plan", "up"])
@pytest.mark.parametrize(
    "plan",
    [
        b"{}",
        b'{"resourcePlans":{}}',
        b'{"update":{"value":1.25},"unchanged":null,"nested":{"x":[true,3]}}',
    ],
)
def test_roundtrip_noop_update_and_distinct_controller_head_base(
    environment, command, plan
):
    kms = FakeKms()
    contract = build(("operator",), command=command, target=environment)
    context = execution(environment)
    raw = seal(kms, plan, contract, context)
    assert unseal(kms, raw, contract, context) == plan
    public = json.loads(raw)
    binding = public["binding"]
    assert binding["controller_sha"] == "c" * 40
    assert binding["head_sha"] == "a" * 40
    assert binding["base_sha"] == "b" * 40
    assert binding["purpose"] == "operator-saved-plan-v1"
    assert binding["workflow_path"] == ".github/workflows/pulumi-pr-command-runner.yml"
    assert binding["contract_digest"] == contract.contract_digest
    assert binding["selection_digest"] == contract.selection_digest
    policy_context = {
        "purpose": "operator-saved-plan-v1",
        "repository": "VilnaCRM-Org/bootstrap-infrastructure",
        "repository_id": "1098568429",
        "repository_owner_id": "114362548",
        "account": context.account_id,
        "project": "github-ci-bootstrap",
        "stack": environment,
        "backend": context.backend,
        "workflow_path": ".github/workflows/pulumi-pr-command-runner.yml",
    }
    assert {key: binding[key] for key in policy_context} == policy_context
    assert {"expires_at", "created_at"}.isdisjoint(binding)
    assert (
        kms.generated[0]["EncryptionContext"] == kms.decrypted[0]["EncryptionContext"]
    )
    assert kms.generated[0]["KeyId"] == context.kms_key_arn
    assert kms.generated[0]["KeySpec"] == "AES_256"
    assert kms.decrypted[0]["CiphertextBlob"] == kms.wrapped
    assert len(base64.b64decode(public["nonce"])) == 12
    assert set(public) == {"schema", "binding", "wrapped_key", "nonce", "ciphertext"}


def test_nonce_randomization_and_private_transport(capsys, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    kms = FakeKms()
    plan = b'{"private-property":"value-not-for-an-artifact"}'
    first, second = seal(kms, plan), seal(kms, plan)
    assert first != second
    assert plan not in first
    assert base64.b64encode(plan) not in first
    assert not list(tmp_path.iterdir())
    assert capsys.readouterr() == ("", "")
    # Crypto is not a one-time apply ledger. Same-context opens remain valid.
    assert unseal(kms, first) == unseal(kms, first) == plan


@pytest.mark.parametrize(
    "field,value",
    [
        ("environment", "staging"),
        ("environment", []),
        ("account_id", "111122223333"),
        ("region", "us-east-1"),
        ("project", "bootstrap-infrastructure"),
        ("backend", "s3://pulumi-bootstrap-infrastructure-test-state/state/test"),
        ("kms_key_arn", envelope.ACCOUNTS["prod"][1]),
        ("checkpoint", None),
        ("provider", None),
    ],
)
def test_bad_execution_coordinates_fail_before_kms(field, value):
    kms = FakeKms()
    with pytest.raises(envelope.EnvelopeError):
        seal(kms, context=replace(execution(), **{field: value}))
    assert not kms.generated


@pytest.mark.parametrize(
    "field,value",
    [
        ("bucket", "wrong"),
        ("key", ".pulumi/stacks/platform/test.json"),
        ("version_id", ""),
        ("version_id", "null"),
        ("version_id", "x\n"),
        ("version_id", "x" * 1025),
        ("etag", ""),
        ("etag", 1),
    ],
)
def test_bad_checkpoint_metadata_fails_before_kms(field, value):
    context = execution()
    context = replace(context, checkpoint=replace(context.checkpoint, **{field: value}))
    with pytest.raises(envelope.EnvelopeError):
        seal(FakeKms(), context=context)


@pytest.mark.parametrize(
    "field,value",
    [
        ("key_arn", envelope.ACCOUNTS["prod"][1]),
        ("state_sha256", ""),
        ("state_sha256", True),
        ("uri", "awskms://alias/key?region=us-east-1"),
        ("uri", "awskms://alias/key?region=eu-central-1#fragment"),
        ("uri", ""),
        ("uri", "awskms://alias/key\n?region=eu-central-1"),
    ],
)
def test_bad_provider_metadata_fails_before_kms(field, value):
    context = execution()
    context = replace(context, provider=replace(context.provider, **{field: value}))
    with pytest.raises(envelope.EnvelopeError):
        seal(FakeKms(), context=context)


def test_invalid_contract_unselected_operator_and_wrong_execution_type_fail():
    with pytest.raises(envelope.EnvelopeError, match="invalid-contract"):
        seal(FakeKms(), contract=replace(build(), contract_digest="0" * 64))
    with pytest.raises(envelope.EnvelopeError, match="operator-not-selected"):
        seal(FakeKms(), contract=build(("platform",)))
    with pytest.raises(envelope.EnvelopeError, match="execution-type"):
        envelope.seal_plan(
            b"{}",
            contract=build(),
            execution=cast(envelope.ExecutionBinding, {}),
            generate_key=FakeKms().generate,
        )


@pytest.mark.parametrize(
    "plan",
    [
        b"",
        b"[]",
        b"null",
        b"{",
        b"\xff",
        b'{"x":1,"x":2}',
        b'{"x":{"nested":1,"nested":2}}',
        b'{"x":NaN}',
        b'{"x":Infinity}',
        b'{"x":1e999}',
        b"[" * 2000 + b"]" * 2000,
    ],
)
def test_invalid_duplicate_or_nonfinite_plan_json_fails_before_kms(plan):
    kms = FakeKms()
    with pytest.raises(envelope.EnvelopeError):
        seal(kms, plan)
    assert not kms.generated


def test_all_transport_size_limits_are_bounded(monkeypatch):
    kms = FakeKms()
    monkeypatch.setattr(envelope, "MAX_PLAN_BYTES", 1)
    with pytest.raises(envelope.EnvelopeError, match="plan-size"):
        seal(kms)
    monkeypatch.setattr(envelope, "MAX_PLAN_BYTES", 100)
    monkeypatch.setattr(envelope, "MAX_CONTEXT_BYTES", 10)
    with pytest.raises(envelope.EnvelopeError, match="binding-size"):
        seal(kms)
    monkeypatch.setattr(envelope, "MAX_CONTEXT_BYTES", 8192)
    monkeypatch.setattr(envelope, "MAX_ENVELOPE_BYTES", 10)
    with pytest.raises(envelope.EnvelopeError, match="envelope-size"):
        seal(kms)
    with pytest.raises(envelope.EnvelopeError, match="envelope-size"):
        unseal(kms, b"x" * 11)


@pytest.mark.parametrize("field", ["wrapped_key", "nonce", "ciphertext"])
def test_authenticated_fields_cannot_be_changed(field):
    kms = FakeKms()
    public = json.loads(seal(kms))
    value = bytearray(base64.b64decode(public[field]))
    value[0] ^= 1
    public[field] = base64.b64encode(value).decode()
    with pytest.raises(envelope.EnvelopeError, match="authentication-failed"):
        unseal(kms, json.dumps(public).encode())


@pytest.mark.parametrize(
    "field",
    [
        "controller_sha",
        "head_sha",
        "base_sha",
        "run_id",
        "run_attempt",
        "comment_id",
        "source_run_id",
        "selection_digest",
        "contract_digest",
        "execution_sha256",
        "account",
        "workflow_path",
        "purpose",
    ],
)
def test_untrusted_binding_changes_are_rejected_before_kms(field):
    kms = FakeKms()
    public = json.loads(seal(kms))
    public["binding"][field] = "different"
    with pytest.raises(envelope.EnvelopeError, match="binding-mismatch"):
        unseal(kms, json.dumps(public).encode())
    assert not kms.decrypted


@pytest.mark.parametrize("part", ["checkpoint", "provider", "account", "run"])
def test_valid_new_context_cannot_replay_existing_ciphertext(part):
    kms = FakeKms()
    raw = seal(kms)
    context, contract = execution(), build(("operator",))
    if part == "checkpoint":
        context = replace(
            context, checkpoint=replace(context.checkpoint, version_id="v2")
        )
    elif part == "provider":
        context = replace(
            context, provider=replace(context.provider, state_sha256="f" * 64)
        )
    elif part == "account":
        context = execution("prod")
    else:
        import deployment_controller as controller

        request, evidence, metadata = input_facts(("operator",))
        contract = controller.build_deployment_contract(
            request,
            evidence,
            controller=replace(metadata, run_id="101"),
            selector_sha256="d" * 64,
            complete=True,
        )
    with pytest.raises(envelope.EnvelopeError, match="binding-mismatch"):
        unseal(kms, raw, contract, context)
    assert not kms.decrypted


@pytest.mark.parametrize(
    "change,error",
    [
        ({"schema": True}, "schema"),
        ({"schema": 2}, "schema"),
        ({"extra": "field"}, "envelope-fields"),
        ({"nonce": None}, "encoded-size"),
        ({"nonce": "!"}, "invalid-base64"),
        ({"nonce": ""}, "decoded-size"),
        ({"nonce": "A" * 17}, "encoded-size"),
        ({"wrapped_key": "Zh=="}, "noncanonical-base64"),
    ],
)
def test_malformed_envelope_fields_fail_before_kms(change, error):
    kms = FakeKms()
    public = json.loads(seal(kms))
    public.update(change)
    with pytest.raises(envelope.EnvelopeError, match=error):
        unseal(kms, json.dumps(public).encode())
    assert not kms.decrypted


@pytest.mark.parametrize("raw", [b"", b"[]", b"{}", b"\xff", b'{"x":1,"x":2}'])
def test_invalid_outer_json_fails(raw):
    with pytest.raises(envelope.EnvelopeError):
        unseal(FakeKms(), raw)


@pytest.mark.parametrize(
    "response,error",
    [
        (None, "kms-response"),
        ({"KeyId": "wrong"}, "foreign-kms-key"),
        ({"Plaintext": b"x"}, "kms-data-key"),
        ({"Plaintext": b"x" * 32, "CiphertextBlob": b""}, "wrapped-key-size"),
        ({"Plaintext": b"x" * 32, "CiphertextBlob": b"x" * 6145}, "wrapped-key-size"),
    ],
)
def test_kms_response_validation(response, error):
    supplied = response
    if isinstance(response, dict):
        supplied = {"KeyId": execution().kms_key_arn, **response}
    with pytest.raises(envelope.EnvelopeError, match=error):
        envelope.seal_plan(
            b"{}",
            contract=build(),
            execution=execution(),
            generate_key=lambda _: supplied,
        )


def test_kms_errors_do_not_expose_callback_details(capsys):
    def fail(_):
        raise RuntimeError("PRIVATE KMS RESPONSE")

    with pytest.raises(envelope.EnvelopeError, match="^kms-failed$"):
        envelope.seal_plan(
            b"{}", contract=build(), execution=execution(), generate_key=fail
        )
    assert capsys.readouterr() == ("", "")


def test_authenticated_non_json_plan_is_still_rejected():
    kms = FakeKms()
    public = json.loads(seal(kms))
    aad = envelope._canonical(
        {
            "binding": public["binding"],
            "wrapped_key_sha256": envelope._digest(kms.wrapped),
        }
    )
    ciphertext = envelope.AESGCM(kms.key).encrypt(
        base64.b64decode(public["nonce"]), b"[]", aad
    )
    public["ciphertext"] = base64.b64encode(ciphertext).decode()
    with pytest.raises(envelope.EnvelopeError, match="plan-object"):
        unseal(kms, json.dumps(public).encode())


def test_recomputed_public_bindings_cannot_rebind_ciphertext():
    kms = FakeKms()
    public = json.loads(seal(kms))
    context = execution()
    context = replace(
        context, checkpoint=replace(context.checkpoint, version_id="different-version")
    )
    public["binding"] = envelope._binding(build(("operator",)), context)
    # Even a fake KMS that ignores encryption context cannot bypass AES-GCM AAD.
    with pytest.raises(envelope.EnvelopeError, match="authentication-failed"):
        unseal(kms, json.dumps(public).encode(), context=context)
