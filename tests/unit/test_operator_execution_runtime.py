"""Offline execution sequencing with real plan validation and AES-GCM envelopes."""

import copy
import hashlib
import io
import sys
import zipfile
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))

import operator_execution_runtime as runtime  # noqa: E402
from operator_execution_transport import Snapshot, encode  # noqa: E402
from operator_plan_validation import INLINE, ROLE  # noqa: E402
from test_deployment_controller import build as contract_for  # noqa: E402
from test_operator_plan_envelope import FakeKms, execution  # noqa: E402
from test_operator_plan_validation import change, fixture, validate  # noqa: E402
from test_seed_policy_registry import key_for  # noqa: E402


@pytest.fixture(params=["test", "prod"])
def scenario(tmp_path, monkeypatch, request):
    """Use synthetic full-plan evidence; no fixture claims installed enrollment."""
    environment = request.param
    data = fixture(environment)
    contract = contract_for()
    context = execution(environment)
    snapshot = Snapshot(
        context,
        encode(data["checkpoint"]),
        data["checkpoint"]["deployment"]["secrets_providers"],
    )
    events = []
    kms = FakeKms()

    class Transport:
        """Record concrete operation order while replacing external effects."""

        def tools(self, head):
            assert head == contract.identity.head_sha
            events.append("tools")

        def snapshot(self):
            events.append("snapshot")
            return snapshot

        def pulumi(self, stage, actual, plan=None):
            assert actual == snapshot
            events.append(stage)
            if stage == "apply":
                assert plan == encode(data["plan"])
                return b"", b""
            return encode(data["plan"]), encode(data["preview"])

        def kms(self, action, request):
            events.append(action)
            return (
                kms.generate(request)
                if action == "generate-data-key"
                else kms.decrypt(request)
            )

        def aws(self, service, action, arguments):
            assert (service, action) == ("accessanalyzer", "validate-policy")
            assert arguments["policyType"] in ("IDENTITY_POLICY", "RESOURCE_POLICY")
            events.append("iam")
            return {"findings": []}

    args = SimpleNamespace(
        stage="preview",
        account=environment,
        seed_key_arn=key_for(environment).arn,
        public_dir=tmp_path,
        artifact_id="1",
        artifact_sha256="a" * 64,
        contract_sha256="b" * 64,
        plan_artifact_id="22",
        plan_artifact_sha256="c" * 64,
    )

    def admitted(_):
        events.append("admission")
        return contract

    def enrolled(_, purpose):
        events.append("enrollment-" + purpose)

    monkeypatch.setattr(runtime, "_contract", admitted)
    monkeypatch.setattr(runtime, "enrollment", enrolled)
    return SimpleNamespace(
        args=args,
        data=data,
        contract=contract,
        transport=Transport(),
        events=events,
        snapshot=snapshot,
    )


def test_preview_encrypts_full_evidence_only_after_real_validation(scenario):
    result = runtime.execute(scenario.args, scenario.transport)
    path = scenario.args.public_dir / "saved-plan.encrypted.json"
    encrypted = path.read_bytes()
    assert result == {
        "plan_validated": "true",
        "envelope_sha256": hashlib.sha256(encrypted).hexdigest(),
    }
    assert b"resourcePlans" not in encrypted and b"synthetic-provider" not in encrypted
    assert scenario.events.index("enrollment-preview") < scenario.events.index(
        "preview"
    )
    assert scenario.events[-1] == "generate-data-key"
    assert scenario.events.count("enrollment-preview") == 2
    assert scenario.events.count("iam") >= 3


def test_apply_reauthenticates_and_rechecks_enrollment_and_checkpoint(
    scenario, monkeypatch
):
    runtime.execute(scenario.args, scenario.transport)
    encrypted = (scenario.args.public_dir / "saved-plan.encrypted.json").read_bytes()
    monkeypatch.setattr(runtime, "_encrypted_artifact", lambda *_: encrypted)
    scenario.events.clear()
    scenario.args.stage = "apply"
    assert runtime.execute(scenario.args, scenario.transport) == {}
    position = scenario.events.index("apply")
    assert scenario.events[position - 3 : position] == [
        "admission",
        "enrollment-apply",
        "snapshot",
    ]
    assert scenario.events[-1] == "snapshot"
    assert scenario.events.count("enrollment-apply") == 2


def test_drift_runs_actual_refresh_preview_and_validates_no_changes(scenario):
    scenario.args.stage = "drift"
    assert runtime.execute(scenario.args, scenario.transport) == {}
    assert "drift" in scenario.events
    assert "iam" not in scenario.events
    assert "generate-data-key" not in scenario.events


@pytest.mark.parametrize("failure", ["enrollment", "state", "plan", "iam", "admission"])
def test_preview_never_emits_artifact_after_failed_evidence(
    scenario, monkeypatch, failure
):
    if failure == "enrollment":

        def reject(*_):
            raise ValueError("not-enrolled")

        monkeypatch.setattr(runtime, "enrollment", reject)
    elif failure == "state":
        reads = iter(
            [scenario.snapshot, replace(scenario.snapshot, checkpoint=b"changed")]
        )
        monkeypatch.setattr(scenario.transport, "snapshot", lambda: next(reads))
    elif failure == "plan":
        scenario.data["plan"]["resourcePlans"] = {}
    elif failure == "iam":
        monkeypatch.setattr(
            scenario.transport,
            "aws",
            lambda *_: {"findings": [{"findingType": "ERROR"}]},
        )
    else:
        values = iter([scenario.contract, None])
        monkeypatch.setattr(runtime, "_contract", lambda _: next(values))
    with pytest.raises(ValueError):
        runtime.execute(scenario.args, scenario.transport)
    assert not (scenario.args.public_dir / "saved-plan.encrypted.json").exists()


def test_tampered_ciphertext_never_reaches_apply(scenario, monkeypatch):
    runtime.execute(scenario.args, scenario.transport)
    raw = (scenario.args.public_dir / "saved-plan.encrypted.json").read_bytes()
    monkeypatch.setattr(
        runtime,
        "_encrypted_artifact",
        lambda *_: raw.replace(b'"schema":1', b'"schema":2'),
    )
    scenario.events.clear()
    scenario.args.stage = "apply"
    with pytest.raises(ValueError):
        runtime.execute(scenario.args, scenario.transport)
    assert "apply" not in scenario.events


@pytest.mark.parametrize("environment", ["test", "prod"])
def test_real_seed_key_binding_is_required_and_account_local(environment):
    selected = runtime.selected_registry(environment, key_for(environment).arn)
    assert len(selected.policies) == 55
    for key in ("", "arn:aws:kms:eu-central-1:000000000000:key/placeholder", None):
        with pytest.raises(ValueError):
            runtime.selected_registry(environment, key)


def test_enrollment_uses_actual_collector_and_active_verifier(monkeypatch):
    expected = runtime.selected_registry("test", key_for().arn)
    calls = []
    monkeypatch.setattr(runtime, "AwsCliRead", lambda *args, **kwargs: "transport")
    monkeypatch.setattr(
        runtime,
        "collect_enrollment",
        lambda *args, **kwargs: calls.append(kwargs) or "observation",
    )
    monkeypatch.setattr(
        runtime.registry,
        "verify_active_enrollment",
        lambda actual, observation: (actual, observation),
    )
    assert runtime.enrollment(expected, "apply") == (expected, "observation")
    assert calls == [{"purpose": "apply", "call": "transport"}]


def test_exact_zip_artifact_origin_and_digest(scenario, monkeypatch):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("saved-plan.encrypted.json", b"ciphertext-only")
    raw = stream.getvalue()
    digest = hashlib.sha256(raw).hexdigest()
    scenario.args.plan_artifact_sha256 = digest
    identity = scenario.contract.identity
    metadata = {
        "id": 22,
        "name": runtime._artifact_name(scenario.contract, scenario.args.account),
        "expired": False,
        "digest": "sha256:" + digest,
        "size_in_bytes": len(raw),
        "workflow_run": {
            "id": int(identity.controller.run_id),
            "head_sha": identity.controller.sha,
            "repository_id": identity.repository_id,
            "head_repository_id": identity.repository_id,
        },
    }
    monkeypatch.setattr(runtime.preflight, "gh", lambda *_: metadata)
    monkeypatch.setattr(runtime, "run", lambda *_args, **_kwargs: raw)
    monkeypatch.setenv("GH_TOKEN", "synthetic-token")
    assert (
        runtime._encrypted_artifact(scenario.args, scenario.contract)
        == b"ciphertext-only"
    )
    for key, value in [("expired", True), ("digest", "wrong"), ("name", "foreign")]:
        altered = copy.deepcopy(metadata)
        altered[key] = value
        monkeypatch.setattr(
            runtime.preflight, "gh", lambda *_, response=altered: response
        )
        with pytest.raises(ValueError):
            runtime._encrypted_artifact(scenario.args, scenario.contract)


def test_bundle_fields_and_current_destructive_label_fail_closed(monkeypatch):
    with pytest.raises(ValueError):
        runtime._unbundle(encode({"plan": ""}))
    contract = contract_for()
    preview = encode(
        {
            "steps": [
                {
                    "op": "delete",
                    "urn": "urn",
                    "oldState": {"type": "aws:iam/policy:Policy"},
                }
            ]
        }
    )
    monkeypatch.setattr(runtime.preflight, "gh", lambda *_: [])
    with pytest.raises(ValueError, match="destructive-review"):
        runtime._destructive(preview, contract)
    monkeypatch.setattr(
        runtime.preflight, "gh", lambda *_: [{"name": "allow-destructive-infra-change"}]
    )
    runtime._destructive(preview, contract)


def test_main_redacts_all_execution_errors(tmp_path, monkeypatch, capsys):
    def reject(*_):
        raise ValueError("private-state-or-secret-text")

    monkeypatch.setattr(runtime, "selected_registry", reject)
    result = runtime.main(
        [
            "--stage",
            "preview",
            "--account",
            "test",
            "--seed-key-arn",
            "missing",
            "--artifact-id",
            "1",
            "--artifact-sha256",
            "a" * 64,
            "--contract-sha256",
            "b" * 64,
            "--output",
            str(tmp_path / "output"),
        ]
    )
    assert result == 1
    assert "private-state-or-secret-text" not in capsys.readouterr().err
    assert not (tmp_path / "output").exists()


@pytest.mark.parametrize("stage", ["resolve", "preview", "apply", "drift"])
def test_main_dispatches_real_stage_and_only_public_outputs(
    scenario, monkeypatch, tmp_path, stage
):
    output = tmp_path / "outputs"
    calls = []
    monkeypatch.setattr(runtime, "OperatorTransport", lambda *args: calls.append(args))
    monkeypatch.setattr(runtime, "execute", lambda args, port: {"result": args.stage})
    assert (
        runtime.main(
            [
                "--stage",
                stage,
                "--account",
                "test",
                "--seed-key-arn",
                key_for().arn,
                "--artifact-id",
                "1",
                "--artifact-sha256",
                "a" * 64,
                "--contract-sha256",
                "b" * 64,
                "--output",
                str(output),
            ]
        )
        == 0
    )
    actual = output.read_text()
    if stage == "resolve":
        assert not calls
        assert "account_id=891377212104" in actual
        assert (
            "preview_role=arn:aws:iam::891377212104:role/GitHubOperatorPreview-test"
            in actual
        )
    else:
        assert len(calls) == 1
        assert actual == f"result={stage}\n"


def test_contract_uses_existing_authenticated_artifact_loader(monkeypatch):
    calls = []
    monkeypatch.setattr(
        runtime, "load_verified_contract", lambda **kw: calls.append(kw)
    )
    runtime._contract(
        SimpleNamespace(
            artifact_id="1",
            artifact_sha256="a" * 64,
            contract_sha256="b" * 64,
            account="test",
        )
    )
    assert calls == [
        {
            "artifact_id": "1",
            "artifact_sha256": "a" * 64,
            "contract_sha256": "b" * 64,
            "scope": "operator",
            "environment": "test",
        }
    ]


def test_iam_handles_absent_goals_without_inventing_documents(scenario):
    runtime._iam(
        encode({"resourcePlans": {"removed": {}}}),
        scenario.snapshot.checkpoint,
        scenario.transport,
    )
    assert "iam" not in scenario.events


def test_analyzer_uses_validated_replacement_diff_base(scenario, monkeypatch):
    data = scenario.data
    document = '{"Statement":{"Effect":"Deny","Action":"*","Resource":"*"}}'
    replacement = change(
        data,
        INLINE,
        {"policy": document},
        ("delete-replaced", "replace", "create-replacement"),
    )
    goal = data["plan"]["resourcePlans"][replacement["urn"]]["goal"]
    goal["deleteBeforeReplace"] = True
    goal["inputDiff"] = {"adds": replacement["inputs"]}
    for step in data["preview"]["steps"]:
        if step["urn"] == replacement["urn"] and step["op"] in {
            "delete-replaced",
            "replace",
        }:
            step["oldState"]["delete"] = True
    assert validate(data).changed_urns == (replacement["urn"],)
    documents = []
    monkeypatch.setattr(
        runtime, "_analyze", lambda value, key, _: documents.append((value, key))
    )
    runtime._iam(encode(data["plan"]), encode(data["checkpoint"]), scenario.transport)
    assert (document, "policy") in documents
    assert documents.count((document, "policy")) == 1


@pytest.mark.parametrize("stage", ["preview", "apply"])
def test_embedded_policy_finding_blocks(scenario, monkeypatch, stage):
    document = '{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}'
    change(
        scenario.data,
        ROLE,
        {"inlinePolicies": [{"name": "inline", "policy": document}]},
    )
    assert validate(scenario.data).changed_urns
    if stage == "apply":
        runtime.execute(scenario.args, scenario.transport)
        encrypted = (
            scenario.args.public_dir / "saved-plan.encrypted.json"
        ).read_bytes()
        monkeypatch.setattr(runtime, "_encrypted_artifact", lambda *_: encrypted)
        scenario.args.stage = "apply"
    scenario.events.clear()
    analyzed = []

    def aws(service, action, arguments):
        assert (service, action) == ("accessanalyzer", "validate-policy")
        analyzed.append(arguments)
        if arguments["policyDocument"] == document:
            return {"findings": [{"findingType": "SECURITY_WARNING"}]}
        return {"findings": []}

    monkeypatch.setattr(scenario.transport, "aws", aws)
    with pytest.raises(ValueError, match="iam-analysis-failed"):
        runtime.execute(scenario.args, scenario.transport)
    assert {"policyDocument": document, "policyType": "IDENTITY_POLICY"} in analyzed
    assert "apply" not in scenario.events
    assert "generate-data-key" not in scenario.events
    if stage == "preview":
        assert not (scenario.args.public_dir / "saved-plan.encrypted.json").exists()


@pytest.mark.parametrize(
    "result",
    [
        {"findings": [], "nextToken": "more"},
        {"findings": None},
        {"findings": [{"findingType": "SECURITY_WARNING"}]},
    ],
)
def test_native_analyzer_cannot_approve_partial_or_unsafe_result(
    scenario, monkeypatch, result
):
    monkeypatch.setattr(scenario.transport, "aws", lambda *_: result)
    with pytest.raises(ValueError, match="iam-analysis"):
        runtime._analyze("{}", "policy", scenario.transport)


@pytest.mark.parametrize(
    "field,value",
    [
        ("plan_artifact_id", "0"),
        ("plan_artifact_id", "../1"),
        ("plan_artifact_sha256", "A" * 64),
        ("plan_artifact_sha256", None),
    ],
)
def test_artifact_coordinates_reject_before_download(scenario, field, value):
    setattr(scenario.args, field, value)
    with pytest.raises(ValueError, match="plan-artifact"):
        runtime._encrypted_artifact(scenario.args, scenario.contract)


@pytest.mark.parametrize(
    "members",
    [
        [("../saved-plan.encrypted.json", b"cipher")],
        [],
        [("saved-plan.encrypted.json", b"")],
        [("saved-plan.encrypted.json", b"cipher"), ("extra", b"unexpected")],
    ],
)
def test_zip_rejects_noncanonical_members(scenario, monkeypatch, members):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        for name, content in members:
            archive.writestr(name, content)
    raw = stream.getvalue()
    scenario.args.plan_artifact_sha256 = hashlib.sha256(raw).hexdigest()
    monkeypatch.setattr(
        runtime,
        "_artifact_metadata",
        lambda *_: ("exact-endpoint", {"size_in_bytes": len(raw)}),
    )
    monkeypatch.setattr(runtime, "run", lambda *_, **__: raw)
    monkeypatch.setenv("GH_TOKEN", "synthetic-token")
    with pytest.raises(ValueError, match="plan-artifact"):
        runtime._encrypted_artifact(scenario.args, scenario.contract)
