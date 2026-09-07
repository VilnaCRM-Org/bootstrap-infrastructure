"""Rebuild real aggregate evidence before constructing any publication requests."""

from __future__ import annotations

import hashlib
import json
import sys
from copy import deepcopy
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))

import deployment_promotion_publication as publication  # noqa: E402
from deployment_contract_io import MAX_CONTRACT_BYTES  # noqa: E402
from test_deployment_promotion_proof import (  # noqa: E402
    PLATFORM_ONLY,
    prove,
    publish_jobs,
    timestamp,
)
from test_deployment_promotion_proof import github as _github_fixture  # noqa: E402
from test_deployment_promotion_proof import graph as _graph_fixture  # noqa: E402
from test_deployment_promotion_proof import (  # noqa: E402
    promotion as _promotion_fixture,
)
from test_deployment_promotion_proof import (  # noqa: E402
    receipt_data as _receipt_fixture,
)

github = _github_fixture
receipt_data = _receipt_fixture
graph = _graph_fixture
promotion = _promotion_fixture


@pytest.fixture
def prepared(promotion):
    proof = prove(promotion)
    payload = publication._canonical(proof) + b"\n"
    promotion.prepared = proof
    promotion.publication_args = {
        **promotion.args,
        "needs_payload": json.dumps(promotion.dependencies),
        "proof_payload": payload,
        "proof_file_sha256": hashlib.sha256(payload).hexdigest(),
    }
    promotion.state.github.calls.clear()
    promotion.downloads.clear()
    return promotion


def revalidate(prepared):
    return publication.revalidate_publication(**prepared.publication_args)


def rewrite(prepared, path, value):
    proof = deepcopy(prepared.prepared)
    target = proof
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    payload = publication._canonical(proof) + b"\n"
    prepared.publication_args.update(
        proof_payload=payload, proof_file_sha256=hashlib.sha256(payload).hexdigest()
    )


@pytest.mark.parametrize("receipt_data", [PLATFORM_ONLY], indirect=True)
class TestRevalidation:
    @pytest.mark.parametrize("text", [False, True])
    def test_real_proof_becomes_requests_only(self, prepared, capsys, text):
        if text:
            prepared.publication_args["proof_payload"] = prepared.publication_args[
                "proof_payload"
            ].decode()
        requests = revalidate(prepared)
        identity = prepared.prepared["identity"]
        digest = hashlib.sha256(publication._canonical(prepared.prepared)).hexdigest()
        assert requests["proof_digest"] == digest
        assert requests["proof_file_sha256"] != digest
        assert requests["protocol"] == "central-v2"
        assert requests["head_sha"] == identity["head_sha"]
        assert [node["environment"] for node in requests["deployments"]] == [
            "test",
            "prod",
        ]
        status = requests["commit_status"]
        assert (
            status["path"]
            == f"repos/{identity['repository']}/statuses/{identity['head_sha']}"
        )
        assert status["payload"]["context"] == "Infrastructure Promotion"
        assert (
            status["payload"]["description"]
            == f"central-v2 PR{identity['pull_request_number']}: {digest}"
        )
        assert len(status["payload"]["description"]) <= 140
        assert (
            status["payload"]["target_url"]
            == f"https://github.com/{identity['repository']}/actions/runs/100"
        )
        for node in requests["deployments"]:
            create = node["create_payload"]
            assert node["create_path"] == f"repos/{identity['repository']}/deployments"
            assert create["ref"] == identity["head_sha"]
            assert create["environment"] == node["environment"]
            assert create["production_environment"] is (node["environment"] == "prod")
            assert create["auto_merge"] is False and create["required_contexts"] == []
            evidence = create["payload"]
            assert evidence["identity"] == identity
            assert evidence["scopes"] == ["platform"]
            assert evidence["proof_digest"] == digest
            assert evidence["evidence_kind"] == "receipt-and-job-provenance"
            assert set(evidence["barriers"]) == {"test", "prod"}
            assert set(evidence["receipts"]) == {"platform_test", "platform_prod"}
            assert all(
                set(ref) == set(publication.RECEIPT_REFERENCES)
                for ref in evidence["receipts"].values()
            )
            assert node["success_payload"]["auto_inactive"] is False
            assert node["success_payload"]["state"] == "success"
            assert "success_path" not in node  # Requires a verified API response ID.
        assert prepared.downloads == ["999", "123", "123", "124"]
        assert prepared.state.github.calls
        assert all("--method" not in args for _, args in prepared.state.github.calls)
        assert not prepared.proof_path.exists() and not prepared.output_path.exists()
        assert not capsys.readouterr().out
        assert "Governance Promotion" not in json.dumps(requests)
        assert "saved_plan" not in json.dumps(requests)

    @pytest.mark.parametrize(
        "path,value",
        [
            (("schema_version",), 1),
            (("protocol",), "service"),
            (("completion_kind",), "plan"),
            (("evidence_kind",), "saved-plan-provenance"),
            (("scopes",), []),
            (("scopes",), ["operator", "governance", "platform"]),
            (("identity", "head_sha"), "f" * 40),
            (("identity", "base_sha"), "f" * 40),
            (("identity", "repository"), "foreign/repository"),
            (("identity", "repository_id"), 1),
            (("identity", "owner_id"), 1),
            (("identity", "command"), "plan"),
            (("identity", "target_environment"), "test"),
            (("identity", "pull_request_number"), "999"),
            (("identity", "source_run_id"), "999"),
            (("identity", "comment_id"), "999"),
            (("identity", "controller", "run_id"), "101"),
            (("identity", "controller", "run_attempt"), True),
            (("identity", "controller", "sha"), "f" * 40),
            (("selection_digest",), "f" * 64),
            (("contract_digest",), "f" * 64),
            (("admission", "artifact_id"), "1"),
            (("barriers", "test", "barrier", "environment"), "prod"),
            (("barriers", "prod", "artifact", "artifact_id"), "201"),
            (("workers", "platform_prod", "result"), "skipped"),
            (("jobs", "whole_test", "completed_at"), timestamp(5)),
            (("unexpected",), "extra"),
        ],
    )
    def test_rehashed_proof_cannot_change_evidence(self, prepared, path, value):
        rewrite(prepared, path, value)
        with pytest.raises(ValueError, match="differs from current evidence"):
            revalidate(prepared)
        assert not prepared.proof_path.exists() and not prepared.output_path.exists()

    @pytest.mark.parametrize("change", ["head", "base", "closed", "edited", "writer"])
    def test_current_facts_rechecked(self, prepared, change):
        facts = prepared.state.github.evidence
        if change in ("head", "base"):
            facts["pr"][change]["sha"] = "f" * 40
            if change == "base":
                repo = prepared.prepared["identity"]["repository"]
                endpoint = f"repos/{repo}/compare/{'f' * 40}...{'a' * 40}"
                prepared.state.github.overrides[endpoint] = {
                    "files": facts["changed_file_records"]
                }
        elif change == "closed":
            facts["pr"]["state"] = "closed"
        elif change == "edited":
            facts["comment"]["body"] = "/pulumi prod plan"
        else:
            facts["permission"] = "read"
        with pytest.raises(ValueError):
            revalidate(prepared)

    @pytest.mark.parametrize(
        "name,value",
        [
            ("GITHUB_RUN_ID", "101"),
            ("GITHUB_RUN_ATTEMPT", "2"),
            ("GITHUB_SHA", "f" * 40),
            ("GITHUB_REPOSITORY_ID", "1"),
            ("GITHUB_REPOSITORY_OWNER_ID", "1"),
            ("GITHUB_WORKFLOW_REF", "foreign/repository/workflow.yml@refs/heads/main"),
            ("DEPLOYMENT_COORDINATOR_MODE", "inactive"),
        ],
    )
    def test_root_replay_rejected(self, prepared, monkeypatch, name, value):
        monkeypatch.setenv(name, value)
        if name == "GITHUB_RUN_ID":
            repo = prepared.prepared["identity"]["repository"]
            endpoint = f"repos/{repo}/actions/runs/100"
            prepared.state.github.overrides[endpoint[:-3] + value] = {
                **prepared.state.github.overrides[endpoint],
                "id": int(value),
            }
        with pytest.raises(ValueError):
            revalidate(prepared)

    @pytest.mark.parametrize(
        "name", ["whole_test", "whole_prod", "platform_prod / Platform IAM validation"]
    )
    def test_failed_job_revokes_snapshot(self, prepared, name):
        row = next(row for row in prepared.state.jobs if row["name"] == name)
        row["conclusion"] = "failure"
        publish_jobs(prepared.state)
        with pytest.raises(ValueError):
            revalidate(prepared)

    def test_changed_valid_graph_still_rejected(self, prepared):
        row = next(row for row in prepared.state.jobs if row["name"] == "whole_prod")
        row["completed_at"] = timestamp(7)
        publish_jobs(prepared.state)
        with pytest.raises(ValueError, match="differs from current evidence"):
            revalidate(prepared)

    @pytest.mark.parametrize("identifier", ["123", "124", "201", "202"])
    def test_original_artifacts_are_downloaded_again(self, prepared, identifier):
        prepared.archives[identifier] += b"tampered"
        with pytest.raises(ValueError):
            revalidate(prepared)

    @pytest.mark.parametrize(
        "field", ["artifact_id", "artifact_sha256", "contract_sha256"]
    )
    def test_trusted_inputs_are_not_taken_from_proof(self, prepared, field):
        prepared.publication_args[field] = "0" if field == "artifact_id" else "f" * 64
        with pytest.raises(ValueError):
            revalidate(prepared)

    def test_no_cache_survives_later_revocation(self, prepared):
        first = revalidate(prepared)
        assert first["commit_status"]["payload"]["state"] == "success"
        prepared.state.github.evidence["permission"] = "read"
        with pytest.raises(ValueError):
            revalidate(prepared)

    def test_payloads_do_not_alias(self, prepared):
        requests = revalidate(prepared)
        requests["deployments"][0]["create_payload"]["payload"]["scopes"].clear()
        assert requests["deployments"][1]["create_payload"]["payload"]["scopes"] == [
            "platform"
        ]
        assert prepared.prepared["scopes"] == ["platform"]


@pytest.mark.parametrize(
    "receipt_data",
    [
        ("governance", "test", "up", ("governance",)),
        ("platform", "test", "up", ("governance", "platform")),
    ],
    indirect=True,
)
def test_all_selected_scopes_stay_in_both_accounts(prepared):
    requests = revalidate(prepared)
    scopes = list(prepared.state.contract.selection.stacks)
    for node in requests["deployments"]:
        evidence = node["create_payload"]["payload"]
        assert evidence["scopes"] == scopes
        assert set(evidence["receipts"]) == {
            f"{scope}_{account}" for scope in scopes for account in ("test", "prod")
        }


@pytest.mark.parametrize("digest", [None, True, "", "a" * 63, "A" * 64])
def test_bad_digest_before_collection(monkeypatch, digest):
    monkeypatch.setattr(
        publication,
        "build_promotion_proof",
        lambda **kwargs: pytest.fail("must not collect"),
    )
    with pytest.raises(ValueError, match="Invalid prepared proof SHA256"):
        publication.revalidate_publication(
            proof_payload=b"{}\n",
            proof_file_sha256=digest,
            artifact_id="1",
            artifact_sha256="a" * 64,
            contract_sha256="b" * 64,
            needs_payload="{}",
        )


@pytest.mark.parametrize(
    "payload",
    [
        b"[]\n",
        b"null\n",
        b"invalid",
        b'{"x":1,"x":1}\n',
        b'{"x":NaN}\n',
        b"x" * (MAX_CONTRACT_BYTES + 1),
        b"\xff",
        None,
    ],
)
def test_invalid_document_before_collection(monkeypatch, payload):
    monkeypatch.setattr(
        publication,
        "build_promotion_proof",
        lambda **kwargs: pytest.fail("must not collect"),
    )
    with pytest.raises(ValueError):
        publication.revalidate_publication(
            proof_payload=payload,
            proof_file_sha256="a" * 64,
            artifact_id="1",
            artifact_sha256="a" * 64,
            contract_sha256="b" * 64,
            needs_payload="{}",
        )


@pytest.mark.parametrize("payload", [b"{}", b" {}\n", b"{}\n\n"])
def test_noncanonical_proof_rejected(payload):
    with pytest.raises(ValueError, match="not canonical"):
        publication._prepared_proof(payload, hashlib.sha256(payload).hexdigest())


def test_file_digest_is_not_semantic_digest():
    with pytest.raises(ValueError, match="file SHA256 differs"):
        publication._prepared_proof(b"{}\n", hashlib.sha256(b"{}").hexdigest())
