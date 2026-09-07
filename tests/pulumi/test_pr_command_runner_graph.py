"""Evaluate controller YAML conditions and pure account reduction.

These tests prove graph ordering and fail-closed condition semantics. They do not
authenticate GitHub job/artifact provenance or prove deployed infrastructure.
"""

from __future__ import annotations

import ast
import itertools
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

HERE = Path(__file__).resolve().parent
SOURCE = Path(__file__).resolve().parents[2]
WORKFLOW_PATH = SOURCE / ".github/workflows/pulumi-pr-command-runner.yml"
sys.path.insert(0, str(SOURCE / "scripts"))
sys.path.insert(0, str(SOURCE / "tests/unit"))

from deployment_controller import (  # noqa: E402
    AccountNodeReceipt,
    StageResult,
    reduce_account_barrier,
)
from deployment_promotion_proof import ROOT_JOBS, WORKERS  # noqa: E402
from deployment_receipt_runtime import OUTPUT_FIELDS, _worker_names  # noqa: E402
from test_deployment_controller import build  # noqa: E402

WORKFLOW = yaml.safe_load(WORKFLOW_PATH.read_text())
JOBS = WORKFLOW["jobs"]
SCOPES = ("operator", "governance", "platform")
SUBSETS = [
    tuple(scope for scope, bit in zip(SCOPES, bits) if bit)
    for bits in itertools.product((False, True), repeat=3)
]


def test_publisher_serializes_with_scope_status_writer():
    assert JOBS["publish_promotion"]["concurrency"] == {
        "group": "promotion-status-${{ needs.preflight.outputs.pull_request_number }}",
        "cancel-in-progress": False,
    }
    scope = yaml.safe_load(
        (SOURCE / ".github/workflows/governance-promotion.yml").read_text()
    )
    assert scope["concurrency"] == {
        "group": "promotion-status-${{ github.event.pull_request.number }}",
        "cancel-in-progress": False,
    }


def evaluate_ast(node):
    """Interpret only the literal Boolean subset used in these YAML conditions."""
    if isinstance(node, ast.Expression):
        return evaluate_ast(node.body)
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.BoolOp):
        values = [evaluate_ast(value) for value in node.values]
        return all(values) if isinstance(node.op, ast.And) else any(values)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return not evaluate_ast(node.operand)
    if isinstance(node, ast.Compare) and len(node.ops) == 1:
        equal = evaluate_ast(node.left) == evaluate_ast(node.comparators[0])
        return equal if isinstance(node.ops[0], ast.Eq) else not equal
    raise AssertionError(f"Unsupported workflow condition node: {type(node)}")


def condition(name, states, cancelled=False, github=None):
    expression = JOBS[name]["if"].removeprefix("${{").removesuffix("}}").strip()

    def field(match):
        value = states.get(match[1], {})
        return repr(
            value.get("outputs", {}).get(match[2], "")
            if match[2]
            else value.get("result", "")
        )

    expression = re.sub(
        r"needs\.([a-z_]+)\.(?:outputs\.([a-z0-9_]+)|(result))", field, expression
    )
    context = {
        "repository": "VilnaCRM-Org/bootstrap-infrastructure",
        "ref": "refs/heads/main",
        "event_name": "repository_dispatch",
        **(github or {}),
    }
    expression = re.sub(
        r"github\.([a-z_]+)", lambda match: repr(context[match[1]]), expression
    )
    expression = expression.replace("always()", "True").replace(
        "cancelled()", str(cancelled)
    )
    expression = expression.replace("&&", " and ").replace("||", " or ")
    expression = re.sub(r"!(?!=)", "not ", expression)
    return bool(evaluate_ast(ast.parse(" ".join(expression.split()), mode="eval")))


def initial(selected, target="prod", *, ready="true"):
    return {
        "preflight": {
            "result": "success",
            "outputs": {
                "execution_ready": ready,
                "target_environment": target,
                "has_deployment_scopes": str(bool(selected)).lower(),
                **{
                    scope + "_selected": str(scope in selected).lower()
                    for scope in SCOPES
                },
            },
        },
        "validate_inputs": {"result": "success", "outputs": {}},
    }


def simulate(selected, command, target, faults=None):
    """Run actual YAML guards, then the existing pure reducer on modeled receipts."""
    contract = build(scopes=selected, command=command, target=target)
    states, trace, barriers = initial(selected, target), [], {}
    states["preflight"]["outputs"]["command"] = command
    faults = faults or {}
    for account in ("test", "prod"):
        receipts = {}
        for scope in SCOPES:
            name = f"{scope}_{account}"
            result = "skipped"
            if condition(name, states):
                trace.append(name)
                result = faults.get(name, "success")
            states[name] = {"result": result, "outputs": {}}
            if result == "success":
                receipts[scope] = AccountNodeReceipt(
                    contract.identity,
                    contract.contract_digest,
                    contract.selection_digest,
                    scope,
                    account,
                    tuple(
                        StageResult(step.operation, "success")
                        for step in contract.schedule
                        if step.scope == scope and step.environment == account
                    ),
                )
        name = f"whole_{account}"
        states[name] = {"result": "skipped", "outputs": {}}
        if condition(name, states):
            try:
                barriers[account] = reduce_account_barrier(
                    contract,
                    environment=account,
                    results={
                        scope: states[f"{scope}_{account}"]["result"]
                        for scope in SCOPES
                    },
                    receipts=receipts,
                    test_barrier=barriers.get("test") if account == "prod" else None,
                )
            except ValueError:
                states[name]["result"] = "failure"
            else:
                states[name] = {
                    "result": "success",
                    "outputs": {
                        "completion_kind": barriers[account].completion_kind,
                        "artifact_id": "model-only",
                        "artifact_sha256": "model-only",
                    },
                }
    return trace, states, barriers


@pytest.mark.parametrize("selected", SUBSETS)
@pytest.mark.parametrize("command", ("plan", "up"))
@pytest.mark.parametrize("target", ("test", "prod"))
def test_all_scope_subsets_and_commands_execute_only_requested_order(
    selected, command, target
):
    trace, states, barriers = simulate(selected, command, target)
    accounts = ("test", "prod") if target == "prod" else ("test",)
    assert trace == [f"{scope}_{account}" for account in accounts for scope in selected]
    assert states["whole_test"]["result"] == "success"
    assert states["whole_prod"]["result"] == (
        "success" if target == "prod" else "skipped"
    )
    expected = (
        "no-deployment"
        if not selected
        else "plan"
        if command == "plan"
        else "apply-drift"
    )
    assert all(barrier.completion_kind == expected for barrier in barriers.values())


@pytest.mark.parametrize(
    "failed_node",
    [f"{scope}_{account}" for account in ("test", "prod") for scope in SCOPES],
)
@pytest.mark.parametrize("result", ("failure", "cancelled", "skipped", ""))
def test_every_selected_bad_result_blocks_all_later_workers(failed_node, result):
    trace, states, _ = simulate(SCOPES, "up", "prod", {failed_node: result})
    ordered = [f"{scope}_{account}" for account in ("test", "prod") for scope in SCOPES]
    assert trace == ordered[: ordered.index(failed_node) + 1]
    assert states["whole_" + failed_node.split("_")[1]]["result"] == "failure"
    assert states["whole_prod"]["result"] != "success"


@pytest.mark.parametrize("scope", SCOPES[:2])
@pytest.mark.parametrize("result", ("success", "failure", "cancelled", ""))
def test_unselected_predecessor_must_be_skipped(scope, result):
    states = initial(("platform",))
    states.update({f"{s}_test": {"result": "skipped"} for s in SCOPES})
    states[f"{scope}_test"] = {"result": result}
    assert not condition("platform_test", states)


@pytest.mark.parametrize("ready", ("", "false", "active", True))
def test_missing_or_untrusted_admission_readiness_never_schedules_credentials(ready):
    states = initial(SCOPES, ready=ready)
    assert all(not condition(f"{scope}_test", states) for scope in SCOPES)
    assert not condition("validate_inputs", states)


def test_cancellation_or_failed_noncloud_validation_blocks_credentials():
    states = initial(SCOPES)
    assert not condition("operator_test", states, cancelled=True)
    states["validate_inputs"]["result"] = "failure"
    assert not condition("operator_test", states)


@pytest.mark.parametrize("result", ("failure", "cancelled", "skipped", ""))
def test_no_prod_worker_can_bypass_whole_test_barrier(result):
    states = initial(SCOPES)
    states["whole_test"] = {
        "result": result,
        "outputs": {"artifact_id": "123", "artifact_sha256": "digest"},
    }
    states.update({f"{scope}_prod": {"result": "success"} for scope in SCOPES})
    assert all(not condition(f"{scope}_prod", states) for scope in SCOPES)


def test_successful_test_job_without_artifact_outputs_cannot_open_prod():
    states = initial(SCOPES)
    states["whole_test"] = {"result": "success", "outputs": {}}
    assert not condition("operator_prod", states)


def test_literal_call_contract_permissions_and_locks_are_exact():
    calls = {name: job for name, job in JOBS.items() if "uses" in job}
    assert list(calls) == [
        f"{scope}_{account}" for account in ("test", "prod") for scope in SCOPES
    ]
    for name, job in calls.items():
        scope, account = name.split("_")
        assert job["name"] == name
        assert job["uses"] == f"./.github/workflows/pulumi-{scope}-account.yml"
        assert job["with"] == {
            "account": account,
            "artifact_id": "${{ needs.preflight.outputs.artifact_id }}",
            "artifact_sha256": "${{ needs.preflight.outputs.artifact_sha256 }}",
            "contract_sha256": "${{ needs.preflight.outputs.contract_file_sha256 }}",
        }
        assert job["permissions"]["id-token"] == "write"
        assert "concurrency" not in job and "secrets" not in job
        if account == "prod":
            assert "whole_test" in job["needs"]
    assert all(
        "id-token" not in job["permissions"]
        for name, job in JOBS.items()
        if name not in calls
    )
    assert WORKFLOW["concurrency"]["group"].startswith("pulumi-command-")
    assert all(
        "concurrency" not in job
        for name, job in JOBS.items()
        if name != "publish_promotion"
    )


def test_one_existing_admission_and_no_raw_payload_worker_routes():
    admission = JOBS["preflight"]
    calls = [step for step in admission["steps"] if step.get("id") == "accept"]
    assert len(calls) == 1
    assert 'run_module("deployment_controller_runtime"' in calls[0]["run"]
    assert calls[0]["run"].endswith('"${GITHUB_WORKSPACE}/.trusted/scripts" accept\n')
    assert calls[0]["run"].startswith("python3 -I")
    assert set(calls[0]["env"]) == {
        "GH_TOKEN",
        *[
            "REQUEST_" + name
            for name in (
                "PULL_REQUEST_NUMBER",
                "HEAD_SHA",
                "COMMENT_ID",
                "SOURCE_RUN_ID",
                "COMMAND",
                "TARGET_ENVIRONMENT",
            )
        ],
    }
    assert (
        admission["steps"][-1]["with"]["path"]
        == ".trusted/.artifacts/deployment-selection/contract.json"
    )
    assert (
        admission["steps"][-1]["with"]["name"]
        == "deployment-selection-${{ github.run_id }}-1"
    )
    assert (
        WORKFLOW["env"]["DEPLOYMENT_COORDINATOR_MODE"]
        == "${{ vars.DEPLOYMENT_COORDINATOR_MODE }}"
    )
    assert [
        name
        for name, job in JOBS.items()
        if job["permissions"].get("statuses") == "write"
    ] == ["preflight"]


def test_prod_barrier_receives_all_six_actual_worker_outputs_and_test_barrier():
    assert set(JOBS["whole_prod"]["needs"]) == {
        "preflight",
        "validate_inputs",
        "whole_test",
        *[f"{scope}_{account}" for scope in SCOPES for account in ("test", "prod")],
    }
    for account in ("test", "prod"):
        job = JOBS[f"whole_{account}"]
        step = next(step for step in job["steps"] if step.get("id") == "barrier")
        assert step["env"]["BARRIER_NEEDS"] == "${{ toJSON(needs) }}"
        assert "deployment_account_barrier.py" in step["run"]
        assert f"--environment {account}" in step["run"]


def test_feedback_is_authenticated_and_never_serves_as_promotion():
    assert not condition("comment_result", initial(SCOPES))
    states = initial(SCOPES)
    states["preflight"]["result"] = "failure"
    states["preflight"]["outputs"]["feedback_pull_request_number"] = "78"
    assert condition("comment_result", states)
    feedback = JOBS["comment_result"]["steps"][0]
    assert (
        feedback["env"]["PR_NUMBER"]
        == "${{ needs.preflight.outputs.feedback_pull_request_number }}"
    )
    assert '$graph.publish_promotion.outputs.published == "true"' in feedback["run"]
    text = WORKFLOW_PATH.read_text()
    assert text.count("actions/create-github-app-token@") == 1
    assert JOBS["publish_promotion"]["environment"] == "governance-evidence"
    assert "result=success" not in text
    assert "governance_promotion.py" not in text


@pytest.mark.parametrize("mode", (None, "", "inactive", "unknown"))
def test_actual_isolated_admission_invocation_rejects_uninstalled_mode(tmp_path, mode):
    (tmp_path / ".trusted").symlink_to(SOURCE, target_is_directory=True)
    output = tmp_path / "output"
    environment = {
        "PATH": os.environ["PATH"],
        "GITHUB_WORKSPACE": str(tmp_path),
        "GITHUB_OUTPUT": str(output),
    }
    if mode is not None:
        environment["DEPLOYMENT_COORDINATOR_MODE"] = mode
    step = next(
        step for step in JOBS["preflight"]["steps"] if step.get("id") == "accept"
    )
    process = subprocess.run(
        ["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", step["run"]],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert process.returncode != 0
    assert "Deployment coordinator is not active" in process.stderr
    assert not output.exists()


def test_input_checks_separate_authenticated_prepare_from_pr_execution():
    steps = JOBS["validate_inputs"]["steps"]
    prepare = next(step for step in steps if step.get("id") == "prepare_inputs")
    execute = steps[-1]
    assert steps.index(prepare) == len(steps) - 2
    assert 'deployment_input_validation.py" prepare' in prepare["run"]
    assert prepare["env"]["GH_TOKEN"] == "${{ github.token }}"
    assert 'deployment_input_validation.py" run' in execute["run"]
    assert set(execute["env"]) == {"VALIDATION_PLAN_SHA256"}
    assert (
        execute["env"]["VALIDATION_PLAN_SHA256"]
        == "${{ steps.prepare_inputs.outputs.plan_sha256 }}"
    )
    assert "--output" not in execute["run"]
    assert '--plan-path "${RUNNER_TEMP}/deployment-input-plan.json"' in execute["run"]
    checkout = next(
        step for step in steps if step.get("with", {}).get("path") == "source"
    )
    assert checkout["with"]["fetch-depth"] == 0
    assert checkout["with"]["persist-credentials"] is False
    python = next(
        step
        for step in steps
        if step.get("uses", "").startswith("actions/setup-python@")
    )
    assert python["with"]["python-version"] == "3.11"
    assert not any(
        step.get("uses", "").startswith("astral-sh/setup-uv@") for step in steps
    )
    assert "isolated offline container" in execute["name"]
    assert "id-token" not in JOBS["validate_inputs"]["permissions"]


@pytest.mark.parametrize("selected", SUBSETS)
@pytest.mark.parametrize("command", ("plan", "up"))
@pytest.mark.parametrize("target", ("test", "prod"))
def test_prepare_only_for_nonempty_prod_up(selected, command, target):
    _, states, _ = simulate(selected, command, target)
    assert condition("prepare_promotion", states) is (
        bool(selected) and command == "up" and target == "prod"
    )
    assert not condition("prepare_promotion", states, cancelled=True)


@pytest.mark.parametrize("job", ROOT_JOBS)
@pytest.mark.parametrize("result", ("failure", "cancelled", "skipped", ""))
def test_prepare_rejects_failed_root_job(job, result):
    _, states, _ = simulate(("platform",), "up", "prod")
    states[job]["result"] = result
    assert not condition("prepare_promotion", states)


@pytest.mark.parametrize("account", ("test", "prod"))
@pytest.mark.parametrize("kind", ("", "plan", "no-deployment"))
def test_prepare_requires_apply_drift(account, kind):
    _, states, _ = simulate(("platform",), "up", "prod")
    states[f"whole_{account}"]["outputs"]["completion_kind"] = kind
    assert not condition("prepare_promotion", states)


def test_prepare_uses_real_cli_and_exact_needs():
    job = JOBS["prepare_promotion"]
    assert set(job["needs"]) == {*ROOT_JOBS, *WORKERS}
    assert len(job["needs"]) == len(set(job["needs"]))
    assert job["permissions"] == {
        "contents": "read",
        "actions": "read",
        "issues": "read",
        "pull-requests": "read",
    }
    prepare = next(step for step in job["steps"] if step.get("id") == "prepare")
    assert prepare["env"] == {
        "GH_TOKEN": "${{ github.token }}",
        "CONTRACT_ARTIFACT_ID": "${{ needs.preflight.outputs.artifact_id }}",
        "CONTRACT_ARTIFACT_SHA256": "${{ needs.preflight.outputs.artifact_sha256 }}",
        "CONTRACT_SHA256": "${{ needs.preflight.outputs.contract_file_sha256 }}",
        "PROMOTION_NEEDS": "${{ toJSON(needs) }}",
    }
    assert 'deployment_promotion_proof.py" prepare' in prepare["run"]
    assert prepare["run"].startswith("python3 -I ")
    assert "--proof-path .artifacts/deployment-promotion/proof.json" in prepare["run"]
    upload = job["steps"][-1]
    assert upload["with"] == {
        "name": "deployment-promotion-${{ github.run_id }}-1",
        "path": ".artifacts/deployment-promotion/proof.json",
        "if-no-files-found": "error",
        "retention-days": 7,
    }
    assert job["outputs"]["proof_digest"] == "${{ steps.prepare.outputs.proof_digest }}"
    assert (
        job["outputs"]["proof_file_sha256"]
        == "${{ steps.prepare.outputs.proof_file_sha256 }}"
    )
    assert (
        job["outputs"]["artifact_sha256"]
        == "${{ steps.proof.outputs.artifact-digest }}"
    )
    assert "prepare_promotion" in JOBS["comment_result"]["needs"]


@pytest.mark.parametrize("scope", SCOPES)
def test_current_worker_io_matches_root_calls(scope):
    path = SOURCE / f".github/workflows/pulumi-{scope}-account.yml"
    worker = yaml.safe_load(path.read_text())
    call = worker["on"]["workflow_call"]
    assert set(call["inputs"]) == {
        "account",
        "artifact_id",
        "artifact_sha256",
        "contract_sha256",
    }
    assert all(
        value["type"] == "string" and value["required"]
        for value in call["inputs"].values()
    )
    assert set(call["outputs"]) == OUTPUT_FIELDS
    assert not any(event != "workflow_call" for event in worker["on"])
    assert (
        worker["env"]["DEPLOYMENT_COORDINATOR_MODE"]
        == "${{ vars.DEPLOYMENT_COORDINATOR_MODE }}"
    )


@pytest.mark.parametrize(
    "module,args",
    (
        ("deployment_promotion_proof", ["prepare"]),
        ("deployment_account_barrier", []),
        ("deployment_promotion_emitter", []),
        ("deployment_input_validation", ["prepare"]),
    ),
)
def test_real_cli_argument_contract(module, args):
    process = subprocess.run(
        [
            sys.executable,
            "-I",
            str(SOURCE / "scripts" / (module + ".py")),
            *args,
            "--help",
        ],
        cwd=HERE,
        env={"PATH": os.environ["PATH"]},
        capture_output=True,
        text=True,
        check=False,
    )
    assert process.returncode == 0, process.stderr
    assert all(
        option in process.stdout
        for option in (
            "--artifact-id",
            "--artifact-sha256",
            "--contract-sha256",
            "--output",
        )
    )


def publication_states(selected=SCOPES, command="up", target="prod"):
    _, states, _ = simulate(selected, command, target)
    states["prepare_promotion"] = {
        "result": "success",
        "outputs": {
            "artifact_id": "301",
            "artifact_sha256": "a" * 64,
            "proof_file_sha256": "b" * 64,
        },
    }
    return states


@pytest.mark.parametrize("selected", SUBSETS)
@pytest.mark.parametrize("command", ("up", "plan"))
@pytest.mark.parametrize("target", ("test", "prod"))
def test_publisher_only_nonempty_prod_up(selected, command, target):
    states = publication_states(selected, command, target)
    assert condition("publish_promotion", states) is (
        bool(selected) and command == "up" and target == "prod"
    )
    assert not condition("publish_promotion", states, cancelled=True)


@pytest.mark.parametrize("name", (*ROOT_JOBS, "prepare_promotion"))
@pytest.mark.parametrize("result", ("failure", "cancelled", "skipped", ""))
def test_publisher_blocks_failed_dependency(name, result):
    states = publication_states()
    states[name]["result"] = result
    assert not condition("publish_promotion", states)


@pytest.mark.parametrize(
    "field", ("artifact_id", "artifact_sha256", "proof_file_sha256")
)
def test_publisher_requires_proof_refs(field):
    states = publication_states()
    states["prepare_promotion"]["outputs"].pop(field)
    assert not condition("publish_promotion", states)


@pytest.mark.parametrize(
    "field,value",
    (
        ("repository", "attacker/bootstrap-infrastructure"),
        ("ref", "refs/heads/feature"),
        ("ref", "refs/tags/main"),
        ("event_name", "pull_request"),
    ),
)
def test_publisher_requires_trusted_main(field, value):
    assert not condition(
        "publish_promotion", publication_states(), github={field: value}
    )


def test_publisher_token_boundary_is_closed():
    job = JOBS["publish_promotion"]
    assert job["name"] == "publish_promotion"
    assert job["environment"] == "governance-evidence"
    assert job["permissions"] == {"contents": "read"}
    assert set(job["needs"]) == {*ROOT_JOBS, *WORKERS, "prepare_promotion"}
    assert len(job["needs"]) == 11
    checkout, token, publish = job["steps"]
    assert checkout["with"] == {
        "ref": "${{ github.sha }}",
        "path": ".trusted",
        "persist-credentials": False,
    }
    assert (
        token["uses"]
        == "actions/create-github-app-token@fee1f7d63c2ff003460e3d139729b119787bc349"
    )
    assert token["with"] == {
        "app-id": "${{ vars.GOVERNANCE_PROMOTION_APP_ID }}",
        "private-key": "${{ secrets.GOVERNANCE_PROMOTION_APP_PRIVATE_KEY }}",
        "owner": "VilnaCRM-Org",
        "repositories": "bootstrap-infrastructure",
        "permission-statuses": "write",
        "permission-deployments": "write",
        "permission-actions": "read",
        "permission-contents": "read",
        "permission-pull-requests": "read",
    }
    assert publish["env"]["GH_TOKEN"] == "${{ steps.promotion_app.outputs.token }}"
    assert set(job["outputs"]) == {"published", "head_sha", "proof_digest", "status_id"}
    assert job["outputs"]["published"] == "${{ steps.publish.outputs.published }}"
    for name, other in JOBS.items():
        text = yaml.safe_dump(other)
        if name != "publish_promotion":
            assert "secrets." not in text
            assert "promotion_app.outputs.token" not in text
        assert "token" not in other.get("outputs", {})
        for step in other.get("steps", []):
            assert "${{" not in step.get("run", "")


def test_publisher_artifact_arguments_match():
    publish = JOBS["publish_promotion"]["steps"][-1]
    assert publish["env"] == {
        "GH_TOKEN": "${{ steps.promotion_app.outputs.token }}",
        "CONTRACT_ARTIFACT_ID": "${{ needs.preflight.outputs.artifact_id }}",
        "CONTRACT_ARTIFACT_SHA256": "${{ needs.preflight.outputs.artifact_sha256 }}",
        "CONTRACT_SHA256": "${{ needs.preflight.outputs.contract_file_sha256 }}",
        "PROOF_ARTIFACT_ID": "${{ needs.prepare_promotion.outputs.artifact_id }}",
        "PROOF_ARTIFACT_SHA256": (
            "${{ needs.prepare_promotion.outputs.artifact_sha256 }}"
        ),
        "PROOF_FILE_SHA256": "${{ needs.prepare_promotion.outputs.proof_file_sha256 }}",
        "ALL_PROMOTION_NEEDS": "${{ toJSON(needs) }}",
    }
    assert (
        'python3 -I "${GITHUB_WORKSPACE}/.trusted/scripts/'
        'deployment_promotion_emitter.py"' in publish["run"]
    )
    for option, variable in (
        ("artifact-id", "CONTRACT_ARTIFACT_ID"),
        ("artifact-sha256", "CONTRACT_ARTIFACT_SHA256"),
        ("contract-sha256", "CONTRACT_SHA256"),
        ("proof-artifact-id", "PROOF_ARTIFACT_ID"),
        ("proof-artifact-sha256", "PROOF_ARTIFACT_SHA256"),
        ("proof-file-sha256", "PROOF_FILE_SHA256"),
        ("output", "GITHUB_OUTPUT"),
    ):
        assert f'--{option} "${{{variable}}}"' in publish["run"]


def test_actual_jq_filter_preserves_ten_edges(tmp_path):
    values = {
        name: {"result": "success", "outputs": {"marker": "$(touch forbidden)"}}
        for name in JOBS
    }
    script = JOBS["publish_promotion"]["steps"][-1]["run"].split("python3 -I", 1)[0]
    result = subprocess.run(
        [
            "bash",
            "-e",
            "-o",
            "pipefail",
            "-c",
            script + 'printf "%s" "${PROMOTION_NEEDS}"',
        ],
        cwd=tmp_path,
        env={"PATH": os.environ["PATH"], "ALL_PROMOTION_NEEDS": json.dumps(values)},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        name: values[name] for name in (*ROOT_JOBS, *WORKERS)
    }
    assert not (tmp_path / "forbidden").exists()


@pytest.mark.parametrize(
    "result,published,expected",
    (
        ("success", "true", True),
        ("success", "", False),
        ("failure", "true", False),
        ("skipped", "", False),
    ),
)
def test_comment_uses_verified_publication(tmp_path, result, published, expected):
    fake_gh = tmp_path / "gh"
    fake_gh.write_text("#!/bin/sh\ncat\n")
    fake_gh.chmod(0o755)
    states = publication_states()
    states["publish_promotion"] = {
        "result": result,
        "outputs": {"published": published},
    }
    feedback = JOBS["comment_result"]["steps"][0]
    process = subprocess.run(
        ["bash", "-e", "-o", "pipefail", "-c", feedback["run"]],
        cwd=tmp_path,
        env={
            "PATH": str(tmp_path) + ":" + os.environ["PATH"],
            "PR_NUMBER": "78",
            "DISPLAY_COMMAND": "/pulumi prod up",
            "HEAD_SHA": "a" * 40,
            "RUN_URL": "https://github.com/run",
            "GITHUB_REPOSITORY": "VilnaCRM-Org/bootstrap-infrastructure",
            "GRAPH_RESULTS": json.dumps(states),
        },
        capture_output=True,
        text=True,
        check=False,
    )
    assert process.returncode == 0, process.stderr
    body = json.loads(process.stdout)["body"]
    assert ("Infrastructure Promotion: verified and published." in body) is expected
    assert "publish_promotion" in JOBS["comment_result"]["needs"]


@pytest.mark.parametrize("scope", SCOPES)
def test_current_receipt_job_names_match(scope):
    worker = yaml.safe_load(
        (SOURCE / f".github/workflows/pulumi-{scope}-account.yml").read_text()
    )
    expected = _worker_names(scope, "test")
    assert len(expected) == 7
    assert {
        f"{scope}_test / {job['name']}": name for name, job in worker["jobs"].items()
    } == expected
