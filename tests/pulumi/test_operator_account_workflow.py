"""Operator account jobs use trusted tooling, exact OIDC and encrypted replay."""

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / ".github/workflows/pulumi-operator-account.yml"
WORKFLOW = yaml.safe_load(PATH.read_text())
JOBS = WORKFLOW["jobs"]


def test_only_root_artifact_inputs_and_account_are_exposed():
    assert set(WORKFLOW["on"]) == {"workflow_call"}
    call = WORKFLOW["on"]["workflow_call"]
    assert set(call["inputs"]) == {
        "account",
        "artifact_id",
        "artifact_sha256",
        "contract_sha256",
    }
    assert "secrets" not in call
    assert WORKFLOW["concurrency"]["cancel-in-progress"] is False
    assert "inputs.account" in WORKFLOW["concurrency"]["group"]
    assert (
        "AWS_OPERATOR_TEST_SEED_KMS_KEY_ARN"
        in WORKFLOW["env"]["OPERATOR_SEED_KMS_KEY_ARN"]
    )
    assert (
        "AWS_OPERATOR_PROD_SEED_KMS_KEY_ARN"
        in WORKFLOW["env"]["OPERATOR_SEED_KMS_KEY_ARN"]
    )


@pytest.mark.parametrize("name", ["resolve", "preview", "apply", "post_apply_drift"])
def test_every_image_build_preserves_root_owned_child_readable_plugin(name):
    build = next(
        step["run"]
        for step in JOBS[name]["steps"]
        if "docker build" in step.get("run", "")
    )
    permission = (
        "RUN chmod 0755 /opt/operator-plugins /opt/operator-plugins/plugins "
        "/opt/operator-plugins/plugins/resource-aws-v7.23.0"
    )
    assert build.count(permission) == 1
    assert (
        build.index("USER root")
        < build.index("plugin install resource aws 7.23.0")
        < build.index("sha256sum -c -")
        < build.index(permission)
    )
    assert "chmod 0777" not in build and "chown" not in build


@pytest.mark.parametrize(
    "name,suffix",
    [("preview", "-preview"), ("apply", ""), ("post_apply_drift", "-drift")],
)
def test_oidc_follows_authentication_and_trusted_build(name, suffix):
    job = JOBS[name]
    assert (
        job["environment"]
        == "${{ format('{0}-operator" + suffix + "', inputs.account) }}"
    )
    assert "refs/heads/main" in job["if"] and "repository_dispatch" in job["if"]
    assert job["permissions"]["id-token"] == "write"
    steps = job["steps"]
    check = next(i for i, step in enumerate(steps) if step.get("id") == "recheck")
    build = next(
        i for i, step in enumerate(steps) if "docker build" in step.get("run", "")
    )
    oidc = next(
        i
        for i, step in enumerate(steps)
        if step.get("uses", "").startswith("aws-actions/")
    )
    assert check < build < oidc
    assert steps[0]["with"]["ref"] == "${{ github.sha }}"
    assert steps[0]["with"]["persist-credentials"] is False
    assert (
        steps[oidc]["with"]["allowed-account-ids"]
        == "${{ needs.resolve.outputs.account_id }}"
    )


@pytest.mark.parametrize("name", ["preview", "apply", "post_apply_drift"])
def test_stage_uses_readonly_source_and_private_container_with_fresh_recheck(name):
    stage = next(step for step in JOBS[name]["steps"] if step.get("id") == "execute")
    script = stage["run"]
    assert script.index("deployment_worker_runtime.py") < script.index("docker run")
    for value in (
        "--read-only",
        "--cap-drop ALL",
        "--security-opt no-new-privileges",
        "dst=/trusted,readonly",
        "dst=/source,readonly",
        "python -I",
        "operator_execution_runtime.py",
    ):
        assert value in script
    for forbidden in (
        "docker.sock",
        "make ",
        "--env-file",
        "AWS_PROFILE",
        "AWS_SHARED_CREDENTIALS_FILE",
    ):
        assert forbidden not in script
    assert "GH_TOKEN" in stage["env"]
    assert "--seed-key-arn" in script


def test_replay_and_receipts_use_actual_same_run_job_outputs():
    apply = next(step for step in JOBS["apply"]["steps"] if step.get("id") == "execute")
    assert (
        apply["env"]["PLAN_ARTIFACT_ID"]
        == "${{ needs.preview.outputs.plan_artifact_id }}"
    )
    assert (
        apply["env"]["PLAN_ARTIFACT_SHA256"]
        == "${{ needs.preview.outputs.plan_artifact_sha256 }}"
    )
    upload = next(
        step for step in JOBS["preview"]["steps"] if step.get("id") == "upload"
    )
    assert upload["with"]["path"].endswith("/saved-plan.encrypted.json")
    assert JOBS["post_apply_drift"]["needs"] == ["resolve", "apply"]
    receipt = next(
        step for step in JOBS["receipt"]["steps"] if step.get("id") == "receipt"
    )
    assert "deployment_worker_receipt.py" in receipt["run"]
    assert receipt["env"]["APPLY_RESULT"] == "${{ needs.apply.result }}"
    assert receipt["env"]["DRIFT_RESULT"] == "${{ needs.post_apply_drift.result }}"
    assert set(JOBS["receipt"]["needs"]) == set(JOBS) - {"receipt"}


def test_full_plan_and_iam_gates_are_completed_before_apply():
    for gate in ("destructive_diff", "iam_validation"):
        assert gate in JOBS["apply"]["needs"]
        assert (
            JOBS[gate]["steps"][0]["env"]["VALIDATED"]
            == "${{ needs.preview.outputs.plan_validated }}"
        )
    assert "command == 'up'" in JOBS["apply"]["if"]
    assert "command == 'up'" in JOBS["post_apply_drift"]["if"]
