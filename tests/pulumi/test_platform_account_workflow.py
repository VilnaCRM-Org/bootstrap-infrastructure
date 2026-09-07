"""Closed-account and credential boundaries for the reusable platform worker."""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / ".github/workflows/pulumi-platform-account.yml"
WORKFLOW = yaml.safe_load(PATH.read_text())
JOBS = WORKFLOW["jobs"]
CREDENTIAL_JOBS = ("preview", "iam_validation", "apply", "post_apply_drift")
DEPENDENCIES = {
    "preview": ["resolve"],
    "destructive_diff": ["resolve", "preview"],
    "iam_validation": ["resolve", "preview", "destructive_diff"],
    "apply": ["resolve", "preview", "destructive_diff", "iam_validation"],
    "post_apply_drift": ["resolve", "apply"],
    "receipt": [
        "resolve",
        "preview",
        "destructive_diff",
        "iam_validation",
        "apply",
        "post_apply_drift",
    ],
}


def script(job, needle):
    return next(step for step in JOBS[job]["steps"] if needle in step.get("run", ""))


def test_workflow_only_accepts_account_and_authenticated_artifact_references():
    trigger = WORKFLOW.get("on", WORKFLOW.get(True))
    assert set(trigger) == {"workflow_call"}
    call = trigger["workflow_call"]
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
    assert "secrets" not in call
    assert set(JOBS) == {"resolve", *DEPENDENCIES}
    raw = PATH.read_text()
    for forbidden in (
        "repository_dispatch:",
        "workflow_dispatch:",
        "client_payload",
        "claim_request",
        "pulumi-command-",
        "create-github-app-token",
        "governance_promotion.py",
        "statuses: write",
        "issues: write",
        "strategy:",
        "matrix.",
    ):
        assert forbidden not in raw
    assert "uses: ./.github/workflows/pulumi-pr-command-runner.yml" not in raw


def test_account_workflow_holds_existing_backend_lock_across_entire_graph():
    assert WORKFLOW["concurrency"] == {
        "group": "bootstrap-infrastructure-${{ inputs.account }}-state",
        "cancel-in-progress": False,
    }
    assert all("concurrency" not in job for job in JOBS.values())


@pytest.mark.parametrize("name,needs", DEPENDENCIES.items())
def test_scope_dependencies_are_explicit_and_sequential(name, needs):
    assert JOBS[name]["needs"] == needs
    assert isinstance(JOBS[name]["timeout-minutes"], int)
    assert JOBS[name]["timeout-minutes"] <= 30


@pytest.mark.parametrize("name", CREDENTIAL_JOBS)
def test_credentials_follow_protected_environment_and_authenticated_artifact(name):
    job = JOBS[name]
    expected = (
        "${{ inputs.account }}"
        if name == "apply"
        else ("${{ format('{0}-preview', inputs.account) }}")
    )
    assert job["environment"] == expected
    assert job["permissions"] == {
        "contents": "read",
        "actions": "read",
        "issues": "read",
        "pull-requests": "read",
        "id-token": "write",
    }
    steps = job["steps"]
    check_index = next(i for i, step in enumerate(steps) if step.get("id") == "recheck")
    trusted_index = next(
        i
        for i, step in enumerate(steps)
        if step.get("with", {}).get("path") == ".trusted"
    )
    config_index = next(
        i for i, step in enumerate(steps) if step.get("id") == "ci_config"
    )
    credentials_index = next(
        i
        for i, step in enumerate(steps)
        if step.get("uses", "").startswith("aws-actions/configure-aws-credentials@")
    )
    assert trusted_index < check_index < config_index < credentials_index
    checkout = steps[trusted_index]
    assert checkout["with"]["ref"] == "${{ github.sha }}"
    assert checkout["with"]["persist-credentials"] is False
    assert steps[config_index]["uses"] == "./.trusted/.github/actions/load-aws-ci-env"
    assert steps[credentials_index]["with"]["allowed-account-ids"] == (
        "${{ needs.resolve.outputs.aws_account_id }}"
    )
    assert all("continue-on-error" not in step for step in steps)


@pytest.mark.parametrize("name", ["resolve", *CREDENTIAL_JOBS])
def test_every_runtime_recheck_uses_isolated_trusted_code_and_all_digest_inputs(name):
    steps = [
        step
        for step in JOBS[name]["steps"]
        if "deployment_worker_runtime.py" in step.get("run", "")
    ]
    assert len(steps) == (2 if name == "apply" else 1)
    for step in steps:
        command = step["run"]
        assert command.startswith(
            'python3 -I "${GITHUB_WORKSPACE}/.trusted/scripts/'
            'deployment_worker_runtime.py"'
        )
        assert '--scope platform --environment "${ACCOUNT}"' in command
        assert '--artifact-id "${CONTRACT_ARTIFACT_ID}"' in command
        assert '--artifact-sha256 "${CONTRACT_ARTIFACT_SHA256}"' in command
        assert '--contract-sha256 "${CONTRACT_SHA256}"' in command
        assert '--output "${GITHUB_OUTPUT}"' in command
        assert step["env"]["CONTRACT_ARTIFACT_ID"] == "${{ inputs.artifact_id }}"
        assert (
            step["env"]["CONTRACT_ARTIFACT_SHA256"] == "${{ inputs.artifact_sha256 }}"
        )
        assert step["env"]["CONTRACT_SHA256"] == "${{ inputs.contract_sha256 }}"
        assert "working-directory" not in step


@pytest.mark.parametrize("name", CREDENTIAL_JOBS)
def test_scope_roles_and_stack_configuration_cannot_be_caller_selected(name):
    steps = JOBS[name]["steps"]
    config = next(step for step in steps if step.get("id") == "ci_config")
    role = (
        "apply"
        if name == "apply"
        else "drift"
        if name == "post_apply_drift"
        else "preview"
    )
    credentials = next(
        step
        for step in steps
        if step.get("uses", "").startswith("aws-actions/configure-aws-credentials@")
    )
    assert credentials["with"]["role-to-assume"] == (
        "${{ steps.ci_config.outputs.aws-" + role + "-role-arn }}"
    )
    assert f"AWS_{role.upper()}_ROLE_ARN" in config["with"]["required-keys"]
    config_role = "apply_config_role" if name == "apply" else "preview_config_role"
    assert config["with"]["config-role-arn"] == (
        "${{ needs.resolve.outputs." + config_role + " }}"
    )
    boundary = script(name, 'test "${PULUMI_DIR:-pulumi}" = pulumi')
    assert 'test "${!STACK_VARIABLE}" = "${ACCOUNT}"' in boundary["run"]
    assert "PULUMI_DIR=pulumi" in boundary["run"]
    assert boundary["env"]["STACK_VARIABLE"] == (
        "PULUMI_DRIFT_STACKS" if name == "post_apply_drift" else "PULUMI_PREVIEW_STACKS"
    )


@pytest.mark.parametrize("name", CREDENTIAL_JOBS)
def test_plan_has_no_apply_or_drift_and_credentials_never_override_failed_needs(
    name,
):
    condition = JOBS[name].get("if")
    if name in {"apply", "post_apply_drift"}:
        assert condition == "${{ needs.resolve.outputs.command == 'up' }}"
    else:
        assert condition is None
    # GitHub's implicit success condition remains in force for credential jobs.
    assert all(
        word not in str(condition)
        for word in ("always()", "failure()", "skipped", "cancelled()")
    )


def test_exact_source_checkout_and_saved_plan_execution_preserve_existing_gates():
    for name in (*CREDENTIAL_JOBS, "destructive_diff"):
        source = next(
            step
            for step in JOBS[name]["steps"]
            if step.get("with", {}).get("path") == "source"
        )
        assert source["with"]["ref"] == "${{ needs.resolve.outputs.head_sha }}"
        assert source["with"]["persist-credentials"] is False
    assert script("preview", "make pulumi-plan")["env"]["PULUMI_COMMIT_SHA"] == (
        "${{ needs.resolve.outputs.head_sha }}"
    )
    assert script("destructive_diff", "make test-destructive-diff")
    assert script("iam_validation", "make test-iam-validation")
    assert script("post_apply_drift", "make test-drift")
    apply = script("apply", "make pulumi-up-plan")
    text = apply["run"]
    assert text.index("make test-destructive-diff") < text.index("make pulumi-up-plan")
    assert 'test "${found_preview}" = true' in text
    assert "issues/${PR_NUMBER}/labels" in text
    for predicate in (".state", ".merged", ".head.sha", ".base.ref", ".base.sha"):
        assert predicate in text
    assert "git rev-parse HEAD" in text
    assert "PULUMI_EXPECTED_SHA" in apply["env"]
    assert "make pulumi-up\n" not in text
    steps = JOBS["apply"]["steps"]
    check = next(i for i, step in enumerate(steps) if step.get("id") == "apply_recheck")
    assert steps[check + 1] == apply


def test_artifact_names_are_unique_and_downloads_use_exact_same_run_ids():
    names = []
    for job in JOBS.values():
        for step in job["steps"]:
            action = step.get("uses", "")
            if action.startswith("actions/upload-artifact@"):
                settings = step["with"]
                name = settings["name"]
                names.append(name)
                for part in (
                    "github.run_id",
                    "github.run_attempt",
                    "platform",
                    "inputs.account",
                    "needs.resolve.outputs.head_sha",
                ):
                    assert part in name
                assert settings["if-no-files-found"] == "error"
            if action.startswith("actions/download-artifact@"):
                assert action == (
                    "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093"
                )
                assert set(step["with"]) == {"artifact-ids", "path", "merge-multiple"}
                # v4.3.0 uses named subdirectories for ID-based downloads unless
                # merge-multiple is true, even when exactly one ID is selected.
                assert step["with"]["merge-multiple"] is True
                assert step["with"]["artifact-ids"] in {
                    "${{ needs.preview.outputs.preview_artifact_id }}",
                    "${{ needs.preview.outputs.plan_artifact_id }}",
                }
    assert len(names) == len(set(names)) == 3


def test_receipt_is_credential_free_and_only_trusted_cli_can_accept_stages():
    job = JOBS["receipt"]
    assert job["if"] == "${{ always() }}"
    assert "environment" not in job
    assert job["permissions"] == {
        "contents": "read",
        "actions": "read",
        "issues": "read",
        "pull-requests": "read",
    }
    assert len(job["steps"]) == 4
    assert job["steps"][0]["with"]["ref"] == "${{ github.sha }}"
    assert job["steps"][0]["with"]["path"] == ".trusted"
    check = job["steps"][1]
    assert check["run"].startswith(
        'python3 -I "${GITHUB_WORKSPACE}/.trusted/scripts/deployment_worker_receipt.py"'
    )
    for flag, variable, name in (
        ("plan", "PLAN", "preview"),
        ("destructive", "DESTRUCTIVE", "destructive_diff"),
        ("iam", "IAM", "iam_validation"),
        ("apply", "APPLY", "apply"),
        ("drift", "DRIFT", "post_apply_drift"),
    ):
        assert f'--{flag}-result "${{{variable}_RESULT}}"' in check["run"]
        assert check["env"][f"{variable}_RESULT"] == "${{ needs." + name + ".result }}"
    assert "--artifact-sha256" in check["run"] and "--contract-sha256" in check["run"]
    assert "--scope platform" in check["run"]
    assert "--receipt-path .artifacts/deployment-receipt/receipt.json" in check["run"]
    assert "upload-artifact@" in job["steps"][2]["uses"]
    assert "result=success" in job["steps"][3]["run"]
    assert all(
        "if" not in step and "continue-on-error" not in step for step in job["steps"]
    )
    assert set(job["outputs"]) >= {
        "receipt_artifact_id",
        "receipt_artifact_sha256",
        "receipt_digest",
        "receipt_file_sha256",
        "selection_digest",
        "contract_digest",
        "completion_kind",
        "result",
    }


def account_configuration(tmp_path, account, **overrides):
    output = tmp_path / "outputs"
    env = {
        "PATH": os.environ["PATH"],
        "GITHUB_OUTPUT": str(output),
        "ACCOUNT": account,
        "COMMAND": "up",
        "TEST_ACCOUNT_ID": "111111111111",
        "TEST_REGION": "eu-central-1",
        "TEST_CONFIG_ROLE": "arn:aws:iam::111111111111:role/TestConfig",
        "PROD_ACCOUNT_ID": "222222222222",
        "PROD_REGION": "eu-central-1",
        "PROD_PREVIEW_CONFIG_ROLE": "arn:aws:iam::222222222222:role/ProdPreviewConfig",
        "PROD_CONFIG_ROLE": "arn:aws:iam::222222222222:role/ProdConfig",
        **overrides,
    }
    step = next(
        step for step in JOBS["resolve"]["steps"] if step.get("id") == "account"
    )
    result = subprocess.run(
        ["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", step["run"]],
        cwd=tmp_path,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    values = (
        dict(line.split("=", 1) for line in output.read_text().splitlines())
        if output.exists()
        else {}
    )
    return result, values


@pytest.mark.parametrize(
    "account,prefix,suffix",
    [
        ("test", "111111111111", "test"),
        ("prod", "222222222222", "prod-preview"),
    ],
)
def test_rendered_account_mapping_selects_only_its_fixed_account(
    tmp_path, account, prefix, suffix
):
    result, values = account_configuration(tmp_path, account)
    assert result.returncode == 0, result.stderr
    assert values["aws_account_id"] == prefix
    assert values["preview_config_suffix"] == suffix
    assert f"::{prefix}:role/" in values["preview_config_role"]
    assert f"::{prefix}:role/" in values["apply_config_role"]


@pytest.mark.parametrize(
    "account", ["", "TEST", "staging", "test\nprod", "test; echo injected", "../prod"]
)
def test_rendered_account_mapping_rejects_unknown_accounts_without_outputs(
    tmp_path, account
):
    result, values = account_configuration(tmp_path, account)
    assert result.returncode != 0
    assert values == {}


@pytest.mark.parametrize(
    "field,value",
    [
        ("PROD_ACCOUNT_ID", ""),
        ("PROD_REGION", ""),
        ("PROD_PREVIEW_CONFIG_ROLE", ""),
        ("PROD_CONFIG_ROLE", ""),
        ("PROD_ACCOUNT_ID", "111111111111\nhead_sha=other"),
        ("PROD_REGION", "eu-central-1\noutput=injected"),
        ("PROD_CONFIG_ROLE", "arn:aws:iam::111111111111:role/WrongAccount"),
    ],
)
def test_prod_configuration_cannot_fall_back_to_test_or_inject_outputs(
    tmp_path, field, value
):
    result, values = account_configuration(tmp_path, "prod", **{field: value})
    assert result.returncode != 0
    assert values == {}


def test_external_actions_are_immutable_and_local_helper_remains_isolated():
    for job in JOBS.values():
        for step in job["steps"]:
            action = step.get("uses")
            if action and not action.startswith("./"):
                assert re.fullmatch(r"[^@]+@[0-9a-f]{40}", action)
    action = yaml.safe_load(
        (ROOT / ".github/actions/load-aws-ci-env/action.yml").read_text()
    )
    for step in action["runs"]["steps"]:
        if "python3" in step.get("run", ""):
            assert "python3 -I" in step["run"]
    validator = next(
        step
        for step in action["runs"]["steps"]
        if "validate_ci_environment.py" in step.get("run", "")
    )
    assert (
        "${CI_CONFIG_ACTION_PATH}/../../../scripts/validate_ci_environment.py"
        in validator["run"]
    )


def test_plan_only_needs_preview_configuration_and_still_authenticates_first(tmp_path):
    result, values = account_configuration(
        tmp_path, "prod", COMMAND="plan", PROD_CONFIG_ROLE=""
    )
    assert result.returncode == 0, result.stderr
    assert values["apply_config_role"] == ""
    assert values["preview_config_role"].endswith("/ProdPreviewConfig")
    assert [step.get("id") for step in JOBS["resolve"]["steps"]] == [
        None,
        "resolve",
        "account",
    ]


@pytest.mark.parametrize("command", ["", "destroy", "up\ncommand=plan"])
def test_account_mapping_rejects_unsupported_admitted_command(tmp_path, command):
    result, values = account_configuration(tmp_path, "test", COMMAND=command)
    assert result.returncode != 0
    assert values == {}


@pytest.mark.parametrize("name", CREDENTIAL_JOBS)
@pytest.mark.parametrize("account", ["test", "prod"])
@pytest.mark.parametrize(
    "project,stack,accepted",
    [
        ("pulumi", "matching", True),
        ("", "matching", True),
        ("pulumi/governance", "matching", False),
        ("pulumi/github-ci-bootstrap", "matching", False),
        ("../pulumi", "matching", False),
        ("pulumi", "opposite", False),
        ("pulumi", "test prod", False),
        ("pulumi", "", False),
    ],
)
def test_rendered_scope_binding_rejects_other_projects_or_account_stacks(
    tmp_path, name, account, project, stack, accepted
):
    boundary = script(name, 'test "${PULUMI_DIR:-pulumi}" = pulumi')
    if stack == "matching":
        stack = account
    elif stack == "opposite":
        stack = "prod" if account == "test" else "test"
    variable = boundary["env"]["STACK_VARIABLE"]
    output = tmp_path / "environment"
    result = subprocess.run(
        [
            "bash",
            "--noprofile",
            "--norc",
            "-e",
            "-o",
            "pipefail",
            "-c",
            boundary["run"],
        ],
        env={
            "PATH": os.environ["PATH"],
            "GITHUB_ENV": str(output),
            "ACCOUNT": account,
            "PULUMI_DIR": project,
            "STACK_VARIABLE": variable,
            variable: stack,
        },
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
    )
    assert (result.returncode == 0) is accepted
    if accepted:
        assert output.read_text() == "PULUMI_DIR=pulumi\n"
    else:
        assert not output.exists()


def test_every_trusted_cli_inherits_the_repository_activation_variable():
    expected = "${{ vars.DEPLOYMENT_COORDINATOR_MODE }}"
    assert WORKFLOW["env"] == {"DEPLOYMENT_COORDINATOR_MODE": expected}
    invocations = []
    for name, job in JOBS.items():
        for step in job["steps"]:
            command = step.get("run", "")
            if (
                "deployment_worker_runtime.py" in command
                or "deployment_worker_receipt.py" in command
            ):
                effective = {
                    **WORKFLOW["env"],
                    **job.get("env", {}),
                    **step.get("env", {}),
                }
                assert effective["DEPLOYMENT_COORDINATOR_MODE"] == expected
                invocations.append((name, step.get("id")))
    assert invocations == [
        ("resolve", "resolve"),
        ("preview", "recheck"),
        ("iam_validation", "recheck"),
        ("apply", "recheck"),
        ("apply", "apply_recheck"),
        ("post_apply_drift", "recheck"),
        ("receipt", "receipt"),
    ]
    # No active fallback or caller-provided override: unset/unknown values reach
    # the existing runtime's closed activation-mode validator unchanged.
    assert "||" not in expected and "active" not in expected
