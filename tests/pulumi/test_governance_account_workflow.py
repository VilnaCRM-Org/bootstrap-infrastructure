"""Governance workers bind one account, isolated state, real gates and receipts."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / ".github/workflows/pulumi-governance-account.yml"
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


def test_only_fixed_account_and_trusted_artifact_inputs_are_callable():
    assert set(WORKFLOW["on"]) == {"workflow_call"}
    call = WORKFLOW["on"]["workflow_call"]
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
    assert WORKFLOW["env"] == {
        "DEPLOYMENT_COORDINATOR_MODE": "${{ vars.DEPLOYMENT_COORDINATOR_MODE }}"
    }
    for job in JOBS.values():
        assert "DEPLOYMENT_COORDINATOR_MODE" not in job.get("env", {})
        assert "statuses" not in job["permissions"]
        assert job["permissions"].get("issues") != "write"
    for forbidden in (
        "client_payload",
        "claim_request",
        "create-github-app-token",
        "governance_promotion.py",
        "strategy:",
        "matrix.",
        "load-aws-ci-env",
    ):
        assert forbidden not in PATH.read_text()


def test_whole_worker_owns_account_backend_lock_and_legacy_route_stays_separate():
    assert WORKFLOW["concurrency"] == {
        "group": "bootstrap-infrastructure-governance-${{ inputs.account }}-state",
        "cancel-in-progress": False,
    }
    assert all("concurrency" not in job for job in JOBS.values())
    # Legacy has no account backend lock. Its retirement is a root activation step.
    legacy = yaml.safe_load(
        (ROOT / ".github/workflows/pulumi-governance.yml").read_text()
    )
    assert legacy["concurrency"]["group"].startswith("pulumi-command-")
    assert "Disable the legacy governance route before activation" in PATH.read_text()


@pytest.mark.parametrize("name,needs", DEPENDENCIES.items())
def test_gates_and_account_operations_have_exact_dependency_order(name, needs):
    assert JOBS[name]["needs"] == needs
    assert JOBS[name]["timeout-minutes"] <= 30


@pytest.mark.parametrize("name", CREDENTIAL_JOBS)
def test_dedicated_governance_credentials_follow_authentication_and_backend_guard(name):
    job = JOBS[name]
    assert job["environment"] == (
        "governance" if name == "apply" else "governance-preview"
    )
    assert job["permissions"]["id-token"] == "write"
    assert job["permissions"]["actions"] == "read"
    assert job["permissions"]["issues"] == "read"
    steps = job["steps"]
    trusted = next(
        i
        for i, step in enumerate(steps)
        if step.get("with", {}).get("path") == ".trusted"
    )
    recheck = next(i for i, step in enumerate(steps) if step.get("id") == "recheck")
    boundary = next(
        i
        for i, step in enumerate(steps)
        if 'test "${PULUMI_DIR}"' in step.get("run", "")
    )
    credentials = next(
        i
        for i, step in enumerate(steps)
        if step.get("uses", "").startswith("aws-actions/configure-aws-credentials@")
    )
    assert trusted < recheck < boundary < credentials
    assert steps[trusted]["with"]["ref"] == "${{ github.sha }}"
    assert steps[trusted]["with"]["persist-credentials"] is False
    role = (
        "apply"
        if name == "apply"
        else "drift"
        if name == "post_apply_drift"
        else "preview"
    )
    assert (
        steps[credentials]["with"]["role-to-assume"]
        == "${{ needs.resolve.outputs." + role + "_role }}"
    )
    assert (
        steps[credentials]["with"]["allowed-account-ids"]
        == "${{ needs.resolve.outputs.aws_account_id }}"
    )
    assert (
        steps[credentials]["with"]["aws-region"]
        == "${{ needs.resolve.outputs.aws_region }}"
    )
    assert job["env"]["PULUMI_DIR"] == "pulumi/governance"
    for variable in ("PULUMI_STACK", "PULUMI_PREVIEW_STACKS", "PULUMI_DRIFT_STACKS"):
        assert job["env"][variable] == "${{ inputs.account }}"
    assert (
        job["env"]["PULUMI_BACKEND_URL"] == "${{ needs.resolve.outputs.backend_url }}"
    )
    assert (
        job["env"]["PULUMI_SECRETS_PROVIDER"]
        == "${{ needs.resolve.outputs.secrets_provider }}"
    )
    expected_if = (
        "${{ needs.resolve.outputs.command == 'up' }}"
        if name in {"apply", "post_apply_drift"}
        else None
    )
    assert job.get("if") == expected_if
    assert all("continue-on-error" not in step for step in steps)


@pytest.mark.parametrize("name", ["resolve", *CREDENTIAL_JOBS])
def test_isolated_rechecks_bind_all_artifact_digests_and_fixed_scope(name):
    checks = [
        step
        for step in JOBS[name]["steps"]
        if "deployment_worker_runtime.py" in step.get("run", "")
    ]
    assert len(checks) == (2 if name == "apply" else 1)
    for step in checks:
        assert step["run"].startswith(
            'python3 -I "${GITHUB_WORKSPACE}/.trusted/scripts/'
            'deployment_worker_runtime.py"'
        )
        assert '--scope governance --environment "${ACCOUNT}"' in step["run"]
        assert '--artifact-id "${CONTRACT_ARTIFACT_ID}"' in step["run"]
        assert '--artifact-sha256 "${CONTRACT_ARTIFACT_SHA256}"' in step["run"]
        assert '--contract-sha256 "${CONTRACT_SHA256}"' in step["run"]
        assert step["env"]["ACCOUNT"] == "${{ inputs.account }}"
        assert step["env"]["CONTRACT_ARTIFACT_ID"] == "${{ inputs.artifact_id }}"
        assert (
            step["env"]["CONTRACT_ARTIFACT_SHA256"] == "${{ inputs.artifact_sha256 }}"
        )
        assert step["env"]["CONTRACT_SHA256"] == "${{ inputs.contract_sha256 }}"
        assert "working-directory" not in step
        assert "DEPLOYMENT_COORDINATOR_MODE" not in step["env"]


def test_preview_iam_destructive_and_saved_apply_are_real_operations():
    assert (
        script("preview", "make pulumi-plan")["env"]["PULUMI_COMMIT_SHA"]
        == "${{ needs.resolve.outputs.head_sha }}"
    )
    assert script("destructive_diff", "make test-destructive-diff")
    assert script("iam_validation", "make test-iam-validation")
    assert script("post_apply_drift", "make test-drift")
    apply = script("apply", "make pulumi-up-plan")
    text = apply["run"]
    assert text.index("make test-destructive-diff") < text.index("make pulumi-up-plan")
    assert 'test "${found_preview}" = true' in text
    assert "issues/${PR_NUMBER}/labels" in text
    assert "rm -f .artifacts/pulumi-preview/pull-request-event.json" in text
    for predicate in (".state", ".merged", ".head.sha", ".base.ref", ".base.sha"):
        assert predicate in text
    assert "git rev-parse HEAD" in text
    assert (
        apply["env"]["PULUMI_EXPECTED_SHA"] == "${{ needs.resolve.outputs.head_sha }}"
    )
    steps = JOBS["apply"]["steps"]
    recheck = next(
        i for i, step in enumerate(steps) if step.get("id") == "apply_recheck"
    )
    assert steps[recheck + 1] == apply
    assert "make pulumi-up\n" not in text
    for name in (*CREDENTIAL_JOBS, "destructive_diff"):
        source = next(
            step
            for step in JOBS[name]["steps"]
            if step.get("with", {}).get("path") == "source"
        )
        assert source["with"]["ref"] == "${{ needs.resolve.outputs.head_sha }}"
        assert source["with"]["persist-credentials"] is False


def test_artifacts_use_unique_account_names_and_verified_id_capable_download_action():
    names = []
    downloads = 0
    for job in JOBS.values():
        for step in job["steps"]:
            action = step.get("uses", "")
            if action:
                assert re.fullmatch(r"[^@]+@[0-9a-f]{40}", action)
            if action.startswith("actions/upload-artifact@"):
                settings = step["with"]
                names.append(settings["name"])
                for field in (
                    "github.run_id",
                    "github.run_attempt",
                    "governance",
                    "inputs.account",
                    "needs.resolve.outputs.head_sha",
                ):
                    assert field in settings["name"]
                assert settings["if-no-files-found"] == "error"
            if action.startswith("actions/download-artifact@"):
                downloads += 1
                assert (
                    action == "actions/download-artifact@"
                    "d3f86a106a0bac45b974a628896c90dbdf5c8093"
                )
                assert set(step["with"]) == {"artifact-ids", "path", "merge-multiple"}
                assert step["with"]["merge-multiple"] is True
                assert step["with"]["artifact-ids"] in {
                    "${{ needs.preview.outputs.preview_artifact_id }}",
                    "${{ needs.preview.outputs.plan_artifact_id }}",
                }
    assert len(names) == len(set(names)) == 3
    assert downloads == 4


def test_receipt_accepts_actual_results_only_and_has_no_credentials_or_promotion():
    job = JOBS["receipt"]
    assert job["if"] == "${{ always() }}"
    assert "environment" not in job
    assert "id-token" not in job["permissions"]
    assert len(job["steps"]) == 4
    assert job["steps"][0]["with"]["ref"] == "${{ github.sha }}"
    receipt = job["steps"][1]
    assert receipt["run"].startswith(
        'python3 -I "${GITHUB_WORKSPACE}/.trusted/scripts/deployment_worker_receipt.py"'
    )
    assert "--scope governance" in receipt["run"]
    assert "--receipt-path .artifacts/deployment-receipt/receipt.json" in receipt["run"]
    for flag, variable, dependency in (
        ("plan", "PLAN", "preview"),
        ("destructive", "DESTRUCTIVE", "destructive_diff"),
        ("iam", "IAM", "iam_validation"),
        ("apply", "APPLY", "apply"),
        ("drift", "DRIFT", "post_apply_drift"),
    ):
        assert f'--{flag}-result "${{{variable}_RESULT}}"' in receipt["run"]
        assert (
            receipt["env"][f"{variable}_RESULT"]
            == "${{ needs." + dependency + ".result }}"
        )
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


def run_shell(tmp_path, command, environment):
    trusted = tmp_path / ".trusted/scripts"
    trusted.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(
        ROOT / "scripts/validate_ci_environment.py",
        trusted / "validate_ci_environment.py",
    )
    return subprocess.run(
        ["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", command],
        cwd=tmp_path,
        env={
            "PATH": os.environ["PATH"],
            "GITHUB_WORKSPACE": str(tmp_path),
            **environment,
        },
        check=False,
        capture_output=True,
        text=True,
    )


def account_configuration(tmp_path, account, **overrides):
    output = tmp_path / "outputs"
    environment = {"ACCOUNT": account, "COMMAND": "up", "GITHUB_OUTPUT": str(output)}
    for prefix, identifier in (("TEST", "111111111111"), ("PROD", "222222222222")):
        environment.update(
            {
                f"{prefix}_ACCOUNT_ID": identifier,
                f"{prefix}_REGION": "eu-central-1",
                f"{prefix}_BACKEND_URL": f"s3://bootstrap-{prefix.lower()}-state/governance",
                f"{prefix}_SECRETS_PROVIDER": f"awskms://alias/bootstrap-{prefix.lower()}?region=eu-central-1",
                **{
                    f"{prefix}_{role}_ROLE_ARN": (
                        f"arn:aws:iam::{identifier}:role/Governance{role}"
                    )
                    for role in ("PREVIEW", "APPLY", "DRIFT")
                },
            }
        )
    step = next(
        step for step in JOBS["resolve"]["steps"] if step.get("id") == "account"
    )
    result = run_shell(tmp_path, step["run"], {**environment, **overrides})
    values = (
        dict(line.split("=", 1) for line in output.read_text().splitlines())
        if output.exists()
        else {}
    )
    return result, values


@pytest.mark.parametrize(
    "account,identifier", [("test", "111111111111"), ("prod", "222222222222")]
)
def test_account_configuration_selects_fixed_dedicated_values(
    tmp_path, account, identifier
):
    result, values = account_configuration(tmp_path, account)
    assert result.returncode == 0, result.stderr
    assert values["aws_account_id"] == identifier
    assert values["backend_url"] == f"s3://bootstrap-{account}-state/governance"
    for role in ("preview", "apply", "drift"):
        assert (
            values[f"{role}_role"]
            == f"arn:aws:iam::{identifier}:role/Governance{role.upper()}"
        )
    mapping = next(
        step for step in JOBS["resolve"]["steps"] if step.get("id") == "account"
    )["env"]
    for prefix in ("TEST", "PROD"):
        for field in (
            "ACCOUNT_ID",
            "BACKEND_URL",
            "SECRETS_PROVIDER",
            "PREVIEW_ROLE_ARN",
            "APPLY_ROLE_ARN",
            "DRIFT_ROLE_ARN",
        ):
            assert (
                mapping[f"{prefix}_{field}"]
                == "${{ vars.AWS_GOVERNANCE_" + prefix + "_" + field + " }}"
            )


@pytest.mark.parametrize(
    "account", ["", "TEST", "staging", "test\nprod", "test; echo injected", "../prod"]
)
def test_unknown_accounts_never_produce_execution_configuration(tmp_path, account):
    result, values = account_configuration(tmp_path, account)
    assert result.returncode != 0
    assert values == {}


@pytest.mark.parametrize(
    "field,value",
    [
        ("PROD_ACCOUNT_ID", ""),
        ("PROD_REGION", ""),
        ("PROD_PREVIEW_ROLE_ARN", ""),
        ("PROD_APPLY_ROLE_ARN", ""),
        ("PROD_DRIFT_ROLE_ARN", ""),
        ("PROD_APPLY_ROLE_ARN", "arn:aws:iam::111111111111:role/WrongAccount"),
        ("PROD_BACKEND_URL", "s3://bucket/platform"),
        ("PROD_BACKEND_URL", "s3://bucket/governance/"),
        ("PROD_BACKEND_URL", "s3://bucket/governance\nhead_sha=bad"),
        ("PROD_SECRETS_PROVIDER", ""),
        ("PROD_SECRETS_PROVIDER", "awskms://alias/test\nhead_sha=bad"),
        ("PROD_REGION", "eu-central-1\nhead_sha=bad"),
    ],
)
def test_prod_configuration_never_falls_back_or_injects_outputs(tmp_path, field, value):
    result, values = account_configuration(tmp_path, "prod", **{field: value})
    assert result.returncode != 0
    assert values == {}


def test_plan_only_requires_preview_role_and_resolves_after_authentication(tmp_path):
    result, values = account_configuration(
        tmp_path, "prod", COMMAND="plan", PROD_APPLY_ROLE_ARN="", PROD_DRIFT_ROLE_ARN=""
    )
    assert result.returncode == 0, result.stderr
    assert values["apply_role"] == values["drift_role"] == ""
    assert [step.get("id") for step in JOBS["resolve"]["steps"]] == [
        None,
        "resolve",
        "account",
    ]


@pytest.mark.parametrize("command", ["", "destroy", "up\ncommand=plan"])
def test_unsupported_commands_do_not_produce_configuration(tmp_path, command):
    result, values = account_configuration(tmp_path, "test", COMMAND=command)
    assert result.returncode != 0
    assert values == {}


@pytest.mark.parametrize("job", CREDENTIAL_JOBS)
@pytest.mark.parametrize(
    "field,value",
    [
        ("PULUMI_DIR", "pulumi"),
        ("PULUMI_DIR", "pulumi/github-ci-bootstrap"),
        ("PULUMI_STACK", "prod"),
        ("PULUMI_PREVIEW_STACKS", "test prod"),
        ("PULUMI_DRIFT_STACKS", "prod"),
        ("PULUMI_BACKEND_URL", "s3://bucket/platform"),
        ("PULUMI_SECRETS_PROVIDER", ""),
    ],
)
def test_precredential_boundary_rejects_other_projects_stacks_or_backends(
    tmp_path, job, field, value
):
    environment = {
        "ACCOUNT": "test",
        "AWS_ACCOUNT_ID": "111111111111",
        "AWS_REGION": "eu-central-1",
        "PULUMI_DIR": "pulumi/governance",
        "PULUMI_STACK": "test",
        "PULUMI_PREVIEW_STACKS": "test",
        "PULUMI_DRIFT_STACKS": "test",
        "PULUMI_BACKEND_URL": "s3://bucket/governance",
        "PULUMI_SECRETS_PROVIDER": "awskms://alias/bootstrap-test?region=eu-central-1",
    }
    command = script(job, 'test "${PULUMI_DIR}"')["run"]
    assert run_shell(tmp_path, command, environment).returncode == 0
    assert run_shell(tmp_path, command, {**environment, field: value}).returncode != 0


@pytest.mark.parametrize("job", ["resolve", *CREDENTIAL_JOBS])
def test_kms_validation_uses_isolated_trusted_helper_before_credentials(job):
    step = (
        next(step for step in JOBS[job]["steps"] if step.get("id") == "account")
        if job == "resolve"
        else script(job, 'test "${PULUMI_DIR}"')
    )
    assert (
        'python3 -I "${GITHUB_WORKSPACE}/.trusted/scripts/'
        'validate_ci_environment.py"' in step["run"]
    )
    assert (
        "--required-keys AWS_ACCOUNT_ID,AWS_REGION,PULUMI_SECRETS_PROVIDER"
        in step["run"]
    )
    if job == "resolve":
        assert 'AWS_ACCOUNT_ID="${account_id}" AWS_REGION="${region}"' in step["run"]
        assert 'PULUMI_SECRETS_PROVIDER="${secrets_provider}"' in step["run"]
        assert step["run"].index("validate_ci_environment.py") < step["run"].index(
            "printf 'aws_account_id="
        )
    else:
        assert JOBS[job]["env"]["AWS_ACCOUNT_ID"] == (
            "${{ needs.resolve.outputs.aws_account_id }}"
        )
        assert (
            JOBS[job]["env"]["AWS_REGION"] == "${{ needs.resolve.outputs.aws_region }}"
        )


def kms_configuration(tmp_path, job, provider):
    if job == "resolve":
        result, values = account_configuration(
            tmp_path, "prod", PROD_SECRETS_PROVIDER=provider
        )
        return result, values
    environment = {
        "ACCOUNT": "prod",
        "AWS_ACCOUNT_ID": "222222222222",
        "AWS_REGION": "eu-central-1",
        "PULUMI_DIR": "pulumi/governance",
        "PULUMI_STACK": "prod",
        "PULUMI_PREVIEW_STACKS": "prod",
        "PULUMI_DRIFT_STACKS": "prod",
        "PULUMI_BACKEND_URL": "s3://bucket/governance",
        "PULUMI_SECRETS_PROVIDER": provider,
    }
    command = script(job, 'test "${PULUMI_DIR}"')["run"]
    return run_shell(tmp_path, command, environment), {}


@pytest.mark.parametrize("job", ["resolve", *CREDENTIAL_JOBS])
@pytest.mark.parametrize(
    "provider",
    [
        "awskms://alias/bootstrap-prod?region=us-east-1",
        "awskms://alias/bootstrap-prod?region=eu-central-1#fragment",
        "awskms://alias/bootstrap-prod",
        "awskms://alias/bootstrap-prod?region=",
        "awskms://alias/bootstrap-prod?region=eu-central-1&region=eu-central-1",
        "awskms://alias/bootstrap-prod?region=eu-central-1&profile=other",
        "awskms://?region=eu-central-1",
        "awskms://[",
        "awskms://alias/%00?region=eu-central-1",
        "awskms://alias/bootstrap-prod?region=eu-central-1\n",
        "awskms://arn:aws:kms:us-east-1:222222222222:key/existing?region=eu-central-1",
        "awskms://arn:aws:kms:eu-central-1:111111111111:key/existing?region=eu-central-1",
        "awskms://arn:aws-cn:kms:eu-central-1:222222222222:key/existing?region=eu-central-1",
    ],
)
def test_kms_region_fragment_and_explicit_account_mismatch_fail_before_oidc(
    tmp_path, job, provider
):
    result, values = kms_configuration(tmp_path, job, provider)
    assert result.returncode != 0
    assert values == {}
    assert provider not in result.stdout + result.stderr


@pytest.mark.parametrize("job", ["resolve", *CREDENTIAL_JOBS])
@pytest.mark.parametrize(
    "identifier",
    [
        "alias/bootstrap-prod",
        "12345678-1234-1234-1234-123456789012",
        "arn:aws:kms:eu-central-1:222222222222:key/existing",
        "arn:aws:kms:eu-central-1:222222222222:alias/bootstrap-prod",
        "arn%3Aaws%3Akms%3Aeu-central-1%3A222222222222%3Aalias/bootstrap-prod",
    ],
)
def test_existing_supported_kms_identifiers_keep_exact_region_context(
    tmp_path, job, identifier
):
    provider = f"awskms://{identifier}?region=eu-central-1"
    result, values = kms_configuration(tmp_path, job, provider)
    assert result.returncode == 0, result.stderr
    if job == "resolve":
        assert values["secrets_provider"] == provider
