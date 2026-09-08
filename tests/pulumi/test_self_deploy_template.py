"""Structure-only lint for the ``user-service-infrastructure`` self-deploy
template (E5.S2).

The self-deploy workflow under
``pulumi/user-service-infrastructure/.github/workflows/self-deploy.yml`` is an
in-repo TEMPLATE asset (the operator copies/pushes it to the real managed repo).
These tests assert STRUCTURE ONLY — they parse the workflow YAML and inspect the
text, and MUST NOT run ``pulumi preview``/``up`` (the scaffold is preview-blocked
until the operator applies governance, FEASIBILITY-6). They cover:

- the workflow is valid YAML and PR-comment driven (``repository_dispatch``),
- the deploy flow mirrors the bootstrap pattern: preflight -> test plan ->
  test apply (saved-plan) -> prod,
- AWS credentials come ONLY via OIDC role assumption through
  ``./.github/actions/load-aws-ci-env`` + ``aws-actions/configure-aws-credentials``,
- the config-role-arn comes from ``vars.AWS_TEST_CI_CONFIG_ROLE_ARN`` and the
  ``role-to-assume`` from the loaded apply-role output,
- applies use the saved-plan IaC-only path ``make pulumi-up-plan`` (never
  ``make pulumi-up``),
- no static AWS keys, no ``AdministratorAccess`` (gitleaks-style assertion),
- NAME PARITY: every governance role name the template references is byte-equal
  to the name the governance component renders for this repo (single source of
  truth — a ``user-service`` short-name reference FAILS the test).
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
SCAFFOLD_DIR = ROOT / "pulumi" / "user-service-infrastructure"
WORKFLOW_PATH = SCAFFOLD_DIR / ".github" / "workflows" / "self-deploy.yml"
SCRIPTS_DIR = ROOT / "scripts"
INFRA_DIR = ROOT / "pulumi"
for extra_path in (str(SCRIPTS_DIR), str(INFRA_DIR)):
    if extra_path not in sys.path:
        sys.path.insert(0, extra_path)

REPO_SLUG = "user-service-infrastructure"
# Static-key markers that must never appear anywhere in the workflow template
# (OIDC-only posture). The ``AKIA`` prefix is a real access-key-id leak signal.
_STATIC_AWS_KEY_MARKERS = (
    "aws_access_key_id",
    "aws_secret_access_key",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AKIA",
)


def _workflow_text() -> str:
    """Return the raw workflow template text."""
    return WORKFLOW_PATH.read_text()


def _workflow_document() -> dict:
    """Return the parsed workflow YAML mapping.

    ``yaml.safe_load`` parses the bare ``on:`` key as the boolean ``True`` per
    the YAML 1.1 spec, so callers look it up via ``document[True]``.
    """
    document = yaml.safe_load(_workflow_text())
    assert isinstance(document, dict)  # nosec B101
    return document


def test_self_deploy_template_is_present() -> None:
    """The self-deploy workflow template exists at the documented path."""
    assert WORKFLOW_PATH.is_file()  # nosec B101


def test_self_deploy_template_is_valid_yaml() -> None:
    """The workflow parses as a YAML mapping with name + jobs."""
    document = _workflow_document()

    assert document["name"]  # nosec B101
    assert isinstance(document["jobs"], dict)  # nosec B101


def test_self_deploy_is_pr_comment_driven() -> None:
    """The workflow is triggered by the PR-comment dispatch event, not push."""
    document = _workflow_document()
    # YAML 1.1 parses the bare ``on`` key as boolean True.
    triggers = document[True]

    assert "repository_dispatch" in triggers  # nosec B101
    dispatch = triggers["repository_dispatch"]
    assert "pulumi-pr-command" in dispatch["types"]  # nosec B101
    # PR-comment driven: never push/pull_request auto-deploy.
    assert "push" not in triggers  # nosec B101


def test_flow_mirrors_bootstrap_preflight_test_then_prod() -> None:
    """Jobs cover preflight -> test plan -> test apply -> prod (ordered)."""
    jobs = _workflow_document()["jobs"]

    assert "preflight" in jobs  # nosec B101
    # Test stages precede prod; prod stages depend on the test stages.
    assert "test_preview" in jobs  # nosec B101
    assert "test_apply" in jobs  # nosec B101
    assert "prod_preview" in jobs  # nosec B101
    assert "prod_apply" in jobs  # nosec B101

    def _needs(job: str) -> list[str]:
        value = jobs[job].get("needs", [])
        return [value] if isinstance(value, str) else list(value)

    # test apply is gated on the test preview/plan stage (saved-plan handoff).
    assert "test_preview" in _needs("test_apply")  # nosec B101
    # prod apply is gated on the test apply succeeding first (test before prod).
    prod_chain = set(_needs("prod_apply")) | set(_needs("prod_preview"))
    assert "test_apply" in prod_chain or "test_post_apply_drift" in prod_chain  # nosec B101


def test_credentials_come_only_from_oidc_role_assumption() -> None:
    """Every AWS credential step uses OIDC role assumption, never static keys."""
    text = _workflow_text()

    # OIDC role assumption action is present.
    assert "aws-actions/configure-aws-credentials" in text  # nosec B101
    # The CI config secret is read through the shared OIDC config-read action.
    assert "./.trusted/.github/actions/load-aws-ci-env" in text  # nosec B101
    # Role assumption is by ARN (role-to-assume), the OIDC mechanism.
    assert "role-to-assume:" in text  # nosec B101

    # Jobs that assume AWS credentials must request id-token: write (OIDC).
    document = _workflow_document()
    for job_name, job in document["jobs"].items():
        steps = job.get("steps", [])
        uses_oidc = any(
            isinstance(step, dict)
            and "configure-aws-credentials" in str(step.get("uses", ""))
            for step in steps
        )
        loads_ci = any(
            isinstance(step, dict) and "load-aws-ci-env" in str(step.get("uses", ""))
            for step in steps
        )
        if uses_oidc or loads_ci:
            permissions = job.get("permissions", {})
            assert permissions.get("id-token") == "write", (  # nosec B101
                f"job {job_name} assumes AWS creds but lacks id-token: write"
            )


def test_config_role_and_apply_role_wiring() -> None:
    """The config-role comes from repo-vars; role-to-assume from the loaded output."""
    text = _workflow_text()

    # The non-secret config-read role ARN is read from the GitHub repo variable
    # (set by the operator from the governance githubVariables output).
    assert "${{ vars.AWS_TEST_CI_CONFIG_ROLE_ARN }}" in text  # nosec B101
    # The deploy role-to-assume comes from the CI-config secret load output, not
    # a hardcoded ARN.
    assert "steps.ci_config.outputs.aws-apply-role-arn" in text  # nosec B101
    assert "steps.ci_config.outputs.aws-preview-role-arn" in text  # nosec B101


def test_apply_replays_saved_plan() -> None:
    """Apply steps use the saved-plan target, never the direct-apply target."""
    document = _workflow_document()
    run_commands: list[str] = []
    for job in document["jobs"].values():
        for step in job.get("steps", []):
            if isinstance(step, dict) and "run" in step:
                run_commands.append(str(step["run"]))

    joined = "\n".join(run_commands)
    # Saved-plan IaC-only apply path is present.
    assert "make pulumi-up-plan" in joined  # nosec B101
    # Direct apply (make pulumi-up, not the -plan variant) is never invoked.
    for command in run_commands:
        for line in command.splitlines():
            tokens = line.split()
            assert "pulumi-up" not in tokens, (  # nosec B101
                "self-deploy must use the saved-plan path make pulumi-up-plan, "
                "never direct make pulumi-up"
            )


def test_no_static_keys_or_admin_access() -> None:
    """No static AWS key literals and no AdministratorAccess (gitleaks-style)."""
    text = _workflow_text()

    for marker in _STATIC_AWS_KEY_MARKERS:
        assert marker not in text, (  # nosec B101
            f"self-deploy template must not embed the static-key marker {marker!r}"
        )
    assert "AdministratorAccess" not in text  # nosec B101
    # No inline secret/passphrase material either.
    assert "PULUMI_ACCESS_TOKEN" not in text  # nosec B101
    assert "_".join(("PULUMI", "CONFIG", "PASSPHRASE")) not in text  # nosec B101


def _rendered_governance_role_names() -> dict[str, str]:
    """Return the governance-rendered role names for this repo (source of truth)."""
    from infra.bootstrap_settings import BootstrapSettings  # noqa: PLC0415
    from infra.ci_bootstrap import _ci_role_name  # noqa: PLC0415
    from infra.ci_config import _ci_config_read_role_name  # noqa: PLC0415

    def _settings(env: str) -> BootstrapSettings:
        return BootstrapSettings(
            org="VilnaCRM-Org",
            repo=None,
            environment=env,
            owner="platform",
            cost_center="core",
            data_classification="internal",
            criticality="high",
            retention_class="standard",
            github_branch="main",
            logging_prefix="company",
            replication_region="eu-west-1",
            github_token=None,
            github_oidc_provider_arn=None,
        )

    test_settings = _settings("test")
    prod_settings = _settings("prod")
    project = test_settings.sanitize_bucket_component(REPO_SLUG, "repoSlug").replace(
        ".", "-"
    )
    return {
        "preview_test": _ci_role_name(test_settings, "preview", project),
        "apply_test": _ci_role_name(test_settings, "apply", project),
        "drift_test": _ci_role_name(test_settings, "drift", project),
        "apply_prod": _ci_role_name(prod_settings, "apply", project),
        "config_read_test": _ci_config_read_role_name(test_settings, "test", REPO_SLUG),
        "config_read_prod": _ci_config_read_role_name(prod_settings, "prod", REPO_SLUG),
        "config_read_prod_preview": _ci_config_read_role_name(
            prod_settings, "prod-preview", REPO_SLUG
        ),
    }


def test_referenced_role_names_match_governance_rendered_names() -> None:
    """Role names named in the template are byte-equal to the rendered ones.

    The template documents (in comments / evidence) which governance roles it
    consumes. Whatever ``GitHubCi*-user-service-...`` role names it names MUST be
    byte-equal to the names the governance component renders for this repo —
    otherwise the operator-set repo variables would point at non-existent roles.
    A ``user-service`` short-name reference fails this test.
    """
    text = _workflow_text()
    rendered = _rendered_governance_role_names()

    # The template references at least the apply + config-read role names so the
    # parity assertion has teeth (single source of truth).
    assert rendered["apply_test"] in text  # nosec B101
    assert rendered["config_read_test"] in text  # nosec B101

    # Every governance role name appearing in the template must be a rendered name.
    # Tokens are stripped of surrounding prose punctuation (a role name may end a
    # comment sentence, e.g. ``...-test.``) before the byte-equality check.
    rendered_names = set(rendered.values())
    for line in text.splitlines():
        for raw_token in line.replace("`", " ").replace(",", " ").split():
            token = raw_token.strip(".()[]'\";:")
            if token.startswith("GitHubCi"):
                assert token in rendered_names, (  # nosec B101
                    f"template names governance role {token!r} which does not "
                    "match any rendered governance role name (name-parity drift)"
                )


@pytest.mark.parametrize(
    "malformed_role", ["GitHubCiApply-user-svc-prod", "GitHubCiDrift-other-test"]
)
def test_malformed_role_without_service_substring_fails_parity(
    monkeypatch, malformed_role
) -> None:
    """Unexpected GitHubCi tokens cannot evade parity through a different slug."""
    template = _workflow_text() + f"\n# {malformed_role}\n"
    monkeypatch.setattr(sys.modules[__name__], "_workflow_text", lambda: template)
    with pytest.raises(AssertionError, match="name-parity drift"):
        test_referenced_role_names_match_governance_rendered_names()


def test_short_name_reference_would_fail_parity() -> None:
    """A ``user-service`` short-name role is NOT a rendered governance name.

    Guards the parity test itself: the short-name a mistaken template might use
    (``GitHubCiApply-user-service-test``) must be absent from the rendered set,
    so the parity check above would reject it.
    """
    rendered_names = set(_rendered_governance_role_names().values())

    assert "GitHubCiApply-user-service-test" not in rendered_names  # nosec B101
    assert (  # nosec B101
        "GitHubCiConfigRead-user-service-test" not in rendered_names
    )


def test_template_carries_no_static_aws_keys_via_file_scan() -> None:
    """File-level scan: the workflow file holds no static AWS key material."""
    text = WORKFLOW_PATH.read_text()

    # No access-key-id value prefix anywhere in the deployable workflow file.
    assert "AKIA" not in text  # nosec B101


def test_scheduled_drift_uses_only_protected_main_read_roles():
    """Scheduled runs cannot enter comment apply or promotion jobs."""
    dispatch = _workflow_document()
    workflow = yaml.safe_load(
        (WORKFLOW_PATH.parent / "scheduled-drift.yml").read_text()
    )
    assert set(workflow[True]) == {"schedule"}
    assert workflow[True]["schedule"] == [{"cron": "17 3 * * *"}]
    assert set(dispatch[True]) == {"repository_dispatch"}
    assert set(workflow["jobs"]) == {
        "scheduled_test_drift",
        "scheduled_prod_drift",
    }
    assert not set(workflow["jobs"]) & set(dispatch["jobs"])
    assert workflow["name"] == "Service Scheduled Drift"
    assert dispatch["name"] == "Service Self Deploy"
    assert "needs.preflight" not in str(workflow)
    assert "client_payload" not in str(workflow)
    assert (
        dispatch["jobs"]["preflight"]["if"]
        == "github.event_name == 'repository_dispatch'"
    )
    for environment in ("test", "prod"):
        job = workflow["jobs"][f"scheduled_{environment}_drift"]
        assert (
            job["if"]
            == "github.event_name == 'schedule' && github.ref == 'refs/heads/main'"
        )
        assert job["environment"] == f"{environment}-drift"
        assert "needs" not in job
        assert job["permissions"]["id-token"] == "write"
        steps = job["steps"]
        checkouts = [
            step
            for step in steps
            if step.get("uses", "").startswith("actions/checkout@")
        ]
        assert all(step["with"]["ref"] == "${{ github.sha }}" for step in checkouts)
        guard_index = next(
            i
            for i, step in enumerate(steps)
            if step.get("name")
            == "Verify trusted scheduled revision before credentials"
        )
        loader_index = next(
            i for i, step in enumerate(steps) if step.get("id") == "ci_config"
        )
        assert guard_index < loader_index
        loader = steps[loader_index]["with"]
        assert loader["environment"] == (
            "prod-preview" if environment == "prod" else "test"
        )
        role_variable = (
            "AWS_PROD_PREVIEW_CI_CONFIG_ROLE_ARN"
            if environment == "prod"
            else "AWS_TEST_CI_CONFIG_ROLE_ARN"
        )
        assert loader["config-role-arn"] == "${{ vars." + role_variable + " }}"
        assert "AWS_DRIFT_ROLE_ARN" in loader["required-keys"]
        assert "AWS_APPLY_ROLE_ARN" not in loader["required-keys"]
        role = next(
            step
            for step in steps
            if step.get("uses", "").startswith("aws-actions/configure-aws-credentials@")
        )
        assert (
            role["with"]["role-to-assume"]
            == "${{ steps.ci_config.outputs.aws-drift-role-arn }}"
        )
        assert (
            role["with"]["allowed-account-ids"]
            == "${{ vars.AWS_" + environment.upper() + "_ACCOUNT_ID }}"
        )
        assert steps[-1]["run"] == "make test-drift"
        assert "pulumi-up" not in str(job) and "deployments: write" not in str(job)


def test_pr_destructive_gates_exclude_scheduled_execution():
    """PR-head gates explicitly exclude schedule even before needs resolution."""
    jobs = _workflow_document()["jobs"]
    dispatch = "github.event_name == 'repository_dispatch'"
    for environment in ("test", "prod"):
        job = jobs[f"{environment}_destructive_diff"]
        expected = dispatch
        if environment == "prod":
            expected += " && needs.preflight.outputs.target_environment == 'prod'"
        assert " ".join(job.get("if", "").split()) == expected
        assert "preflight" in job["needs"]
        assert f"{environment}_preview" in job["needs"]


def test_state_operations_share_cross_workflow_stack_mutex():
    """A cron drift and a PR state operation cannot hold the same stack at once."""

    def load(name):
        return yaml.safe_load((SCAFFOLD_DIR / ".github/workflows" / name).read_text())

    workflows = {
        name: load(name) for name in ("self-deploy.yml", "scheduled-drift.yml")
    }
    operations = {"make pulumi-plan", "make pulumi-up-plan", "make test-drift"}
    state_jobs = {
        name: (workflow, job)
        for workflow in workflows.values()
        for name, job in workflow["jobs"].items()
        if any(
            operations.intersection(step.get("run", "").splitlines())
            for step in job["steps"]
        )
    }
    assert set(state_jobs) == {
        "test_preview",
        "test_apply",
        "test_post_apply_drift",
        "prod_preview",
        "prod_apply",
        "prod_post_apply_drift",
        "scheduled_test_drift",
        "scheduled_prod_drift",
    }
    groups = {}
    for name, (workflow, job) in state_jobs.items():
        environment = "test" if "test" in name else "prod"
        group = (
            "pulumi-state-${{ github.repository }}-" + environment + "-" + environment
        )
        assert job["concurrency"] == {"group": group, "cancel-in-progress": False}
        assert workflow["concurrency"]["group"] != group
        if name.startswith("scheduled_"):
            assert job["environment"] == environment + "-drift"
        else:
            assert job["environment"] in {environment, environment + "-preview"}
        groups.setdefault(environment, set()).add(group)
    assert len(groups["test"]) == len(groups["prod"]) == 1
    assert groups["test"].isdisjoint(groups["prod"])


_PR_CREDENTIAL_JOB_CASES = [
    (path, job_id)
    for path in (WORKFLOW_PATH,)
    for job_id, job in yaml.safe_load(path.read_text())["jobs"].items()
    if any(
        step.get("uses", "").startswith("aws-actions/configure-aws-credentials@")
        for step in job.get("steps", [])
    )
]


@pytest.mark.parametrize("workflow_path,job_id", _PR_CREDENTIAL_JOB_CASES)
@pytest.mark.parametrize(
    "change,accepted",
    [
        ("none", True),
        ("retarget", False),
        ("base_moved", False),
        ("base_missing", False),
        ("head_moved", False),
        ("closed", False),
        ("merged", False),
        ("checkout_moved", False),
    ],
)
def test_credential_jobs_recheck_authenticated_pr_base(
    tmp_path, workflow_path, job_id, change, accepted
):
    """Execute each credential guard; moved PR metadata cannot reach credentials."""
    assert {name for _, name in _PR_CREDENTIAL_JOB_CASES} == {
        f"{account}_{stage}"
        for account in ("test", "prod")
        for stage in ("preview", "apply", "post_apply_drift")
    }
    workflow = yaml.safe_load(workflow_path.read_text())
    assert (
        workflow["jobs"]["preflight"]["outputs"]["base_sha"]
        == "${{ steps.resolve.outputs.base_sha }}"
    )
    steps = workflow["jobs"][job_id]["steps"]
    guard = next(
        s
        for s in steps
        if s.get("name") == "Recheck current PR head before credentials"
    )
    loader_index = next(
        i
        for i, s in enumerate(steps)
        if "load-aws-ci-env" in s.get("uses", "")
        or s.get("uses", "").startswith("aws-actions/configure-aws-credentials@")
    )
    assert steps.index(guard) < loader_index
    assert (
        guard["env"]["EXPECTED_BASE_SHA"] == "${{ needs.preflight.outputs.base_sha }}"
    )
    assert guard["env"]["EXPECTED_SHA"] == "${{ needs.preflight.outputs.head_sha }}"
    head, base = "a" * 40, "b" * 40
    payload = {
        "state": "open",
        "merged": False,
        "head": {"sha": head},
        "base": {"ref": "main", "sha": base},
    }
    if change == "retarget":
        payload["base"]["ref"] = "unprotected"
    elif change == "base_moved":
        payload["base"]["sha"] = "c" * 40
    elif change == "base_missing":
        del payload["base"]
    elif change == "head_moved":
        payload["head"]["sha"] = "c" * 40
    elif change == "closed":
        payload["state"] = "closed"
    elif change == "merged":
        payload["merged"] = True
    response = tmp_path / "pr.json"
    response.write_text(json.dumps(payload))
    tools = tmp_path / "bin"
    tools.mkdir()
    for name, body in {
        "gh": 'cat "$PR_RESPONSE_FILE"',
        "git": 'printf "%s\\n" "$CHECKOUT_SHA"',
    }.items():
        tool = tools / name
        tool.write_text("#!/bin/sh\n" + body + "\n")
        tool.chmod(0o755)
    marker = tmp_path / "credentials-reached"
    result = subprocess.run(
        [
            "bash",
            "--noprofile",
            "--norc",
            "-e",
            "-o",
            "pipefail",
            "-c",
            guard["run"] + '\nprintf ready > "$CREDENTIAL_MARKER"',
        ],
        env={
            "PATH": str(tools) + os.pathsep + os.environ["PATH"],
            "GH_TOKEN": "synthetic",
            "GITHUB_REPOSITORY": "org/repo",
            "PR_NUMBER": "39",
            "PR_RESPONSE_FILE": str(response),
            "EXPECTED_SHA": head,
            "EXPECTED_BASE_SHA": base,
            "CHECKOUT_SHA": "c" * 40 if change == "checkout_moved" else head,
            "CREDENTIAL_MARKER": str(marker),
        },
        capture_output=True,
        text=True,
        check=False,
    )
    assert (result.returncode == 0) is accepted, result.stderr
    assert marker.exists() is accepted


# Reuse the fake GitHub collector while executing the real central admission and
# worker validators. Service jobs above retain their separate shell protocol.
sys.path.insert(0, str(ROOT / "tests/unit"))
import deployment_worker_runtime as central_runtime  # noqa: E402
from deployment_controller_runtime import accept as central_accept  # noqa: E402
from test_deployment_controller_runtime import (  # noqa: E402
    github as _central_github_fixture,
)
from test_deployment_controller_runtime import (  # noqa: E402
    set_request,
)
from test_deployment_worker_recheck import root_run  # noqa: E402
from test_deployment_worker_runtime import make_zip  # noqa: E402

central_github = _central_github_fixture

CENTRAL_CREDENTIAL_JOBS = [
    (scope, name, job)
    for scope in ("operator", "governance", "platform")
    for name, job in yaml.safe_load(
        (ROOT / f".github/workflows/pulumi-{scope}-account.yml").read_text()
    )["jobs"].items()
    if any(
        step.get("uses", "").startswith("aws-actions/configure-aws-credentials@")
        for step in job.get("steps", [])
    )
]


@pytest.fixture
def central_artifact(central_github, monkeypatch):
    set_request(
        central_github, monkeypatch, scopes=("operator", "governance", "platform")
    )
    contract = central_accept()
    payload = central_github.contract.read_bytes()
    raw = make_zip([("contract.json", payload)])
    base = f"repos/{central_runtime.REPOSITORY}"
    central_github.overrides[f"{base}/actions/runs/100"] = root_run(contract)
    central_github.overrides[f"{base}/actions/artifacts/123"] = {
        "id": 123,
        "name": "deployment-selection-100-1",
        "expired": False,
        "digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
        "size_in_bytes": len(raw),
        "workflow_run": {
            "id": 100,
            "repository_id": central_runtime.REPOSITORY_ID,
            "head_repository_id": central_runtime.REPOSITORY_ID,
            "head_branch": "main",
            "head_sha": contract.identity.controller.sha,
        },
    }
    monkeypatch.setattr(central_runtime, "_download_zip", lambda identifier: raw)
    central_github.writes.clear()
    return {
        "artifact_id": "123",
        "artifact_sha256": hashlib.sha256(raw).hexdigest(),
        "contract_sha256": hashlib.sha256(payload).hexdigest(),
        "environment": "test",
    }


@pytest.mark.parametrize("scope,name,job", CENTRAL_CREDENTIAL_JOBS)
@pytest.mark.parametrize(
    "change",
    (
        "none",
        "retarget",
        "base_moved",
        "base_missing",
        "head_moved",
        "closed",
        "merged",
    ),
)
def test_central_precredential_recheck(
    central_artifact, central_github, scope, name, job, change
):
    """Actual account worker rechecks reject moved metadata before credentials."""
    assert len(CENTRAL_CREDENTIAL_JOBS) == 11
    steps = job["steps"]
    recheck = next(step for step in steps if step.get("id") == "recheck")
    credential_index = next(
        index
        for index, step in enumerate(steps)
        if step.get("uses", "").startswith("aws-actions/configure-aws-credentials@")
    )
    assert steps.index(recheck) < credential_index
    assert (
        'python3 -I "${GITHUB_WORKSPACE}/.trusted/scripts/deployment_worker_runtime.py"'
        in recheck["run"]
    )
    assert f"--scope {scope}" in recheck["run"]
    assert '--environment "${ACCOUNT}"' in recheck["run"]
    assert recheck["env"]["ACCOUNT"] == "${{ inputs.account }}"
    for variable, output in (
        ("CONTRACT_ARTIFACT_ID", "artifact_id"),
        ("CONTRACT_ARTIFACT_SHA256", "artifact_sha256"),
        ("CONTRACT_SHA256", "contract_sha256"),
    ):
        assert recheck["env"][variable] == "${{ inputs." + output + " }}"
    facts = central_github.evidence
    if change == "retarget":
        facts["pr"]["base"]["ref"] = "unprotected"
    elif change == "base_moved":
        facts["pr"]["base"]["sha"] = "c" * 40
        endpoint = f"repos/{central_runtime.REPOSITORY}/compare/{'c' * 40}...{'a' * 40}"
        central_github.overrides[endpoint] = {"files": facts["changed_file_records"]}
    elif change == "base_missing":
        del facts["pr"]["base"]
    elif change == "head_moved":
        facts["pr"]["head"]["sha"] = "c" * 40
    elif change == "closed":
        facts["pr"]["state"] = "closed"
    elif change == "merged":
        facts["pr"]["merged"] = True
    if change == "none":
        result = central_runtime.load_verified_contract(**central_artifact, scope=scope)
        assert scope in result.selection.stacks
    else:
        with pytest.raises((ValueError, KeyError)):
            central_runtime.load_verified_contract(**central_artifact, scope=scope)
    assert not central_github.writes


@pytest.mark.parametrize(
    "scope,name,job",
    [case for case in CENTRAL_CREDENTIAL_JOBS if case[0] != "operator"],
)
@pytest.mark.parametrize("moved", (False, True))
def test_central_exact_checkout_before_oidc(tmp_path, scope, name, job, moved):
    steps = job["steps"]
    guard = next(
        step for step in steps if step.get("name") == "Verify exact admitted checkout"
    )
    credential_index = next(
        index
        for index, step in enumerate(steps)
        if step.get("uses", "").startswith("aws-actions/configure-aws-credentials@")
    )
    assert steps.index(guard) < credential_index
    assert guard["env"]["EXPECTED_SHA"] == "${{ needs.resolve.outputs.head_sha }}"
    git = tmp_path / "git"
    git.write_text('#!/bin/sh\nprintf "%s\\n" "$CHECKOUT_SHA"\n')
    git.chmod(0o755)
    process = subprocess.run(
        ["bash", "-e", "-o", "pipefail", "-c", guard["run"]],
        cwd=tmp_path,
        env={
            "PATH": str(tmp_path) + ":" + os.environ["PATH"],
            "EXPECTED_SHA": "a" * 40,
            "CHECKOUT_SHA": ("b" if moved else "a") * 40,
        },
        capture_output=True,
        text=True,
        check=False,
    )
    assert (process.returncode == 0) is not moved
