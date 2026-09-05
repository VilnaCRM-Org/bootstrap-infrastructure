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

import sys
from pathlib import Path

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


def test_apply_uses_saved_plan_not_direct_up() -> None:
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
            if token.startswith("GitHubCi") and "user-service" in token:
                assert token in rendered_names, (  # nosec B101
                    f"template names governance role {token!r} which does not "
                    "match any rendered governance role name (name-parity drift)"
                )


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
