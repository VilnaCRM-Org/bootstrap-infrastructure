"""Doc contract: CI trust and PR-credential claims must match rendered source.

Every assertion ties a documentation statement to the workflow YAML, Makefile or
rendered IAM trust it describes, so a doc can no longer claim pull-request AWS
credentials, a Reviewed PR Preview role trust, or a credential-free
`make ci-pr` that the source does not implement.
"""

from __future__ import annotations

import inspect
import json
import re
from pathlib import Path

import yaml
from infra import ci_bootstrap, ci_config
from infra.bootstrap_settings import BootstrapSettings

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs"
WORKFLOWS = ROOT / ".github" / "workflows"
REPO = "VilnaCRM-Org/bootstrap-infrastructure"
PREFIX = "token.actions.githubusercontent.com:"
PROVIDER = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
MAIN_SUBJECT = f"repo:{REPO}:ref:refs/heads/main"
REVIEWED_SUBJECT = f"repo:{REPO}:environment:reviewed-pr-preview"
SUBJECT_TOKEN = re.compile(r"`(repo:[^`]+)`")


def _settings() -> BootstrapSettings:
    """Return the central repository's TEST bootstrap settings."""
    return BootstrapSettings(
        org="VilnaCRM-Org",
        repo="bootstrap-infrastructure",
        environment="test",
        owner="platform",
        cost_center="core",
        data_classification="internal",
        criticality="high",
        retention_class="standard",
        github_branch="main",
        logging_prefix="company",
        replication_region=None,
        github_token=None,
        github_oidc_provider_arn=PROVIDER,
        github_repository_id="1098568429",
        github_repository_owner_id="114362548",
    )


def _doc(name: str) -> str:
    """Return a docs page with whitespace normalized."""
    return " ".join((DOCS / name).read_text(encoding="utf-8").split())


def _raw(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _workflow(name: str) -> dict:
    return yaml.safe_load(_raw(WORKFLOWS / name))


def _triggers(workflow: dict) -> dict:
    return workflow.get("on", workflow.get(True, {}))


def _table_row(doc: str, prefix: str) -> str:
    rows = [line for line in doc.splitlines() if line.startswith(prefix)]
    assert len(rows) == 1, prefix  # nosec B101
    return rows[0]


def _reader_condition(suffix: str) -> dict:
    document = ci_config._ci_config_read_assume_role_policy(
        PROVIDER, _settings(), suffix
    )
    return json.loads(document)["Statement"][0]["Condition"]["StringEquals"]


def _preview_role_condition() -> dict:
    settings = _settings()
    document = ci_bootstrap._deployment_assume_role_policy(
        PROVIDER,
        REPO,
        ci_bootstrap._deployment_role_subjects(settings, "preview"),
        repository_id=settings.github_repository_id,
        owner_id=settings.github_repository_owner_id,
        branch_ref=None,
    )
    return json.loads(document)["Statement"][0]["Condition"]["StringEquals"]


def _make_recipe(target: str) -> list[str]:
    lines = _raw(ROOT / "Makefile").splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith(f"{target}:"))
    recipe = []
    for line in lines[start + 1 :]:
        if not line.startswith("\t"):
            break
        recipe.append(line.strip())
    return recipe


def _all_docs() -> dict[str, str]:
    paths = sorted(DOCS.glob("*.md")) + [ROOT / "README.md", ROOT / "AGENTS.md"]
    return {path.name: " ".join(_raw(path).split()) for path in paths}


# --- R3-1: Reviewed PR Preview row is tied to the rendered trust -------------


def test_rendered_trust_rejects_reviewed_pr_preview_subject_today() -> None:
    """Stage 1: neither the test-pr reader nor the preview role accepts it."""
    settings = _settings()
    reader_subjects = ci_config._github_actions_subjects(settings, "test-pr")
    role_subjects = ci_bootstrap._deployment_role_subjects(settings, "preview")
    assert reader_subjects == [MAIN_SUBJECT]  # nosec B101
    assert REVIEWED_SUBJECT not in reader_subjects  # nosec B101
    assert REVIEWED_SUBJECT not in role_subjects  # nosec B101
    assert not any(s.endswith(":pull_request") for s in reader_subjects + role_subjects)  # nosec B101
    reader = _reader_condition("test-pr")
    assert reader[PREFIX + "workflow"] == ["Reviewed PR Preview"]  # nosec B101
    preview = _preview_role_condition()
    assert PREFIX + "workflow" not in preview  # nosec B101
    assert PREFIX + "ref" not in preview  # nosec B101
    create_role = inspect.getsource(ci_bootstrap._create_role)
    assert "workflow_name" not in create_role  # nosec B101


def test_reviewed_workflow_presents_only_the_reviewed_environment_subject() -> None:
    workflow = _workflow("reviewed-pr-preview.yml")
    oidc_jobs = {
        job_id: job
        for job_id, job in workflow["jobs"].items()
        if job.get("permissions", {}).get("id-token") == "write"
    }
    assert set(oidc_jobs) == {"preview", "iam_validation"}  # nosec B101
    assert {job["environment"] for job in oidc_jobs.values()} == {  # nosec B101
        "reviewed-pr-preview"
    }
    admission_if = " ".join(workflow["jobs"]["admission"]["if"].split())
    assert "vars.REVIEWED_SOURCE_PREVIEW_ACTIVE == 'true'" in admission_if  # nosec B101


def test_bootstrap_reviewed_row_lists_exactly_the_rendered_subjects() -> None:
    """The row must state the rendered subjects, fail closed and name Stage 2."""
    settings = _settings()
    row = _table_row(
        _raw(DOCS / "github-ci-bootstrap-stack.md"),
        "| Reviewed PR Preview (`reviewed-pr-preview` environment) | `test-pr` |",
    )
    cells = [cell.strip() for cell in row.strip("|").split("|")]
    assert "AWS_PREVIEW_ROLE_ARN" not in cells[2]  # nosec B101
    assert "none today" in cells[2]  # nosec B101
    assert "dedicated" in cells[2]  # nosec B101
    expected = {
        *ci_config._github_actions_subjects(settings, "test-pr"),
        *ci_bootstrap._deployment_role_subjects(settings, "preview"),
        REVIEWED_SUBJECT,
    }
    assert set(SUBJECT_TOKEN.findall(row)) == expected  # nosec B101
    assert "fails closed" in row  # nosec B101
    assert "with no workflow claim" in row  # nosec B101
    assert "Stage 2" in row  # nosec B101
    assert "accept only `environment:reviewed-pr-preview`" in row  # nosec B101
    assert "never `pull_request`" in row  # nosec B101
    assert "trusts only a main-ref subject with the `Reviewed PR Preview`" not in row  # nosec B101


def test_bootstrap_push_main_guardrail_row_matches_test_reader() -> None:
    settings = _settings()
    assert MAIN_SUBJECT in ci_config._github_actions_subjects(settings, "test")  # nosec B101
    assert "Pulumi PR Guardrails" in _reader_condition("test")[PREFIX + "workflow"]  # nosec B101
    assert _reader_condition("test")[PREFIX + "ref"] == "refs/heads/main"  # nosec B101
    assert MAIN_SUBJECT in ci_bootstrap._deployment_role_subjects(settings, "preview")  # nosec B101
    row = _table_row(
        _raw(DOCS / "github-ci-bootstrap-stack.md"),
        "| PR guardrails preview / IAM validation (push to `main`) |",
    )
    assert "| `test` | `AWS_PREVIEW_ROLE_ARN` |" in row  # nosec B101
    assert f"`{MAIN_SUBJECT}`" in row  # nosec B101
    assert "`Pulumi PR Guardrails` workflow claim" in row  # nosec B101


# --- R3-4: the only reachable privileged guardrail path is push to main -----


def test_pr_guardrails_privileged_path_is_push_to_main_with_test_reader() -> None:
    workflow = _workflow("pulumi-pr-guardrails.yml")
    selector = workflow["jobs"]["preview_mode"]["steps"][0]["run"]
    assert 'if [[ "${GITHUB_EVENT_NAME}" == "pull_request" ]]; then' in selector  # nosec B101
    assert "privileged=false" in selector  # nosec B101
    assert set(_triggers(workflow)["push"]["branches"]) == {"main"}  # nosec B101
    target = next(
        step["run"]
        for step in workflow["jobs"]["preview"]["steps"]
        if step.get("id") == "ci_config_target"
    )
    assert 'ci_environment="test"' in target  # nosec B101
    doc = _doc("ci-guardrails.md")
    assert "The only reachable privileged path is push to `main`" in doc  # nosec B101
    assert "assume the TEST (`test`) CI configuration reader" in doc  # nosec B101
    assert (
        "Its privileged path first assumes the TEST PR CI configuration reader"
        not in doc
    )  # nosec B101
    assert "uses main-ref OIDC with the `test-pr` CI configuration" not in doc  # nosec B101


# --- R3-2 / I-8: ci-architecture row -----------------------------------------


def test_ci_architecture_row_scopes_real_preview_to_main_and_saved_plans() -> None:
    row = _table_row(
        _raw(DOCS / "ci-architecture.md"), "| `pulumi-pr-guardrails.yml` |"
    )
    commands = row.split("|")[2]
    workflow_text = _raw(WORKFLOWS / "pulumi-pr-guardrails.yml")
    for command in re.findall(r"`(make [a-z-]+)`", commands):
        assert command in workflow_text  # nosec B101
    assert "Push to `main`:" in commands and "Pull requests:" in commands  # nosec B101
    summary = _raw(ROOT / "scripts" / "publish_pulumi_preview_summary.py")
    assert '["make", "test-preview"]' in summary  # nosec B101
    assert "`/pulumi <env> plan`" in row  # nosec B101
    assert "only once its Stage 2 cutover is enrolled" in row  # nosec B101
    assert "and in the protected Reviewed PR Preview |" not in row  # nosec B101


# --- R3-3: security baseline and Well-Architected evidence -------------------


def test_security_baseline_does_not_claim_pr_preview_artifacts() -> None:
    doc = _doc("security-baseline.md")
    assert "Every infrastructure PR now produces a Pulumi preview artifact" not in doc  # nosec B101
    assert "produce only the unprivileged placeholder preview artifact" in doc  # nosec B101
    assert (
        "The same preview artifact is reused for destructive-change gating" not in doc
    )  # nosec B101


def test_well_architected_workflows_match_their_documented_credentials() -> None:
    data = _workflow("well-architected-evidence.yml")
    assert "pull_request" in _triggers(data)  # nosec B101
    assert "id-token" not in _raw(WORKFLOWS / "well-architected-evidence.yml")  # nosec B101
    trusted = _workflow("trusted-well-architected.yml")
    assert set(_triggers(trusted)) == {"workflow_dispatch"}  # nosec B101
    for job in trusted["jobs"].values():
        assert "github.ref == 'refs/heads/main'" in job["if"]  # nosec B101
    collect = trusted["jobs"]["collect"]
    assert "environment" not in collect  # nosec B101
    assert collect["permissions"]["id-token"] == "write"  # nosec B101
    assert "config-role-arn" not in _raw(WORKFLOWS / "trusted-well-architected.yml")  # nosec B101
    publisher = _raw(ROOT / "scripts" / "_well_architected_publisher.py")
    assert "role/GitHubCiPreview-[A-Za-z0-9+=,.@_-]+-test" in publisher  # nosec B101
    guardrails = _doc("ci-guardrails.md")
    assert "real test-account OIDC role for trusted PRs" not in guardrails  # nosec B101
    assert "The trusted PR and push path is enforced" not in guardrails  # nosec B101
    assert (
        "The hosted Well-Architected Evidence workflow runs the verifier"
        not in guardrails
    )  # nosec B101
    assert (
        "No pull-request workflow runs this collector with AWS credentials."
        in guardrails
    )  # nosec B101
    for workflow_file in WORKFLOWS.glob("*.yml"):
        text = _raw(workflow_file)
        assert "verify-well-architected-questions" not in text  # nosec B101
        assert "report-well-architected-closeout" not in text  # nosec B101
    bootstrap = _raw(DOCS / "github-ci-bootstrap-stack.md")
    assert "| Well-Architected evidence | `test-pr`" not in bootstrap  # nosec B101
    row = _table_row(
        bootstrap,
        "| Well-Architected Data Validation (`well-architected-evidence.yml`) |",
    )
    assert "| none | none |" in row  # nosec B101


def test_trust_contract_doc_matches_rendered_test_pr_subjects() -> None:
    doc = _doc("ci-config-trust-contract.md")
    assert "`test-pr` intentionally retains pull-request subjects" not in doc  # nosec B101
    assert f"`{MAIN_SUBJECT}`" in doc  # nosec B101
    assert ci_config._github_actions_subjects(_settings(), "test-pr") == [MAIN_SUBJECT]  # nosec B101
    assert PREFIX + "ref" not in _reader_condition("test-pr")  # nosec B101
    assert "`test-pr` has no main-branch ref condition" in doc  # nosec B101


# --- R3-5: make ci-pr is the credentialed superset ---------------------------


def test_make_ci_pr_is_documented_as_credentialed_superset() -> None:
    ci_pr = _make_recipe("ci-pr")
    unprivileged = _make_recipe("ci-pr-unprivileged")
    assert "$(MAKE) test-guardrails" in ci_pr  # nosec B101
    assert "$(MAKE) test-guardrails" not in unprivileged  # nosec B101
    assert "$(MAKE) test-guardrails-unprivileged" in unprivileged  # nosec B101
    assert _make_recipe("test-guardrails")[0] == "$(MAKE) test-preview"  # nosec B101
    local = _raw(WORKFLOWS / "pulumi-local.yml")
    assert 'if [[ "${PULUMI_ENABLE_AUTOMATION_STACK_TESTS}" == "true" ]]; then' in local  # nosec B101
    makefile = _raw(ROOT / "Makefile")
    assert "ci-pr: ## Run the credentialed local superset" in makefile  # nosec B101
    assert "Run the GitHub PR battery except" not in makefile  # nosec B101
    stale = [
        r"`make ci-pr` (mirrors|is the canonical local equivalent|backs the required)",
        r"`make ci-pr` when you want the non-mutation GitHub PR battery",
        r"For the full non-mutation PR battery: ```bash make ci-pr ```",
        r"ci-pr +Run the non-mutation GitHub pull-request battery",
        r"`make test-guardrails`[^.]{0,160}"
        r"without (requiring )?(live )?AWS credentials",
        r"credential-free PR preview flow locally, use: "
        r"```bash make test-guardrails ```",
    ]
    for name, text in _all_docs().items():
        for pattern in stale:
            assert not re.search(pattern, text), (name, pattern)  # nosec B101


# --- R3-6: policy pack scope and integration gating --------------------------


def test_policy_pack_scope_matches_preview_and_integration_sources() -> None:
    preview_script = _raw(ROOT / "scripts" / "run_pulumi_preview.py")
    assert '"--policy-pack",' in preview_script  # nosec B101
    integration = _raw(WORKFLOWS / "pulumi-integration.yml")
    assert "make test-integration-unprivileged" in integration  # nosec B101
    unprivileged = " ".join(_make_recipe("test-integration-unprivileged"))
    assert "test_policy_pack_enforcement.py" not in unprivileged  # nosec B101
    doc = _doc("pulumi-guardrails.md")
    assert (
        "For pull requests the pack evaluates real changes only at saved-plan time"
        in doc
    )  # nosec B101
    assert "`make test-preview` also passes `--policy-pack`" in doc  # nosec B101
    assert "`PULUMI_ENABLE_AUTOMATION_STACK_TESTS` repository variable is `true`" in doc  # nosec B101
    assert "are caught before merge." not in doc  # nosec B101


# --- I-3 / I-4 / I-5 ----------------------------------------------------------


def test_security_operating_evidence_names_push_path_subject() -> None:
    doc = _doc("security-operating-evidence.md")
    assert f"present `{MAIN_SUBJECT}`" in doc  # nosec B101
    assert "Environment-scoped OIDC trust using" not in doc  # nosec B101
    assert "pull requests request no OIDC token" in doc  # nosec B101


def test_cutover_validation_list_names_real_loader_workflows() -> None:
    names = {yaml.safe_load(_raw(path))["name"] for path in WORKFLOWS.glob("*.yml")}
    text = _raw(DOCS / "aws-secrets-manager-ci-cutover.md")
    section = text.split("## Validate", 1)[1].split("Expected loader summary", 1)[0]
    listed = re.findall(r"^- `([^`]+)`", section, flags=re.MULTILINE)
    assert listed  # nosec B101
    for name in listed:
        assert name in names, name  # nosec B101
        path = next(
            p
            for p in WORKFLOWS.glob("*.yml")
            if yaml.safe_load(_raw(p))["name"] == name
        )
        assert "load-aws-ci-env" in _raw(path), name  # nosec B101
    assert "`Well-Architected Evidence`" not in section  # nosec B101


def test_compensating_controls_list_every_platform_apply_gate() -> None:
    row = _table_row(
        _raw(DOCS / "well-architected-operating-evidence.md"),
        "| P0 | Keep infrastructure changes reviewable and reversible.",
    )
    gates = row.split("IAM Access Analyzer gates in", 1)[1].split("(", 1)[0]
    files = re.findall(r"`([a-z-]+\.yml)`", gates)
    assert "pulumi-prod.yml" in files  # nosec B101
    for name in files:
        text = _raw(WORKFLOWS / name)
        assert "make test-destructive-diff" in text, name  # nosec B101
        assert "make test-iam-validation" in text, name  # nosec B101
        assert "make pulumi-up-plan" in text, name  # nosec B101
    for path in WORKFLOWS.glob("*.yml"):
        text = _raw(path)
        if "make pulumi-up-plan" in text:
            assert path.name in files, path.name  # nosec B101


# --- I-7: no doc maps Reviewed PR Preview to test-preview or a PR role -------


def test_no_doc_maps_reviewed_preview_to_test_preview_or_a_pr_role() -> None:
    patterns = [
        r"`test-preview`[^.;|]{0,200}Reviewed PR Preview",
        r"Reviewed PR Preview[^.;|]{0,200}`test-preview`",
        r"(?i)bounded PR role",
        r"(?i)\bPR (preview |config[a-z-]* )?role\b",
        r"(?i)\btrusted PRs\b",
        r"Reviewed PR Preview[^|]{0,120}\| `test-pr` \| `AWS_PREVIEW_ROLE_ARN`",
    ]
    for name, text in _all_docs().items():
        for pattern in patterns:
            assert not re.search(pattern, text), (name, pattern)  # nosec B101
    sre = _raw(DOCS / "sre-operations.md")
    section = sre.split("## GitHub Environment Operations", 1)[1]
    block = section[section.index("\n- ") :].split("\n\n", 1)[0]
    bullets = [" ".join(b.split()) for b in block.split("\n- ")]
    test_preview = [b for b in bullets if b.lstrip("- ").startswith("`test-preview`")]
    reviewed = [
        b for b in bullets if b.lstrip("- ").startswith("`reviewed-pr-preview`")
    ]
    assert len(test_preview) == 1 and "Reviewed" not in test_preview[0]  # nosec B101
    assert len(reviewed) == 1 and "fail closed" in reviewed[0]  # nosec B101
    assert "assumes the `test-pr` CI configuration" not in reviewed[0]  # nosec B101
