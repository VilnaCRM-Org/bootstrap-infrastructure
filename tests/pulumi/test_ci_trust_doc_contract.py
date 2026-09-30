"""Doc contract: CI trust and PR-credential claims must match rendered source.

Every assertion ties a documentation statement to the workflow YAML, Makefile or
rendered IAM trust it describes, so a doc can no longer claim pull-request AWS
credentials, a Reviewed PR Preview role trust, or a credential-free
`make ci-pr` that the source does not implement.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from types import SimpleNamespace

import pytest
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


class _RoleCaptured(Exception):
    """Stop `_create_role` once the real trust policy has been rendered."""


def _created_role_condition(monkeypatch: pytest.MonkeyPatch, purpose: str) -> dict:
    """Render one TEST CI role trust exactly as `_create_role` builds it."""
    captured: dict = {}

    def fake_role(_name: str, **kwargs: object) -> None:
        captured.update(kwargs)
        raise _RoleCaptured

    monkeypatch.setattr(
        ci_bootstrap.pulumi.Output, "from_input", staticmethod(lambda value: value)
    )
    monkeypatch.setattr(ci_bootstrap, "apply_output", lambda arn, fn: fn(arn))
    monkeypatch.setattr(
        ci_bootstrap, "_role_permissions_boundary", lambda *_a, **_k: None
    )
    monkeypatch.setattr(ci_bootstrap, "_iam_role_exists", lambda _name: False)
    monkeypatch.setattr(ci_bootstrap.aws.iam, "Role", fake_role)
    settings = _settings()
    context = SimpleNamespace(
        settings=settings,
        repo=settings.repo,
        project=None,
        name="ci",
        account_id="123456789012",
        partition="aws",
        external_role_boundaries=None,
        provider_arn=PROVIDER,
        parent=None,
        protect_resources=False,
    )
    spec = ci_bootstrap._CiRoleSpec(
        purpose,
        f"GitHubCi{purpose.title()}-bootstrap-test",
        ci_bootstrap._deployment_role_subjects(settings, purpose),
        [],
    )
    with pytest.raises(_RoleCaptured):
        ci_bootstrap._create_role(context, spec)
    document = json.loads(captured["assume_role_policy"])
    return document["Statement"][0]["Condition"]["StringEquals"]


def _created_preview_role_condition(monkeypatch: pytest.MonkeyPatch) -> dict:
    return _created_role_condition(monkeypatch, "preview")


def _make_recipe(target: str) -> list[str]:
    lines = _raw(ROOT / "Makefile").splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith(f"{target}:"))
    recipe = []
    for line in lines[start + 1 :]:
        if not line.startswith("\t"):
            break
        recipe.append(line.strip())
    return recipe


def _make_closure(target: str) -> set[str]:
    """Return every make target reachable from `target` through `$(MAKE)` calls."""
    seen: set[str] = set()
    pending = [target]
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        seen.add(current)
        for step in _make_recipe(current):
            match = re.fullmatch(r"\$\(MAKE\) ([a-z][a-z0-9-]*)", step)
            if match:
                pending.append(match.group(1))
    return seen


def _gated_targets(workflow_name: str) -> tuple[str, str]:
    """Return (variable true, otherwise) make targets from the gated run block."""
    gated = [
        step["run"]
        for job in _workflow(workflow_name)["jobs"].values()
        for step in job["steps"]
        if "PULUMI_ENABLE_AUTOMATION_STACK_TESTS" in step.get("run", "")
    ]
    assert len(gated) == 1, workflow_name  # nosec B101
    lines = [line.strip() for line in gated[0].strip().splitlines()]
    assert lines[0] == (  # nosec B101
        'if [[ "${PULUMI_ENABLE_AUTOMATION_STACK_TESTS}" == "true" ]]; then'
    )
    assert lines[2] == "else" and lines[4] == "fi" and len(lines) == 5  # nosec B101
    return lines[1], lines[3]


def _flat_quote(path: Path) -> str:
    """Flatten a blockquote so wrapping and `> ` markers cannot hide a phrase."""
    lines = [re.sub(r"^>\s?", "", line) for line in _raw(path).splitlines()]
    return " ".join(" ".join(lines).split())


def _all_docs() -> dict[str, str]:
    paths = sorted(DOCS.rglob("*.md")) + [ROOT / "README.md", ROOT / "AGENTS.md"]
    return {path.name: " ".join(_raw(path).split()) for path in paths}


# --- R3-1: Reviewed PR Preview row is tied to the rendered trust -------------


def test_rendered_trust_rejects_reviewed_pr_preview_subject_today(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
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
    preview = _created_preview_role_condition(monkeypatch)
    assert PREFIX + "workflow" not in preview  # nosec B101
    assert PREFIX + "ref" not in preview  # nosec B101
    immutable = (
        "repo:VilnaCRM-Org@114362548/bootstrap-infrastructure@1098568429:"
        "environment:reviewed-pr-preview"
    )
    for subject in (REVIEWED_SUBJECT, immutable):
        assert subject not in preview[PREFIX + "sub"]  # nosec B101
        assert subject not in reader[PREFIX + "sub"]  # nosec B101
    assert any("@1098568429:" in sub for sub in preview[PREFIX + "sub"])  # nosec B101
    assert any("@1098568429:" in sub for sub in reader[PREFIX + "sub"])  # nosec B101


def test_test_pr_payload_preview_role_is_the_shared_preview_role() -> None:
    """The reviewed route would assume the shared role until Stage 2."""
    settings = _settings()
    context = SimpleNamespace(
        settings=settings,
        account_id="123456789012",
        partition="aws",
        region="eu-central-1",
    )
    overrides = ci_bootstrap._PayloadOverrides(
        role_arns={
            "preview": "arn:aws:iam::123456789012:role/GitHubCiPreview-x-test",
            "apply": "arn:aws:iam::123456789012:role/GitHubCiApply-x-test",
            "drift": "arn:aws:iam::123456789012:role/GitHubCiDrift-x-test",
        },
        operations_alert_triage_role_arn="arn:aws:iam::123456789012:role/Triage",
        pulumi_backend_url=None,
        pulumi_dir="pulumi",
        pulumi_secrets_provider=None,
    )
    payloads = ci_bootstrap._payloads(context, overrides)
    shared = overrides.role_arns["preview"]
    assert payloads["test-pr"]["AWS_PREVIEW_ROLE_ARN"] == shared  # nosec B101
    assert payloads["test"]["AWS_PREVIEW_ROLE_ARN"] == shared  # nosec B101
    assert "AWS_APPLY_ROLE_ARN" not in payloads["test-pr"]  # nosec B101
    workflow = _raw(WORKFLOWS / "reviewed-pr-preview.yml")
    assert "role-to-assume: ${{ steps.ci_config.outputs.aws-preview-role-arn }}" in (  # nosec B101
        workflow
    )


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
    assert cells[2].startswith(  # nosec B101
        "`AWS_PREVIEW_ROLE_ARN` from the `test-pr` payload"
    )
    assert "unreachable in Stage 1" in cells[2]  # nosec B101
    assert "Stage 2: dedicated TEST reviewed-preview role" in cells[2]  # nosec B101
    assert "immutable-ID form" in row  # nosec B101
    expected = {
        *ci_config._github_actions_subjects(settings, "test-pr"),
        *ci_bootstrap._deployment_role_subjects(settings, "preview"),
        REVIEWED_SUBJECT,
    }
    assert set(SUBJECT_TOKEN.findall(row)) == expected  # nosec B101
    flat = " ".join(row.split())
    reader_text = flat.split("The `test-pr` config reader trusts only", 1)[1].split(
        ", and the shared TEST", 1
    )[0]
    role_text = flat.split("the shared TEST `AWS_PREVIEW_ROLE_ARN` trusts only", 1)[
        1
    ].split("with no workflow claim", 1)[0]
    assert set(SUBJECT_TOKEN.findall(reader_text)) == set(  # nosec B101
        ci_config._github_actions_subjects(settings, "test-pr")
    )
    assert set(SUBJECT_TOKEN.findall(role_text)) == set(  # nosec B101
        ci_bootstrap._deployment_role_subjects(settings, "preview")
    )
    assert REVIEWED_SUBJECT not in reader_text + role_text  # nosec B101
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
        if command == "make test-preview":
            continue  # reached through publish-pulumi-preview-summary below
        exact = rf"(?<![-\w]){re.escape(command)}(?![-\w])"
        assert re.search(exact, workflow_text), command  # nosec B101
    assert "Push to `main`:" in commands and "Pull requests:" in commands  # nosec B101
    summary = _raw(ROOT / "scripts" / "publish_pulumi_preview_summary.py")
    assert '["make", "test-preview"]' in summary  # nosec B101
    assert "`/pulumi <env> plan`" in row  # nosec B101
    assert "only once its Stage 2 cutover is enrolled" in row  # nosec B101
    assert "and in the protected Reviewed PR Preview |" not in row  # nosec B101


# --- R3-3: security baseline and Well-Architected evidence -------------------


def test_security_baseline_does_not_claim_pr_preview_artifacts() -> None:
    doc = _doc("security-baseline.md")
    guardrails = _workflow("pulumi-pr-guardrails.yml")
    selector = guardrails["jobs"]["preview_mode"]["steps"][0]["run"]
    assert "privileged=false" in selector  # nosec B101
    assert 'if [[ "${GITHUB_EVENT_NAME}" == "pull_request" ]]; then' in selector  # nosec B101
    assert "id-token" not in json.dumps(  # nosec B101
        _workflow("pulumi-pr-guardrails.yml")["jobs"]["preview_mode"]
    )
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


# --- R3-5: make ci-pr is the credentialed variant, not a superset ------------


def test_make_ci_pr_is_a_credentialed_variant_not_a_superset() -> None:
    """`ci-pr` runs a real preview but never reaches IAM-input extraction."""
    ci_pr = _make_closure("ci-pr")
    unprivileged = _make_closure("ci-pr-unprivileged")
    assert "test-iam-validation-unprivileged" in unprivileged  # nosec B101
    assert "test-iam-validation-unprivileged" not in ci_pr  # nosec B101
    assert "test-iam-validation" not in ci_pr | unprivileged  # nosec B101
    assert "test-preview" in ci_pr - unprivileged  # nosec B101
    assert "test-preview-unprivileged" in unprivileged - ci_pr  # nosec B101
    ci = _make_closure("ci")
    assert ci == ci_pr | {"ci", "test-mutation"} | _make_closure("test-mutation")  # nosec B101
    assert "test-mutation" not in ci_pr | unprivileged  # nosec B101
    makefile = _raw(ROOT / "Makefile")
    assert "ci-pr: ## Run the credentialed local variant" in makefile  # nosec B101
    assert "no IAM-input extraction" in makefile  # nosec B101
    assert "ci: ## Run make ci-pr (needs AWS credentials)" in makefile  # nosec B101
    for name in ("testing.md", "sre-operations.md", "ci-quality-gates.md"):
        flat = " ".join(_doc(name).split())
        assert re.search(r"omits (the )?IAM-input extraction", flat), name  # nosec B101
    for name, text in _all_docs().items():
        assert "superset" not in text.lower(), name  # nosec B101
        assert not re.search(  # nosec B101
            r"full local equivalent of (all|every) GitHub check", text
        ), name


def test_make_ci_pr_is_documented_as_credentialed_variant() -> None:
    ci_pr = _make_recipe("ci-pr")
    unprivileged = _make_recipe("ci-pr-unprivileged")
    assert "$(MAKE) test-guardrails" in ci_pr  # nosec B101
    assert "$(MAKE) test-guardrails" not in unprivileged  # nosec B101
    assert "$(MAKE) test-guardrails-unprivileged" in unprivileged  # nosec B101
    assert _make_recipe("test-guardrails")[0] == "$(MAKE) test-preview"  # nosec B101
    assert _gated_targets("pulumi-local.yml") == (  # nosec B101
        "make ci-pr",
        "make ci-pr-unprivileged",
    )
    makefile = _raw(ROOT / "Makefile")
    assert "Run the GitHub PR battery except" not in makefile  # nosec B101
    assert "full local equivalent of all GitHub checks" not in makefile  # nosec B101
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
    assert _gated_targets("pulumi-integration.yml") == (  # nosec B101
        "make test-integration",
        "make test-integration-unprivileged",
    )
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
    guardrails = _workflow("pulumi-pr-guardrails.yml")
    assert set(_triggers(guardrails)["push"]["branches"]) == {"main"}  # nosec B101
    assert MAIN_SUBJECT in ci_bootstrap._deployment_role_subjects(  # nosec B101
        _settings(), "preview"
    )
    assert "pull_request" in _triggers(guardrails)  # nosec B101
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
        r"Reviewed PR Preview[^|]{0,120}\| `test-pr` \| `AWS_PREVIEW_ROLE_ARN` \|",
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


# --- audit follow-ups: boundaries, "never runs" claims, specs banners ---------


def test_preview_role_boundary_row_lists_every_rendered_test_subject() -> None:
    row = _table_row(_raw(DOCS / "security-operating-evidence.md"), "| Preview role |")
    for subject in ci_bootstrap._deployment_role_subjects(_settings(), "preview"):
        suffix = subject.split(f"repo:{REPO}:", 1)[1]
        label = "`main` ref" if suffix == "ref:refs/heads/main" else f"`{suffix}`"
        assert label in row, suffix  # nosec B101
    assert "no workflow or ref claim condition" in row  # nosec B101
    assert "deployment-branch policies" in row  # nosec B101


def test_test_preview_claims_name_the_workflow_and_local_battery_gate() -> None:
    guardrails = _raw(WORKFLOWS / "pulumi-pr-guardrails.yml")
    assert "make test-preview-unprivileged" in guardrails  # nosec B101
    assert "make publish-pulumi-preview-summary" in guardrails  # nosec B101
    for name, text in _all_docs().items():
        assert "On pull requests `make test-preview` never runs" not in text, name  # nosec B101
        assert "pull requests never run `make test-preview`" not in text, name  # nosec B101
    for doc in ("pulumi-guardrails.md", "testing.md"):
        text = _doc(doc)
        assert "`Pulumi PR Guardrails` never runs `make test-preview`" in text  # nosec B101
        assert "leave that variable unset for pull-request CI" in text  # nosec B101
    main = _raw(ROOT / "pulumi" / "__main__.py")
    assert "aws.get_caller_identity()" in main  # nosec B101
    assert "awskms://" in _raw(ROOT / "pulumi" / "Pulumi.test.yaml")  # nosec B101


def test_real_preview_lists_include_main_dispatched_production() -> None:
    prod = _workflow("pulumi-prod.yml")
    assert set(_triggers(prod)) == {"workflow_dispatch"}  # nosec B101
    assert "make test-iam-validation" in _raw(WORKFLOWS / "pulumi-prod.yml")  # nosec B101
    checks = {
        "ci-guardrails.md": "`main`-dispatched `Pulumi Production` preview",
        "ci-architecture.md": "`main`-dispatched `Pulumi Production` preview",
        "security-baseline.md": "`main`-dispatched `Pulumi Production` preview",
    }
    for doc, phrase in checks.items():
        assert phrase in _doc(doc), doc  # nosec B101
    cost_proxy_users = [
        path.name
        for path in WORKFLOWS.glob("*.yml")
        if "make test-cost-proxy" in _raw(path)
    ]
    assert set(cost_proxy_users) == {  # nosec B101
        "pulumi-pr-guardrails.yml",
        "reviewed-pr-preview.yml",
    }
    assert "`Pulumi PR Guardrails` push-to-`main` preview artifact also feeds" in (  # nosec B101
        _doc("security-baseline.md")
    )


def test_test_guardrails_description_matches_recipe() -> None:
    recipe = _make_recipe("test-guardrails")
    assert not any("iam" in step for step in recipe)  # nosec B101
    assert any("iam" in step for step in _make_recipe("test-guardrails-unprivileged"))  # nosec B101
    assert "then the destructive-diff and cost-proxy gates (no IAM step)" in _doc(  # nosec B101
        "testing.md"
    )


def test_activation_text_requires_stage_two_trust() -> None:
    doc = _doc("ci-guardrails.md")
    assert "meaning the three `Reviewed*` contexts below are required" not in doc  # nosec B101
    assert doc.count("Stage 2 dedicated role and `test-pr` reader trust") >= 2  # nosec B101


def test_specs_historical_banners_are_scoped_and_link_to_live_docs() -> None:
    banner = "> Historical record: pull-request credential, preview and `test-pr`"
    specs = [
        path for path in sorted((ROOT / "specs").rglob("*.md")) if banner in _raw(path)
    ]
    assert len(specs) >= 15  # nosec B101
    for path in specs:
        text = _flat_quote(path)
        assert "Today `bootstrap-infrastructure` pull requests receive no AWS" in text  # nosec B101
        assert "Governed repositories' `test-pr` config readers" in text  # nosec B101
        assert "Today pull requests receive no AWS credentials" not in text  # nosec B101
        for link in re.findall(
            r"\]\(([^)]+\.md)\)", " ".join(_raw(path).split()).split(banner, 1)[1][:900]
        ):
            assert (path.parent / link).resolve().is_file(), (path, link)  # nosec B101
    governed = ci_config._github_actions_subjects(
        _settings(), "test-pr", "user-service-infrastructure"
    )
    assert governed == [  # nosec B101
        "repo:VilnaCRM-Org/user-service-infrastructure:pull_request"
    ]


# --- final-round follow-ups: artifacts, per-role claims -----------------------


def test_no_doc_claims_scheduled_well_architected_uploads() -> None:
    """Only the trusted publisher uploads a collector result; the data workflow none."""
    data_workflow = _raw(WORKFLOWS / "well-architected-evidence.yml")
    assert "upload-artifact" not in data_workflow  # nosec B101
    assert "schedule" in _triggers(_workflow("well-architected-evidence.yml"))  # nosec B101
    for path in WORKFLOWS.glob("*.yml"):
        text = _raw(path)
        assert "report-well-architected-evidence" not in text, path.name  # nosec B101
        if (
            "collect_well_architected_evidence" in text
            or "publish_well_architected.py collect" in text
        ):
            assert path.name == "trusted-well-architected.yml"  # nosec B101
    trusted = _workflow("trusted-well-architected.yml")
    assert set(_triggers(trusted)) == {"workflow_dispatch"}  # nosec B101
    assert "upload-artifact" in _raw(WORKFLOWS / "trusted-well-architected.yml")  # nosec B101
    stale = [
        r"`Well-Architected Evidence` workflow now runs",
        r"Scheduled runs remain advisory[^.]{0,80}upload",
        r"upload the metadata-only evidence bundle",
        r"After a scheduled or manual collector run",
        r"retain the scheduled workflow history",
    ]
    for name, text in _all_docs().items():
        for pattern in stale:
            assert not re.search(pattern, text), (name, pattern)  # nosec B101
    alert = _doc("alert-routing-evidence.md")
    assert "uploads no artifact" in alert  # nosec B101
    assert "No workflow runs `make report-well-architected-evidence`" in alert  # nosec B101


@pytest.mark.parametrize("purpose", ["apply", "drift", "preview"])
def test_deployment_roles_bind_no_workflow_claim(
    monkeypatch: pytest.MonkeyPatch, purpose: str
) -> None:
    """`_create_role` never sets a workflow claim; only readers and triage do."""
    condition = _created_role_condition(monkeypatch, purpose)
    assert PREFIX + "workflow" not in condition  # nosec B101
    if purpose == "preview":
        # Current state: the preview role also has no ref condition.
        assert PREFIX + "ref" not in condition  # nosec B101
    else:
        assert condition[PREFIX + "ref"] == "refs/heads/main"  # nosec B101
    assert condition[PREFIX + "aud"] == "sts.amazonaws.com"  # nosec B101


def test_per_role_claim_docs_match_rendered_claims() -> None:
    assert PREFIX + "workflow" in _reader_condition("test")  # nosec B101
    assert PREFIX + "ref" in _reader_condition("test")  # nosec B101
    assert PREFIX + "ref" not in _reader_condition("test-pr")  # nosec B101
    source = _raw(ROOT / "pulumi" / "infra" / "ci_bootstrap.py")
    assert source.count("workflow_name=") == 1  # nosec B101
    assert 'workflow_name="Operations Alert Issue Triage"' in source  # nosec B101
    doc = _doc("github-ci-bootstrap-stack.md")
    assert (
        "the apply and drift roles bind the `main` ref but no `workflow` claim" in doc
    )  # nosec B101
    assert "the preview role binds neither a `workflow` nor a `ref` claim" in doc  # nosec B101
    assert "`job_workflow_ref` is for reusable workflows" in doc  # nosec B101
    stale = [
        r"Ordinary workflows bind the `workflow` claim",
        r"subject, workflow and ref\b",
        r"exact workflow and ref contracts",
    ]
    for name, text in _all_docs().items():
        for pattern in stale:
            assert not re.search(pattern, text), (name, pattern)  # nosec B101
    admission = _doc("reviewed-source-admission.md")
    assert "main-only deployment-branch policies" in admission  # nosec B101
    assert "issue #289" in admission  # nosec B101
    assert "issue #289" in _doc("github-actions-secrets.md")  # nosec B101
    for name in (
        "github-ci-bootstrap-stack.md",
        "ci-guardrails.md",
        "aws-secrets-manager-ci-cutover.md",
    ):
        assert "GitHubCiPreview-*-test` read role" not in _doc(name), name  # nosec B101


def test_audit_round_doc_claims_match_source():
    """Pin the sentences corrected by the attempt-5 pre-gate audit to source."""
    cutover = " ".join(_doc("aws-secrets-manager-ci-cutover.md").split())
    assert PREFIX + "ref" not in _reader_condition("test-pr")  # nosec B101
    assert "`ref` claims on the config-read roles except `test-pr`" in cutover  # nosec B101
    assert "`ref` claims on every role type except preview" not in cutover  # nosec B101
    guardrails = " ".join(_doc("ci-guardrails.md").split())
    for stale in (
        "early signal that a pull request",
        "Pull requests that exceed that threshold",
    ):
        assert stale not in guardrails, stale  # nosec B101
    assert "Pull requests get no cost signal" in guardrails  # nosec B101
    deploy = _raw(ROOT / ".github/workflows/pulumi-test-deploy.yml")
    assert "test-cost-proxy" not in deploy  # nosec B101
    admission = " ".join(_doc("reviewed-source-admission.md").split())
    assert "retire generic PR subjects only for" not in admission  # nosec B101
    evidence = _doc("well-architected-operating-evidence.md")
    assert "bounded by policy-pack" not in evidence  # nosec B101
    assert "make test-repository-fanout" in evidence  # nosec B101
    structural = _raw(ROOT / ".github/workflows/pulumi-structural.yml")
    assert "make test-repository-fanout" in structural  # nosec B101
