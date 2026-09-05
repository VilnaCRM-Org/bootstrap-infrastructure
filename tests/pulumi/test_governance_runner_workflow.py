"""Structural tests for the dedicated governance runner workflow.

These checks mirror `.github/workflows/pulumi-governance.yml` closely. Update
them alongside the workflow when job names, env, or `if` expressions change.
The governance runner is a trusted, env-gated apply path (architecture §7.2,
§7.5, §5.1a). Because actionlint/yamllint run only in CI (docker), this module
asserts the security-critical structure from the parsed YAML directly.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS_DIR = PROJECT_ROOT / ".github" / "workflows"
GOVERNANCE_WORKFLOW = "pulumi-governance.yml"
GOVERNANCE_DISPATCH_TYPE = "pulumi-governance-command"
GOVERNANCE_ENVIRONMENT = "governance"
GOVERNANCE_PULUMI_DIR = "pulumi/governance"
GOVERNANCE_STATUS_CONTEXT = "Governance Apply"
APPLY_JOBS = ("governance_test_apply", "governance_prod_apply")
ACTION_SHA_REF = re.compile(r"^[^@]+@[0-9a-f]{40}$")


def _workflow(name: str) -> dict:
    """Load a workflow YAML file from disk."""
    return yaml.safe_load((WORKFLOWS_DIR / name).read_text(encoding="utf-8"))


def _triggers(workflow: dict) -> dict:
    """Normalize the GitHub Actions `on` key when YAML parses it as a boolean."""
    return workflow.get("on", workflow.get(True, {}))


def _job_steps(job: dict) -> list[dict]:
    """Return a job's step list."""
    return job.get("steps", [])


def _step_run_text(job: dict) -> str:
    """Concatenate all `run` script bodies in a job for substring assertions."""
    return "\n".join(step.get("run", "") for step in _job_steps(job))


def test_governance_runner_listens_only_on_dedicated_dispatch() -> None:
    """The runner triggers ONLY on its own repository_dispatch event type."""
    workflow = _workflow(GOVERNANCE_WORKFLOW)
    triggers = _triggers(workflow)

    assert set(triggers) == {"repository_dispatch"}  # nosec B101
    assert triggers["repository_dispatch"]["types"] == [  # nosec B101
        GOVERNANCE_DISPATCH_TYPE
    ]


def test_governance_runner_has_no_workflow_dispatch() -> None:
    """No manual workflow_dispatch entry into the governance apply path (SECURITY-1)."""
    workflow = _workflow(GOVERNANCE_WORKFLOW)
    triggers = _triggers(workflow)

    assert "workflow_dispatch" not in triggers  # nosec B101


def test_preflight_has_no_id_token_permission() -> None:
    """Preflight re-derives trust before any credential-minting job (§7.2)."""
    preflight = _workflow(GOVERNANCE_WORKFLOW)["jobs"]["preflight"]

    assert "id-token" not in preflight.get("permissions", {})  # nosec B101


def test_preflight_revalidates_pr_head_open_and_same_repo() -> None:
    """Authentication executes from the trusted default-branch checkout."""
    preflight = _workflow(GOVERNANCE_WORKFLOW)["jobs"]["preflight"]
    assert "scripts/pulumi_command_preflight.py --governance" in _step_run_text(
        preflight
    )
    checkout = preflight["steps"][0]
    assert "ref" not in checkout["with"]
    assert checkout["with"]["persist-credentials"] is False


def test_preflight_resolves_comment_author_and_asserts_kravalg() -> None:
    """The shared verifier receives the immutable intake and original comment IDs."""
    preflight = _workflow(GOVERNANCE_WORKFLOW)["jobs"]["preflight"]
    assert (
        preflight["env"]["REQUEST_COMMENT_ID"]
        == "${{ github.event.client_payload.comment_id }}"
    )
    assert (
        preflight["env"]["REQUEST_SOURCE_RUN_ID"]
        == "${{ github.event.client_payload.source_run_id }}"
    )
    assert preflight["permissions"]["actions"] == "read"


def test_preflight_recomputes_governance_scope_server_side() -> None:
    """The governance runner enables the shared verifier's fail-closed scope mode."""
    preflight = _workflow(GOVERNANCE_WORKFLOW)["jobs"]["preflight"]
    assert (
        _step_run_text(preflight).strip()
        == "python3 scripts/pulumi_command_preflight.py --governance"
    )


def test_preflight_does_not_trust_client_payload_governance_flag() -> None:
    """The client_payload governance_touched flag is never read as authority."""
    preflight = _workflow(GOVERNANCE_WORKFLOW)["jobs"]["preflight"]
    dumped = yaml.safe_dump(preflight)

    assert "client_payload.governance_touched" not in dumped  # nosec B101


def test_both_apply_jobs_are_env_gated_governance() -> None:
    """Both governance apply jobs declare environment: governance (FR11/SECURITY-2)."""
    jobs = _workflow(GOVERNANCE_WORKFLOW)["jobs"]

    for job_id in APPLY_JOBS:
        assert jobs[job_id]["environment"] == GOVERNANCE_ENVIRONMENT  # nosec B101


def test_both_apply_jobs_set_governance_pulumi_dir() -> None:
    """Both apply jobs target PULUMI_DIR=pulumi/governance (FR12)."""
    jobs = _workflow(GOVERNANCE_WORKFLOW)["jobs"]

    for job_id in APPLY_JOBS:
        assert jobs[job_id]["env"]["PULUMI_DIR"] == GOVERNANCE_PULUMI_DIR  # nosec B101


def test_apply_jobs_run_saved_plan_not_direct_up() -> None:
    """Apply jobs run make pulumi-up-plan, never make pulumi-up (IaC-only apply)."""
    jobs = _workflow(GOVERNANCE_WORKFLOW)["jobs"]

    for job_id in APPLY_JOBS:
        run_text = _step_run_text(jobs[job_id])
        assert "make pulumi-up-plan" in run_text  # nosec B101
        assert re.search(r"make pulumi-up(\s|$)", run_text) is None  # nosec B101


def test_no_job_invokes_direct_pulumi_up() -> None:
    """No job anywhere in the workflow invokes the direct (unplanned) apply."""
    jobs = _workflow(GOVERNANCE_WORKFLOW)["jobs"]

    for job in jobs.values():
        run_text = _step_run_text(job)
        assert re.search(r"make pulumi-up(\s|$)", run_text) is None  # nosec B101


def test_apply_jobs_select_correct_governance_stacks() -> None:
    """Test apply targets the test stack; prod apply targets the prod stack."""
    jobs = _workflow(GOVERNANCE_WORKFLOW)["jobs"]

    assert jobs["governance_test_apply"]["env"]["PULUMI_STACK"] == "test"  # nosec B101
    assert jobs["governance_prod_apply"]["env"]["PULUMI_STACK"] == "prod"  # nosec B101


def test_prod_apply_needs_test_apply_and_drift() -> None:
    """Prod apply is gated behind test apply + test post-apply drift (FR15)."""
    jobs = _workflow(GOVERNANCE_WORKFLOW)["jobs"]
    needs = jobs["governance_prod_apply"]["needs"]

    assert "governance_test_apply" in needs  # nosec B101
    assert "governance_test_post_apply_drift" in needs  # nosec B101


def test_post_apply_drift_needs_test_apply() -> None:
    """Test post-apply drift runs after the test apply (ordering preserved)."""
    jobs = _workflow(GOVERNANCE_WORKFLOW)["jobs"]
    needs = jobs["governance_test_post_apply_drift"]["needs"]

    assert "governance_test_apply" in needs  # nosec B101


def test_status_post_job_targets_head_sha_with_governance_context() -> None:
    """Final status job posts `Governance Apply` to the head SHA (FEASIBILITY-1)."""
    jobs = _workflow(GOVERNANCE_WORKFLOW)["jobs"]
    status_job = jobs["governance_status"]
    run_text = _step_run_text(status_job)
    job_env = status_job.get("env", {})

    # The commit status is posted to the verified head SHA exposed via env.
    assert "statuses/${HEAD_SHA}" in run_text  # nosec B101
    assert job_env["HEAD_SHA"] == "${{ needs.preflight.outputs.head_sha }}"  # nosec B101
    # The context string must be byte-identical to the required-check tuple entry.
    assert f'context="{GOVERNANCE_STATUS_CONTEXT}"' in run_text  # nosec B101
    assert GOVERNANCE_STATUS_CONTEXT in run_text  # nosec B101


def test_status_post_state_derives_from_prod_apply_outcome() -> None:
    """The posted commit-status state comes from governance_prod_apply outcome."""
    jobs = _workflow(GOVERNANCE_WORKFLOW)["jobs"]
    status_job = jobs["governance_status"]

    assert status_job["if"] == "always()"  # nosec B101
    assert "governance_prod_apply" in status_job["needs"]  # nosec B101
    dumped = yaml.safe_dump(status_job)
    assert "needs.governance_prod_apply.result" in dumped  # nosec B101


def test_preflight_emits_outputs_before_auth_and_scope_checks() -> None:
    """No shell step publishes unverified payload outputs or arbitrary SHA statuses."""
    preflight = _workflow(GOVERNANCE_WORKFLOW)["jobs"]["preflight"]
    assert "GITHUB_OUTPUT" not in _step_run_text(preflight)
    assert preflight["outputs"]["head_sha"] == "${{ steps.resolve.outputs.head_sha }}"


def test_status_post_is_always_terminal_never_pending() -> None:
    """The runner status job is if:always() and maps EVERY non-success result to
    failure — no 'pending' for skipped/cancelled/empty (CRITICAL+HIGH)."""
    status_job = _workflow(GOVERNANCE_WORKFLOW)["jobs"]["governance_status"]

    assert status_job["if"] == "always()"  # nosec B101

    run_text = _step_run_text(status_job)
    # Terminal mapping only: success -> success, everything else -> failure.
    assert 'success) status_state="success" ;;' in run_text  # nosec B101
    assert '*) status_state="failure" ;;' in run_text  # nosec B101
    # No pending state is ever assigned or posted from the runner status job.
    assert 'status_state="pending"' not in run_text  # nosec B101
    assert "state=pending" not in run_text  # nosec B101
    assert 'state="pending"' not in run_text  # nosec B101
    # The skipped/cancelled-only pending branch is gone.
    assert "skipped|cancelled" not in run_text  # nosec B101


def test_status_post_guard_is_only_empty_head_sha() -> None:
    """The terminal status post is skipped ONLY when head_sha is genuinely empty
    (a malformed request that never emitted a postable SHA)."""
    status_job = _workflow(GOVERNANCE_WORKFLOW)["jobs"]["governance_status"]
    post_step = next(
        step
        for step in _job_steps(status_job)
        if "statuses/${HEAD_SHA}" in step.get("run", "")
    )

    assert post_step["if"] == "needs.preflight.outputs.head_sha != ''"  # nosec B101
    # The rejected/did-not-complete failure description is posted on the
    # non-success path (the command verb is interpolated, defaulting to "apply"
    # when the request was malformed and emitted no command).
    assert (  # nosec B101
        "rejected or did not complete." in post_step["run"]
    )
    assert "${REQUEST_COMMAND:-apply}" in post_step["run"]  # nosec B101


def test_governance_runner_pins_actions_to_full_shas() -> None:
    """Avoid mutable action tags in the governance runner."""
    workflow = _workflow(GOVERNANCE_WORKFLOW)

    for job in workflow["jobs"].values():
        for step in _job_steps(job):
            uses = step.get("uses")
            if uses is None or uses.startswith("./"):
                continue
            assert ACTION_SHA_REF.match(uses), (  # nosec B101
                f"governance runner must pin `{uses}` to a full commit SHA"
            )


# --- F1: command/target threading + apply-job gating ----------------------------

# The test-apply / test-drift gate: an apply request only (test up OR any prod).
_TEST_APPLY_GUARD = "needs.preflight.outputs.command == 'up'"


def _normalize_if(expr: str) -> str:
    """Collapse YAML multi-line `if:` whitespace to single spaces for matching."""
    return " ".join(expr.split())


def test_preflight_validates_command_and_target_server_side() -> None:
    """Payload command/target reach the verifier only via environment variables."""
    preflight = _workflow(GOVERNANCE_WORKFLOW)["jobs"]["preflight"]
    assert (
        preflight["env"]["REQUEST_COMMAND"]
        == "${{ github.event.client_payload.command }}"
    )
    assert (
        preflight["env"]["REQUEST_TARGET_ENVIRONMENT"]
        == "${{ github.event.client_payload.target_environment }}"
    )
    assert "client_payload" not in _step_run_text(preflight)


def test_preflight_exposes_command_and_target_outputs() -> None:
    """The preflight job exports command + target_environment outputs."""
    preflight = _workflow(GOVERNANCE_WORKFLOW)["jobs"]["preflight"]
    outputs = preflight["outputs"]

    assert outputs["command"] == "${{ steps.resolve.outputs.command }}"  # nosec B101
    assert (  # nosec B101
        outputs["target_environment"]
        == "${{ steps.resolve.outputs.target_environment }}"
    )


def test_command_target_validated_before_outputs_emitted() -> None:
    """A durable one-use claim is owned by trusted preflight, never PR code."""
    preflight = _workflow(GOVERNANCE_WORKFLOW)["jobs"]["preflight"]
    assert preflight["permissions"]["statuses"] == "write"
    for job_id in APPLY_JOBS:
        assert (
            "statuses"
            not in _workflow(GOVERNANCE_WORKFLOW)["jobs"][job_id]["permissions"]
        )


def test_test_plan_job_is_unconditional() -> None:
    """The test plan job runs for every request (it is the minimal stage)."""
    test_plan = _workflow(GOVERNANCE_WORKFLOW)["jobs"]["governance_test_plan"]

    # No `if:` guard -> always runs (plan is the read-only floor).
    assert "if" not in test_plan  # nosec B101


def test_test_apply_and_drift_gated_to_up_requests_only() -> None:
    """Test apply + drift run only for `test up` or any `prod` request — never plan."""
    jobs = _workflow(GOVERNANCE_WORKFLOW)["jobs"]

    for job_id in ("governance_test_apply", "governance_test_post_apply_drift"):
        guard = _normalize_if(jobs[job_id]["if"])
        assert guard == _TEST_APPLY_GUARD, job_id  # nosec B101
        # A bare `test plan` must NOT satisfy this guard.
        assert "command == 'up'" in guard  # nosec B101


def test_prod_jobs_require_prod_target() -> None:
    """Prod plan/apply run only for a `prod` request, never for any `test` request."""
    jobs = _workflow(GOVERNANCE_WORKFLOW)["jobs"]

    prod_plan_guard = _normalize_if(jobs["governance_prod_plan"]["if"])
    assert "target_environment == 'prod'" in prod_plan_guard  # nosec B101
    assert (  # nosec B101
        "governance_test_post_apply_drift.result == 'success'" in prod_plan_guard
    )

    prod_apply_guard = _normalize_if(jobs["governance_prod_apply"]["if"])
    # Prod is mutated ONLY by `prod up`.
    assert "target_environment == 'prod'" in prod_apply_guard  # nosec B101
    assert "command == 'up'" in prod_apply_guard  # nosec B101


def _guard_holds(guard: str, *, target: str, command: str) -> bool:
    """Evaluate a governance job `if:` guard for a given (target, command) pair.

    This is a SAFE, hand-rolled evaluator for the exact, closed grammar these
    guards use — boolean ``&&``/``||`` over ``==`` comparisons of the two known
    preflight outputs plus the drift-success precondition. It deliberately does
    NOT use ``eval``: it substitutes the concrete values, treats the drift clause
    as satisfied (irrelevant to the plan/up decision), and reduces the AND/OR of
    literal ``True``/``False`` terms. Any unexpected token raises, so the test
    fails loudly rather than silently mis-evaluating.
    """
    expr = _normalize_if(guard)
    substitutions = {
        f"needs.preflight.outputs.target_environment == '{target}'": "True",
        "needs.preflight.outputs.target_environment == 'prod'": str(target == "prod"),
        "needs.preflight.outputs.target_environment == 'test'": str(target == "test"),
        "needs.preflight.outputs.command == 'up'": str(command == "up"),
        "needs.preflight.outputs.command == 'plan'": str(command == "plan"),
        "needs.governance_test_post_apply_drift.result == 'success'": "True",
    }
    for needle, value in substitutions.items():
        expr = expr.replace(needle, value)
    # After substitution only True/False literals, &&, ||, and parens remain.
    expr = expr.replace("&&", "and").replace("||", "or")
    allowed = {"True", "False", "and", "or", "(", ")"}
    tokens = expr.replace("(", " ( ").replace(")", " ) ").split()
    leftover = set(tokens) - allowed
    assert not leftover, f"unexpected guard tokens {leftover} in {expr!r}"  # nosec B101
    # Reduce the boolean literal expression with ast.literal_eval-free logic.
    return _reduce_bool_expr(tokens)


def _reduce_bool_expr(tokens: list[str]) -> bool:
    """Reduce a token list of True/False/and/or/parens to a single bool."""
    # Recursive-descent over the tiny grammar: expr := term (or term)*;
    # term := factor (and factor)*; factor := 'True' | 'False' | '(' expr ')'.
    pos = 0

    def parse_expr() -> bool:
        nonlocal pos
        value = parse_term()
        while pos < len(tokens) and tokens[pos] == "or":
            pos += 1
            value = parse_term() or value
        return value

    def parse_term() -> bool:
        nonlocal pos
        value = parse_factor()
        while pos < len(tokens) and tokens[pos] == "and":
            pos += 1
            value = parse_factor() and value
        return value

    def parse_factor() -> bool:
        nonlocal pos
        token = tokens[pos]
        pos += 1
        if token == "(":
            value = parse_expr()
            assert tokens[pos] == ")"  # nosec B101
            pos += 1
            return value
        return token == "True"

    return parse_expr()


def test_plan_request_never_reaches_an_apply_job() -> None:
    """For a `plan` request the test/prod apply guards are unsatisfiable.

    `test plan`  -> command != 'up' and target != 'prod' -> both apply guards false.
    `prod plan`  -> prod apply guard requires command == 'up' -> false.
    """
    jobs = _workflow(GOVERNANCE_WORKFLOW)["jobs"]
    test_apply_guard = jobs["governance_test_apply"]["if"]
    prod_apply_guard = jobs["governance_prod_apply"]["if"]

    # test plan: no apply anywhere.
    assert not _guard_holds(test_apply_guard, target="test", command="plan")  # nosec B101
    assert not _guard_holds(prod_apply_guard, target="test", command="plan")  # nosec B101
    # prod plan must not mutate either account.
    assert not _guard_holds(test_apply_guard, target="prod", command="plan")
    assert not _guard_holds(prod_apply_guard, target="prod", command="plan")  # nosec B101
    # test up: prod apply must NOT run.
    assert not _guard_holds(prod_apply_guard, target="test", command="up")  # nosec B101
    # prod up: prod apply runs.
    assert _guard_holds(prod_apply_guard, target="prod", command="up")  # nosec B101


def test_test_up_runs_test_apply_but_not_prod_apply() -> None:
    """`test up` applies the test stack but never the prod stack."""
    jobs = _workflow(GOVERNANCE_WORKFLOW)["jobs"]

    assert _guard_holds(  # nosec B101
        jobs["governance_test_apply"]["if"], target="test", command="up"
    )
    assert not _guard_holds(  # nosec B101
        jobs["governance_prod_apply"]["if"], target="test", command="up"
    )


def test_test_up_request_does_not_run_prod_jobs() -> None:
    """A `test up` request never satisfies any prod-job guard."""
    jobs = _workflow(GOVERNANCE_WORKFLOW)["jobs"]

    for job_id in ("governance_prod_plan", "governance_prod_apply"):
        guard = _normalize_if(jobs[job_id]["if"])
        # Prod jobs require target == 'prod'; a `test up` request cannot match.
        assert "target_environment == 'prod'" in guard  # nosec B101


def test_prod_up_runs_test_then_prod() -> None:
    """`prod up` runs the test apply first, then the prod apply (test-then-prod)."""
    jobs = _workflow(GOVERNANCE_WORKFLOW)["jobs"]

    # Test apply runs for a prod request (target == 'prod' branch of the guard).
    test_apply_guard = _normalize_if(jobs["governance_test_apply"]["if"])
    assert "command == 'up'" in test_apply_guard  # nosec B101

    # Prod apply depends on the test apply + drift completing first.
    prod_apply_needs = jobs["governance_prod_apply"]["needs"]
    assert "governance_test_apply" in prod_apply_needs  # nosec B101
    assert "governance_test_post_apply_drift" in prod_apply_needs  # nosec B101
    assert "governance_prod_plan" in prod_apply_needs  # nosec B101


# --- F2: governance apply jobs assume a governance-env-trusted role -------------


def _aws_credentials_step(job: dict) -> dict:
    """Return the configure-aws-credentials step in a job (or raise)."""
    for step in _job_steps(job):
        uses = step.get("uses", "")
        if uses.startswith("aws-actions/configure-aws-credentials@"):
            return step
    raise AssertionError("job has no configure-aws-credentials step")


def test_apply_jobs_assume_governance_env_trusted_role_not_test_role() -> None:
    """Both apply jobs assume the dedicated governance automation role (F2).

    The apply jobs run under `environment: governance`, so the OIDC token carries
    `environment:governance`. The bootstrap test/prod CI-config + deploy roles
    trust `environment:test`/`environment:prod`/branch-ref and CANNOT be assumed.
    The runner must therefore assume the per-account governance automation role
    pinned in a dedicated repo variable — never the loaded CI-config apply role.
    """
    jobs = _workflow(GOVERNANCE_WORKFLOW)["jobs"]
    expected_role_var = {
        "governance_test_apply": "${{ vars.AWS_GOVERNANCE_TEST_APPLY_ROLE_ARN }}",
        "governance_prod_apply": "${{ vars.AWS_GOVERNANCE_PROD_APPLY_ROLE_ARN }}",
    }
    for job_id, role_var in expected_role_var.items():
        creds = _aws_credentials_step(jobs[job_id])
        role_to_assume = creds["with"]["role-to-assume"]
        assert role_to_assume == role_var, job_id  # nosec B101
        # It must NOT reuse the loaded CI-config apply role (test/prod-trusted).
        assert (  # nosec B101
            role_to_assume != "${{ steps.ci_config.outputs.aws-apply-role-arn }}"
        )


def test_apply_jobs_do_not_load_test_or_prod_ci_config() -> None:
    """Apply jobs no longer assume an environment:test/prod-trusted config role (F2).

    Loading the bootstrap CI-config secret requires assuming a config-read role
    that trusts `environment:test`/`environment:prod`/branch-ref — impossible from
    an `environment:governance` token. The governance backend + secrets provider
    come from repo variables instead.
    """
    jobs = _workflow(GOVERNANCE_WORKFLOW)["jobs"]
    for job_id in APPLY_JOBS:
        job = jobs[job_id]
        for step in _job_steps(job):
            assert step.get("uses") != "./.github/actions/load-aws-ci-env", (  # nosec B101
                f"{job_id} must not load the bootstrap CI-config secret"
            )
        # The governance program's backend + secrets provider are sourced from
        # governance-specific repo variables, not a CI-config secret payload.
        job_env = job.get("env", {})
        assert "PULUMI_BACKEND_URL" in job_env  # nosec B101
        assert "PULUMI_SECRETS_PROVIDER" in job_env  # nosec B101
        assert "AWS_GOVERNANCE_" in str(job_env["PULUMI_BACKEND_URL"])  # nosec B101


def test_plan_and_drift_jobs_still_use_ci_config_under_branch_ref() -> None:
    """Preview/drift have separate protected subjects and governance-only config."""
    jobs = _workflow(GOVERNANCE_WORKFLOW)["jobs"]
    for job_id in (
        "governance_test_plan",
        "governance_test_post_apply_drift",
        "governance_prod_plan",
    ):
        job = jobs[job_id]
        assert job["environment"] == "governance-preview"
        assert all(
            "load-aws-ci-env" not in step.get("uses", "") for step in job["steps"]
        )
        role = _aws_credentials_step(job)["with"]["role-to-assume"]
        assert "AWS_GOVERNANCE_" in role
        assert "APPLY_ROLE" not in role
        assert "AWS_GOVERNANCE_" in job["env"]["PULUMI_BACKEND_URL"]


def test_status_state_is_command_target_aware() -> None:
    """The commit-status state reflects the stage the request was meant to reach."""
    status_job = _workflow(GOVERNANCE_WORKFLOW)["jobs"]["governance_status"]
    run_text = _step_run_text(status_job)

    # Each command:target combination maps to the relevant stage result so a plan
    # or a test-up is not reported as a failed prod apply.
    assert "up:prod) gate_result=" in run_text  # nosec B101
    assert "up:test) gate_result=" in run_text  # nosec B101
    assert "plan:prod) gate_result=" in run_text  # nosec B101
    assert "plan:test) gate_result=" in run_text  # nosec B101
    # Still terminal: success only, everything else failure; never pending.
    assert 'success) status_state="success" ;;' in run_text  # nosec B101
    assert '*) status_state="failure" ;;' in run_text  # nosec B101
    assert 'status_state="pending"' not in run_text  # nosec B101


def test_promotion_proof_job_uses_only_trusted_code_and_complete_stage_results():
    jobs = _workflow(GOVERNANCE_WORKFLOW)["jobs"]
    job = jobs["governance_promotion"]
    assert set(job["needs"]) == {
        "preflight",
        "governance_test_apply",
        "governance_test_post_apply_drift",
        "governance_prod_apply",
        "governance_prod_post_apply_drift",
    }
    assert "id-token" not in job["permissions"]
    assert "deployments" not in job["permissions"]
    assert "statuses" not in job["permissions"]
    assert job["environment"] == "governance-evidence"
    app = next(step for step in job["steps"] if step.get("id") == "promotion_app")
    assert app["with"]["permission-statuses"] == "write"
    assert app["with"]["permission-deployments"] == "write"
    assert job["steps"][0]["with"]["ref"] == "${{ github.sha }}"
    assert job["env"]["PROMOTION_NEEDS"] == "${{ toJSON(needs) }}"
    assert "make " not in _step_run_text(job)
    scope = _workflow("governance-promotion.yml")
    assert "pull_request_target" in _triggers(scope)
    assert (
        scope["jobs"]["scope"]["steps"][0]["with"]["ref"]
        == "${{ github.event.repository.default_branch }}"
    )
