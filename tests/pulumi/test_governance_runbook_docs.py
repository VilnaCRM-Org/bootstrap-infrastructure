"""Doc-presence tests for the governance operator runbook (E4.S2).

These assert that ``docs/governance-stack.md`` exists, is linked from
``AGENTS.md``, documents the design overview (two-account isolation, per-account
OIDC provider, sole approver, IaC-only applies), and enumerates every operator
step from architecture §10.2 — each tagged ``OPERATOR``:

1. one-time governance bootstrap apply (local direct ``pulumi up``,
   hardware-MFA admin session, test stack then prod stack);
2. pin the per-account OIDC provider ARN before first apply
   (test -> 891 provider, prod -> 933 provider; the stack raises if unset);
3. verify each stack's ``costAnomalyMonitorArn`` matches its account
   (test -> 891377212104, prod -> 933245420672; do NOT repoint prod);
4. configure the protected ``governance`` environment + branch protection;
5. set GitHub repo variables from the governance ``githubVariables`` output;
6. create ``user-service-infrastructure`` + push the scaffold;
7. gated real applies via ``@Kravalg`` PR comments;
8. audited break-glass if ``@Kravalg`` is unavailable.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RUNBOOK = ROOT / "docs" / "governance-stack.md"
TEST_ACCOUNT_ID = "891377212104"
PROD_ACCOUNT_ID = "933245420672"


def _runbook() -> str:
    return RUNBOOK.read_text()


def test_runbook_exists_and_is_linked_from_agents() -> None:
    """The runbook exists and ``AGENTS.md`` points at it."""
    assert RUNBOOK.is_file()  # nosec B101
    assert "docs/governance-stack.md" in (ROOT / "AGENTS.md").read_text()  # nosec B101


def test_runbook_states_two_account_isolation() -> None:
    """Hard account-model facts are stated accurately (separate accounts)."""
    runbook = _runbook()

    assert TEST_ACCOUNT_ID in runbook  # nosec B101  (test account)
    assert PROD_ACCOUNT_ID in runbook  # nosec B101  (prod account)
    assert "eu-central-1" in runbook  # nosec B101
    assert "separate" in runbook.lower()  # nosec B101  (separate-account isolation)


def test_runbook_states_sole_approver_and_iac_only() -> None:
    """Sole approver @Kravalg, @dmytrocraft opener, IaC-only saved-plan applies."""
    runbook = _runbook()

    assert "@Kravalg" in runbook  # nosec B101
    assert "@dmytrocraft" in runbook  # nosec B101
    assert "make pulumi-up-plan" in runbook  # nosec B101  (saved-plan, IaC-only)
    assert "Governance Apply" in runbook  # nosec B101


def test_runbook_step_one_one_time_bootstrap_apply_is_operator() -> None:
    """Step 1: one-time local direct apply, hardware-MFA, test then prod stack."""
    runbook = _runbook()

    assert "Step 1 — One-time governance bootstrap apply [OPERATOR]" in runbook  # nosec B101
    assert "hardware-MFA" in runbook  # nosec B101
    # Exact per-account commands with their secrets providers.
    assert (  # nosec B101
        "pulumi -C pulumi/governance up --stack test --yes" in runbook
    )
    assert (  # nosec B101
        "pulumi -C pulumi/governance up --stack prod --yes" in runbook
    )
    assert (  # nosec B101
        "awskms://alias/pulumi-platform-bootstrap-test?region=eu-central-1" in runbook
    )
    assert (  # nosec B101
        "awskms://alias/pulumi-platform-bootstrap-prod?region=eu-central-1" in runbook
    )
    # test stack applies before prod stack (ordering).
    assert runbook.index("--stack test --yes") < runbook.index(  # nosec B101
        "--stack prod --yes"
    )


def test_runbook_step_two_oidc_arn_pin_is_operator() -> None:
    """Step 2: pin per-account OIDC provider ARN before first apply; stack raises."""
    runbook = _runbook()

    assert (  # nosec B101
        "Step 2 — Pin the per-account OIDC provider ARN before first apply [OPERATOR]"
        in runbook
    )
    assert "githubOidcProviderArn" in runbook  # nosec B101
    assert "raises if the ARN is unset" in runbook  # nosec B101
    assert (  # nosec B101
        f"arn:aws:iam::{TEST_ACCOUNT_ID}:oidc-provider/" in runbook
    )
    assert (  # nosec B101
        f"arn:aws:iam::{PROD_ACCOUNT_ID}:oidc-provider/" in runbook
    )


def test_runbook_step_three_cost_anomaly_matches_stack_is_operator() -> None:
    """Step 3: cost-anomaly ARN matches its stack; do NOT repoint prod from 933."""
    runbook = _runbook()

    assert (  # nosec B101
        "Step 3 — Verify each stack's cost-anomaly monitor matches its account "
        "[OPERATOR]" in runbook
    )
    assert "costAnomalyMonitorArn" in runbook  # nosec B101
    assert "do NOT repoint prod away from `933245420672`" in runbook  # nosec B101
    assert "Absence is permitted" in runbook  # nosec B101


def test_runbook_step_four_protected_environment_is_operator() -> None:
    """Step 4: protected governance environment + branch protection via the script."""
    runbook = _runbook()

    assert (  # nosec B101
        "Step 4 — Configure the protected governance environment + branch protection "
        "[OPERATOR]" in runbook
    )
    assert (  # nosec B101
        "scripts/configure_github_repository_controls.py" in runbook
    )
    assert "--apply" in runbook  # nosec B101
    assert "environments/governance" in runbook  # nosec B101


def test_runbook_step_five_repo_variables_is_operator() -> None:
    """Step 5: set GitHub repo variables from the governance githubVariables output."""
    runbook = _runbook()

    assert (  # nosec B101
        "Step 5 — Set GitHub repo variables from the governance githubVariables "
        "output [OPERATOR]" in runbook
    )
    assert "gh variable set" in runbook  # nosec B101
    assert "githubVariables" in runbook  # nosec B101


def test_runbook_step_six_repo_create_and_push_is_operator() -> None:
    """Step 6: create user-service-infrastructure + push the scaffold."""
    runbook = _runbook()

    assert (  # nosec B101
        "Step 6 — Publish the scaffold to the identified repository [OPERATOR]"
        in runbook
    )
    assert "scripts/scaffold_infrastructure_repository.py" in runbook  # nosec B101
    assert "pulumi/user-service-infrastructure/" in runbook  # nosec B101


def test_runbook_step_seven_gated_real_applies_is_operator() -> None:
    """Step 7: gated real applies via @Kravalg PR comments."""
    runbook = _runbook()

    assert (  # nosec B101
        "Step 7 — Maintainer request and separate @Kravalg approval [OPERATOR]"
        in runbook
    )
    assert "/pulumi test up" in runbook  # nosec B101
    assert "/pulumi prod up" in runbook  # nosec B101
    assert "environment: governance" in runbook  # nosec B101


def test_runbook_step_eight_break_glass_is_operator() -> None:
    """Step 8: audited break-glass if @Kravalg is unavailable."""
    runbook = _runbook()

    assert (  # nosec B101
        "Step 8 — Audited break-glass if @Kravalg is unavailable [OPERATOR]" in runbook
    )
    assert "break-glass" in runbook  # nosec B101
    assert "logged" in runbook  # nosec B101


def test_runbook_enumerates_eight_operator_steps() -> None:
    """All eight steps are present, in order, each tagged OPERATOR."""
    runbook = _runbook()
    step_headers = [
        "Step 1 — One-time governance bootstrap apply [OPERATOR]",
        "Step 2 — Pin the per-account OIDC provider ARN before first apply [OPERATOR]",
        "Step 3 — Verify each stack's cost-anomaly monitor matches its account "
        "[OPERATOR]",
        "Step 4 — Configure the protected governance environment + branch protection "
        "[OPERATOR]",
        "Step 5 — Set GitHub repo variables from the governance githubVariables "
        "output [OPERATOR]",
        "Step 6 — Publish the scaffold to the identified repository [OPERATOR]",
        "Step 7 — Maintainer request and separate @Kravalg approval [OPERATOR]",
        "Step 8 — Audited break-glass if @Kravalg is unavailable [OPERATOR]",
    ]

    last_index = -1
    for header in step_headers:
        index = runbook.find(header)
        assert index != -1, f"missing operator step: {header}"  # nosec B101
        assert index > last_index, f"operator step out of order: {header}"  # nosec B101
        last_index = index

    # Every enumerated step carries the OPERATOR tag (no step is unlabeled).
    assert runbook.count("[OPERATOR]") >= len(step_headers)  # nosec B101
