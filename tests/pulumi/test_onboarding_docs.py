"""Doc-presence tests for the multi-repo governance onboarding flow (E4.S1).

These assert that ``AGENTS.md`` documents identity resolution before the
PR-A / PR-B / publish-scaffold / PR-C sequence for a new service. Every step is
tagged ``CODE`` or ``OPERATOR``, that the gated ``/pulumi`` commands and the
``repositories.governance.json`` config-only contract are referenced, and that
the required ``specs/`` BMAD/BMALPH planning phrases are preserved.
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _agents_md() -> str:
    return (ROOT / "AGENTS.md").read_text()


def test_onboarding_section_header_present() -> None:
    assert "Multi-repo governance onboarding flow" in _agents_md()  # nosec B101


def test_onboarding_four_step_sequence_present() -> None:
    """identity / PR-A / PR-B / publish-scaffold / PR-C are documented, in order."""
    agents = _agents_md()
    markers = (
        "First resolve the actual GitHub repository identity",
        "PR A — Grant deploy roles",
        "PR B — Bootstrap generic infra",
        "Publish scaffold to the identified repo",
        "PR C — Grant OIDC apply permissions",
    )

    last_index = -1
    for marker in markers:
        index = agents.find(marker)
        assert index != -1, f"missing onboarding step: {marker}"  # nosec B101
        assert index > last_index, f"onboarding step out of order: {marker}"  # nosec B101
        last_index = index


def test_each_onboarding_step_is_labeled_code_or_operator() -> None:
    """No step may omit its CODE/OPERATOR tag."""
    agents = _agents_md()

    pr_b = "PR B — Bootstrap generic infra for `X-infrastructure` [CODE, gated apply]"

    assert "PR A — Grant deploy roles (governance) [CODE]" in agents  # nosec B101
    assert "**[OPERATOR]**" in agents  # nosec B101
    assert pr_b in agents  # nosec B101
    assert "Publish scaffold to the identified repo [OPERATOR]" in agents  # nosec B101
    assert "PR C — Grant OIDC apply permissions [CODE, @Kravalg-gated]" in agents  # nosec B101


def test_onboarding_references_governance_catalog_and_gated_commands() -> None:
    """The flow references the config-only catalog and the gated /pulumi commands."""
    agents = _agents_md()

    assert "pulumi/repositories.governance.json" in agents  # nosec B101
    assert "/pulumi test up" in agents  # nosec B101
    assert "/pulumi prod up" in agents  # nosec B101


def test_onboarding_states_two_account_isolation_and_sole_approver() -> None:
    """Hard account-model + approver facts are stated accurately."""
    agents = _agents_md()

    assert "891377212104" in agents  # nosec B101  (test account)
    assert "933245420672" in agents  # nosec B101  (prod account)
    assert "eu-central-1" in agents  # nosec B101
    assert "@Kravalg" in agents  # nosec B101
    assert "@dmytrocraft" in agents  # nosec B101
    normalized = " ".join(agents.split())
    assert (
        "current write-permission maintainer other than `@Kravalg` requests"
        in normalized
    )
    assert "`@Kravalg` reviews and approves the protected environment" in normalized


def test_onboarding_describes_self_deploy_and_governance_promotion_check() -> None:
    """Self-deploy hand-off and required Governance Promotion are documented."""
    agents = _agents_md()

    assert "self-deploy.yml" in agents  # nosec B101
    assert "Governance Promotion" in agents  # nosec B101
    assert "docs/governance-stack.md" in agents  # nosec B101


def test_onboarding_does_not_self_manage_bootstrap_repo() -> None:
    """bootstrap-infrastructure must never be added to the governance catalog."""
    normalized = " ".join(_agents_md().split())

    assert (  # nosec B101
        "Never add `bootstrap-infrastructure` to "
        "`pulumi/repositories.governance.json`" in normalized
    )


def test_agents_md_preserves_required_specs_phrases() -> None:
    """The structural BMAD/BMALPH specs/ phrases must stay intact (regression guard)."""
    agents = _agents_md()

    for phrase in (
        "Keep BMAD and BMALPH planning artifacts under `specs/`.",
        "specs/<issue-or-feature-slug>/",
        "output_folder: specs",
        "planning_artifacts: specs",
        "Do not commit generated BMAD/BMALPH/Ralph framework or state files",
        "Do not commit alternate planning roots",
    ):
        assert phrase in agents  # nosec B101
