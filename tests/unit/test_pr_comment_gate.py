"""Decision-matrix tests for the path-aware @Kravalg author gate (E3.S1).

These cover the governance branch added to ``author_is_authorized`` plus the
``--author-login`` / ``--governance-touched`` CLI flags threaded through
``build_outputs``. The non-governance / ``plan`` paths must keep the existing
``AUTHORIZED_ASSOCIATIONS`` behaviour unchanged (defense-in-depth: the
governance runner's server-side re-auth in E1.S8 is the hard control).
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parents[2] / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

pulumi_pr_comment = importlib.import_module("pulumi_pr_comment")


def test_kravalg_login_constant_is_defined() -> None:
    assert pulumi_pr_comment.KRAVALG_LOGIN == "Kravalg"


def test_governance_up_authorizes_only_kravalg() -> None:
    # Positive: governance + Kravalg + up -> authorized regardless of association.
    assert (
        pulumi_pr_comment.author_is_authorized(
            "NONE",
            author_login="Kravalg",
            governance_touched=True,
            action="up",
        )
        is True
    )


def test_governance_up_rejects_non_kravalg_even_if_owner() -> None:
    # Negative: governance + non-Kravalg + up -> rejected even if association OWNER.
    assert (
        pulumi_pr_comment.author_is_authorized(
            "OWNER",
            author_login="dmytrocraft",
            governance_touched=True,
            action="up",
        )
        is False
    )


def test_governance_up_login_compare_is_case_insensitive() -> None:
    # Edge: case-insensitive login compare (kravalg == Kravalg) with surrounding ws.
    assert (
        pulumi_pr_comment.author_is_authorized(
            "NONE",
            author_login="  kravalg  ",
            governance_touched=True,
            action="up",
        )
        is True
    )


def test_governance_up_missing_login_defaults_to_rejected() -> None:
    # Edge: missing --author-login defaults to rejected for governance up.
    assert (
        pulumi_pr_comment.author_is_authorized(
            "OWNER",
            governance_touched=True,
            action="up",
        )
        is False
    )


def test_governance_plan_uses_association_rule() -> None:
    # Positive: governance + anyone + plan -> association rule (plan is read-only).
    assert (
        pulumi_pr_comment.author_is_authorized(
            "OWNER",
            author_login="dmytrocraft",
            governance_touched=True,
            action="plan",
        )
        is True
    )
    assert (
        pulumi_pr_comment.author_is_authorized(
            "NONE",
            author_login="dmytrocraft",
            governance_touched=True,
            action="plan",
        )
        is False
    )


def test_non_governance_up_keeps_association_rule() -> None:
    # Edge: non-governance + up keeps the existing association rule unchanged.
    assert (
        pulumi_pr_comment.author_is_authorized(
            "OWNER",
            author_login="dmytrocraft",
            governance_touched=False,
            action="up",
        )
        is True
    )
    assert (
        pulumi_pr_comment.author_is_authorized(
            "NONE",
            author_login="Kravalg",
            governance_touched=False,
            action="up",
        )
        is False
    )


def test_build_outputs_threads_governance_gate_for_up() -> None:
    command = pulumi_pr_comment.PulumiPrCommand("prod", "up")

    rejected = pulumi_pr_comment.build_outputs(
        command,
        "OWNER",
        author_login="dmytrocraft",
        governance_touched=True,
    )
    authorized = pulumi_pr_comment.build_outputs(
        command,
        "NONE",
        author_login="kravalg",
        governance_touched=True,
    )

    assert rejected["authorized"] == "false"
    assert rejected["skip"] == "false"
    assert rejected["command"] == "up"
    assert authorized["authorized"] == "true"


def test_build_outputs_governance_plan_uses_association() -> None:
    command = pulumi_pr_comment.PulumiPrCommand("prod", "plan")

    outputs = pulumi_pr_comment.build_outputs(
        command,
        "MEMBER",
        author_login="dmytrocraft",
        governance_touched=True,
    )

    assert outputs["authorized"] == "true"
    assert outputs["command"] == "plan"


def test_build_outputs_defaults_preserve_non_governance_behaviour() -> None:
    command = pulumi_pr_comment.PulumiPrCommand("prod", "up")

    outputs = pulumi_pr_comment.build_outputs(command, "MEMBER")

    assert outputs == {
        "authorized": "true",
        "skip": "false",
        "target_environment": "prod",
        "command": "up",
        "display_command": "/pulumi prod up",
    }


def test_build_outputs_skip_without_command_still_applies_gate() -> None:
    # No parsed command: gate falls back to association (action is empty so the
    # governance branch never fires even when governance_touched is true).
    outputs = pulumi_pr_comment.build_outputs(
        None,
        "OWNER",
        author_login="dmytrocraft",
        governance_touched=True,
    )

    assert outputs == {"authorized": "true", "skip": "true"}


def test_main_governance_up_rejects_non_kravalg(monkeypatch, tmp_path: Path) -> None:
    output_file = tmp_path / "github-output"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output_file))

    exit_code = pulumi_pr_comment.main(
        [
            "/pulumi prod up",
            "--author-association",
            "OWNER",
            "--author-login",
            "dmytrocraft",
            "--governance-touched",
            "true",
        ]
    )

    assert exit_code == 0
    rendered = output_file.read_text(encoding="utf-8")
    assert "authorized=false\n" in rendered
    assert "command=up\n" in rendered


def test_main_governance_up_authorizes_kravalg(monkeypatch, tmp_path: Path) -> None:
    output_file = tmp_path / "github-output"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output_file))

    exit_code = pulumi_pr_comment.main(
        [
            "/pulumi prod up",
            "--author-association",
            "NONE",
            "--author-login",
            "Kravalg",
            "--governance-touched",
            "true",
        ]
    )

    assert exit_code == 0
    assert "authorized=true\n" in output_file.read_text(encoding="utf-8")


def test_main_defaults_keep_association_rule(monkeypatch, tmp_path: Path) -> None:
    output_file = tmp_path / "github-output"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output_file))

    exit_code = pulumi_pr_comment.main(
        ["/pulumi prod up", "--author-association", "OWNER"]
    )

    assert exit_code == 0
    assert "authorized=true\n" in output_file.read_text(encoding="utf-8")
