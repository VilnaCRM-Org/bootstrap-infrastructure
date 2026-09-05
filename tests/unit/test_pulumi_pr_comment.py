from __future__ import annotations

import importlib
import sys
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parents[2] / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

pulumi_pr_comment = importlib.import_module("pulumi_pr_comment")


def test_parse_command_accepts_canonical_and_compatibility_forms() -> None:
    assert pulumi_pr_comment.parse_command("/pulumi test plan") == (
        pulumi_pr_comment.PulumiPrCommand("test", "plan")
    )
    assert pulumi_pr_comment.parse_command("pulumi PROD UP") == (
        pulumi_pr_comment.PulumiPrCommand("prod", "up")
    )
    assert pulumi_pr_comment.parse_command("/pulumi plan prod") == (
        pulumi_pr_comment.PulumiPrCommand("prod", "plan")
    )
    assert pulumi_pr_comment.parse_command("pulumi up") == (
        pulumi_pr_comment.PulumiPrCommand("test", "up")
    )


def test_parse_command_rejects_non_exact_or_unsafe_forms() -> None:
    for body in (
        "",
        "hello",
        "/pulumi",
        "/pulumi destroy",
        "/pulumi staging plan",
        "/pulumi prod refresh",
        "/pulumi prod up now",
        "/pulumi; prod up",
        "/pulumi test plan\n/pulumi test up",
        "> /pulumi test plan",
        "`/pulumi test plan`",
        "please run /pulumi test plan",
    ):
        assert pulumi_pr_comment.parse_command(body) is None


def test_authorization_uses_github_author_association() -> None:
    for association in ("OWNER", "member", " Collaborator "):
        assert pulumi_pr_comment.author_is_authorized(association) is True

    for association in ("CONTRIBUTOR", "NONE", ""):
        assert pulumi_pr_comment.author_is_authorized(association) is False


def test_build_outputs_marks_skipped_and_actionable_comments() -> None:
    skipped = pulumi_pr_comment.build_outputs(None, "CONTRIBUTOR")
    authorized_skip = pulumi_pr_comment.build_outputs(None, "OWNER")
    command = pulumi_pr_comment.PulumiPrCommand("prod", "up")
    actionable = pulumi_pr_comment.build_outputs(
        command, "MEMBER", author_login="dmytrocraft"
    )

    assert skipped == {"authorized": "false", "skip": "true"}
    assert authorized_skip == {"authorized": "true", "skip": "true"}
    assert actionable == {
        "authorized": "true",
        "skip": "false",
        "target_environment": "prod",
        "command": "up",
        "display_command": "/pulumi prod up",
    }


def test_write_outputs_prints_and_appends_github_outputs(
    capsys, tmp_path: Path
) -> None:
    output_file = tmp_path / "github-output"
    outputs = {"skip": "false", "command": "plan"}

    pulumi_pr_comment.write_outputs(outputs, None)
    pulumi_pr_comment.write_outputs(outputs, str(output_file))

    expected = "skip=false\ncommand=plan\n"
    assert capsys.readouterr().out == expected * 2
    assert output_file.read_text(encoding="utf-8") == expected


def test_main_parses_comment_and_uses_github_output(
    monkeypatch, tmp_path: Path
) -> None:
    output_file = tmp_path / "github-output"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output_file))

    assert (
        pulumi_pr_comment.main(["/pulumi prod plan", "--author-association", "OWNER"])
        == 0
    )

    assert output_file.read_text(encoding="utf-8") == (
        "authorized=true\n"
        "skip=false\n"
        "target_environment=prod\n"
        "command=plan\n"
        "display_command=/pulumi prod plan\n"
    )
