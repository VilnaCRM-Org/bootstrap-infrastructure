"""Requester and sole-approver separation at the advisory comment intake."""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
parser = importlib.import_module("pulumi_pr_comment")


@pytest.mark.parametrize("governance", [False, True])
@pytest.mark.parametrize(
    "login,association,action,authorized",
    [
        ("dmytrocraft", "MEMBER", "up", True),
        ("dmytrocraft", "OWNER", "up", True),
        ("outsider", "NONE", "up", False),
        ("Kravalg", "OWNER", "up", False),
        ("  kravalg  ", "MEMBER", "up", False),
        ("", "OWNER", "up", False),
        ("Kravalg", "OWNER", "plan", True),
        ("dmytrocraft", "MEMBER", "plan", True),
        ("outsider", "NONE", "plan", False),
    ],
)
def test_independent_requester_matrix(
    governance, login, association, action, authorized
):
    assert (
        parser.author_is_authorized(
            association,
            author_login=login,
            governance_touched=governance,
            action=action,
        )
        is authorized
    )


@pytest.mark.parametrize(
    "login,expected", [("Kravalg", "false"), ("dmytrocraft", "true")]
)
def test_cli_preserves_requester_gate(monkeypatch, tmp_path, login, expected):
    output = tmp_path / "output"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    assert (
        parser.main(
            [
                "/pulumi prod up",
                "--author-association",
                "MEMBER",
                "--author-login",
                login,
                "--governance-touched",
                "true",
            ]
        )
        == 0
    )
    assert f"authorized={expected}\n" in output.read_text()
    assert "command=up\n" in output.read_text()


def test_missing_identity_cannot_request_apply():
    assert (
        parser.build_outputs(parser.PulumiPrCommand("prod", "up"), "MEMBER")[
            "authorized"
        ]
        == "false"
    )
    assert parser.build_outputs(None, "MEMBER") == {
        "authorized": "true",
        "skip": "true",
    }
