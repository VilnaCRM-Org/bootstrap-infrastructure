"""Regression cases from independently validated integration review findings."""

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))


@pytest.mark.parametrize("extra", [{}, {"login": "Kravalg"}])
def test_extra_reviewers_are_rejected(extra):
    module = importlib.import_module("_well_architected_github_environment")
    payload = {
        "reviewers": [{"login": "Kravalg"}, extra],
        "can_admins_bypass": False,
    }
    metadata = module.production_environment_metadata(
        payload, environment="prod", reviewer_login="Kravalg"
    )
    assert metadata.reviewer_count == 2
    assert any(
        "contain only" in item
        for item in module.production_environment_blockers(metadata)
    )


@pytest.mark.parametrize("app_id", [0, -1, 15368])
@pytest.mark.parametrize("mode", ["verify", "apply", "dry-run"])
def test_invalid_issuer_stops_before_api(monkeypatch, app_id, mode):
    module = importlib.import_module("configure_github_repository_controls")

    def forbidden(*args, **kwargs):
        pytest.fail("Invalid issuer must be rejected before any GitHub API call")

    monkeypatch.setattr(module, "_run_gh_api", forbidden)
    with pytest.raises(ValueError, match="dedicated"):
        module.configure(
            "org/repo",
            "Kravalg",
            apply=mode == "apply",
            verify_only=mode == "verify",
            promotion_app_id=app_id,
        )


@pytest.mark.parametrize(
    "name",
    [
        "governance_automation.py",
        "github_identity.py",
        "platform_iam.py",
        "platform_control_iam.py",
    ],
)
def test_operator_modules_require_review(name):
    module = importlib.import_module("governance_paths")
    assert module.paths_touch_governance([f"pulumi/infra/{name}"])
    assert f"/pulumi/infra/{name}" in (ROOT / ".github/CODEOWNERS").read_text()


@pytest.mark.parametrize(
    "name", ["192.168.0.1", "999.999.999.999", "::1", "x.-y", "x-.y", "...", "x" * 64]
)
def test_invalid_catalog_tokens_fail(name):
    module = importlib.import_module("validate_repository_catalogs")
    with pytest.raises(ValueError):
        module._sanitize_project_component(name)


def test_name_collisions_ignore_aliases():
    module = importlib.import_module("validate_repository_catalogs")
    with pytest.raises(ValueError, match="unique"):
        module._validate_unique_projects(
            [
                {"name": "alpha.beta", "project": "different"},
                {"name": "alpha-beta", "project": "also-different"},
            ]
        )
    with pytest.raises(ValueError, match="unique"):
        module._validate_unique_projects(
            [
                {"name": "alpha", "project": "same"},
                {"name": "beta", "project": "same"},
            ]
        )
    module._validate_unique_projects(
        [
            None,
            123,
            {"name": "alpha", "project": 123},
            {"name": "beta", "project": " "},
        ]
    )


def test_scaffold_role_limit_before_write(tmp_path):
    module = importlib.import_module("scaffold_infrastructure_repository")
    destination = tmp_path / "new-service"
    with pytest.raises(ValueError, match="64"):
        module.generate(ROOT, destination, "a" * 30 + "-infrastructure")
    assert not destination.exists()


def _message(detail):
    return {
        "Body": json.dumps(
            {
                "Message": json.dumps(
                    {"source": "aws.backup", "detail-type": "Backup", "detail": detail}
                )
            }
        )
    }


def test_fingerprint_keeps_long_detail():
    module = importlib.import_module("operations_alert_triage")
    left = _message({"state": "FAILED", "reason": "x" * 400 + "A"})
    right = _message({"state": "FAILED", "reason": "x" * 400 + "B"})
    assert module.message_fingerprint(left) != module.message_fingerprint(right)
    assert module.message_fingerprint(
        _message({"reason": "A`B"})
    ) != module.message_fingerprint(_message({"reason": "A'B"}))


def test_large_alert_body_is_bounded():
    module = importlib.import_module("operations_alert_triage")
    message = {
        "MessageId": "😀" * 300,
        "Body": json.dumps(
            {
                "MessageId": "😀" * 300,
                "Timestamp": "😀" * 300,
                "Message": json.dumps(
                    {"source": "😀" * 300, "detail-type": "😀" * 300}
                ),
            }
        ),
        "Attributes": {"SentTimestamp": "😀" * 300},
    }
    context = module.IssueContext(
        "queue", "123456789012", "eu-central-1", "fingerprint"
    )
    body = module.render_issue_body({"Messages": [message] * 500}, context)
    assert "500 message(s)" in body
    assert "490 additional occurrences omitted" in body
    assert len(body.encode()) < 65000


@pytest.mark.parametrize(
    "pr,base,kind",
    [
        (79, "b" * 40, "governance"),
        (78, "c" * 40, "governance"),
        (78, "b" * 40, "platform"),
    ],
)
def test_promotion_cannot_cross_scope(monkeypatch, pr, base, kind):
    module = importlib.import_module("governance_promotion")
    monkeypatch.setenv("PROMOTION_APP_SLUG", "issuer")
    status = {
        "context": module.CONTEXT,
        "state": "success",
        "description": module.promotion_description(78, "b" * 40, "governance"),
        "creator": {"login": "issuer[bot]"},
    }
    assert module.verified_promotion_status(status, 78, "b" * 40, "governance")
    assert not module.verified_promotion_status(status, pr, base, kind)


def test_string_catalog_names_collide():
    module = importlib.import_module("validate_repository_catalogs")
    with pytest.raises(ValueError, match="unique"):
        module._validate_unique_projects(["alpha.beta", "alpha-beta"])


def test_scaffold_accepts_maximum_name(tmp_path):
    module = importlib.import_module("scaffold_infrastructure_repository")
    name = "a" * 17 + "-infrastructure"
    assert len(f"GitHubCiConfigRead-{name}-prod-preview") == 64
    manifest = module.generate(ROOT, tmp_path / "service", name)
    assert manifest["repository"] == name


def test_newest_app_status_controls_reuse(monkeypatch):
    module = importlib.import_module("governance_promotion")
    monkeypatch.setenv("PROMOTION_APP_SLUG", "issuer")
    valid = {
        "context": module.CONTEXT,
        "state": "success",
        "description": module.promotion_description(78, "b" * 40, "governance"),
        "creator": {"login": "issuer[bot]"},
    }
    newer = {
        **valid,
        "description": module.promotion_description(79, "b" * 40, "governance"),
    }
    monkeypatch.setattr(module, "gh", lambda *args: [[newer, valid]])
    assert not module.matching_promotion_exists(
        "repos/org/repo", "a" * 40, 78, "b" * 40, "governance"
    )


def test_fingerprint_version_is_explicit():
    module = importlib.import_module("operations_alert_triage")
    payload = module.grouped_alerts_payload(
        {"Messages": [_message({"state": "FAILED"})]}
    )
    assert payload["fingerprintVersion"] == 2
    assert len(payload["groups"][0]["fingerprint"]) == 24
