"""Adversarial boundary cases identified by the security mutation campaign."""

import copy
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import governance_promotion as promotion  # noqa: E402
import pulumi_command_preflight as preflight  # noqa: E402


def test_retry_cannot_claim_a_new_command(monkeypatch):
    """A retry must fail before any event, cloud, or GitHub evidence is fetched."""
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "2")
    monkeypatch.setenv("GITHUB_EVENT_NAME", "repository_dispatch")
    monkeypatch.setenv("GITHUB_REF", "refs/heads/main")
    reached = []
    monkeypatch.setattr(preflight, "read_request", lambda: reached.append(True) or {})
    with pytest.raises(ValueError, match="Re-run rejected"):
        preflight.main([])
    assert reached == []


@pytest.mark.parametrize(
    "fault",
    [
        "invalid-number",
        "invalid-head",
        "foreign-base",
        "invalid-base",
        "moved-head",
        "moved-base",
    ],
)
def test_scope_cannot_publish_for_invalid_or_moving_pr(monkeypatch, tmp_path, fault):
    """An allow result must refer to one well-formed, immutable main-based diff."""
    monkeypatch.setenv("GITHUB_REPOSITORY", "org/repo")
    monkeypatch.setenv("GITHUB_SERVER_URL", "https://github.com")
    event = tmp_path / "event.json"
    event.write_text(json.dumps({"number": -1 if fault == "invalid-number" else 78}))
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event))
    pr = {
        "head": {"sha": "a" * 40},
        "base": {"ref": "main", "sha": "b" * 40},
        "changed_files": 1,
    }
    if fault == "invalid-head":
        pr["head"]["sha"] = "main"
    if fault == "invalid-base":
        pr["base"]["sha"] = "main"
    if fault == "foreign-base":
        pr["base"]["ref"] = "attacker"
    reads = []
    writes = []

    def api(path, *args):
        if "/compare/" in path:
            return {"files": [{"filename": "README.md"}]}
        if "/statuses?" in path:
            return [[]]
        current = copy.deepcopy(pr)
        if reads and fault in {"moved-head", "moved-base"}:
            current["head" if fault == "moved-head" else "base"]["sha"] = "c" * 40
        reads.append(path)
        return current

    monkeypatch.setattr(promotion, "gh", api)
    monkeypatch.setattr(promotion, "api_write", lambda *args: writes.append(args))
    with pytest.raises(ValueError):
        promotion.report_scope()
    assert writes == []


def test_publisher_rejects_unrestricted_evidence_environment(monkeypatch):
    """A valid App token must remain inaccessible from an unrestricted branch."""
    monkeypatch.setenv("GITHUB_REPOSITORY", "org/repo")
    monkeypatch.setattr(promotion, "gh", lambda *args: {})
    with pytest.raises(ValueError, match="Evidence environment"):
        promotion.main(["verify-environment"])


def test_runner_cannot_claim_both_service_and_governance_scope(monkeypatch):
    """Conflicting modes must stop before scope validation or any claim write."""
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "1")
    monkeypatch.setenv("GITHUB_EVENT_NAME", "repository_dispatch")
    monkeypatch.setenv("GITHUB_REF", "refs/heads/main")
    monkeypatch.setattr(preflight, "read_request", dict)
    monkeypatch.setattr(preflight, "collect_evidence", lambda request: {})
    reached = []
    monkeypatch.setattr(preflight, "validate_request", lambda *a, **kw: {})
    monkeypatch.setattr(preflight, "verify_environments", lambda *a, **kw: None)
    monkeypatch.setattr(preflight, "claim_request", lambda *a: reached.append(True))
    monkeypatch.setattr(preflight, "write_outputs", lambda *a: None)
    with pytest.raises(ValueError, match="Conflicting repository scopes"):
        preflight.main(["--service", "--governance"])
    assert reached == []
