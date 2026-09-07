"""Replayable service drift setup preserves protected deployments."""

import copy
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import _github_repository_controls as controls
import configure_github_repository_controls as configure

REPO = "VilnaCRM-Org/user-service-infrastructure"


class GitHub:
    def __init__(self, existing=False):
        self.environments = {
            n: controls.protected_reviewer_environment_payload(7)
            for n in configure.SERVICE_PROTECTED_ENVIRONMENTS
        }
        self.policies = {
            n: [{"id": i + 1, "name": "main", "type": "branch"}]
            for i, n in enumerate(self.environments)
        }
        if existing:
            for n in controls.SERVICE_DRIFT_ENVIRONMENTS:
                self.environments[n] = controls.service_drift_environment_payload()
                self.policies[n] = [{"id": 20, "name": "main", "type": "branch"}]
        self.calls = []
        self.admin = True
        self.inventory_override = None
        self.corrupt_after_create = False
        self.unexpected_new_policy = False

    def run(self, args, *, input_payload=None):
        endpoint = args[0]
        method = args[args.index("--method") + 1] if "--method" in args else "GET"
        self.calls.append((endpoint, method, copy.deepcopy(input_payload)))
        if endpoint == "users/Kravalg":
            return {"id": 7}
        if endpoint == f"repos/{REPO}":
            return {"permissions": {"admin": self.admin}}
        if endpoint.endswith("environments?per_page=100"):
            if self.inventory_override is not None:
                return self.inventory_override
            return {
                "total_count": len(self.environments),
                "environments": [{"name": n} for n in self.environments],
            }
        prefix = f"repos/{REPO}/environments/"
        assert endpoint.startswith(prefix)
        name, _, tail = endpoint[len(prefix) :].partition("/")
        if not tail:
            if method == "PUT":
                assert name in controls.SERVICE_DRIFT_ENVIRONMENTS
                self.environments[name] = copy.deepcopy(input_payload)
                if self.corrupt_after_create:
                    self.environments[name]["can_admins_bypass"] = True
                self.policies[name] = (
                    [{"id": 30, "name": "*", "type": "branch"}]
                    if self.unexpected_new_policy
                    else []
                )
            return copy.deepcopy(self.environments[name])
        assert tail == "deployment-branch-policies"
        if method == "POST":
            self.policies[name].append({"id": 30, **input_payload})
        return {
            "total_count": len(self.policies[name]),
            "branch_policies": copy.deepcopy(self.policies[name]),
        }

    @property
    def writes(self):
        return [x for x in self.calls if x[1] != "GET"]


@pytest.fixture
def github(monkeypatch):
    api = GitHub()
    monkeypatch.setattr(configure, "_run_gh_api", api.run)
    return api


def test_create_only_two_environments_then_read_back_and_replay(github, capsys):
    original = copy.deepcopy(github.environments)
    assert configure.main(["--repo", REPO, "--service-drift-only", "--apply"]) == 0
    assert json.loads(capsys.readouterr().out)["verified"] is True
    assert [m for _, m, _ in github.writes] == ["PUT", "POST", "PUT", "POST"]
    assert all(github.environments[n] == d for n, d in original.items())
    github.calls.clear()
    configure.configure_service_drift(REPO, "Kravalg", apply=True, verify_only=False)
    assert github.writes == []
    assert json.loads(capsys.readouterr().out)["verified"] is True


@pytest.mark.parametrize("verify_only", [False, True])
def test_no_write_dry_run_or_verify(github, verify_only, capsys):
    if verify_only:
        with pytest.raises(RuntimeError, match="missing"):
            configure.configure_service_drift(
                REPO, "Kravalg", apply=False, verify_only=True
            )
    else:
        configure.configure_service_drift(
            REPO, "Kravalg", apply=False, verify_only=False
        )
        assert json.loads(capsys.readouterr().out)["verified"] is False
    assert github.writes == []


def test_existing_valid_environment_verifies_without_admin(monkeypatch, capsys):
    api = GitHub(existing=True)
    api.admin = False
    monkeypatch.setattr(configure, "_run_gh_api", api.run)
    assert (
        configure.main(["--repo", REPO, "--service-drift-only", "--verify-only"]) == 0
    )
    assert json.loads(capsys.readouterr().out)["verified"]
    assert api.writes == []


@pytest.mark.parametrize(
    "change",
    [
        {"can_admins_bypass": True},
        {"reviewers": [{"type": "User", "id": 7}]},
        {"reviewers": None},
        {"wait_timer": 1},
        {"wait_timer": False},
        {"protection_rules": [{"type": "required_reviewers", "reviewers": []}]},
        {"protection_rules": [{"type": "custom_deployment_protection_rule"}]},
        {"protection_rules": [None]},
        {"protection_rules": None},
        {
            "deployment_branch_policy": {
                "protected_branches": True,
                "custom_branch_policies": False,
            }
        },
    ],
)
def test_unknown_existing_drift_configuration_is_never_rewritten(monkeypatch, change):
    api = GitHub(existing=True)
    api.environments["prod-drift"].update(change)
    monkeypatch.setattr(configure, "_run_gh_api", api.run)
    with pytest.raises(RuntimeError):
        configure.configure_service_drift(
            REPO, "Kravalg", apply=True, verify_only=False
        )
    assert api.writes == []


@pytest.mark.parametrize("name", configure.SERVICE_PROTECTED_ENVIRONMENTS)
def test_weakened_protected_environment_stops_all_drift_writes(github, name):
    github.environments[name]["reviewers"] = []
    with pytest.raises(RuntimeError, match="reviewer"):
        configure.configure_service_drift(
            REPO, "Kravalg", apply=True, verify_only=False
        )
    assert github.writes == []


@pytest.mark.parametrize(
    "inventory",
    [
        [],
        {},
        {"total_count": True, "environments": []},
        {"total_count": 2, "environments": []},
        {"total_count": 1, "environments": [None]},
        {"total_count": 1, "environments": [{"name": None}]},
        {"total_count": 2, "environments": [{"name": "test"}, {"name": "test"}]},
    ],
)
def test_incomplete_or_malformed_inventory_never_means_absent(github, inventory):
    github.inventory_override = inventory
    with pytest.raises(ValueError):
        configure.configure_service_drift(
            REPO, "Kravalg", apply=True, verify_only=False
        )
    assert github.writes == []


def test_missing_admin_stops_before_any_environment_write(github):
    github.admin = False
    with pytest.raises(RuntimeError, match="admin rights"):
        configure.configure_service_drift(
            REPO, "Kravalg", apply=True, verify_only=False
        )
    assert github.writes == []


def test_failed_final_readback_never_reports_verified(github, capsys):
    github.corrupt_after_create = True
    assert configure.main(["--repo", REPO, "--service-drift-only", "--apply"]) == 1
    assert not capsys.readouterr().out


def test_new_unexpected_branch_policy_is_not_deleted(github):
    github.unexpected_new_policy = True
    with pytest.raises(RuntimeError, match="unexpected branch policies"):
        configure.configure_service_drift(
            REPO, "Kravalg", apply=True, verify_only=False
        )
    assert len(github.writes) == 1 and github.writes[0][1] == "PUT"


def test_non_object_drift_readback_fails(monkeypatch):
    monkeypatch.setattr(configure, "_run_gh_api", lambda _: [])
    assert configure._service_drift_blockers(REPO, "test-drift")


def test_normal_bootstrap_still_requires_valid_promotion_issuer(github):
    assert configure.main(["--repo", REPO, "--dry-run"]) == 1
    assert github.calls == []


@pytest.mark.parametrize("names", [["TEST-DRIFT"], ["test-drift", "TEST-DRIFT"]])
def test_case_insensitive_environment_alias_cannot_be_overwritten(github, names):
    github.inventory_override = {
        "total_count": len(names),
        "environments": [{"name": name} for name in names],
    }
    with pytest.raises(ValueError, match="casing|duplicate"):
        configure.configure_service_drift(
            REPO, "Kravalg", apply=True, verify_only=False
        )
    assert github.writes == []
