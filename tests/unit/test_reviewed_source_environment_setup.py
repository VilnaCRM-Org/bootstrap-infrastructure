"""Reviewed-source GitHub environments stay main-only and unattended."""

import copy
import json
import runpy
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import configure_reviewed_source_environments as setup
from _github_repository_controls import service_drift_environment_payload


class GitHub:
    """In-memory GitHub environment API with observable writes."""

    def __init__(self):
        self.environments = {}
        self.policies = {}
        self.calls = []
        self.inventory_override = None
        self.unexpected_new_policy = False

    def run(self, args, *, input_payload=None):
        endpoint = args[0]
        method = args[args.index("--method") + 1] if "--method" in args else "GET"
        self.calls.append((method, endpoint))
        if endpoint.endswith("/environments?per_page=100"):
            if self.inventory_override is not None:
                return copy.deepcopy(self.inventory_override)
            names = list(self.environments)
            return {
                "total_count": len(names),
                "environments": [{"name": name} for name in names],
            }
        prefix = f"repos/{setup.REPOSITORY}/environments/"
        assert endpoint.startswith(prefix)
        name, _, tail = endpoint[len(prefix) :].partition("/")
        if not tail:
            if method == "PUT":
                self.environments[name] = {
                    **copy.deepcopy(input_payload),
                    "name": name,
                }
                self.policies[name] = (
                    [{"id": 99, "name": "wildcard", "type": "branch"}]
                    if self.unexpected_new_policy
                    else []
                )
            return self._environment(name)
        if tail == "deployment-branch-policies?per_page=100":
            rows = self.policies[name]
            return {"total_count": len(rows), "branch_policies": copy.deepcopy(rows)}
        assert tail == "deployment-branch-policies" and method == "POST"
        assert input_payload == {"name": "main", "type": "branch"}
        self.policies[name].append({"id": 100, **input_payload})
        return self.policies[name][-1]

    def _environment(self, name):
        return {
            **copy.deepcopy(self.environments[name]),
            "protection_rules": self.environments[name].get(
                "protection_rules",
                [{"type": "branch_policy"}] if self.policies[name] else [],
            ),
        }

    def install(self, name):
        self.environments[name] = {
            **service_drift_environment_payload(),
            "name": name,
        }
        self.policies[name] = [{"id": 1, "name": "main", "type": "branch"}]


@pytest.fixture
def github(monkeypatch):
    fake = GitHub()
    monkeypatch.setattr(setup, "_gh", fake.run)
    monkeypatch.setattr(setup, "_admin_allowed", lambda: True)
    return fake


def test_dry_run_then_create_missing_and_verify_idempotently(github):
    dry = setup.configure(apply=False, verify_only=False)
    assert dry["missing"] == list(setup.ENVIRONMENTS)
    assert dry["verified"] is False
    assert all(method == "GET" for method, _ in github.calls)

    applied = setup.configure(apply=True, verify_only=False)
    assert applied["missing"] == []
    assert applied["verified"] is True
    assert set(github.environments) == set(setup.ENVIRONMENTS)
    assert all(
        github.policies[name] == [{"id": 100, "name": "main", "type": "branch"}]
        for name in setup.ENVIRONMENTS
    )
    writes = sum(method != "GET" for method, _ in github.calls)
    assert writes == 4
    assert setup.configure(apply=False, verify_only=True)["verified"] is True
    assert setup.configure(apply=True, verify_only=False)["missing"] == []
    assert sum(method != "GET" for method, _ in github.calls) == writes


def test_existing_weak_environment_rejects_before_any_write(github):
    name = setup.ENVIRONMENTS[0]
    github.install(name)
    github.environments[name]["can_admins_bypass"] = True
    with pytest.raises(ValueError, match="disable admin bypass"):
        setup.configure(apply=True, verify_only=False)
    assert all(method == "GET" for method, _ in github.calls)
    assert setup.ENVIRONMENTS[1] not in github.environments


@pytest.mark.parametrize("observed", [[], {"name": "other"}])
def test_existing_environment_identity_must_match(github, monkeypatch, observed):
    name = setup.ENVIRONMENTS[0]
    github.install(name)
    original = github.run

    def changed(args, *, input_payload=None):
        if args == [f"repos/{setup.REPOSITORY}/environments/{name}"]:
            return observed
        return original(args, input_payload=input_payload)

    monkeypatch.setattr(setup, "_gh", changed)
    with pytest.raises(ValueError, match="identity differs"):
        setup.configure(apply=False, verify_only=False)


@pytest.mark.parametrize(
    "change,fragment",
    [
        (lambda env, policies: policies.clear(), "allow only main"),
        (lambda env, policies: policies[0].update(name="release"), "allow only main"),
        (lambda env, policies: env.update(reviewers=[{"id": 7}]), "not require"),
        (lambda env, policies: env.update(wait_timer=1), "wait timer"),
        (
            lambda env, policies: env.update(
                protection_rules=[{"type": "required_reviewers"}]
            ),
            "unknown execution gate",
        ),
    ],
)
def test_existing_environment_must_keep_exact_unattended_boundary(
    github, change, fragment
):
    name = setup.ENVIRONMENTS[0]
    github.install(name)
    change(github.environments[name], github.policies[name])
    with pytest.raises(ValueError, match=fragment):
        setup.configure(apply=False, verify_only=False)


def test_verify_requires_both_environments_and_apply_requires_admin(
    github, monkeypatch
):
    with pytest.raises(ValueError, match="is missing"):
        setup.configure(apply=False, verify_only=True)
    monkeypatch.setattr(setup, "_admin_allowed", lambda: False)
    with pytest.raises(RuntimeError, match="admin rights"):
        setup.configure(apply=True, verify_only=False)
    assert all(method == "GET" for method, _ in github.calls)


@pytest.mark.parametrize(
    "inventory,fragment",
    [
        ([], "not an object"),
        ({"total_count": 1, "environments": []}, "incomplete"),
        ({"total_count": 1, "environments": [None]}, "ambiguous"),
        (
            {
                "total_count": 2,
                "environments": [{"name": "A"}, {"name": "a"}],
            },
            "ambiguous",
        ),
        (
            {"total_count": 1, "environments": [{"name": "Reviewed-pr-preview"}]},
            "case variant",
        ),
    ],
)
def test_incomplete_or_ambiguous_inventory_never_writes(github, inventory, fragment):
    github.inventory_override = inventory
    with pytest.raises(ValueError, match=fragment):
        setup.configure(apply=True, verify_only=False)
    assert all(method == "GET" for method, _ in github.calls)


def test_creation_stops_on_unexpected_existing_branch_policy(github):
    github.unexpected_new_policy = True
    with pytest.raises(RuntimeError, match="unexpected policies"):
        setup.configure(apply=True, verify_only=False)
    assert github.policies[setup.ENVIRONMENTS[0]][0]["name"] == "wildcard"
    assert setup.ENVIRONMENTS[1] not in github.environments


def test_cli_reports_dry_run_and_verified_apply(github, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["configure_reviewed_source_environments.py"])
    setup.main()
    assert json.loads(capsys.readouterr().out)["missing"] == list(setup.ENVIRONMENTS)
    monkeypatch.setattr(
        sys, "argv", ["configure_reviewed_source_environments.py", "--apply"]
    )
    setup.main()
    assert json.loads(capsys.readouterr().out)["verified"] is True


def test_python_entrypoint_uses_same_closed_dry_run(github, monkeypatch, capsys):
    def run(command, *, input, check, capture_output, text):
        assert check is False and capture_output and text
        assert command[:2] == ["gh", "api"]
        payload = json.loads(input) if input else None
        return subprocess.CompletedProcess(
            command,
            0,
            json.dumps(github.run(command[2:], input_payload=payload)),
            "",
        )

    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setattr(sys, "argv", ["configure_reviewed_source_environments.py"])
    runpy.run_module("configure_reviewed_source_environments", run_name="__main__")
    assert json.loads(capsys.readouterr().out)["missing"] == list(setup.ENVIRONMENTS)


def test_api_failures_do_not_expose_response_body(monkeypatch):
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args, 1, "", "sensitive"),
    )
    with pytest.raises(RuntimeError, match="GitHub API request failed") as error:
        setup._gh(["repos/example"])
    assert "sensitive" not in str(error.value)


@pytest.mark.parametrize(
    "response", [{}, [], {"total_count": 1, "branch_policies": []}]
)
def test_incomplete_branch_policy_pages_are_rejected(response):
    with pytest.raises(ValueError, match="incomplete"):
        setup._branch_policies(response)
