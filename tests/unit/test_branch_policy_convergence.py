"""Branch-policy convergence validates complete input before policy mutations."""

import importlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
controls = importlib.import_module("configure_github_repository_controls")
ENDPOINT = "repos/org/repo/environments/test"


def policy(identifier=1, name="main", kind="branch"):
    """Return a realistic branch-policy API record."""
    return {"id": identifier, "name": name, "type": kind}


@pytest.mark.parametrize(
    "response",
    [
        None,
        [],
        {},
        {"branch_policies": None},
        {"branch_policies": {}},
        {"branch_policies": "main"},
        {"total_count": 2, "branch_policies": [policy(1, "*"), None]},
        {"total_count": 2, "branch_policies": [policy(1, "*"), {}]},
        {"total_count": 2, "branch_policies": [policy(1, "*"), policy(1)]},
        {"branch_policies": [], "total_count": 1},
        {"branch_policies": [policy()], "total_count": True},
        {"branch_policies": [policy()], "total_count": "1"},
        {"branch_policies": [policy()], "total_count": None},
    ],
)
def test_bad_response_never_mutates(monkeypatch, response):
    """Even a malformed final record must prevent deletion of earlier entries."""
    calls = []

    def api(args, **kwargs):
        calls.append((args, kwargs))
        return response

    monkeypatch.setattr(controls, "_run_gh_api", api)
    with pytest.raises(ValueError):
        controls._configure_main_branch_policy(ENDPOINT)
    assert calls == [([f"{ENDPOINT}/deployment-branch-policies"], {})]


@pytest.mark.parametrize("identifier", [None, True, False, 0, -1, "2", "../../3", 2.0])
def test_bad_policy_id_never_mutates(monkeypatch, identifier):
    """Only positive integer IDs may become a DELETE endpoint."""
    test_bad_response_never_mutates(
        monkeypatch,
        {"total_count": 2, "branch_policies": [policy(1, "*"), policy(identifier)]},
    )


@pytest.mark.parametrize("name", [None, 1, "", " ", " main", "main "])
def test_bad_policy_name_never_mutates(monkeypatch, name):
    """Invalid names must fail before processing any valid extra rule."""
    test_bad_response_never_mutates(
        monkeypatch,
        {"total_count": 2, "branch_policies": [policy(1, "*"), policy(2, name)]},
    )


@pytest.mark.parametrize("kind", [None, "", "Branch", "ref", True, {}])
def test_bad_policy_type_never_mutates(monkeypatch, kind):
    """Unknown rule kinds cannot be silently removed as though understood."""
    test_bad_response_never_mutates(
        monkeypatch,
        {"total_count": 2, "branch_policies": [policy(1, "*"), policy(2, kind=kind)]},
    )


@pytest.mark.parametrize("reverse", [False, True])
def test_duplicate_main_keeps_smallest_id(monkeypatch, reverse):
    """API ordering cannot change which exact main policy survives."""
    records = [policy(9), policy(3), policy(7, kind="tag"), policy(2, "*")]
    if reverse:
        records.reverse()
    calls = []

    def api(args, **kwargs):
        calls.append((args, kwargs))
        return {"branch_policies": records, "total_count": 4}

    monkeypatch.setattr(controls, "_run_gh_api", api)
    controls._configure_main_branch_policy(ENDPOINT)
    assert [args for args, _ in calls[1:]] == [
        [f"{ENDPOINT}/deployment-branch-policies/{identifier}", "--method", "DELETE"]
        for identifier in (2, 7, 9)
    ]
    assert sorted(record["id"] for record in records) == [2, 3, 7, 9]


@pytest.mark.parametrize("records", [[], [policy(4, "*"), policy(2, kind="tag")]])
def test_missing_main_is_created_once(monkeypatch, records):
    """Create main only after every obsolete valid record has been removed."""
    calls = []

    def api(args, **kwargs):
        calls.append((args, kwargs))
        return {"branch_policies": records, "total_count": len(records)}

    monkeypatch.setattr(controls, "_run_gh_api", api)
    controls._configure_main_branch_policy(ENDPOINT)
    assert calls[-1] == (
        [f"{ENDPOINT}/deployment-branch-policies", "--method", "POST"],
        {"input_payload": {"name": "main", "type": "branch"}},
    )
    assert sum("POST" in args for args, _ in calls) == 1


def test_evidence_bad_list_holds_mutation(monkeypatch):
    """Earlier environment PUT is permitted; malformed policy lists stay intact."""
    calls = []

    def api(args, **kwargs):
        calls.append((args, kwargs))
        return {"total_count": 2, "branch_policies": [policy(1, "*"), None]}

    monkeypatch.setattr(controls, "_run_gh_api", api)
    with pytest.raises(ValueError):
        controls._configure_evidence_environment("org/repo")
    assert len(calls) == 2
    assert calls[0][0][-1] == "PUT"
    assert "--method" not in calls[1][0]


def test_policy_api_failure_is_reported(monkeypatch):
    """A failed mutation is not swallowed or followed by a replacement POST."""
    calls = []

    def api(args, **kwargs):
        calls.append((args, kwargs))
        if "DELETE" in args:
            raise RuntimeError("GitHub policy deletion failed")
        return {"total_count": 1, "branch_policies": [policy(1, "*")]}

    monkeypatch.setattr(controls, "_run_gh_api", api)
    with pytest.raises(RuntimeError, match="deletion failed"):
        controls._configure_main_branch_policy(ENDPOINT)
    assert len(calls) == 2
