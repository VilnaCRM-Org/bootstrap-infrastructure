"""Verify the semantic mutation gate cannot mistake a broken run for a kill."""

import ast
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import run_mutation_tests as component_gate  # noqa: E402
import run_security_mutation_tests as gate  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]


def test_inventory_produces_valid_single_expression_security_mutants():
    """The selected real predicates remain present and every edit compiles."""
    mutants = gate.inventory(ROOT)
    assert len(mutants) >= 60
    assert {
        item.path for item in mutants
    } == gate.GUARDS.keys() | gate.REQUIREMENTS.keys()
    assert {
        "remove-immutable-identity-pin",
        "drop-promotion-status-predicate",
    } <= {item.operator for item in mutants}
    for mutant in mutants:
        source = (ROOT / mutant.path).read_text()
        changed = gate.mutate(source, mutant)
        assert ast.dump(ast.parse(changed)) != ast.dump(ast.parse(source))
        compile(changed, mutant.path, "exec")
        assert (ROOT / mutant.path).read_text() == source


def test_missing_target_or_empty_inventory_fails_closed(monkeypatch, tmp_path):
    monkeypatch.setattr(gate, "GUARDS", {"sample.py": {"missing"}})
    monkeypatch.setattr(gate, "REQUIREMENTS", {})
    (tmp_path / "sample.py").write_text("def other():\n    return True\n")
    with pytest.raises(ValueError, match="disappeared"):
        gate.inventory(tmp_path)
    monkeypatch.setattr(gate, "GUARDS", {})
    with pytest.raises(ValueError, match="empty"):
        gate.inventory(tmp_path)


def test_stale_mutation_location_fails_closed():
    mutant = gate.Mutant("sample.py", "f", 99, 0, "Compare", "True", "test")
    with pytest.raises(ValueError, match="exactly one"):
        gate.mutate("answer = True\n", mutant)


@pytest.mark.parametrize(
    "returncode,body,expected",
    [
        (0, '<testcase name="passed"/>', "survived"),
        (1, "<testcase><failure>AssertionError</failure></testcase>", "killed"),
        (1, "<testcase><failure>KeyError: Condition</failure></testcase>", "killed"),
        (1, "<testcase><error>Fixture failed</error></testcase>", "error"),
        (2, "<testcase><failure>AssertionError</failure></testcase>", "error"),
        (0, "<testcase><failure>AssertionError</failure></testcase>", "error"),
        (1, '<testcase name="passed"/>', "error"),
        (0, "", "error"),
    ],
)
def test_results_distinguish_survival_from_infrastructure_failure(
    tmp_path, returncode, body, expected
):
    report = tmp_path / "result.xml"
    report.write_text(f"<testsuite>{body}</testsuite>")
    assert gate.classify(returncode, report) == expected


def test_missing_or_malformed_report_never_kills_a_mutant(tmp_path):
    report = tmp_path / "result.xml"
    assert gate.classify(1, report) == "error"
    report.write_text("not xml")
    assert gate.classify(1, report) == "error"


def test_test_execution_uses_private_report_and_disables_cache(monkeypatch, tmp_path):
    report = tmp_path / "result.xml"
    monkeypatch.setenv("PYTEST_ADDOPTS", "--cov=unrelated")

    def command(arguments, **options):
        assert options["cwd"] == tmp_path
        assert options["timeout"] == 90
        assert "PYTEST_ADDOPTS" not in options["env"]
        assert options["env"]["PYTHONDONTWRITEBYTECODE"] == "1"
        assert "tests.security_mutation_guard" in arguments
        assert f"--junitxml={report}" in arguments
        report.write_text('<testsuite><testcase name="passed"/></testsuite>')
        return SimpleNamespace(returncode=0, stdout="passed", stderr="")

    monkeypatch.setattr(gate.subprocess, "run", command)
    assert gate.execute(tmp_path, report) == "survived"
    assert report.with_suffix(".log").read_text() == "passed"


def test_timeout_never_counts_as_a_kill(monkeypatch, tmp_path):
    def command(*args, **kwargs):
        raise subprocess.TimeoutExpired("pytest", 90)

    monkeypatch.setattr(gate.subprocess, "run", command)
    assert gate.execute(tmp_path, tmp_path / "result.xml") == "timeout"


@pytest.mark.parametrize(
    "outcome,code", [("killed", 0), ("survived", 1), ("error", 1), ("timeout", 1)]
)
def test_campaign_preserves_source_and_requires_every_mutant_killed(
    monkeypatch, tmp_path, outcome, code
):
    root = tmp_path / "source"
    root.mkdir()
    source = "def f(value):\n    if value:\n        raise ValueError('denied')\n"
    (root / "sample.py").write_text(source)
    mutant = gate.Mutant("sample.py", "f", 2, 7, "Name", "False", "bypass")
    monkeypatch.setattr(gate, "inventory", lambda _: [mutant])
    runs = []

    def execute(isolated, report):
        assert isolated != root
        runs.append((isolated / "sample.py").read_text())
        return "survived" if len(runs) == 1 else outcome

    monkeypatch.setattr(gate, "execute", execute)
    output = tmp_path / "reports"
    assert gate.run_campaign(root, output) == code
    assert runs[0] == source
    assert runs[1] != source
    assert (root / "sample.py").read_text() == source
    assert json.loads((output / "results.json").read_text())[0]["outcome"] == outcome


def test_failed_baseline_stops_before_mutation(monkeypatch, tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    monkeypatch.setattr(gate, "execute", lambda *args: "error")
    with pytest.raises(ValueError, match="baseline failed"):
        gate.run_campaign(root, tmp_path / "reports")


def test_main_uses_repository_owned_report_directory(monkeypatch, tmp_path):
    monkeypatch.setattr(gate, "repo_root", lambda _: tmp_path)
    calls = []
    monkeypatch.setattr(gate, "run_campaign", lambda *args: calls.append(args) or 1)
    assert gate.main() == 1
    assert calls == [(tmp_path, tmp_path / ".artifacts/security-mutation")]


def test_component_overrides_cannot_disable_security_mutation(monkeypatch, tmp_path):
    """A caller may narrow ordinary mutmut while the security gate stays mandatory."""
    monkeypatch.setattr(component_gate, "repo_root", lambda _: tmp_path)
    monkeypatch.setattr(component_gate, "find_uv_binary", lambda: "uv")
    monkeypatch.setenv("MUTATION_PATHS", "pulumi/app")
    monkeypatch.setenv("MUTATION_RUNNER", "custom component runner")
    commands = []
    monkeypatch.setattr(
        component_gate, "run", lambda command, **kw: commands.append(command)
    )
    assert component_gate.main() == 0
    assert commands[-1] == [
        "uv",
        "run",
        "python",
        "./scripts/run_security_mutation_tests.py",
    ]
    assert commands[-2][2] == "mutmut"


def test_component_default_runner_stops_at_failure_but_baseline_runs_all(
    monkeypatch, tmp_path
):
    """Repeated failing async outputs must not inflate mutant timing."""
    monkeypatch.setattr(component_gate, "repo_root", lambda _: tmp_path)
    monkeypatch.setattr(component_gate, "find_uv_binary", lambda: "uv")
    for name in (
        "MUTATION_RUNNER",
        "MUTATION_TEST_TARGETS",
        "MUTATION_COVERAGE_TARGETS",
        "MUTATION_TEST_TIME_MULTIPLIER",
    ):
        monkeypatch.delenv(name, raising=False)
    commands = []
    monkeypatch.setattr(
        component_gate, "run", lambda command, **kw: commands.append(command)
    )
    assert component_gate.main() == 0
    targets = [
        "tests/unit/test_environment_component.py",
        "tests/unit/test_guardrails.py",
    ]
    assert commands[0][-2:] == targets
    assert "-x" not in commands[0]
    assert commands[1][commands[1].index("--runner") + 1] == (
        "uv run pytest -q -x " + " ".join(targets)
    )
    assert commands[1][commands[1].index("--test-time-multiplier") + 1] == "3"
