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
    } == gate.GUARDS.keys() | gate.REQUIREMENTS.keys() | gate.SEMANTIC_TARGETS.keys()
    assert {
        "remove-immutable-identity-pin",
        "widen-iam-resource-scope",
        "drop-promotion-status-predicate",
        "remove-checkpoint-deny",
    } <= {item.operator for item in mutants}
    assert len(mutants) == 173
    for module in (
        "pulumi/seed/poc_publisher_stack_verification.py",
        "pulumi/seed/poc_runtime_fence_stack.py",
        "pulumi/seed/poc_runtime_verification.py",
        "pulumi/seed/poc_runtime.py",
    ):
        assert any(item.path == module for item in mutants)
    assert "tests/unit/test_poc_runtime_fence_stack.py" in gate.TARGETS
    assert (
        sum(item.path == "pulumi/infra/governance_automation.py" for item in mutants)
        == 16
    )
    assert "pulumi/infra/iam/account.py" in gate.GUARDS
    assert "tests/unit/test_platform_entrypoint_boundary.py" in gate.TARGETS
    for mutant in mutants:
        source = (ROOT / mutant.path).read_text()
        changed = gate.mutate(source, mutant)
        assert ast.dump(ast.parse(changed)) != ast.dump(ast.parse(source))
        compile(changed, mutant.path, "exec")
        assert (ROOT / mutant.path).read_text() == source


def test_missing_target_or_empty_inventory_fails_closed(monkeypatch, tmp_path):
    monkeypatch.setattr(gate, "GUARDS", {"sample.py": {"missing"}})
    monkeypatch.setattr(gate, "REQUIREMENTS", {})
    monkeypatch.setattr(gate, "SEMANTIC_TARGETS", {})
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

    calls = []

    def command(arguments, **options):
        calls.append(arguments)
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
    assert calls[-1][-len(gate.TARGETS) :] == list(gate.TARGETS)
    assert gate.execute(tmp_path, report, gate.ENROLLMENT_TARGETS) == "survived"
    assert calls[-1][-2:] == list(gate.ENROLLMENT_TARGETS)
    assert not set(gate.TARGETS) & set(calls[-1])
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
    suites = []

    def execute(isolated, report, targets):
        assert isolated != root
        runs.append((isolated / "sample.py").read_text())
        suites.append(targets)
        return "survived" if len(runs) == 1 else outcome

    monkeypatch.setattr(gate, "execute", execute)
    output = tmp_path / "reports"
    assert gate.run_campaign(root, output) == code
    assert runs[0] == source
    assert runs[1] != source
    assert suites == [gate.TARGETS + gate.ENROLLMENT_TARGETS, gate.TARGETS]
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


def test_feedback_predicates_stay_targeted():
    """Refactoring authentication cannot silently remove its rejection mutants."""
    mutants = gate.inventory(ROOT)
    intake = [item for item in mutants if item.function == "authenticate_intake"]
    assert len(intake) == 14
    assert {item.operator for item in intake} == {"bypass-required-evidence"}
    assert {
        "bypass-feedback-authentication",
        "expose-feedback-as-execution",
        "misclassify-repository-scope",
    } <= {item.operator for item in mutants}


def test_active_enrollment_predicates_stay_targeted():
    """The installer-authenticated --active path keeps real rejection mutants."""
    mutants = [
        item for item in gate.inventory(ROOT) if item.path in gate.ENROLLMENT_PATHS
    ]
    counts = {}
    for item in mutants:
        key = (item.path, item.function, item.operator)
        counts[key] = counts.get(key, 0) + 1
    observation = "scripts/operator_seed_observation.py"
    verifier = "pulumi/seed/policy_registry.py"
    assert counts == {
        (observation, "_installer_name", "bypass-enrollment-check"): 4,
        (observation, "_authenticate_installer", "bypass-enrollment-check"): 3,
        (observation, "_observe", "skip-installer-authentication"): 1,
        (observation, "observe_active_enrollment", "skip-active-verification"): 1,
        (observation, "_key_binding", "bypass-enrollment-check"): 2,
        (observation, "main", "misroute-active-mode"): 2,
        (verifier, "_verify_catalog_hash", "bypass-enrollment-check"): 1,
        (verifier, "_verify_observation", "bypass-enrollment-check"): 7,
        (verifier, "_verify_active_executor", "bypass-enrollment-check"): 4,
        (verifier, "_verify_mutable_role", "bypass-enrollment-check"): 4,
        (verifier, "verify_active_enrollment", "misroute-principal-check"): 4,
    }
    assert gate.ENROLLMENT_TARGETS == (
        "tests/unit/test_operator_seed_observation.py",
        "tests/unit/test_seed_policy_registry.py",
    )
    assert {gate._targets(item) for item in mutants} == {gate.ENROLLMENT_TARGETS}
    assert gate._targets(
        gate.Mutant("scripts/x.py", "f", 1, 0, "Name", "True", "t")
    ) == (gate.TARGETS)


def test_missing_semantic_target_is_error(monkeypatch, tmp_path):
    """A missing implementation cannot silently become a zero-mutant operator."""
    monkeypatch.setattr(gate, "GUARDS", {})
    monkeypatch.setattr(gate, "REQUIREMENTS", {})
    monkeypatch.setattr(gate, "SEMANTIC_TARGETS", {"sample.py": {"expected"}})
    (tmp_path / "sample.py").write_text("def other():\n    return True\n")
    with pytest.raises(ValueError, match="disappeared"):
        gate.inventory(tmp_path)
