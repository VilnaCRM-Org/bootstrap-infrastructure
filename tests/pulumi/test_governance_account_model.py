"""Account-model correctness verification for the governance stack (E4.S2).

These assert the two-account model facts (architecture §0/D1, §2.2, §10.2):

- NO account-number literal (``891377212104``/``933245420672``) is hardcoded as
  a runtime value in any ``pulumi/infra/*.py`` component module. The literal must
  live only in the per-stack config files, never in component code. Explanatory
  docstrings may mention the accounts (they document *that* the literal does not
  live in code), so the check inspects executable string/number literals only and
  ignores docstrings and comments.
- The governance ``test`` stack config pins ``891377212104`` and the ``prod``
  stack config pins ``933245420672`` (each pins ONLY its own account).
- IF ``costAnomalyMonitorArn`` is present in a stack config, its account matches
  that stack (test -> ``891377212104``, prod -> ``933245420672``). Absence is
  permitted (FEASIBILITY-6); ``prod`` is never repointed away from ``933245420672``.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
INFRA_DIR = ROOT / "pulumi" / "infra"
GOVERNANCE_DIR = ROOT / "pulumi" / "governance"
TEST_ACCOUNT_ID = "891377212104"
PROD_ACCOUNT_ID = "933245420672"
ACCOUNT_IDS = (TEST_ACCOUNT_ID, PROD_ACCOUNT_ID)


def _executable_literals(source: str) -> list[str]:
    """Return executable string/number literal text, excluding docstrings.

    Docstrings (module/class/function/leading-expression string constants) are
    documentation, not runtime values, so they are skipped — they legitimately
    explain that the account literal lives in stack config, not in code.
    """
    tree = ast.parse(source)
    docstring_nodes: set[int] = set()
    doc_holders = (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
    for node in ast.walk(tree):
        if isinstance(node, doc_holders):
            doc = ast.get_docstring(node, clean=False)
            if doc is not None:
                body = getattr(node, "body", [])
                if body and isinstance(body[0], ast.Expr):
                    docstring_nodes.add(id(body[0].value))

    literals: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and id(node) not in docstring_nodes:
            if isinstance(node.value, str):
                literals.append(node.value)
            elif isinstance(node.value, int) and not isinstance(node.value, bool):
                literals.append(str(node.value))
    return literals


def _stack_config(stack_file: str) -> dict[str, str]:
    payload = yaml.safe_load((GOVERNANCE_DIR / stack_file).read_text())
    return payload["config"]


def _arn_account(arn: str) -> str | None:
    """Extract the 12-digit AWS account id from an ARN, if present."""
    match = re.search(r"arn:aws:[^:]*:[^:]*:(\d{12}):", arn)
    return match.group(1) if match else None


def test_no_account_literal_in_infra_component_python() -> None:
    """No 891377212104/933245420672 runtime literal in any pulumi/infra/*.py."""
    offenders: list[str] = []
    for module in sorted(INFRA_DIR.glob("*.py")):
        for literal in _executable_literals(module.read_text()):
            if any(account in literal for account in ACCOUNT_IDS):
                offenders.append(f"{module.name}: {literal!r}")

    assert not offenders, (  # nosec B101
        "account-number literal hardcoded in component code: " + "; ".join(offenders)
    )


def test_docstrings_may_mention_accounts_but_code_does_not() -> None:
    """Guard the AST seam: governance.py mentions accounts only in docstrings."""
    source = (INFRA_DIR / "governance.py").read_text()

    # The raw source mentions the accounts (in docstrings) ...
    assert TEST_ACCOUNT_ID in source  # nosec B101
    # ... but no executable literal contains either account number.
    for literal in _executable_literals(source):
        assert TEST_ACCOUNT_ID not in literal  # nosec B101
        assert PROD_ACCOUNT_ID not in literal  # nosec B101


def test_test_stack_config_pins_test_account_only() -> None:
    """The governance test stack config pins 891377212104 and not the prod account."""
    config = _stack_config("Pulumi.test.yaml")
    text = (GOVERNANCE_DIR / "Pulumi.test.yaml").read_text()

    assert config["governance:awsAccountId"] == TEST_ACCOUNT_ID  # nosec B101
    assert PROD_ACCOUNT_ID not in text  # nosec B101


def test_prod_stack_config_pins_prod_account_only() -> None:
    """The governance prod stack config pins 933245420672 and not the test account."""
    config = _stack_config("Pulumi.prod.yaml")
    text = (GOVERNANCE_DIR / "Pulumi.prod.yaml").read_text()

    assert config["governance:awsAccountId"] == PROD_ACCOUNT_ID  # nosec B101
    assert TEST_ACCOUNT_ID not in text  # nosec B101


def test_cost_anomaly_monitor_arn_matches_its_stack_when_present() -> None:
    """If costAnomalyMonitorArn is present, its account matches the stack."""
    expected = {
        "Pulumi.test.yaml": TEST_ACCOUNT_ID,
        "Pulumi.prod.yaml": PROD_ACCOUNT_ID,
    }

    for stack_file, account in expected.items():
        config = _stack_config(stack_file)
        arn = config.get("governance:costAnomalyMonitorArn")
        if arn is None:
            # Absence is permitted (FEASIBILITY-6) — the code path tolerates unset.
            continue
        arn_account = _arn_account(arn)
        assert arn_account == account, (  # nosec B101
            f"{stack_file} costAnomalyMonitorArn account {arn_account!r} "
            f"does not match stack account {account!r}"
        )
