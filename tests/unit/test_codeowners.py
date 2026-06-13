"""Unit tests for ``.github/CODEOWNERS`` (§7.1, FR10, D5, SECURITY-4).

The CODEOWNERS file scopes every governance / IAM / policy / trust-or-scope
glob to the sole approver ``@Kravalg`` and adds **no** catch-all ``*`` line, so
unrelated paths stay unowned (D5, no over-scoping). The ``@Kravalg`` glob set
must stay byte/set-equal to ``scripts/governance_paths.GOVERNANCE_PATH_GLOBS``
(the single source of truth); any drift between the two lists is a CI failure.
"""

from __future__ import annotations

import importlib
import sys
from fnmatch import fnmatch
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

governance_paths = importlib.import_module("governance_paths")

CODEOWNERS_PATH = REPO_ROOT / ".github" / "CODEOWNERS"
SOLE_APPROVER = "@Kravalg"


def _parse_codeowners() -> list[tuple[str, tuple[str, ...]]]:
    """Return ``(glob, owners)`` rules in file order (blank/comment lines skipped)."""
    rules: list[tuple[str, tuple[str, ...]]] = []
    for raw in CODEOWNERS_PATH.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        glob, *owners = line.split()
        rules.append((glob, tuple(owners)))
    return rules


def _kravalg_globs() -> list[str]:
    """Return the globs whose only owner is ``@Kravalg`` (case-insensitive)."""
    return [
        glob
        for glob, owners in _parse_codeowners()
        if [owner.lower() for owner in owners] == [SOLE_APPROVER.lower()]
    ]


def _glob_to_patterns(glob: str) -> tuple[str, ...]:
    """Translate one CODEOWNERS glob into repo-relative fnmatch patterns."""
    anchored = glob.lstrip("/")
    if anchored.endswith("/"):
        prefix = anchored.rstrip("/")
        return (prefix, f"{prefix}/*")
    return (anchored,)


def _resolve_owner(path: str) -> str | None:
    """Return the owner CODEOWNERS assigns ``path`` (last matching rule wins)."""
    normalized = path.strip().lstrip("/")
    matched: str | None = None
    for glob, owners in _parse_codeowners():
        if any(fnmatch(normalized, pat) for pat in _glob_to_patterns(glob)):
            matched = owners[0] if owners else None
    return matched


def test_codeowners_file_exists() -> None:
    assert CODEOWNERS_PATH.is_file(), f"missing {CODEOWNERS_PATH}"


def test_kravalg_globs_set_equal_to_governance_path_globs() -> None:
    """Drift-equality both directions (SECURITY-4): no path in one list only."""
    codeowners = _kravalg_globs()
    source = governance_paths.GOVERNANCE_PATH_GLOBS

    # No duplicate globs in the CODEOWNERS @Kravalg block.
    assert len(codeowners) == len(set(codeowners)), "duplicate @Kravalg glob lines"

    parsed = set(codeowners)
    expected = set(source)
    assert parsed == expected, (
        "CODEOWNERS @Kravalg globs drifted from GOVERNANCE_PATH_GLOBS; "
        f"codeowners-only={sorted(parsed - expected)} "
        f"globs-only={sorted(expected - parsed)}"
    )


def test_every_governance_glob_resolves_to_kravalg() -> None:
    """Positive: each governance/IAM/policy glob resolves to @Kravalg."""
    for glob in governance_paths.GOVERNANCE_PATH_GLOBS:
        # Probe a concrete path that the glob is meant to own.
        if glob.endswith("/"):
            sample = f"{glob}sample_file.py"
        else:
            sample = glob
        assert _resolve_owner(sample) == SOLE_APPROVER, (
            f"glob {glob!r} (probe {sample!r}) does not resolve to {SOLE_APPROVER}"
        )


def test_unrelated_paths_have_no_owner() -> None:
    """Negative: non-governance paths stay unowned (no catch-all '*' line)."""
    for unrelated in (
        "docs/x.md",
        "README.md",
        "pulumi/app/main.py",
        "pulumi/user-service-infrastructure/pulumi/__main__.py",
        "scripts/some_unrelated_helper.py",
        "tests/x.py",
        "tests/unit/test_codeowners.py",
        ".github/workflows/ci.yml",
    ):
        assert _resolve_owner(unrelated) is None, (
            f"unrelated path {unrelated!r} is unexpectedly owned "
            f"by {_resolve_owner(unrelated)!r} (over-scoping / catch-all leak)"
        )


def test_no_catch_all_wildcard_rule() -> None:
    """A bare ``*`` (or ``/``) catch-all would over-scope every path (D5)."""
    for glob, _owners in _parse_codeowners():
        assert glob not in {"*", "/", "/*", "**"}, f"catch-all rule {glob!r} present"


def test_codeowners_file_itself_owned_by_kravalg() -> None:
    """Edge: .github/CODEOWNERS itself is owned by @Kravalg."""
    assert _resolve_owner(".github/CODEOWNERS") == SOLE_APPROVER


def test_every_owned_line_owner_is_kravalg() -> None:
    """No other owner appears anywhere in the file (sole-approver invariant)."""
    for glob, owners in _parse_codeowners():
        assert [owner.lower() for owner in owners] == [SOLE_APPROVER.lower()], (
            f"line {glob!r} has owners {owners!r}, expected only {SOLE_APPROVER}"
        )
