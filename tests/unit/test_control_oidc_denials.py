"""Controller denials preserve provider metadata reads and reject all mutations."""

from copy import deepcopy
from dataclasses import replace
from fnmatch import fnmatchcase

import pytest
from infra import config, platform_iam


@pytest.mark.parametrize("compressed", [False, True])
@pytest.mark.parametrize(
    ("action", "denied"),
    [
        ("GetOpenIDConnectProvider", False),
        ("ListOpenIDConnectProviders", False),
        ("ListOpenIDConnectProviderTags", False),
        ("CreateOpenIDConnectProvider", True),
        ("DeleteOpenIDConnectProvider", True),
        ("AddClientIDToOpenIDConnectProvider", True),
        ("RemoveClientIDFromOpenIDConnectProvider", True),
        ("UpdateOpenIDConnectProviderThumbprint", True),
        ("TagOpenIDConnectProvider", True),
        ("UntagOpenIDConnectProvider", True),
    ],
)
def test_control_oidc_denial_covers_mutations_only(action, denied, compressed):
    """The raw guard and compact boundary must both permit reference lookups."""
    statements = deepcopy(
        platform_iam.platform_control_denies(
            "123456789012",
            replace(
                config.settings, repo="bootstrap-infrastructure", environment="test"
            ),
        )
    )
    if compressed:
        platform_iam._compress_sensitive_statements(statements)
    matches = any(
        fnmatchcase(f"iam:{action}".lower(), pattern.lower())
        for statement in statements
        if statement["Effect"] == "Deny"
        for pattern in statement["Action"]
    )
    assert matches is denied
