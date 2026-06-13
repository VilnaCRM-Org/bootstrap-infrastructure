"""IAM component exports for Pulumi stacks."""

from .github_oidc import GitHubOidcRoles
from .readonly import ClaudeReadOnlyRole

__all__ = ("ClaudeReadOnlyRole", "GitHubOidcRoles")
