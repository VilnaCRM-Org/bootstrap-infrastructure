# CI configuration trust contract

CI configuration role construction requires repository-scoped settings. An
explicit repository argument must equal `settings.repo`; its default branch and
immutable repository/owner IDs belong in those settings. Governance already
passes scoped settings. Pure secret-name and ARN helpers still support explicit
repository names for calculations.

Config-read trusts require the fixed workflow names for each CI secret suffix,
alongside the existing exact repository, audience, subject and identity claims.
The workflow claim contains a name, not a repository file path. The separate
repository claim pins the path. `test-pr` intentionally retains pull-request
subjects without a main-branch ref condition; other suffixes retain their fixed
branch and environment subject constraints.

A same-repository pull request can reuse an allowed workflow name. This allowlist
narrows workflow access and does not prove that workflow code is trusted. The
isolated interpreter, reviewed immutable action closure, bounded config-reader
permissions and existing review controls remain necessary. No condition is
removed to make room: the existing 2,048-character trust-size check still applies.

Governance explicitly selects the committed service scaffold workflow contract:
`Service Self Deploy` for test, prod-preview and prod; `Initialize Service Stack`
for test and prod. The platform defaults do not gain these names, and service
scope is never inferred from a repository name. The existing test-pr list stays
unchanged. Tests parse the actual scaffold workflows and render real governed
config-reader resources, including a service-specific branch and immutable IDs.
