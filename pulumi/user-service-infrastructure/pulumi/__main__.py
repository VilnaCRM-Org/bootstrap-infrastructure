"""Thin self-deploy baseline for ``user-service-infrastructure``.

This is the generic per-repo baseline the managed service repo runs against its
own AWS account. It **consumes, never creates** the governance-provided
infrastructure:

- the Pulumi **state bucket** ``s3://pulumi-user-service-infrastructure-{env}-state``
  (configured as ``pulumiBackendUrl`` / the Pulumi ``--backend-url``),
- the Pulumi secrets **KMS key + alias**
  ``alias/pulumi-user-service-infrastructure-{env}-secrets`` (the stack's
  ``secretsprovider`` / ``pulumiSecretsProvider``),
- the GitHub OIDC **deploy roles**
  (``GitHubCiPreview/Apply/Drift-user-service-infrastructure-{env}``) and the
  **config-read roles** (``GitHubCiConfigRead-user-service-infrastructure-{suffix}``),
  which the self-deploy workflow assumes via OIDC — they are governance-owned and
  are referenced by name/ARN, never created here.

This scaffold therefore creates **no IAM roles, no OIDC trust, and no Pulumi state
bucket / KMS key** of its own. Its initial apply role is backend-only. Real
workload resources require separately reviewed capabilities and immutable boundary
extensions before they can be deployed.

**Preview-blocked until operator governance apply (FEASIBILITY-6).** The consumed
backend bucket, KMS key, deploy roles, and the GitHub repo-variables the workflow
reads only exist after the operator runs the one-time governance apply for this
repo and sets the variables. Until then ``pulumi preview`` cannot resolve its
backend/secrets provider, so this template is validated by structure only.
"""

from __future__ import annotations

import pulumi

config = pulumi.Config()

# Governance-provided, repo-scoped wiring (CONSUMED — created by the governance
# stack, never by this scaffold). These are surfaced as stack outputs so an
# operator can confirm the self-deploy workflow is pointed at the right
# governance resources before adding real service infrastructure below.
repo_slug = config.require("repoSlug")
environment = config.require("environment")
pulumi_backend_url = config.require("pulumiBackendUrl")
pulumi_secrets_provider = config.require("pulumiSecretsProvider")

# NOTE: do NOT create IAM roles, OIDC providers, the state bucket, or the KMS key
# here. They are owned by the governance stack (see pulumi/infra/governance.py)
# and consumed via the backend URL + secrets provider above. Real workloads
# require a separate reviewed capability grant before resources are added.

pulumi.export("repoSlug", repo_slug)
pulumi.export("environment", environment)
pulumi.export("pulumiBackendUrl", pulumi_backend_url)
pulumi.export("pulumiSecretsProvider", pulumi_secrets_provider)
