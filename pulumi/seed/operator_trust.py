"""Exact active operator OIDC trust; generating a document never activates a role.

The reusable account workflow is pinned here. Admission to its trusted root
caller and the selected PR remain separate worker checks. These public claims
follow IAM's GitHub OIDC condition-key contract and the existing github_identity
legacy/immutable subject convention, without importing Pulumi runtime modules.
"""

from __future__ import annotations

import json

_ACCOUNTS = {"test": "891377212104", "prod": "933245420672"}
_ENVIRONMENTS = {
    "preview": "operator-preview",
    "apply": "operator",
    "drift": "operator-drift",
}
_REPOSITORY = "VilnaCRM-Org/bootstrap-infrastructure"
_REPOSITORY_ID = "1098568429"
_OWNER_ID = "114362548"
_ISSUER = "token.actions.githubusercontent.com"
_WORKFLOW = ".github/workflows/pulumi-operator-account.yml"


def operator_trust_policy(environment: str, purpose: str, *, account_id: str) -> str:
    """Return canonical exact trust for one closed account/executor purpose.

    No wildcard subjects or optional GitHub identity fields are accepted. The
    document is below the default 2,048-character IAM trust-policy limit.
    """
    if (
        type(environment) is not str
        or environment not in _ACCOUNTS
        or account_id != _ACCOUNTS[environment]
    ):
        raise ValueError("Operator trust account/environment mismatch")
    if type(purpose) is not str or purpose not in _ENVIRONMENTS:
        raise ValueError("Unknown operator executor purpose")
    github_environment = _ENVIRONMENTS[purpose]
    subjects = [
        f"repo:{_REPOSITORY}:environment:{github_environment}",
        f"repo:VilnaCRM-Org@{_OWNER_ID}/bootstrap-infrastructure@{_REPOSITORY_ID}"
        f":environment:{github_environment}",
    ]
    claims = {
        "aud": "sts.amazonaws.com",
        "sub": subjects,
        "repository": _REPOSITORY,
        "repository_id": _REPOSITORY_ID,
        "repository_owner_id": _OWNER_ID,
        "ref": "refs/heads/main",
        "job_workflow_ref": f"{_REPOSITORY}/{_WORKFLOW}@refs/heads/main",
        "environment": github_environment,
    }
    document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Federated": f"arn:aws:iam::{account_id}:oidc-provider/{_ISSUER}"
                },
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringEquals": {
                        f"{_ISSUER}:{key}": value for key, value in claims.items()
                    }
                },
            }
        ],
    }
    return json.dumps(document, sort_keys=True, separators=(",", ":"))
