"""
Pulumi entrypoint that wires together shared infrastructure modules.

This stack is intentionally minimal: it provisions the central logging bucket,
an S3 backend for Pulumi state, and the IAM OIDC integration for GitHub
deployments. Additional resources can be layered into the ``infra`` package
without changing this file.
"""

from infra import backup, logging_bucket, pulumi_state  # noqa: F401
from infra.iam import github_oidc, task_roles  # noqa: F401
