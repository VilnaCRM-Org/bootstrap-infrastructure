"""Per-repository KMS keys for Pulumi secrets encryption."""  # pragma: no mutate

from __future__ import annotations  # pragma: no mutate

import json  # pragma: no mutate
from typing import Dict, Sequence  # pragma: no mutate

import pulumi  # pragma: no mutate
import pulumi_aws as aws  # pragma: no mutate

from .config import (
    ManagedRepository,
    managed_repositories,
    pulumi_secrets_alias_name_for_repo,
    pulumi_secrets_provider_for_repo,
)  # pragma: no mutate
from .pulumi_state import _resource_suffix  # pragma: no mutate
from .utils.tags import base_tags  # pragma: no mutate


def _key_policy(account_id: str) -> str:
    """Return a key policy that enables IAM policies in this account."""
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "EnableAccountPermissions",
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                    "Action": "kms:*",
                    "Resource": "*",
                }
            ],
        }
    )


class PulumiSecretsKeys(pulumi.ComponentResource):  # pragma: no mutate
    """Create a customer-managed KMS key and alias for each managed repository."""  # pragma: no mutate

    def __init__(  # pragma: no mutate
        self,  # pragma: no mutate
        name: str,  # pragma: no mutate
        *,  # pragma: no mutate
        repositories: Sequence[ManagedRepository] | None = None,  # pragma: no mutate
        opts: pulumi.ResourceOptions | None = None,  # pragma: no mutate
    ) -> None:  # pragma: no mutate
        super().__init__(
            "bootstrap:kms:PulumiSecretsKeys", name, None, opts
        )  # pragma: no mutate

        repos = (
            list(repositories) if repositories is not None else managed_repositories()
        )  # pragma: no mutate
        account_id = aws.get_caller_identity().account_id  # pragma: no mutate
        region = aws.get_region().name  # pragma: no mutate

        self.key_arns: Dict[str, pulumi.Output[str]] = {}  # pragma: no mutate
        self.alias_names: Dict[str, pulumi.Output[str]] = {}  # pragma: no mutate
        self.provider_urls: Dict[str, pulumi.Output[str]] = {}  # pragma: no mutate

        for repo in repos:  # pragma: no mutate
            suffix = _resource_suffix(repo.name)  # pragma: no mutate
            alias_name = pulumi_secrets_alias_name_for_repo(
                repo.name
            )  # pragma: no mutate

            key = aws.kms.Key(  # pragma: no mutate
                f"{name}-key-{suffix}",  # pragma: no mutate
                description=f"Pulumi secrets KMS key for {repo.name} ({repo.default_branch})",  # pragma: no mutate
                deletion_window_in_days=30,  # pragma: no mutate
                enable_key_rotation=True,  # pragma: no mutate
                policy=_key_policy(account_id),  # pragma: no mutate
                tags=base_tags(
                    {
                        "Purpose": "pulumi-secrets",
                        "Repository": repo.name,
                        "App": repo.name,
                    }
                ),  # pragma: no mutate
                opts=pulumi.ResourceOptions(parent=self),  # pragma: no mutate
            )  # pragma: no mutate

            alias = aws.kms.Alias(  # pragma: no mutate
                f"{name}-alias-{suffix}",  # pragma: no mutate
                name=alias_name,  # pragma: no mutate
                target_key_id=key.key_id,  # pragma: no mutate
                opts=pulumi.ResourceOptions(parent=self),  # pragma: no mutate
            )  # pragma: no mutate

            self.key_arns[repo.name] = key.arn  # pragma: no mutate
            self.alias_names[repo.name] = alias.name  # pragma: no mutate
            self.provider_urls[repo.name] = (
                pulumi.Output.from_input(  # pragma: no mutate
                    pulumi_secrets_provider_for_repo(
                        repo.name, region
                    )  # pragma: no mutate
                )
            )  # pragma: no mutate

        self.register_outputs(  # pragma: no mutate
            {
                "key_arns": self.key_arns,  # pragma: no mutate
                "alias_names": self.alias_names,  # pragma: no mutate
                "provider_urls": self.provider_urls,  # pragma: no mutate
            }
        )
