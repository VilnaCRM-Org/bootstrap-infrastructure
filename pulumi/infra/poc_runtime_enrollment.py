"""Central TEST ECS roles for independently staged enrollment.

Not wired into an entrypoint. The independent publisher stack owns only the
publisher role and its two fences; the four ECS fences await a later reviewed
runtime amendment, so the fence preflight fails closed until they exist.
"""

from __future__ import annotations

import json

import pulumi_aws as aws
from seed.poc_runtime import (
    ACCOUNT_ID,
    REGION,
    disabled_trust,
    enrollment_records,
    execution_policy,
    execution_trust,
    runtime_identities,
)
from seed.policy_registry import RegistryError, canonical_json

import pulumi


def _target(provider: aws.Provider, project: str) -> pulumi.InvokeOptions:
    """Reject wrong ownership/account/region using the explicit resource provider."""
    if not isinstance(provider, aws.Provider):
        raise RegistryError("Runtime enrollment requires an explicit AWS provider")
    if pulumi.get_project() != project:
        raise RegistryError(f"Runtime enrollment requires the {project} project")
    target = pulumi.InvokeOptions(provider=provider)
    if (
        aws.get_caller_identity(opts=target).account_id != ACCOUNT_ID
        or aws.get_region(opts=target).region != REGION
    ):
        raise RegistryError("Runtime enrollment requires TEST eu-central-1")
    return target


def _verify_fences(target: pulumi.InvokeOptions) -> None:
    """Read every independent fence before registering any runtime role."""
    policies, _ = enrollment_records()
    for record in policies:
        try:
            observed = aws.iam.get_policy(arn=record.arn, opts=target)
        except Exception as error:
            raise RegistryError(
                "Independently installed runtime fence missing"
            ) from error
        if (
            observed is None
            or observed.arn != record.arn
            or canonical_json(json.loads(observed.policy)) != record.document_json
        ):
            raise RegistryError("Independently installed runtime fence differs")


def _inline_grants(purpose: str) -> dict[str, str]:
    """Select only fixed pull grants; the disabled task has none."""
    if purpose == "execution":
        return {"Issue219TestImagePull": execution_policy()}
    return {}


def _role_trust(purpose: str) -> str:
    """Select the only trust document allowed for each ECS role."""
    if purpose == "execution":
        return execution_trust()
    return disabled_trust()


class PocRuntimeRoles(pulumi.ComponentResource):
    """Register protected ECS roles with fixed trust and closed grants.

    Execution can pull only the two ECR repositories; task trust stays disabled.
    This proposal is not wired into the current governor's entrypoint.
    """

    def _close_grants(self, identity, provider: aws.Provider) -> None:
        """Manage exactly the sole guard attachment and fixed inline policies."""
        role = self.roles[identity.purpose]
        opts = pulumi.ResourceOptions(parent=self, provider=provider, protect=True)
        inline = _inline_grants(identity.purpose)
        policies = [
            aws.iam.RolePolicy(
                f"{identity.name}-{name}",
                role=role.name,
                name=name,
                policy=text,
                opts=opts,
            )
            for name, text in inline.items()
        ]
        self.grants[identity.purpose] = [*policies]
        attachments = aws.iam.RolePolicyAttachmentsExclusive(
            f"{identity.name}-managed-policy-attachments-exclusive",
            role_name=role.name,
            policy_arns=[identity.policy_arn("guard")],
            opts=opts,
        )
        # An empty name set still enforces that no inline policy exists.
        exclusive = aws.iam.RolePoliciesExclusive(
            f"{identity.name}-inline-policies-exclusive",
            role_name=role.name,
            policy_names=list(inline),
            opts=pulumi.ResourceOptions(
                parent=self, provider=provider, protect=True, depends_on=policies
            ),
        )
        self.grants[identity.purpose] += [attachments, exclusive]

    def __init__(self, *, provider: aws.Provider) -> None:
        target = _target(provider, "governance")
        # Verify before registering any role. The governor never owns or edits
        # these independently installed policies, including in a preview.
        _verify_fences(target)
        super().__init__(
            "bootstrap:governance:PocRuntimeRoles",
            "poc-test-runtime-roles",
            None,
            pulumi.ResourceOptions(provider=provider, protect=True),
        )
        self.roles = {}
        self.grants = {}
        for identity in runtime_identities():
            if identity.purpose == "publisher":
                continue
            self.roles[identity.purpose] = aws.iam.Role(
                identity.name,
                name=identity.name,
                path="/",
                assume_role_policy=_role_trust(identity.purpose),
                permissions_boundary=identity.policy_arn("boundary"),
                max_session_duration=3600,
                tags={
                    "OwnerProject": "governance",
                    "Environment": "test",
                    "Repository": "VilnaCRM-Org/user-service-infrastructure",
                    "Purpose": identity.purpose,
                },
                opts=pulumi.ResourceOptions(
                    parent=self, provider=provider, protect=True
                ),
            )
            self._close_grants(identity, provider)
        self.role_arns = {purpose: role.arn for purpose, role in self.roles.items()}
        self.register_outputs({"roleArns": self.role_arns})
