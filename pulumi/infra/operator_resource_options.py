"""Remove completed import hints only in the operator after ownership cutover."""

from __future__ import annotations

from copy import copy

import pulumi

_OPERATOR_IMPORT_TYPES = {
    "aws:iam/role:Role",
    "aws:iam/policy:Policy",
    "aws:iam/rolePolicy:RolePolicy",
    "aws:iam/rolePolicyAttachment:RolePolicyAttachment",
    "aws:iam/rolePolicyAttachmentsExclusive:RolePolicyAttachmentsExclusive",
    "aws:secretsmanager/secret:Secret",
}


def without_completed_import(
    args: pulumi.ResourceTransformationArgs,
) -> pulumi.ResourceTransformationResult | None:
    """Keep checkpoint ownership; preserve provider/engine reads and all inputs.

    Register only from the operator entrypoint after its required ownership
    migration. This does not adopt resources or establish that migration ran.
    Shared constructors retain import hints for independently authorized adoption
    outside this entrypoint. Pulumi requires removing import hints after import.
    """
    if args.type_ not in _OPERATOR_IMPORT_TYPES:
        return None
    if not args.opts.import_ or args.opts.id is not None or args.opts.urn is not None:
        return None
    # ResourceOptions.merge ignores None, so it cannot clear an existing import.
    # A shallow copy preserves every other option, including resource references.
    options = copy(args.opts)
    options.import_ = None
    return pulumi.ResourceTransformationResult(props=args.props, opts=options)
