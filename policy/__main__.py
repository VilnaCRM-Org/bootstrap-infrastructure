"""Pulumi policy pack entrypoint."""

from pulumi_policy import PolicyPack

try:
    from policy.pack import POLICY_PACK_NAME, build_policies
except ModuleNotFoundError as exc:  # pragma: no cover
    # Pulumi may execute the policy pack with only the pack directory on sys.path.
    if exc.name not in {"policy", "policy.pack"}:
        raise
    from pack import POLICY_PACK_NAME, build_policies

PolicyPack(
    name=POLICY_PACK_NAME,
    policies=build_policies(),
)
