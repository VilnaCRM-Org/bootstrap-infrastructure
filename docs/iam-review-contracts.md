# IAM installation review contracts

## Scope

The platform targets the existing commercial TEST and PROD accounts. These changes
preserve resource names, ownership, all existing trust claims and both exact GitHub
subject formats. No quota increase or AWS mutation is performed by this change.

## KMS ownership tags (3942446563)

`CreateBootstrapKmsKeys` now requires all three request tags: the configured
Environment, one of `pulumi-secrets`, `operations-alerting`, `operations-cloudtrail`,
and Repository equal to the primary repository. The immutable control boundary
inherits the same condition. The two OperationsMonitoring KMS Key constructors now
send Repository; PulumiSecretsKeys already did. No other resource tag set changes.
In the optional library mode without repo, monitoring uses its Pulumi project name;
real entrypoints supply the repository explicitly.

This is a creation restriction, **not closure of the existing untagged-key gap**.
`DenyForeignRepositoryKms` still rejects an explicit foreign Repository tag and
retains its existing missing-tag behavior for legacy compatibility. Existing
platform provider aliases remain exact: `alias/pulumi-platform-bootstrap-test`
and `alias/pulumi-platform-bootstrap-prod`, never an alias wildcard.

Recorded metadata identifies the following legacy targets; it is not a fresh
live readback or permission grant:

| Environment | Purpose | Recorded key ID |
| --- | --- | --- |
| test | platform provider | 1ab201ad-c498-496d-ad36-a529021da6be |
| test | alerting | bcab3af8-99e7-4cce-a81b-4f093f1899c4 |
| test | CloudTrail | 2e1638ca-d430-4f19-b30d-2f39943c6060 |
| prod | platform provider | fdba4c44-71b0-4979-b163-4705a91aa29b |
| prod | alerting | 9c9f44ee-515f-4ea8-b750-57ca403d4b84 |
| prod | CloudTrail | 47f3e069-ae24-4681-8e29-48b77fd7ce0a |

The alerting/CloudTrail checkpoints lack Repository. Platform-provider tag values
were not recorded in the alias inventory. Do not install a blanket missing-tag
Deny, adopt an arbitrary key by tagging it, or infer that these records authorize
new access. A tighter guard needs current key/account/alias/tag evidence and an
exact legacy exception inventory reviewed against the complete effective policy
union. Tagged CreateKey requires `kms:TagResource`; actual authorization under the
intended OIDC role remains a post-install live acceptance prerequisite for PR192.
The user explicitly deferred that live proof for the scoped PR193 installation;
it is not an additional impossible pre-merge PR193 condition. PR193 still requires
the applicable source-based security assessment and honest disclosure of this
legacy gap. The earlier root-caller
probe did not reach CreateKey and provides no success evidence.
[AWS CreateKey permissions](https://docs.aws.amazon.com/kms/latest/APIReference/API_CreateKey.html).

## Generic backend isolation (3942446500)

The shared backend helper includes the legacy platform alias only when the resolved
repository equals `settings.repo`. An explicit different repository receives its
own exact secrets alias. The separate governed-service helper remains unchanged.

## IAM size limits (3942446590, 3942446604)

Automation's first policy is inline and uses the 10,240-character aggregate role
limit. Its separately attached operator guard counts towards that aggregate.
Remaining Automation policies use 6,144 each. CI apply stores every document as a
managed policy, so it checks every document against 6,144 before role registration,
including the otherwise-inline first Automation document. Retained legacy inline
policies outside desired IaC inputs still require live inventory accounting; the
validator does not pretend it can discover them from source.

GitHub trust builders validate the full rendered policy against the supported
unraised default of 2,048 characters, excluding insignificant JSON whitespace.
Supported existing documents return byte-for-byte unchanged. A 39-character owner,
100-character repository, current four TEST preview contexts and current identity
IDs produce 2,084 compact characters and now fail explicitly. Neither subject
format nor an identity condition is removed to fit. A larger account-specific
contract needs a reviewed quota increase and source contract change; AWS's current
adjustable maximum is 8,192, not 4,096. Provider Output values are checked when the
trust document resolves, before a role API can use that document; this is not a
promise that no unrelated Pulumi resources were registered earlier.
[AWS IAM quotas](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_iam-quotas.html).

## Production regression (3942299313)

The effective creation-condition test now covers both TEST and PROD across the
CI, Automation and legacy Deploy policy unions. Wrong Project,
Environment and Purpose constraints cannot be inferred from TEST-only evidence.
