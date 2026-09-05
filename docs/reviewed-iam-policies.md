# Reviewed IAM policy exceptions

The mandatory `iam-no-wildcards` policy rejects broad IAM permissions unless
AWS requires a resource wildcard for an explicitly recognized action, or the
complete policy document matches a reviewed content pin. Policy names and
`AllowWildcardIam` tags do not grant an exception.

`policy/vilnacrm_guardrails.yaml` binds each reviewed SHA256 digest to an exact
Pulumi resource type and physical policy name. Inline policy entries also bind
the owning role name. Digests cover the complete JSON document, including
explicit denials, actions, resources, conditions and version. JSON whitespace
and object-key order do not affect a pin. Arrays retain their order. Changed
permissions, duplicate JSON keys, malformed documents, unknown identities or
extra embedded policy documents cannot use the exception.

The bootstrap operator, platform and governance entrypoints independently pin
the AWS account to the configured account ID before creating resources. The
policy validator makes no cloud calls and cannot establish provider identity
from a policy's resource ARNs. Its content pins complement that account check.

The reviewed inventory contains these limited policy families:

| Family | Why a reviewed exception is needed | Additional boundary |
| --- | --- | --- |
| `PlatformBoundary-control-{test,prod}` | The managed-policy size limit requires compact service action families on the exact platform resource inventory. | A permissions boundary grants no access on its own. IAM/control mutations and state isolation have explicit denials; identity policies supply narrower permissions. |
| `PlatformBoundary-backup-{test,prod}` | AWS Backup needs global metric and bucket/rule discovery actions. | Data and KMS access remain restricted to the platform backup inventory and aliases. |
| `GitHubCiApply-bootstrap-infrastructure-*-iam-boundary-policy` and `github-automation-iam-boundary-policy` | The controller policy includes bounded IAM metadata and service-role administration. | The complete document pins its exact backup role, required boundary and control-role denials. |
| `GitHubCiApply-bootstrap-infrastructure-*-iam-managed-policies` | Creation and enumeration of automation policies require the reviewed bootstrap policy shape. | Creation has the reviewed request-tag condition, updates target the automation policy prefix, and the immutable controller boundary denies changes to control policies. |
| Platform preview/drift `*-read-only` inline policies | Infrastructure previews and evidence collection need the reviewed AWS metadata actions. | The pinned document retains explicit secret-leaking-read denials. State guards apply independently. Each inline policy is bound to its exact role. |

These pins were compared with the 98 generated documents validated by AWS IAM
Access Analyzer and the 222 custom policy simulation cases. They do not replace
effective-permission tests, resource-policy review, OIDC exchanges or actual
deployment evidence. Those separate gates remain mandatory.

Service and governance roles use scoped permissions and AWS-required unscopable
actions; they have no reviewed wildcard exceptions.

The governor's `kms:CreateKey` permission requires all three request tags:
the exact repository, environment and `Purpose=pulumi-secrets`.
`access-analyzer:ValidatePolicy` is recognized as an AWS action with no
resource-level permission support; this does not authorize other analyzer
actions.

Update a pin only after reviewing the complete changed IAM document and
re-running the relevant Access Analyzer, positive/negative permission and
policy-pack tests. Never regenerate and accept pins automatically during a
deployment. The policy directory and validation helpers require the configured
CODEOWNER review and current-head promotion evidence.

AWS references:

- [Permissions boundaries](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html)
- [IAM policy grammar](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_grammar.html)
- [Access Analyzer authorization reference](https://docs.aws.amazon.com/service-authorization/latest/reference/list_accessanalyzer.html)
