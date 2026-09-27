# TEST workload capability v1: source proposal

This is a bounded part of [bootstrap #219](https://github.com/VilnaCRM-Org/bootstrap-infrastructure/issues/219),
under the [#18 PoC plan](https://github.com/VilnaCRM-Org/user-service-infrastructure/issues/18#issuecomment-5575434850).
It is **not approved, installed, or sufficient to deploy a workload**. The new
central resource components are not called by any live entrypoint. Installed seed
catalogs and PROD application authority remain unchanged. See the
[central enrollment slice](runtime-enrollment.md) and [provider audit](provider-audit.md).

## Pinned evidence and ownership

- Bootstrap main incorporated: `570fc727014d78d3a3e7d67f923e37f8873f6707`.
- The refresh preserves main's TEST seed enrollment, disabled prerequisite
  capability gate, and PROD catalog. It does not refresh native AWS observations
  or activate the runtime components.
- Current service contract checked: PR #19 `ed290e48cc0df74f3201337bc68162e632d9725b`.
- Current application contract checked: PR #492 `7ead3b390c331f6813f2e12d540c8b10db68af85`.
- The provider audit below retains its explicitly recorded earlier source pin;
  checking the current image contract does not refresh the entire CRUD audit.
- TEST account `891377212104`, region `eu-central-1`; infrastructure repository
  `VilnaCRM-Org/user-service-infrastructure` (ID `911736693`).
- Application repository `VilnaCRM-Org/user-service` (ID `646535009`); owner ID
  `114362548`. These are source declarations, not authenticated installation evidence.
- Operator/independent seed owns immutable ceilings and guards; governance owns
  deployment and runtime identities. Service owns the workload resource graph.
- `specs/poc/poc-test.json` on the pinned service revision is registry-only. The
  workload contract in `tests/fixtures` is explicitly synthetic and cannot supply
  approved domain, mail, role, KMS, secret or image identities.

## Concrete source increment

The image slice now includes finite ECR pull identity/boundary/guard documents
and TEST ECS trust for the central execution role; the task role stays disabled.
Complete runtime-observation verification is available to an independent
installer but never authorizes activation. The installed registry, governor
authority and entrypoints remain unchanged. See the enrollment document for
the explicit installation stop and remaining complete-registry amendment.

`pulumi/seed/poc_pass_role.py` renders separate, deterministic **amendment
fragments** for the deployment identity, shared boundary and immutable guard.
It accepts only the exact TEST service target and known deployment purposes.
It cannot install policies or register resources.

Apply proposes `iam:PassRole` for exactly:

- `arn:aws:iam::891377212104:role/user-service-infrastructure-test-EcsExecution`
- `arn:aws:iam::891377212104:role/user-service-infrastructure-test-EcsTask`

Both require `iam:PassedToService=ecs-tasks.amazonaws.com`. These preserve the
earlier dormant-runtime proposal's names; they do not assert those roles exist.
The publisher, deployment roles, service-linked roles, foreign roles and PROD
roles are excluded. Preview/drift identity and guard fragments explicitly deny
PassRole even though their shared boundary could allow the pair. Config-reader
policies must retain their own existing denial when the shared boundary changes.

The apply guard fragments explicitly deny other role ARNs and missing/wrong
service context. Offline tests exercise identity/boundary intersection, guard
denials, broad identity grants and denied IAM management. They model only these
fragments, not SCPs, resource policies, current seed denials or AWS authorization.
The existing complete guard can still deny the proposed allow: **append-only
installation of these fragments is not sufficient or authorized**.

AWS documents [exact role resources and PassedToService](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html).
Do not replace exact role selection with role-tag conditions. Passing these roles
also requires separately reviewed ECS task trust and bounded runtime policies.

## Resource/action inventory requiring full-profile review

The following maps the actual pinned program to ownership and required operation
families. It is not a final provider-call allowlist. Before generating deployment
policies, audit each pinned Pulumi AWS provider resource implementation, including
create/read/update/delete/tag APIs and dependent authorization. A resource class
name is not an IAM action name (notably DocumentDB uses RDS IAM operations).

| Plane and pinned source | Required scope/operations | Outstanding exact binding |
| --- | --- | --- |
| ECR: `app/registry.py`, `compute.py` | Two repositories `user-service-test-web` and `user-service-test-worker`; registry create/read/tag; workload lifecycle-policy read/write/delete. Image push remains publisher-only. | Earlier registry-only proposal omitted lifecycle actions; current workload adds two lifecycle policies. Review full provider call inventory and retain immutable tags/scan-on-push in admitted source. |
| ECS/Fargate: `compute.py` | One cluster; web/worker task-definition families and services. Cluster/service/task-definition create/read/update/delete/tag as applicable; exact runtime PassRole pair above. No ECS Exec or standalone arbitrary RunTask capability. | Enforce service name and namespace, exact cluster/service/family ARN scopes and task-definition revision patterns; resource-less APIs need supported conditions and plan checks. |
| ALB: `compute.py`, `access_logs.py` | One public application load balancer, one IP target group, HTTPS listener and HTTP redirect; corresponding lifecycle, attributes, tags, listener/target reads. Generated workload now owns a protected ALB log bucket and seven associated S3 controls. | Exact approved name/ARN selectors; scoped delivery principal/source conditions. New service-owned bucket-policy permission needs independent review and must exclude state buckets. The earlier external-log-bucket assumption is superseded. |
| Network: `network.py` | VPC, Internet gateway, public/app/data subnets, NAT gateways/EIPs, route tables/associations, four security groups and rules. | Many IDs are AWS-generated. Validate create request tags and resource-tag mutation scopes with dependent resource constraints; tags alone do not prove safe security-group peers or routing. Pin AZ/count inputs and native ownership. |
| DocumentDB: `data.py` | Subnet group, encrypted cluster, configured instances, audit/profiler logs and final-snapshot behavior; RDS API lifecycle/read/tag authorization. | Subnet group is auto-named; instances/count remain configurable. Bind exact namespace, approved subnet/security-group references, KMS behavior, logs and final-snapshot namespace. No database API permission is needed in ECS roles for password-based MongoDB traffic. |
| Redis: `data.py` | Subnet group and encrypted/authenticated replication group; ElastiCache lifecycle/read/tag authorization. | Auto-named subnet group, backup/snapshot behavior, exact replication-group ARN and approved network references. Application Redis protocol does not require cache-management IAM. |
| SQS: `messaging.py` | Six queues; create/read/attributes/tag/delete as applicable. Runtime send/receive/delete/change visibility only where application behavior requires; metadata-only health queue. | Current defaults are configurable and include `send-email`, `failed-send-email`, `insert-user-batch`, `domain-events`, `failed-domain-events`, `health-check-queue`. Close and enforce the namespace before granting. Review DLQ redrive attributes and KMS use; no queue policy management grant by assumption. |
| Logs: `compute.py`, `data.py` | Web/worker log groups with retention; runtime CreateLogStream/PutLogEvents limited to exact container stream prefixes. DocumentDB log export uses its service integration. | `/aws/ecs/user-service-infrastructure-test/{web,worker}` only after service-name pinning; evaluate DocumentDB audit/profiler and enhanced container-insights destinations separately. No broad logs writes or logging exemption based on service-controlled tags. |
| Runtime secrets: `runtime_secrets.py` | Ten explicitly named generated secrets/versions; create/read/update/tag/rotation lifecycle only as admitted. ECS execution reads the eight injected secret identities; DB password/Redis token are not injected separately. | Real reviewed names and exact KMS keys are absent from registry contract. AWS ARN suffix selectors must be six characters; KMS use constrained by key, service and encryption context. Existing secret-read explicit denials require independent narrow amendment, not a broad exception. |
| SES: external contract | Task role `ses:SendEmail` only for selected SES v2 transport, verified identity, exact sender and finite TEST recipients. No SES identity/configuration management. | No approved real mail binding supplied. Require nonempty recipients plus all-recipient membership; runtime send evidence remains required. |
| ACM: external contract / `compute.py` | Existing certificate ARN consumed by HTTPS listener; exact DescribeCertificate can support native preflight. | Program creates no certificate. Do not add RequestCertificate/DeleteCertificate/export grants. Authenticate selected certificate account/region, issuance and hostname coverage. |
| Route53: external contract | Program currently creates **no DNS record**. Selected authority and hosted-zone ID alone do not implement HTTPS routing. | Choose explicit DNS owner. Only if service record resources are added, review exact zone, normalized record name/type/action conditions and provider read/GetChange needs. No hosted-zone mutation or account-wide DNS grant now. |

## Central runtime identities and first-use prerequisites

The current workload supplies the same execution/task ARNs to web and worker.
Keep execution separate from application credentials: ECR pull, exact log streams,
eight injected secret reads and constrained Secrets Manager KMS decrypt belong to
execution. Task credentials cover approved SQS operations, health queue metadata
and selected TEST SES send. Review whether producer-only web and consumer/mail
worker roles should be split before accepting the shared task-role privilege union.
Never recreate the removed IAM health-check user/access key.

The distinct proposed publisher is
`arn:aws:iam::891377212104:role/user-service-test-ImagePublisher`, with
`.github/workflows/publish-poc-images.yml`, protected environment `poc-test-images`
and main source. Its ECR authorization token requires global resource scope;
upload/read/digest-query operations must name only the two TEST repositories.
Trust must bind authenticated immutable repository/owner identity, protected
environment and ordinary workflow identity using AWS-supported OIDC keys. A
synthetic subject or reusable-workflow claim is not ordinary-workflow evidence.
No publisher role may reuse infrastructure apply permissions.

Before installation, inspect native first-use service-linked-role requirements
for ECS, ELB, DocumentDB/RDS and ElastiCache, including their exact service names
and role paths. Have the central owner provision absent prerequisites through a
reviewed plan; do not give the service arbitrary CreateServiceLinkedRole or
PassRole for them. Check KMS/service integrations and actual account quotas.

For each final full managed-policy document, enforce 6,144 characters; check
aggregate inline policy size, actual role attachment limits, trust-policy quota,
existing attachments and case-insensitive role-name ownership collisions.
The tests only establish that the new small fragments fit; they do not establish
that merged documents or installed roles fit.

## Release stop and remaining acceptance

1. Fix and verify #185 independent current-head source review before TEST OIDC
   acquisition, including automatic same-repository PR previews. Preserve #184
   destructive-plan rejection and controller requester/serialization controls.
2. Agree the real versioned workload contract and the provider action inventory
   above. Resolve external domain/mail/logging/KMS ownership and runtime-role split.
3. Reconcile full seed boundary/guard documents and governance identity policies
   together. Verify no self-modification, foreign state/key/secret access,
   publisher privilege reuse or unauthorized PassRole, including explicit denies.
4. Install only using separately approved current-source saved plans and protected
   bootstrap workflows. Do not bypass the seed installer or use local AWS apply.
5. Capture native IAM policy versions/attachments/trust, policy-size/attachment
   quota evidence and effective identity/boundary/resource-policy/SCP intersection.
   Exercise allowed workload preview/apply/drift and denied cases; then application
   health, HTTPS, persistence, queues, mail, second release and rollback under #18.

No source test, metadata smoke, policy fragment or proposed ARN closes #219.
