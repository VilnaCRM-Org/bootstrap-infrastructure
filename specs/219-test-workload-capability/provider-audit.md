# Pinned workload/provider action audit

Workload: service PR #19 `521a0648ea27395dbf6b5af76b5b6bcdcef11070`.
The resource source is unchanged from `33f5144ee97b368a4934c7f661283dd97aad5dd3`;
the intervening change affects an integration test only.
[Pulumi AWS 7.23.0's upstream gitlink](https://github.com/pulumi/pulumi-aws/tree/v7.23.0/upstream)
is `4981ec2b44ea4892c1ee4f0c1ed23b761a55f44d`. The API names below come from
that pinned upstream implementation, including generated tag helpers and
paginators. They are review input, not an installed permission set. Network,
service prerequisites and dependent authorization must still be reconciled with
the complete IAM action/resource model before workload activation.

## Observed lifecycle calls and exact resource decisions

| Owner / IAM prefix | Provider calls relevant to the declared resources | Resource binding / exclusions |
| --- | --- | --- |
| ECS / `ecs` | `CreateCluster`, `DescribeClusters`, `UpdateCluster`, `DeleteCluster`; `RegisterTaskDefinition`, `DescribeTaskDefinition`, `DeregisterTaskDefinition`; `CreateService`, `DescribeServices`, `UpdateService`, `DeleteService`; `ListTagsForResource`, `TagResource`, `UntagResource`. | Cluster `user-service-infrastructure-test-ecs`; two families/services ending `-web`/`-worker`. Task revisions require a revision selector. Current services set `wait_for_steady_state=False`; do not automatically add the provider's conditional `DescribeServiceDeployments`, `ListServiceDeployments`, or `StopServiceDeployment` rollback APIs. No `RunTask`, ECS Exec, or arbitrary PassRole. |
| ALB / `elasticloadbalancing` | `CreateLoadBalancer`, `DescribeLoadBalancers`, `DescribeLoadBalancerAttributes`, `ModifyLoadBalancerAttributes`, `SetSecurityGroups`, `SetSubnets`, `SetIpAddressType`, `DeleteLoadBalancer`; `CreateListener`, `DescribeListeners`, `DescribeListenerAttributes`, `ModifyListener`, `ModifyListenerAttributes`, `DeleteListener`; `CreateTargetGroup`, `DescribeTargetGroups`, `DescribeTargetGroupAttributes`, `ModifyTargetGroup`, `ModifyTargetGroupAttributes`, `DeleteTargetGroup`; `AddTags`, `DescribeTags`, `RemoveTags`. | The name function hashes overlength names: ALB `user-service-infrastruc-6e588783`, target group `user-service-infrastruc-a918aecc`. Bind ARN generated-ID patterns to these exact names; listener ARN includes the ALB ID. `DescribeCapacityReservation` is attempted on ALB read but AccessDenied is expressly tolerated; it is not required solely to make refresh pass. Do not add `ModifyCapacityReservation` or `ModifyIpPools` for omitted features. |
| DocumentDB / `rds` | `CreateDBCluster`, `DescribeDBClusters`, `ModifyDBCluster`, `DeleteDBCluster`; `CreateDBInstance`, `DescribeDBInstances`, `ModifyDBInstance`, `DeleteDBInstance`; `CreateDBSubnetGroup`, `DescribeDBSubnetGroups`, `ModifyDBSubnetGroup`, `DeleteDBSubnetGroup`; `AddTagsToResource`, `ListTagsForResource`, `RemoveTagsFromResource`; **unfiltered `DescribeGlobalClusters`** during cluster read. | Cluster `user-service-infrastructure-test-docdb`, declared instance IDs `...-docdb-<index>`, auto-named subnet group. Pin approved count and final snapshot name. No global mutation, snapshot restore, failover, role association or IAM database login is implied. See the read exception below. |
| Redis / `elasticache` | `CreateReplicationGroup`, `DescribeReplicationGroups`, `DescribeCacheClusters`, `ModifyReplicationGroup`, `DeleteReplicationGroup`; `CreateCacheSubnetGroup`, `DescribeCacheSubnetGroups`, `ModifyCacheSubnetGroup`, `DeleteCacheSubnetGroup`; `AddTagsToResource`, `ListTagsForResource`, `RemoveTagsFromResource`. | Replication group `user-service-infrastructure-test-redis`, auto-named subnet group and service-created member cache clusters. `IncreaseReplicaCount`/`DecreaseReplicaCount` are conditional scale updates; pin PoC replica count or review those exact operations. No global group disassociation or shard reconfiguration for undeclared features. |
| Queues / `sqs` | IaC uses `CreateQueue`, `GetQueueAttributes`, `SetQueueAttributes`, `DeleteQueue`, `ListQueueTags`, `TagQueue`, `UntagQueue`. Runtime transport separately uses queue URL/attributes, send, receive, delete and visibility calls. | Six declared queue identities; current names are configurable. The fixed health-check queue needs metadata reads, not send/consume/create. Namespace/ownership, redrive targets and queue encryption must be enforced before grants. No resource-policy grant is justified by a tag. |
| ECR / `ecr` | Registry read/create/tag plus two lifecycle policies: `GetLifecyclePolicy`, `PutLifecyclePolicy`, `DeleteLifecyclePolicy`. The provider has conditional mutability/scanning setters and repository deletion, but source review must decide which lifecycle changes are admissible. | Only `user-service-test-web` and `user-service-test-worker`. Publisher's distinct complete action set is in `runtime-enrollment.md`. No publisher repository management. |
| Secrets / `secretsmanager` | `CreateSecret`, `DescribeSecret`, `UpdateSecret`, `DeleteSecret`, `TagResource`, `UntagResource`; versions use `GetSecretValue`, `PutSecretValue`, `ListSecretVersionIds`, `UpdateSecretVersionStage`. Provider metadata/resource-policy helper reads must also be included in final review. | Ten real generated secret names plus exact KMS keys are still missing from the checked-in registry-phase contract. Do not copy synthetic fixtures. Omitted replication and secret resource-policy features do not justify their mutation APIs. Existing secret-value explicit denials need independently reviewed narrow amendments. |
| SES / `ses` | The selected application SES v2 transport requires `SendEmail`, not SES identity administration. | Exact approved identity ARN, sender and finite nonempty TEST recipient set remain required. No real mail binding is in the registry-phase contract. |

Sources: pinned upstream [ECS](https://github.com/hashicorp/terraform-provider-aws/tree/4981ec2b44ea4892c1ee4f0c1ed23b761a55f44d/internal/service/ecs),
[ELBv2](https://github.com/hashicorp/terraform-provider-aws/tree/4981ec2b44ea4892c1ee4f0c1ed23b761a55f44d/internal/service/elbv2),
[DocumentDB](https://github.com/hashicorp/terraform-provider-aws/tree/4981ec2b44ea4892c1ee4f0c1ed23b761a55f44d/internal/service/docdb),
[ElastiCache](https://github.com/hashicorp/terraform-provider-aws/tree/4981ec2b44ea4892c1ee4f0c1ed23b761a55f44d/internal/service/elasticache),
[SQS](https://github.com/hashicorp/terraform-provider-aws/tree/4981ec2b44ea4892c1ee4f0c1ed23b761a55f44d/internal/service/sqs),
[ECR](https://github.com/hashicorp/terraform-provider-aws/tree/4981ec2b44ea4892c1ee4f0c1ed23b761a55f44d/internal/service/ecr),
[Secrets Manager](https://github.com/hashicorp/terraform-provider-aws/tree/4981ec2b44ea4892c1ee4f0c1ed23b761a55f44d/internal/service/secretsmanager).

## DocumentDB global metadata read decision

The provider's [cluster refresh](https://github.com/hashicorp/terraform-provider-aws/blob/4981ec2b44ea4892c1ee4f0c1ed23b761a55f44d/internal/service/docdb/cluster.go#L747)
always calls `findGlobalClusterByClusterARN`. Its
[helper](https://github.com/hashicorp/terraform-provider-aws/blob/4981ec2b44ea4892c1ee4f0c1ed23b761a55f44d/internal/service/docdb/global_cluster.go#L341)
passes an empty `DescribeGlobalClustersInput`, paginates all returned records,
then filters membership locally. Ordinary authorization denial is fatal; only
not-found and the specific unsupported-global-API error are tolerated.

AWS's [RDS authorization reference](https://docs.aws.amazon.com/service-authorization/latest/reference/list_rds.html)
maps this DocumentDB operation to `rds:DescribeGlobalClusters` and lists optional
`global-cluster` resource support. The ARN form is
`arn:aws:rds::891377212104:global-cluster:<id>` (no region), not the local cluster
ARN. The source's unfiltered call provides no global-cluster ID. A service tag or
local cluster ARN is not a demonstrated restriction for that request.

**Explicit blocker: no `DescribeGlobalClusters` grant is generated or attached.**
First test the account-local `arn:aws:rds::891377212104:global-cluster:*` candidate
against the actual provider request using independently authenticated native
permission evidence. If the empty-input list cannot use that resource scope,
maintainers must choose a reviewed provider change or explicitly accept a
single-action read exception. AWS's
[DocumentDB example](https://docs.aws.amazon.com/r53recovery/latest/dg/security_iam_region_switch_documentdb.html)
uses `Resource: "*"` for this read, but that example is not authorization for this
repository to install it. Any later exception must restrict the TEST endpoint and
exact deployment principals in both identity/boundary and immutable guard context.

An unfiltered list can reveal sibling global-cluster metadata visible to the TEST
caller, and this RDS permission name is shared with Aurora. Region conditions
restrict the endpoint, not every region named in returned global metadata. No
global creation, modification, failover, deletion, or account assumption is needed.
The [DocumentDB API](https://docs.aws.amazon.com/documentdb/latest/APIReference/API_DescribeGlobalClusters.html)
supports a `db-cluster-id` filter, which this provider does not send; server-side
filtering alone still needs separate IAM authorization proof. Do not invent a
resource-tag or local-cluster condition to claim namespace isolation.

## Changed ALB log ownership and remaining external inputs

Current [service access-log source](https://github.com/VilnaCRM-Org/user-service-infrastructure/blob/521a0648ea27395dbf6b5af76b5b6bcdcef11070/pulumi/app/access_logs.py)
creates `user-service-infrastructure-test-891377212104-alb-logs` with ownership,
public-access, SSE-S3, versioning, lifecycle and bucket-policy resources. The
delivery Allow has the ELB log-delivery service principal, exact log prefix and
account/region/physical ALB name in SourceArn. This supersedes the initial inventory's
external central log bucket assumption. Its exact S3 metadata/mutation API set,
resource-policy semantics, native bucket ownership and logging exemption must be
reviewed before adding service S3 authority. No state-bucket policy access follows
from permission to manage this separate bucket.

ACM remains an externally selected certificate and the source still creates no
Route53 record. Thus certificate issuance/deletion and hosted-zone management are
not required by the present resource graph. Native certificate validation and
explicit DNS record ownership remain prerequisites for the direct HTTPS endpoint.
