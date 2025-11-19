import pulumi
import pulumi_aws as aws

from .config import state_bucket_name
from .utils.tags import base_tags


bucket = aws.s3.Bucket(
  "pulumiState",
  bucket=state_bucket_name(),
  versioning=aws.s3.BucketVersioningArgs(enabled=True),
  lifecycle_rules=[
    aws.s3.BucketLifecycleRuleArgs(
      id="expire-old-versions",
      enabled=True,
      noncurrent_version_expiration=aws.s3.BucketLifecycleRuleNoncurrentVersionExpirationArgs(
        days=365
      ),
    )
  ],
  server_side_encryption_configuration=aws.s3.BucketServerSideEncryptionConfigurationArgs(
    rule=aws.s3.BucketServerSideEncryptionConfigurationRuleArgs(
      apply_server_side_encryption_by_default=aws.s3.BucketServerSideEncryptionConfigurationRuleApplyServerSideEncryptionByDefaultArgs(
        sse_algorithm="AES256"
      )
    )
  ),
  tags=base_tags({"Purpose": "pulumi-state"}),
)

aws.s3.BucketPublicAccessBlock(
  "pulumiStatePab",
  bucket=bucket.id,
  block_public_acls=True,
  block_public_policy=True,
  ignore_public_acls=True,
  restrict_public_buckets=True,
)


def _bucket_policy(arn: str) -> str:
  return f"""
{{
  "Version": "2012-10-17",
  "Statement": [
    {{
      "Sid": "RequireTLS",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["{arn}", "{arn}/state/*"],
      "Condition": {{
        "Bool": {{"aws:SecureTransport": "false"}}
      }}
    }}
  ]
}}
"""


aws.s3.BucketPolicy(
  "pulumiStatePolicy",
  bucket=bucket.id,
  policy=bucket.arn.apply(_bucket_policy),
)


pulumi.export("pulumiStateBucket", bucket.bucket)
pulumi.export("pulumiBackendUrl", pulumi.Output.concat("s3://", bucket.bucket, "/state/<stack>"))
