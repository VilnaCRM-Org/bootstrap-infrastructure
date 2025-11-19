import pulumi
import pulumi_aws as aws

from ..config import settings, state_bucket_name


provider = aws.iam.OpenIdConnectProvider(
  "githubOidcProvider",
  client_id_list=["sts.amazonaws.com"],
  thumbprint_list=["6938fd4d98bab03faadb97b34396831e3780aea1"],
  url="https://token.actions.githubusercontent.com",
)

bucket_arn = pulumi.Output.concat("arn:aws:s3:::", state_bucket_name())
objects_arn = pulumi.Output.concat(bucket_arn, "/state/*")

assume_role_policy = pulumi.Output.all(provider.arn).apply(
  lambda values: f"""
{{
  "Version": "2012-10-17",
  "Statement": [
    {{
      "Effect": "Allow",
      "Principal": {{
        "Federated": "{values[0]}"
      }},
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {{
        "StringEquals": {{
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        }},
        "StringLike": {{
          "token.actions.githubusercontent.com:sub": "repo:{settings.org}/{settings.repo}:ref:refs/heads/{settings.github_branch}"
        }}
      }}
    }}
  ]
}}
"""
)

deploy_role = aws.iam.Role(
  "pulumiDeployRole",
  name=f"PulumiDeploy-{settings.repo}",
  assume_role_policy=assume_role_policy,
)

policy = pulumi.Output.all(bucket_arn, objects_arn).apply(
  lambda values: f"""
{{
  "Version": "2012-10-17",
  "Statement": [
    {{
      "Effect": "Allow",
      "Action": ["s3:ListBucket"],
      "Resource": "{values[0]}"
    }},
    {{
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:GetObjectVersion",
        "s3:PutObject",
        "s3:DeleteObject",
        "s3:DeleteObjectVersion"
      ],
      "Resource": "{values[1]}"
    }}
  ]
}}
"""
)

aws.iam.RolePolicy(
  "pulumiDeployPolicy",
  role=deploy_role.id,
  policy=policy,
)

pulumi.export("deployRoleArn", deploy_role.arn)
