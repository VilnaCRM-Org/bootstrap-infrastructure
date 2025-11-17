"""An AWS Python Pulumi program"""

import pulumi
from pulumi_aws import ec2

instance = ec2.Instance(
    "app-server",
    ami="ami-06ce824c157700cd2",
    instance_type="t2.micro",
    tags={"Name": "ExampleAppServerInstance"},
)

# Export the instance details
pulumi.export("instance_id", instance.id)
pulumi.export("instance_public_ip", instance.public_ip)
pulumi.export("instance_private_ip", instance.private_ip)
