import uuid
from abc import ABC, abstractmethod
from typing import List
from typing_extensions import Literal

import troposphere.ec2 as ec2
import troposphere.iam as iam
import troposphere.eks as eks
from troposphere import Template, Sub, Tags, Ref, GetAtt, Output, Export, Join
from troposphere import ImportValue, Split


class BaseAWSTemplate(ABC):
    def __init__(self, *args, **kwargs):
        """Base CloudFormation Template class."""
        self._template = Template()
        self._template.set_version()
        self._template.add_mapping(
            "ServicePrincipalPartitionMap",
            {
                "aws": {
                    "EC2": "ec2.amazonaws.com",
                    "EKS": "eks.amazonaws.com",
                    "EKSFargatePods": "eks-fargate-pods.amazonaws.com",
                },
                "aws-cn": {
                    "EC2": "ec2.amazonaws.com.cn",
                    "EKS": "eks.amazonaws.com",
                    "EKSFargatePods": "eks-fargate-pods.amazonaws.com",
                },
                "aws-us-gov": {
                    "EC2": "ec2.amazonaws.com",
                    "EKS": "eks.amazonaws.com",
                    "EKSFargatePods": "eks-fargate-pods.amazonaws.com",
                },
            },
        )

    def to_json(self):
        return self._template.to_json()

    def to_yaml(self):
        return self._template.to_yaml()

    @abstractmethod
    def _populate_template(self, *args, **kwargs):
        """Populate the CloudFormation template."""
        ...

    def _add_resource(self, resource):
        self._template.add_resource(resource)

    def _add_output(self, output):
        self._template.add_output(output)

    def _get_resource(self, title):
        return self._template.resources[title]


class ClusterAWSTemplate(BaseAWSTemplate):
    def __init__(
        self,
        cluster_name: str,
        availability_zones: List[str],
        cluster_version: str = "1.21",
    ) -> None:
        """A CloudFormation Template to provision an EKS Cluster
        and all required resources.

        Parameters:
            cluster_name:       The cluster name, must start with alphanumeric
                                character and can only container alphanumeric,
                                underscores and dashes. Up to 100 characters.
            availability_zones: The Availability Zones of a region to use
                                for the control plane. At least 2 must be
                                provided. For example:

                                availability_zones = ["ap-northeast-1a",
                                                      "ap-northeast-1c"]
            cluster_version:    The Kubernetes version of the cluster.
        """
        super().__init__()
        self._template.set_description(
            "EKS cluster [created and managed by mist.io]"
        )
        self.public_subnets = []
        self.private_subnets = []
        self.private_route_table_list = []
        self._populate_template(
            cluster_name, availability_zones, cluster_version=cluster_version
        )

    def _populate_template(
        self,
        cluster_name: str,
        availability_zones: List[str],
        cluster_version: str = "1.21",
    ) -> None:
        """Populate the CloudFormation template with the required resources to
        provision an EKS cluster.
        """
        self._populate_vpc()
        self._populate_security_groups()
        self._populate_policies()
        self._populate_subnets(availability_zones)
        self._populate_cluster(cluster_name, cluster_version)
        self._populate_security_group_ingress()
        self._populate_nat()
        self._populate_output()

    def _populate_vpc(self):
        vpc = ec2.VPC(
            "VPC",
            CidrBlock="192.168.0.0/16",
            EnableDnsHostnames=True,
            EnableDnsSupport=True,
            Tags=Tags(Name=Sub("${AWS::StackName}/VPC")),
        )
        self._add_resource(vpc)

        internet_gateway = ec2.InternetGateway(
            "InternetGateway",
            Tags=Tags(Name=Sub("${AWS::StackName}/InternetGateway")),
        )
        self._add_resource(internet_gateway)

        vpc_gateway_attachment = ec2.VPCGatewayAttachment(
            "VPCGatewayAttachment",
            InternetGatewayId=Ref(internet_gateway),
            VpcId=Ref(vpc),
        )
        self._add_resource(vpc_gateway_attachment)

        public_route_table = ec2.RouteTable(
            "PublicRouteTable",
            VpcId=Ref(vpc),
            Tags=Tags(Name=Sub("${AWS::StackName}/PublicRouteTable")),
        )
        self._add_resource(public_route_table)

        public_subnet_route = ec2.Route(
            "PublicSubnetRoute",
            DestinationCidrBlock="0.0.0.0/0",
            GatewayId=Ref(internet_gateway),
            RouteTableId=Ref(public_route_table),
            DependsOn=["VPCGatewayAttachment"],
        )
        self._add_resource(public_subnet_route)

    def _populate_security_groups(self):
        vpc = self._get_resource("VPC")
        control_plane_security_group = ec2.SecurityGroup(
            "ControlPlaneSecurityGroup",
            GroupDescription="Communication between the control plane and worker nodegroups",  # noqa
            VpcId=Ref(vpc),
            Tags=Tags(Name=Sub("${AWS::StackName}/ControlPlaneSecurityGroup")),
        )
        self._add_resource(control_plane_security_group)

        cluster_shared_node_security_group = ec2.SecurityGroup(
            "ClusterSharedNodeSecurityGroup",
            GroupDescription="Communication between all nodes in the cluster",
            VpcId=Ref(vpc),
            Tags=Tags(
                Name=Sub("${AWS::StackName}/ClusterSharedNodeSecurityGroup")
            ),
        )
        self._add_resource(cluster_shared_node_security_group)

    def _populate_policies(self):
        service_role = iam.Role(
            "ServiceRole",
            AssumeRolePolicyDocument={
                "Statement": [
                    {
                        "Action": ["sts:AssumeRole"],
                        "Effect": "Allow",
                        "Principal": {
                            "Service": [
                                {
                                    "Fn::FindInMap": [
                                        "ServicePrincipalPartitionMap",
                                        {"Ref": "AWS::Partition"},
                                        "EKS",
                                    ]
                                }
                            ]
                        },
                    }
                ],
                "Version": "2012-10-17",
            },
            ManagedPolicyArns=[
                Sub(
                    "arn:${AWS::Partition}:iam::aws:policy/AmazonEKSClusterPolicy"  # noqa
                ),
                Sub(
                    "arn:${AWS::Partition}:iam::aws:policy/AmazonEKSVPCResourceController"  # noqa
                ),
            ],
            Tags=Tags(Name=Sub("${AWS::StackName}/ServiceRole")),
        )
        self._add_resource(service_role)

        policy_elb_permissions = iam.PolicyType(
            "PolicyELBPermissions",
            PolicyName=Sub("${AWS::StackName}-PolicyELBPermissions"),
            Roles=[
                Ref(service_role),
            ],
            PolicyDocument={
                "Statement": [
                    {
                        "Action": [
                            "ec2:DescribeAccountAttributes",
                            "ec2:DescribeAddresses",
                            "ec2:DescribeInternetGateways",
                        ],
                        "Effect": "Allow",
                        "Resource": "*",
                    }
                ],
                "Version": "2012-10-17",
            },
        )
        self._add_resource(policy_elb_permissions)

        policy_cloudwatch_metrics = iam.PolicyType(
            "PolicyCloudWatchMetrics",
            PolicyName=Sub("${AWS::StackName}-PolicyCloudWatchMetrics"),
            Roles=[Ref(service_role)],
            PolicyDocument={
                "Statement": [
                    {
                        "Action": ["cloudwatch:PutMetricData"],
                        "Effect": "Allow",
                        "Resource": "*",
                    }
                ],
                "Version": "2012-10-17",
            },
        )
        self._add_resource(policy_cloudwatch_metrics)

    def _populate_subnets(
        self,
        availability_zones,
    ):
        vpc = self._get_resource("VPC")
        public_route_table = self._get_resource("PublicRouteTable")
        counter = 0
        for zone in availability_zones:
            capitalized_name = zone.replace("-", "").upper()
            private_subnet = ec2.Subnet(
                f"SubnetPrivate{capitalized_name}",
                AvailabilityZone=zone,
                CidrBlock=f"192.168.{counter}.0/19",
                VpcId=Ref(vpc),
                Tags=[
                    {"Key": "kubernetes.io/role/internal-elb", "Value": "1"},
                    {
                        "Key": "Name",
                        "Value": Sub(
                            "${AWS::StackName}/SubnetPrivate" + capitalized_name  # noqa
                        ),
                    },
                ],
            )
            self._add_resource(private_subnet)
            self.private_subnets.append(private_subnet)

            private_route_table = ec2.RouteTable(
                f"PrivateRouteTable{capitalized_name}",
                VpcId=Ref(vpc),
                Tags=[
                    {
                        "Key": "Name",
                        "Value": Sub(
                            "${AWS::StackName}/PrivateRouteTable" + capitalized_name  # noqa
                        ),
                    },
                ],
            )
            self._add_resource(private_route_table)
            self.private_route_table_list.append(
                (private_route_table, capitalized_name)
            )

            route_table_association = ec2.SubnetRouteTableAssociation(
                f"RouteTableAssociationPrivate{capitalized_name}",
                RouteTableId=Ref(private_route_table),
                SubnetId=Ref(private_subnet),
            )
            self._add_resource(route_table_association)

            counter += 32
            public_subnet = ec2.Subnet(
                f"SubnetPublic{capitalized_name}",
                AvailabilityZone=zone,
                CidrBlock=f"192.168.{counter}.0/19",
                VpcId=Ref(vpc),
                MapPublicIpOnLaunch=True,
                Tags=[
                    {
                        "Key": "Name",
                        "Value": Sub(
                            "${AWS::StackName}/SubnetPublic" + capitalized_name
                        ),
                    },
                    {"Key": "kubernetes.io/role/elb", "Value": "1"},
                ],
            )
            self._add_resource(public_subnet)
            self.public_subnets.append(public_subnet)

            counter += 32
            route_table_association_public = ec2.SubnetRouteTableAssociation(
                f"RouteTableAssociationPublic{capitalized_name}",
                RouteTableId=Ref(public_route_table),
                SubnetId=Ref(public_subnet),
            )
            self._add_resource(route_table_association_public)

    def _populate_cluster(self, cluster_name, cluster_version):
        service_role = self._get_resource("ServiceRole")
        control_plane_security_group = self._get_resource(
            "ControlPlaneSecurityGroup"
        )
        control_plane = eks.Cluster(
            "ControlPlane",
            Name=cluster_name,
            RoleArn=GetAtt(service_role, "Arn"),
            # The following is supported on latest main branch but not on
            # the current latest version. Ignoring for the moment as it is
            # the default value
            # KubernetesNetworkConfig=eks.KubernetesNetworkConfig(
            #     IpFamily="ipv4",
            # ),
            ResourcesVpcConfig=eks.ResourcesVpcConfig(
                EndpointPrivateAccess=False,
                EndpointPublicAccess=True,
                SecurityGroupIds=[Ref(control_plane_security_group)],
                SubnetIds=[
                    Ref(subnet)
                    for subnet in self.private_subnets + self.public_subnets
                ],
            ),
            Version=cluster_version,
            Tags=Tags(Name=Sub("${AWS::StackName}/ControlPlane")),
        )
        self._add_resource(control_plane)

    def _populate_security_group_ingress(self):
        control_plane = self._get_resource("ControlPlane")
        cluster_shared_node_security_group = self._get_resource(
            "ClusterSharedNodeSecurityGroup"
        )

        ingress_default_cluster_to_node_sg = ec2.SecurityGroupIngress(
            "IngressDefaultClusterToNodeSG",
            Description="Allow managed and unmanaged nodes to communicate with each other (all ports)",  # noqa
            FromPort=0,
            GroupId=Ref(cluster_shared_node_security_group),
            IpProtocol="-1",
            SourceSecurityGroupId=GetAtt(
                control_plane, "ClusterSecurityGroupId"
            ),
            ToPort=65535,
        )
        self._add_resource(ingress_default_cluster_to_node_sg)

        ingress_inter_nodegroup_sg = ec2.SecurityGroupIngress(
            "IngressInterNodeGroupSG",
            Description="Allow nodes to communicate with each other (all ports)",  # noqa
            FromPort=0,
            GroupId=Ref(cluster_shared_node_security_group),
            IpProtocol="-1",
            SourceSecurityGroupId=Ref(cluster_shared_node_security_group),
            ToPort=65535,
        )
        self._add_resource(ingress_inter_nodegroup_sg)

        ingress_node_to_default_cluster_sg = ec2.SecurityGroupIngress(
            "IngressNodeToDefaultClusterSG",
            Description="Allow unmanaged nodes to communicate with control plane (all ports)",  # noqa
            FromPort=0,
            GroupId=GetAtt(control_plane, "ClusterSecurityGroupId"),
            IpProtocol="-1",
            SourceSecurityGroupId=Ref(cluster_shared_node_security_group),
            ToPort=65535,
        )
        self._add_resource(ingress_node_to_default_cluster_sg)

    def _populate_nat(self):
        natip = ec2.EIP(
            "NATIP",
            Domain="vpc",
            Tags=Tags(
                Name=Sub("${AWS::StackName}/NATIP"),
            ),
        )
        self._add_resource(natip)

        nat_gateway = ec2.NatGateway(
            "NATGateway",
            AllocationId=GetAtt(natip, "AllocationId"),
            SubnetId=Ref(self.public_subnets[0]),
            Tags=Tags(Name=Sub("${AWS::StackName}/NATGateway")),
        )
        self._add_resource(nat_gateway)

        for route_table, zone in self.private_route_table_list:
            private_subnet_route = ec2.Route(
                f"NATPrivateSubnetRoute{zone}",
                DestinationCidrBlock="0.0.0.0/0",
                NatGatewayId=Ref(nat_gateway),
                RouteTableId=Ref(route_table),
            )
            self._add_resource(private_subnet_route)

    def _populate_output(self):
        vpc = self._get_resource("VPC")
        control_plane = self._get_resource("ControlPlane")
        control_plane_security_group = self._get_resource(
            "ControlPlaneSecurityGroup"
        )
        service_role = self._get_resource("ServiceRole")
        cluster_shared_node_security_group = self._get_resource(
            "ClusterSharedNodeSecurityGroup"
        )

        self._add_output(
            Output(
                "ARN",
                Value=GetAtt(control_plane, "Arn"),
                Export=Export(Sub("${AWS::StackName}::ARN")),
            )
        )
        self._add_output(
            Output(
                "CertificateAuthorityData",
                Value=GetAtt(control_plane, "CertificateAuthorityData"),
            )
        )
        self._add_output(
            Output(
                "ClusterSecurityGroupId",
                Value=GetAtt(control_plane, "ClusterSecurityGroupId"),
                Export=Export(
                    Sub("${AWS::StackName}::ClusterSecurityGroupId")
                ),
            )
        )
        self._add_output(
            Output("ClusterStackName", Value=Ref("AWS::StackName"))
        )
        self._add_output(
            Output(
                "Endpoint",
                Value=GetAtt(control_plane, "Endpoint"),
                Export=Export(Sub("${AWS::StackName}::Endpoint")),
            )
        )
        self._add_output(Output("FeatureNATMode", Value="Single"))
        self._add_output(
            Output(
                "SecurityGroup",
                Value=Ref(control_plane_security_group),
                Export=Export(Sub("${AWS::StackName}::SecurityGroup")),
            )
        )
        self._add_output(
            Output(
                "ServiceRoleARN",
                Value=GetAtt(service_role, "Arn"),
                Export=Export(Sub("${AWS::StackName}::ServiceRoleARN")),
            )
        )
        self._add_output(
            Output(
                "SharedNodeSecurityGroup",
                Value=Ref(cluster_shared_node_security_group),
                Export=Export(
                    Sub("${AWS::StackName}::SharedNodeSecurityGroup")
                ),
            )
        )
        self._add_output(
            Output(
                "SubnetsPrivate",
                Value=Join(
                    ",", [Ref(subnet) for subnet in self.private_subnets]
                ),
                Export=Export(Sub("${AWS::StackName}::SubnetsPrivate")),
            )
        )
        self._add_output(
            Output(
                "SubnetsPublic",
                Value=Join(
                    ",", [Ref(subnet) for subnet in self.public_subnets]
                ),
                Export=Export(Sub("${AWS::StackName}::SubnetsPublic")),
            )
        )
        self._add_output(
            Output(
                "VPC",
                Value=Ref(vpc),
                Export=Export(Sub("${AWS::StackName}::VPC")),
            )
        )


class ClusterNodeGroupAWSTemplate(BaseAWSTemplate):
    def __init__(
        self,
        cluster_stack_name: str,
        cluster_name: str,
        size: str,
        nodes: int = 2,
        min_nodes: int = 2,
        max_nodes: int = 2,
        volume_size: int = 20,
        volume_type: Literal[
            "gp3", "gp2", "io2", "io1", "st1", "sc1", "standard"
        ] = "gp3",
    ):
        """A class representing a CloudFormation template that will provision
        a nodegroup for an EKS Cluster.

        Parameters:
            cluster_stack_name: The name of the cluster parent stack.
                                A CloudFormation stack is an instance of
                                a template.
            cluster_name:       The cluster name.
            size:               The size slug that will be used to provision
                                the nodegroup's nodes.
            nodes:              The desired number of nodes to provision.
            min_nodes:          The minimum number of nodes that the managed
                                node group can scale in to.
            max_nodes:          The maximum number of nodes that the managed
                                node group can scale in to.
            volume_size:        The root device disk size for the nodegroup.
                                Specified in GBs.
            volume_type:        The root device disk size for the nodegroup.
                                Specified in GBs.
        """
        super().__init__()
        self._template.set_description(
            "EKS Managed Nodes [created by mist.io]"
        )
        self._populate_template(
            cluster_stack_name,
            cluster_name,
            size,
            nodes,
            min_nodes,
            max_nodes,
            volume_size,
            volume_type
        )

    def _populate_template(
        self,
        cluster_stack_name: str,
        cluster_name: str,
        size: str,
        nodes: int,
        min_nodes: int,
        max_nodes: int,
        volume_size: int,
        volume_type: str,
    ):
        self._populate_launch_template(
            cluster_stack_name,
            cluster_name,
            volume_size,
            volume_type,
        )
        self._populate_node_instance_role()
        self._populate_nodegroup(
            cluster_stack_name,
            cluster_name,
            size,
            nodes,
            min_nodes,
            max_nodes,
        )

    def _populate_launch_template(
        self,
        cluster_stack_name,
        cluster_name,
        volume_size,
        volume_type,
    ):
        launch_template = ec2.LaunchTemplate(
            "LaunchTemplate",
            LaunchTemplateData=ec2.LaunchTemplateData(
                BlockDeviceMappings=[
                    ec2.LaunchTemplateBlockDeviceMapping(
                        DeviceName="/dev/xvda",
                        Ebs=ec2.EBSBlockDevice(
                            VolumeSize=volume_size,
                            VolumeType=volume_type,
                        ),
                    )
                ],
                MetadataOptions=ec2.MetadataOptions(
                    HttpPutResponseHopLimit=2, HttpTokens="optional"
                ),
                SecurityGroupIds=[
                    ImportValue(
                        f"{cluster_stack_name}::ClusterSecurityGroupId"
                    )
                ],
                TagSpecifications=[
                    ec2.TagSpecifications(
                        ResourceType="instance",
                        Tags=[
                            {
                                "Key": "Name",
                                "Value": f"{cluster_name}-nodegroup-Node",
                            },
                            {
                                "Key": "mist.io/nodegroup-name",
                                "Value": f"{cluster_name}-nodegroup",
                            },
                            {
                                "Key": "mist.io/nodegroup-type",
                                "Value": "managed",
                            },
                        ],
                    ),
                    ec2.TagSpecifications(
                        ResourceType="volume",
                        Tags=[
                            {
                                "Key": "Name",
                                "Value": f"{cluster_name}-nodegroup-Node",
                            },
                            {
                                "Key": "mist.io/nodegroup-name",
                                "Value": f"{cluster_name}-nodegroup",
                            },
                            {
                                "Key": "mist.io/nodegroup-type",
                                "Value": "managed",
                            },
                        ],
                    ),
                    ec2.TagSpecifications(
                        ResourceType="network-interface",
                        Tags=[
                            {
                                "Key": "Name",
                                "Value": f"{cluster_name}-nodegroup-Node",
                            },
                            {
                                "Key": "mist.io/nodegroup-name",
                                "Value": f"{cluster_name}-nodegroup",
                            },
                            {
                                "Key": "mist.io/nodegroup-type",
                                "Value": "managed",
                            },
                        ],
                    ),
                ],
            ),
        )
        self._add_resource(launch_template)

    def _populate_node_instance_role(self):
        node_instance_role = iam.Role(
            "NodeInstanceRole",
            AssumeRolePolicyDocument={
                "Statement": [
                    {
                        "Action": ["sts:AssumeRole"],
                        "Effect": "Allow",
                        "Principal": {
                            "Service": [
                                {
                                    "Fn::FindInMap": [
                                        "ServicePrincipalPartitionMap",
                                        {"Ref": "AWS::Partition"},
                                        "EC2",
                                    ]
                                }
                            ]
                        },
                    }
                ],
                "Version": "2012-10-17",
            },
            ManagedPolicyArns=[
                Sub(
                    "arn:${AWS::Partition}:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"  # noqa
                ),
                Sub(
                    "arn:${AWS::Partition}:iam::aws:policy/AmazonEKSWorkerNodePolicy"  # noqa
                ),
                Sub(
                    "arn:${AWS::Partition}:iam::aws:policy/AmazonEKS_CNI_Policy"  # noqa
                ),
                Sub(
                    "arn:${AWS::Partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"  # noqa
                ),
            ],
            Path="/",
            Tags=Tags(Name=Sub("${AWS::StackName}/NodeInstanceRole")),
        )
        self._add_resource(node_instance_role)

    def _populate_nodegroup(
        self,
        cluster_stack_name: str,
        cluster_name: str,
        size: str,
        nodes: int,
        min_nodes: int,
        max_nodes: int,
    ):
        launch_template = self._get_resource("LaunchTemplate")
        node_instance_role = self._get_resource("NodeInstanceRole")

        managed_nodegroup = eks.Nodegroup(
            "ManagedNodeGroup",
            AmiType="AL2_x86_64",
            ClusterName=cluster_name,
            InstanceTypes=[size],
            Labels={
                "mist.io/cluster-name": cluster_name,
                "mist.io/nodegroup-name": f"{cluster_name}-nodegroup",
            },
            LaunchTemplate=eks.LaunchTemplateSpecification(
                Id=Ref(launch_template)
            ),
            NodeRole=GetAtt(node_instance_role, "Arn"),
            NodegroupName=f"{cluster_name}-nodegroup-{uuid.uuid4().hex[:10]}",
            ScalingConfig=eks.ScalingConfig(
                DesiredSize=nodes, MaxSize=max_nodes, MinSize=min_nodes
            ),
            Subnets=Split(
                ",", ImportValue(f"{cluster_stack_name}::SubnetsPublic")
            ),
            Tags={
                "mist.io/nodegroup-name": f"{cluster_name}-nodegroup",
                "mist.io/nodegroup-type": "managed",
            },
        )
        self._add_resource(managed_nodegroup)
