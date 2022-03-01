"""Cloud ContainerControllers

A cloud container controller handles all container operations that can be
performed on a cloud, commonly using libcloud under the hood.

It also performs several steps and combines the information stored in the
database with that returned from API calls to provider services.

For each different cloud type, there is a corresponding cloud container
controller defined here. All the different classes inherit
BaseContainerController and share a common interface, with the exception that
some controllers may not have all methods implemented.

A cloud container controller is initialized given a cloud. Most of the time,
it is accessed through a cloud model, using the `ctl` abbreviation, like this:

    cloud = mist.api.clouds.models.Cloud.objects.get(id=cloud_id)
    print(cloud.ctl.container.list_clusters())

"""
import logging
import uuid

from libcloud.container.providers import get_driver as get_container_driver
from libcloud.container.types import Provider as Container_Provider

from mist.api.clouds.controllers.main.base import BaseContainerController

log = logging.getLogger(__name__)


class GoogleContainerController(BaseContainerController):

    def _connect(self, **kwargs):
        return get_container_driver(Container_Provider.GKE)(
            self.cloud.email,
            self.cloud.private_key,
            project=self.cloud.project_id)

    def _list_clusters__cluster_creation_date(self, cluster, cluster_dict):
        return cluster_dict.get('extra', {}).get('createTime')

    def _list_clusters__postparse_cluster(self, cluster, cluster_dict):
        updated = False
        cluster.total_nodes = cluster_dict['node_count']
        updated = True
        cluster.config = cluster_dict['config']
        cluster.credentials = cluster_dict['credentials']
        cluster.total_cpus = cluster_dict['total_cpus']
        cluster.total_memory = cluster_dict['total_memory']
        return updated

    def _validate_create_cluster_request(self, auth_context,
                                         create_cluster_request):
        kwargs = {
            'name': create_cluster_request.name,
        }
        if create_cluster_request.location is None:
            raise Exception('Cluster location is required')

        from mist.api.methods import list_resources
        try:
            [location], _ = list_resources(
                auth_context,
                'location',
                search=f'{create_cluster_request.location} location_type:zone',
                cloud=self.cloud.id,
                limit=1)
        except ValueError:
            raise Exception(f'Location {location} not found')

        kwargs['location'] = location.name
        kwargs['nodepools'] = []
        if create_cluster_request.nodepools:
            for nodepool in create_cluster_request.nodepools:
                if nodepool.size:
                    try:
                        [size], _ = list_resources(
                            auth_context,
                            'size',
                            search=nodepool.size,
                            cloud=self.cloud.id,
                            limit=1
                        )
                    except ValueError:
                        raise Exception(
                            f'Size {nodepool.size} does not exist')

                    # We use "<size-name> (<size-description>)" for size names
                    size = size.name.replace(
                        f" ({size.extra['description']})", '')
                else:
                    size = 'e2-medium'
                disk_size = nodepool.disk_size or 20
                nodes = nodepool.nodes or 2
                preemptible = nodepool.preemptible or False
                disk_type = nodepool.disk_type or 'pd-standard'

                kwargs['nodepools'].append({
                    'node_count': nodes,
                    'size': size,
                    'disk_size': disk_size,
                    'disk_type': disk_type,
                    'preemptible': preemptible,
                })
        else:
            # If no nodepool is given add a default
            kwargs['nodepools'].append({
                'node_count': 2,
                'size': 'e2-medium',
                'disk_size': 20,
                'disk_type': 'pd-standard',
                'preemptible': False,
            })
        return kwargs

    def _create_cluster(self, auth_context, name, location, nodepools):
        return self.connection.create_cluster(name=name,
                                              zone=location,
                                              nodepools=nodepools)

    def _destroy_cluster(self, name, zone):
        return self.connection.destroy_cluster(name=name, zone=zone)


class AmazonContainerController(BaseContainerController):
    def _connect(self, **kwargs):
        return get_container_driver(Container_Provider.EKS)(
            self.cloud.apikey,
            self.cloud.apisecret,
            self.cloud.region)

    def _list_clusters__postparse_cluster(self, cluster, cluster_dict):
        updated = False
        cluster.config = cluster_dict['config']
        updated = True
        cluster.credentials = cluster_dict['credentials']
        cluster.total_cpus = cluster_dict['total_cpus']
        cluster.total_memory = cluster_dict['total_memory']
        return updated

    def _list_clusters__cluster_creation_date(self, cluster, cluster_dict):
        return cluster_dict.get('extra', {}).get('createdAt')

    def _list_clusters__get_pod_node(self, pod, cluster, libcloud_cluster):
        from mist.api.machines.models import Machine
        for node in libcloud_cluster.extra['nodes']:
            if pod.node_name == node['name']:
                provider_id = node['provider_id']
                break
        else:
            log.warning('Failed to get parent node: %s for pod: %s',
                        pod.node_name, pod.id)
            return None

        # provider_id is returned as: 'aws:///<availability-zone>/<external_id>'  # noqa
        provider_id = provider_id.split('/')[-1]
        try:
            node = Machine.objects.get(machine_id=provider_id,
                                       cloud=self.cloud,
                                       cluster=cluster)
            return node
        except Machine.DoesNotExist:
            log.warning('Failed to get parent node: %s for pod: %s',
                        pod.node_name, pod.id)

    def _validate_create_cluster_request(self, auth_context,
                                         create_cluster_request):
        kwargs = {
            'name': create_cluster_request.name,
        }
        nodepools = []
        if create_cluster_request.nodepools:
            for nodepool in create_cluster_request.nodepools:
                nodepool_dict = {}
                if nodepool.size:
                    from mist.api.methods import list_resources
                    try:
                        [size], _ = list_resources(
                            auth_context,
                            'size',
                            search=nodepool.size,
                            cloud=self.cloud.id,
                            limit=1
                        )
                    except ValueError:
                        raise Exception(f'Size {nodepool.size} does not exist')

                    nodepool_dict['size'] = size.external_id
                else:
                    nodepool_dict['size'] = ' t3.medium'

                nodepool_dict['disk_size'] = nodepool.disk_size or 20
                nodepool_dict['nodes'] = nodepool.nodes or 2
                nodepool_dict['disk_type'] = nodepool.disk_type or 'gp3'
                nodepools.append(nodepool_dict)
            kwargs['nodepools'] = nodepools
        else:
            # create a nodepool with the default parameters
            kwargs['nodepools'] = [{
                'size': 't3.medium',
                'nodes': 2,
                'disk_size': 20,
                'disk_type': 'gp3'
            }]
        return kwargs

    def _create_cluster(self, auth_context, name,
                        version="1.21", nodepools=None):
        from mist.api.clouds.models import CloudLocation
        from mist.api.helpers import get_boto_driver, get_aws_tags
        from mist.api.aws_templates import ClusterAWSTemplate
        from mist.api.aws_templates import ClusterNodeGroupAWSTemplate
        zone_names = [location.name for location
                      in CloudLocation.objects(
                          cloud=self.cloud, missing_since=None)]

        cluster_template = ClusterAWSTemplate(cluster_name=name,
                                              availability_zones=zone_names,
                                              cluster_version=version)
        cfn_driver = get_boto_driver(service="cloudformation",
                                     key=self.cloud.apikey,
                                     secret=self.cloud.apisecret,
                                     region=self.cloud.region,
                                     )
        stack_name = f"mist-{name}-cluster"
        stack = cfn_driver.create_stack(
            StackName=stack_name,
            TemplateBody=cluster_template.to_json(),
            Capabilities=["CAPABILITY_IAM"],
            Tags=get_aws_tags(resource_type='cluster', cluster_name=name),
        )

        waiter = cfn_driver.get_waiter("stack_create_complete")
        waiter.wait(StackName=stack["StackId"])
        log.info("Cloud: %s, Cluster %s stack deployment finished",
                 self.cloud, name)
        nodepools = nodepools or []
        stack_ids = []
        for nodepool in nodepools:
            nodepool_template = ClusterNodeGroupAWSTemplate(
                cluster_stack_name=stack_name,
                cluster_name=name,
                size=nodepool['size'],
                nodes=nodepool['nodes'],
                min_nodes=nodepool['nodes'],
                max_nodes=nodepool['nodes'],
                volume_size=nodepool['disk_size'],
                volume_type=nodepool['disk_type'],
            )
            nodegroup_stack_name = (
                f"{stack_name}-nodegroup-{uuid.uuid4().hex[:5]}")
            stack = cfn_driver.create_stack(
                StackName=nodegroup_stack_name,
                TemplateBody=nodepool_template.to_json(),
                Capabilities=["CAPABILITY_IAM"],
                Tags=get_aws_tags(resource_type='nodegroup',
                                  cluster_name=name),
            )
            stack_ids.append(stack["StackId"])

        for stack_id in stack_ids:
            waiter.wait(StackName=stack_id)

    def _destroy_cluster(self, name):
        from mist.api.helpers import get_boto_driver, get_aws_tags
        tag_driver = get_boto_driver(service='resourcegroupstaggingapi',
                                     key=self.cloud.apikey,
                                     secret=self.cloud.apisecret,
                                     region=self.cloud.region,
                                     )
        cluster_stacks = tag_driver.get_resources(
            ResourceTypeFilters=['cloudformation:stack'],
            TagFilters=get_aws_tags(resource_type='cluster',
                                    cluster_name=name,
                                    resource_group_tagging=True)
        )
        cluster_stack_arns = [stack['ResourceARN'] for stack
                              in cluster_stacks['ResourceTagMappingList']]
        # Determine if cluster is created through CloudFormation
        if len(cluster_stack_arns) > 0:
            cluster_stack = cluster_stack_arns[0]
            return self._destroy_cluster_stacks(
                name=name,
                cluster_stack=cluster_stack,
                tag_driver=tag_driver)
        else:
            raise NotImplementedError()

    def _destroy_cluster_stacks(self, name, cluster_stack, tag_driver=None):
        """Helper method to destroy a cluster that is managed with
        CloudFormation stacks deployed by Mist.
        """
        from mist.api.helpers import get_boto_driver, get_aws_tags
        if tag_driver is None:
            tag_driver = get_boto_driver(
                service='resourcegroupstaggingapi',
                key=self.cloud.apikey,
                secret=self.cloud.apisecret,
                region=self.cloud.region,
            )
        cfn_driver = get_boto_driver(
            service='cloudformation',
            key=self.cloud.apikey,
            secret=self.cloud.apisecret,
            region=self.cloud.region,
        )
        # Find all CloudFormation stacks describing deployed nodegroups
        nodegroup_stacks = tag_driver.get_resources(
            ResourceTypeFilters=['cloudformation:stack'],
            TagFilters=get_aws_tags(resource_type='nodegroup',
                                    cluster_name=name,
                                    resource_group_tagging=True)
        )
        nodegroup_stack_arns = [stack['ResourceARN']for stack
                                in nodegroup_stacks['ResourceTagMappingList']]

        log.info('Cloud: %s,Cluster:%s. Deleting nodegroup stacks',
                 self.cloud, name)
        for stack in nodegroup_stack_arns:
            cfn_driver.delete_stack(StackName=stack)

        log.info('Cloud: %s,Cluster:%s. Waiting for nodegroup stacks deletion',
                 self.cloud, name)
        waiter = cfn_driver.get_waiter('stack_delete_complete')
        for stack in nodegroup_stack_arns:
            waiter.wait(StackName=stack)

        log.info('Cloud: %s,Cluster:%s. Deleting cluster stack',
                 self.cloud, name)
        cfn_driver.delete_stack(StackName=cluster_stack)
        waiter.wait(StackName=cluster_stack)
