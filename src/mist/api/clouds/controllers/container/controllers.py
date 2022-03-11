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
import time

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

        if create_cluster_request.role_arn is None:
            raise Exception('Cluster role_arn is required')

        kwargs['role_arn'] = create_cluster_request.role_arn
        kwargs['security_groups'] = create_cluster_request.security_groups
        kwargs['network'] = create_cluster_request.network
        kwargs['subnets'] = create_cluster_request.subnets

        if create_cluster_request.nodepools:
            # TODO support more than one nodegroups
            nodepool = create_cluster_request.nodepools[0]
            if nodepool.role_arn is None:
                raise Exception('Nodepool role_arn is required')

            kwargs['nodegroup_role_arn'] = nodepool.role_arn
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
                    raise Exception(f"Size {nodepool.size} does not exist")

                kwargs['size'] = size.external_id

            kwargs['disk_size'] = nodepool.disk_size
            kwargs['nodes'] = nodepool.nodes

        return kwargs

    def _create_cluster(self, auth_context, name, role_arn,
                        security_groups=None, network=None, subnets=None,
                        nodegroup_role_arn=None, size=None,
                        disk_size=None, nodes=None,):
        from mist.api.methods import list_resources
        from mist.api.networks.models import AmazonSubnet
        network_search = network or ''
        networks, count = list_resources(auth_context,
                                         'network',
                                         search=network_search,
                                         cloud=self.cloud.id,
                                         )
        if count == 0:
            raise Exception(f'Network {network} does not exist')

        # try to use the default network if returned by list_resources
        try:
            network = next(network for network in networks
                           if network.extra.get('is_default') == 'true')
        except StopIteration:
            network = networks[0]

        if subnets:
            subnets = AmazonSubnet.objects(id__in=subnets, network=network)
        else:
            # use the default subnets if no subnet list is given
            subnets = [subnet for subnet
                       in AmazonSubnet.objects(network=network)
                       if subnet.extra.get('default') == 'true']

        subnet_ids = [subnet.subnet_id for subnet in subnets]

        if not security_groups:
            groups = self.cloud.ctl.compute.connection.ex_list_security_groups()  # noqa
            security_groups = [group['id'] for group in groups
                               if group.get('name') == 'default' and
                               group.get('vpc_id') == network.network_id]

        cluster = self.connection.create_cluster(
            name=name,
            role_arn=role_arn,
            vpc_id=network.network_id,
            subnet_ids=subnet_ids,
            security_group_ids=security_groups)

        # Only wait for the cluster to be in running state if we need
        # to create a nodegroup.
        if nodegroup_role_arn:
            for _ in range(40):
                log.info(
                    'Waiting for cluster: %s to be in running state',
                    cluster.name)
                time.sleep(30)
                try:
                    cluster = self.connection.get_cluster(
                        cluster.name, fetch_nodes=False)
                except Exception as exc:
                    log.error('Failed to get cluster with exception %r', exc)
                else:
                    if cluster.status == 'running':
                        break

            log.info('Cluster: %s is running', cluster.name)

            kwargs = {
                'cluster': cluster,
                'name': f'{cluster.name}-nodegroup',
                'role_arn': nodegroup_role_arn,
                'subnet_ids': subnet_ids,
            }

            if nodes:
                kwargs['desired_nodes'] = nodes
                kwargs['max_nodes'] = nodes
                kwargs['min_nodes'] = nodes

            if size:
                kwargs['instance_types'] = [size]

            if disk_size:
                kwargs['node_group_disk_size'] = disk_size

            self.connection.ex_create_cluster_node_group(**kwargs)

        return cluster
