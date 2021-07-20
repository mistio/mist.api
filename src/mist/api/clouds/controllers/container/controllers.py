"""Cloud ContainerControllers

A cloud container controller handles all container operations that can be
performed on a cloud, commonly using libcloud under the hood.

It also performs several steps and combines the information stored in the
database with that returned from API calls to provider services.

For each different cloud type, there is a corresponding cloud container
controller defined here. All the different classes inherit
BaseContainerController and share a commmon interface, with the exception that
some controllers may not have all methods implemented.

A cloud container controller is initialized given a cloud. Most of the time,
it is accessed through a cloud model, using the `ctl` abbreviation, like this:

    cloud = mist.api.clouds.models.Cloud.objects.get(id=cloud_id)
    print(cloud.ctl.container.list_clusters())

"""
import logging

from libcloud.container.providers import get_driver as get_container_driver
from libcloud.container.types import Provider as Container_Provider

from mist.api.clouds.controllers.main.base import BaseContainerController

log = logging.getLogger(__name__)


class GoogleContainerController(BaseContainerController):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.config_keys = [
            'initialNodeCount',
            'nodeConfig',
            'addonsConfig',
            'legacyAbac',
            'networkPolicy',
            'ipAllocationPolicy',
            'masterAuthorizedNetworksConfig',
            'binaryAuthorization',
            'autoscaling',
            'networkConfig',
            'resourceUsageExportConfig',
            'authenticatorGroupsConfig',
            'privateClusterConfig',
            'databaseEncryption',
            'verticalPodAutoscaling',
            'shieldedNodes',
            'workloadIdentityConfig',
        ]

    def _connect(self, **kwargs):
        return get_container_driver(Container_Provider.GKE)(
            self.cloud.email,
            self.cloud.private_key,
            project=self.cloud.project_id)

    def _create_cluster(self, **kwargs):
        return self.connection.ex_create_cluster(**kwargs)

    def _delete_cluster(self, **kwargs):
        return self.connection.ex_delete_cluster(**kwargs)

    def _list_clusters__cluster_creation_date(self, cluster, cluster_dict):
        return cluster_dict.get("createTime")

    def _list_clusters__postparse_cluster(self, cluster, cluster_dict):
        updated = False
        cluster.total_nodes = cluster_dict['currentNodeCount']
        updated = True
        for ck in self.config_keys:
            config_value = cluster_dict.get(ck)
            if config_value is not None:
                cluster.config[ck] = config_value
        return updated

    def _list_clusters__get_cluster_extra(self, cluster, cluster_dict):
        """Return extra dict for libcloud cluster"""
        extra_keys = set(cluster_dict).difference(self.config_keys)
        return {k: cluster_dict[k] for k in extra_keys}
