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

    def _connect(self, **kwargs):
        return get_container_driver(Container_Provider.GKE)(
            self.cloud.email,
            self.cloud.private_key,
            project=self.cloud.project_id)

    def _create_cluster(self, *args, **kwargs):
        return self.connection.ex_create_cluster(*args, **kwargs)

    def _destroy_cluster(self, *args, **kwargs):
        return self.connection.ex_destroy_cluster(*args, **kwargs)

    def _list_clusters__cluster_creation_date(self, cluster, cluster_dict):
        return cluster_dict.get("createTime")

    def _list_clusters__postparse_cluster(self, cluster, cluster_dict):
        updated = False
        cluster.total_nodes = cluster_dict['node_count']
        updated = True
        cluster.config = cluster_dict['config']
        return updated


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
        return updated
