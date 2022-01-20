from mist.api.clouds.controllers.compute.controllers import KubernetesComputeController

class ClusterController(object):
    def __init__(self, cluster):
        """Initialize cluster controller given a cluster

        Most times one is expected to access a controller from inside the
        cluster, like this:
          from mist.api.containers.models import Cluster
          cluster = Cluster.objects.get(id=cluster_id)
          cluster.ctl.destroy()
        """
        self.cluster = cluster
        self.k8s_controller = KubernetesComputeController(self.cluster.cloud.ctl,
                                                          driver=self.cluster.cloud.ctl.container.connection._get_cluster_driver(self.cluster))

    def destroy(self, **kwargs):
        return self.cluster.cloud.ctl.container.destroy_cluster(
            name=self.cluster.name, **kwargs)


class GoogleClusterController(ClusterController):
    def destroy(self):
        zone = self.cluster.location.name or self.cluster.extra.get('location')
        return super().destroy(zone=zone)
