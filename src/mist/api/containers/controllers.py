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

    def destroy(self, **kwargs):
        return self.cluster.cloud.ctl.container.destroy_cluster(
            name=self.cluster.name, **kwargs)
