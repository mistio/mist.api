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

        # this needs improvement, now the main_ctl for the k8s controller is GCE main controller.
        # If list_machines() is called each machine will get GCE.ctl.compute as machine.ctl and
        # not this one. For the moment this is used only to _list_machines__fetch_machines from
        # libcloud.
        self.compute = KubernetesComputeController(self.cluster.cloud.ctl,
                                                   driver=self.cluster.cloud.ctl.container.connection._get_cluster_driver(self.cluster))

    def destroy(self, **kwargs):
        return self.cluster.cloud.ctl.container.destroy_cluster(
            name=self.cluster.name, **kwargs)

    def list_resources(self):
        """
            Simple listing of nodes, pods and containers with the bare minimum info
            using the compute driver of this class.
        """
        items = self.compute._list_machines__fetch_machines()
        ret = []
        for item in items:
            ret.append({
                'type': item['type'],
                'name': item['name'],
                'external_id': item['id'],
                'state':  item['state'],
                'image_name': item.get('image', {}).get('name') or '',
                'os': item.get('os') or '',
                'usage': item['extra'].get('usage', {}).get('total') or item['extra'].get('usage') or '',
                'parent_id': item.get('parent_id') or self.cluster.id,
                'public_ips': item.get('public_ips') or '',
                'private_ips': item.get('private_ips') or ''
            })
        return ret


class GoogleClusterController(ClusterController):
    def destroy(self):
        zone = self.cluster.location.name or self.cluster.extra.get('location')
        return super().destroy(zone=zone)
