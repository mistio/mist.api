from mist.api.models import Cloud
from mist.api.exceptions import PolicyUnauthorizedError


def list_clusters(owner, cloud_id, cached=False, as_dict=True):
    """List all clusters in this cloud via API call to the provider."""
    cloud = Cloud.objects.get(owner=owner, id=cloud_id, deleted=None)
    if not hasattr(cloud.ctl, 'container') or not cloud.container_enabled:
        return []
    try:
        if cached:
            clusters = cloud.ctl.container.list_cached_clusters()
        else:
            clusters = cloud.ctl.container.list_clusters()
    except AttributeError:
        return []
    if not as_dict:
        return clusters
    return [cluster.as_dict() for cluster in clusters]


# SEC
def filter_cluster_ids(auth_context, cloud_id, cluster_ids):
    if not isinstance(cluster_ids, set):
        cluster_ids = set(cluster_ids)

    if auth_context.is_owner():
        return cluster_ids

    # NOTE: We can trust the RBAC Mappings in order to fetch the latest list of
    # clusters for the current user, since mongo has been updated by either the
    # Poller or the above `list_clusters`.

    try:
        auth_context.check_perm('cloud', 'read', cloud_id)
    except PolicyUnauthorizedError:
        return set()

    allowed_ids = set(auth_context.get_allowed_resources(rtype='clusters'))
    return cluster_ids & allowed_ids


# SEC
def filter_list_clusters(auth_context, cloud_id, clusters=None, perm='read',
                         cached=False, as_dict=True):
    """Returns a list of clusters.

    In case of non-Owners, the QuerySet only includes clusters found in the
    RBAC Mappings of the Teams the current user is a member of.
    """
    assert cloud_id

    if clusters is None:
        clusters = list_clusters(
            auth_context.owner, cloud_id, cached=cached, as_dict=as_dict)
    if not clusters:  # Exit early in case the cloud provider returned 0 nodes.
        return []
    if auth_context.is_owner():
        return clusters

    if as_dict:
        cluster_ids = set(cluster['id'] for cluster in clusters)
    else:
        cluster_ids = set(cluster.id for cluster in clusters)
    allowed_cluster_ids = filter_cluster_ids(auth_context, cloud_id,
                                             cluster_ids)
    if as_dict:
        return [cluster for cluster in clusters
                if cluster['id'] in allowed_cluster_ids]
    return [cluster for cluster in clusters
            if cluster.id in allowed_cluster_ids]
