from mist.api.exceptions import CloudNotFoundError

from mist.api.clouds.models import Cloud

from mist.api.methods import connect_provider

from libcloud.compute.types import Provider


def list_networks(owner, cloud_id, cached=False):
    """List the networks of the specified cloud"""
    try:
        cloud = Cloud.objects.get(owner=owner, id=cloud_id)
    except Cloud.DoesNotExist:
        raise CloudNotFoundError()

    if not hasattr(cloud.ctl, 'network'):
        return []

    if cached:
        networks = cloud.ctl.network.list_cached_networks()
    else:
        networks = cloud.ctl.network.list_networks()

    return [n.as_dict() for n in networks]


def filter_list_networks(auth_context, cloud_id, networks=None, perm='read',
                         cached=False):
    """Filter the networks of the specific cloud based on RBAC policy"""
    if networks is None:
        networks = list_networks(auth_context.owner, cloud_id, cached=cached)
    if auth_context.is_owner():
        return networks
    else:
        allowed_resources = auth_context.get_allowed_resources(perm)
        if cloud_id not in allowed_resources['clouds']:
            return []
        filtered = []
        for n in networks:
            if n['id'] in allowed_resources['networks']:
                filtered.append(n)
        return filtered


def associate_ip(owner, cloud_id, network_id, ip,
                 machine_id=None, assign=True):
    cloud = Cloud.objects.get(owner=owner, id=cloud_id, deleted=None)
    conn = connect_provider(cloud)

    if conn.type != Provider.NEPHOSCALE:
        return False

    return conn.ex_associate_ip(ip, server=machine_id, assign=assign)
