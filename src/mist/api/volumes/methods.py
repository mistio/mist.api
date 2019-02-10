from mist.api.exceptions import CloudNotFoundError

from mist.api.clouds.models import Cloud


def list_volumes(owner, cloud_id, cached=False):
    """List the volumes of the specified cloud"""
    try:
        cloud = Cloud.objects.get(owner=owner, id=cloud_id)
    except Cloud.DoesNotExist:
        raise CloudNotFoundError()
    if not hasattr(cloud.ctl, 'storage'):
        return []
    if cached:
        volumes = cloud.ctl.storage.list_cached_volumes()
    else:
        volumes = cloud.ctl.storage.list_volumes()
    return [v.as_dict() for v in volumes]


def filter_list_volumes(auth_context, cloud_id, volumes=None, perm='read',
                        cached=False):
    """Filter the volumes of the specific cloud based on RBAC policy"""
    if volumes is None:
        volumes = list_volumes(auth_context.owner, cloud_id, cached)
    if not auth_context.is_owner():
        allowed_resources = auth_context.get_allowed_resources(perm)
        if cloud_id not in allowed_resources['clouds']:
            return {'cloud_id': cloud_id, 'volumes': []}
        for i in range(len(volumes) - 1, -1, -1):
            if volumes[i]['id'] not in allowed_resources['volumes']:
                volumes.pop(i)
    return volumes
