from mist.api.exceptions import CloudNotFoundError

from mist.api.clouds.models import Cloud


def list_volumes(owner, cloud_id):
    """List the volumes of the specified cloud"""
    try:
        cloud = Cloud.objects.get(owner=owner, id=cloud_id)
    except Cloud.DoesNotExist:
        raise CloudNotFoundError()

    if not hasattr(cloud.ctl, 'storage'):
        return []

    volumes = cloud.ctl.volume.list_volumes()
    ret = []

    for volume in volumes:
        ret.append(volume.as_dict())

    return ret


def filter_list_volumes(auth_context, cloud_id, volumes=None, perm='read'):
    """Filter the volumes of the specific cloud based on RBAC policy"""
    if volumes is None:
        volumes = list_volumes(auth_context.owner, cloud_id)
    if not auth_context.is_owner():
        allowed_resources = auth_context.get_allowed_resources(perm)
        if cloud_id not in allowed_resources['clouds']:
            return {'cloud_id': cloud_id, 'volumes': []}
        for i in xrange(len(volumes) - 1, -1, -1):
            if volumes[i]['id'] not in allowed_resources['volumes']:
                volumes.pop(i)
    return {'cloud_id': cloud_id, 'volumes': volumes}
