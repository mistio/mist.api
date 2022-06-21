from mist.api.clouds.models import Cloud

from mist.api.helpers import trigger_session_update

from mist.api.exceptions import NotFoundError
from mist.api.exceptions import CloudNotFoundError


def list_images(owner, cloud_id, cached=False, term=None, extra=True):
    """List the images of the specified cloud"""
    try:
        cloud = Cloud.objects.get(owner=owner, id=cloud_id)
    except Cloud.DoesNotExist:
        raise CloudNotFoundError()

    if cached:
        images = cloud.ctl.compute.list_cached_images()
    else:
        images = cloud.ctl.compute.list_images(search=term)
    return [image.as_dict(extra=extra) for image in images]


def filter_list_images(auth_context, cloud_id, perm='read',
                       cached=False, term='', extra=True):
    images = list_images(auth_context.owner, cloud_id,
                         cached, term, extra=extra)
    if not auth_context.is_owner():
        allowed_resources = auth_context.get_allowed_resources(perm)
        if cloud_id not in allowed_resources['clouds']:
            return {'cloud_id': cloud_id, 'images': []}
        for i in range(len(images) - 1, -1, -1):
            if images[i]['id'] not in allowed_resources['images']:
                images.pop(i)
    return images


def star_image(owner, cloud_id, image_id):
    """Toggle image star (star/unstar)"""
    try:
        Cloud.objects.get(owner=owner, id=cloud_id)
    except Cloud.DoesNotExist:
        raise CloudNotFoundError()
    from mist.api.images.models import CloudImage
    try:
        image = CloudImage.objects.get(cloud=cloud_id, id=image_id)
    except CloudImage.DoesNotExist:
        try:
            image = CloudImage.objects.get(
                cloud=cloud_id, external_id=image_id)
        except CloudImage.DoesNotExist:
            raise NotFoundError('CloudImage does not exist')

    image.starred = False if image.starred else True
    image.save()
    trigger_session_update(owner, ['images'])

    return image.as_dict()
