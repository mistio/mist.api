from mist.api.clouds.models import Cloud

from mist.api.helpers import trigger_session_update

from mist.api.exceptions import NotFoundError
from mist.api.exceptions import CloudNotFoundError


def list_images(owner, cloud_id, term=None):
    """List the images of the specified cloud"""
    try:
        cloud = Cloud.objects.get(owner=owner, id=cloud_id)
    except Cloud.DoesNotExist:
        raise CloudNotFoundError()

    images = cloud.ctl.compute.list_images(search=term)
    return [image.as_dict() for image in images]


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
        raise NotFoundError('CloudImage does not exist')

    image.starred = False if image.starred else True
    image.save()
    trigger_session_update(owner, ['images'])

    return image.as_dict()
