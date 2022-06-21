from mist.api.helpers import view_config
from mist.api.exceptions import NotFoundError

from mist.api.helpers import params_from_request

from mist.api.clouds.models import Cloud

from mist.api.images import methods

from mist.api.auth.methods import auth_context_from_request


@view_config(route_name='api_v1_images', request_method='POST',
             renderer='json')
def search_image(request):
    """
    Tags: images
    ---
    Search images from cloud. If a search_term is provided, we
    search for that term in the ids and the names
    of the community images. Available for EC2 and Docker.
    READ permission required on cloud.
    ---
    cloud:
      in: path
      required: true
      type: string
    search_term:
      type: string
    """
    cloud_id = request.matchdict['cloud']
    auth_context = auth_context_from_request(request)
    try:
        cloud = Cloud.objects.get(owner=auth_context.owner, id=cloud_id)
    except Cloud.DoesNotExist:
        raise NotFoundError('Cloud does not exist')

    if cloud.ctl.provider not in ['ec2', 'docker']:
        raise NotImplementedError(
            "Search images only supported for EC2 and Docker")

    return list_images(request)


@view_config(route_name='api_v1_images', request_method='GET', renderer='json')
def list_images(request):
    """
    Tags: images
    ---
    List images of specified cloud.
    List images from each cloud. Furthermore if a search_term is provided, we
    loop through each cloud and search for that term in the ids and the names
    of the community images.
    READ permission required on cloud.
    ---
    cloud:
      in: path
      required: true
      type: string
    search_term:
      type: string
    """
    cloud_id = request.matchdict['cloud']
    params = params_from_request(request)
    try:
        term = request.json_body.get('search_term', '')
    except:
        term = None
    auth_context = auth_context_from_request(request)
    auth_context.check_perm("cloud", "read", cloud_id)
    try:
        cloud = Cloud.objects.get(owner=auth_context.owner, id=cloud_id)
    except Cloud.DoesNotExist:
        raise NotFoundError('Cloud does not exist')

    cached = bool(params.get('cached', False))
    extra = params.get('extra', 'True') == 'True'

    return methods.filter_list_images(auth_context,
                                      cloud_id,
                                      cached=cached,
                                      term=term,
                                      extra=extra)


@view_config(route_name='api_v1_image', request_method='POST', renderer='json')
def star_image(request):
    """
    Tags: images
    ---
    Star/unstar an image.
    Toggle image star (star/unstar).
    EDIT permission required on cloud.
    ---
    cloud:
      in: path
      required: true
      type: string
    image:
      description: Id of image to be used with the creation
      in: path
      required: true
      type: string
    """
    cloud_id = request.matchdict['cloud']
    image_id = request.matchdict['image']
    auth_context = auth_context_from_request(request)
    auth_context.check_perm("cloud", "edit", cloud_id)
    try:
        Cloud.objects.get(owner=auth_context.owner, id=cloud_id)
    except Cloud.DoesNotExist:
        raise NotFoundError('Cloud does not exist')

    return methods.star_image(auth_context.owner, cloud_id, image_id)
