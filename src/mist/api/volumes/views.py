import mongoengine as me
from pyramid.response import Response

from mist.api.clouds.models import Cloud
from mist.api.volumes.models import Volume, VOLUMES

from mist.api.volumes.methods import filter_list_volumes

from mist.api.tag.methods import add_tags_to_resource
from mist.api.auth.methods import auth_context_from_request

from mist.api.exceptions import CloudNotFoundError
from mist.api.exceptions import VolumeNotFoundError
from mist.api.exceptions import RequiredParameterMissingError

from mist.api.helpers import params_from_request, view_config
from mist.api.helpers import trigger_session_update


OK = Response("OK", 200)


@view_config(route_name='api_v1_volumes', request_method='GET',
             renderer='json')
def list_volumes(request):
    """
    Tags: volumes
    ---
    List the volumes of a cloud.

    READ permission required on cloud
    ---
    cloud:
      in: path
      required: true
      type: string
    """
    cloud_id = request.matchdict['cloud']

    auth_context = auth_context_from_request(request)

    # SEC
    auth_context.check_perm('cloud', 'read', cloud_id)

    try:
        cloud = Cloud.objects.get(owner=auth_context.owner, id=cloud_id)
    except Cloud.DoesNotExist:
        raise CloudNotFoundError()

    return filter_list_volumes(auth_context, cloud_id)


@view_config(route_name='api_v1_volumes',request_method='POST', renderer='json')
def create_volume(request):
    """
    Tags: volumes
    ---
    Create a new volume.

    READ permission required on cloud.
    CREATE_RESOURCES permission required on cloud
    ---
    cloud:
      in: path
      required: true
      type: string
    size:
      required: true
      type: integer
      description: Size of disk in Gb
    name:
      required: true
      type: string
      description: Name of the disk
    location:
      required: true
      type: string
    disk_type:
      type: string
      description: GCE-specific. One of 'pd-standard'(default) or 'pd-ssd'
    volume_type:
      type: string
      description: EC2-specific. One of 'standard', 'io1', 'gp2', 'sc1', 'st1'
    iops:
      type: string
      description: EC2-specific. Needs to be specified only if volume_type='io1'
    """

    cloud_id = request.matchdict['cloud']

    params = params_from_request(request)
    name = params.get('name')
    size = params.get('size')

    auth_context = auth_context_from_request(request)

    if not name:
        raise RequiredParameterMissingError('name')

    if not size:
        raise RequiredParameterMissingError('size')

    auth_context.check_perm("cloud", "read", cloud_id)
    auth_context.check_perm("cloud", "create_resources", cloud_id)
    tags = auth_context.check_perm("volume", "add", None) or {}

    try:
        cloud = Cloud.objects.get(owner=auth_context.owner, id=cloud_id)
    except me.DoesNotExist:
        raise CloudNotFoundError()

    if not hasattr(cloud.ctl, 'volume'):
        raise NotImplementedError()

    volume = VOLUMES[cloud.ctl.provider].add(cloud=cloud, **params)

    if tags:
        add_tags_to_resource(auth_context.owner, volume, tags)

    # Schedule a UI update
    trigger_session_update(auth_context.owner, ['clouds'])

    return volume.as_dict()


@view_config(route_name='api_v1_volume', request_method='DELETE')
def delete_volume(request):
    """
    Tags: volumes
    ---
    Delete a volume.

    READ permission required on cloud.
    READ permission required on volume.
    REMOVE permission required on volume.
    ---
    parameters:
    - name: cloud
      in: path
      required: true
      schema:
        type: string
    - name: volume
      in: path
      required: true
      schema:
        type: string
    """
    cloud_id = request.matchdict['cloud']
    volume_id = request.matchdict['volume']

    auth_context = auth_context_from_request(request)

    # SEC
    auth_context.check_perm('cloud', 'read', cloud_id)
    auth_context.check_perm('volume', 'read', volume_id)
    auth_context.check_perm('volume', 'remove', volume_id)

    try:
        cloud = Cloud.objects.get(id=cloud_id, owner=auth_context.owner)
    except Cloud.DoesNotExist:
        raise CloudNotFoundError()
    try:
        volume = Volume.objects.get(id=volume_id, cloud=cloud)
    except me.DoesNotExist:
        raise VolumeNotFoundError()

    volume.ctl.delete()

    # Schedule a UI update
    trigger_session_update(auth_context.owner, ['clouds'])

    return OK
