import mongoengine as me
from pyramid.response import Response

from mist.api.clouds.models import Cloud
from mist.api.volumes.models import Volume
from mist.api.machines.models import Machine

from mist.api.volumes.methods import filter_list_volumes

from mist.api.tag.methods import add_tags_to_resource
from mist.api.auth.methods import auth_context_from_request

from mist.api.exceptions import BadRequestError
from mist.api.exceptions import CloudNotFoundError
from mist.api.exceptions import VolumeNotFoundError
from mist.api.exceptions import MachineNotFoundError
from mist.api.exceptions import RequiredParameterMissingError

from mist.api.helpers import params_from_request, view_config


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
    auth_context = auth_context_from_request(request)

    params = params_from_request(request)

    cloud_id = request.matchdict['cloud']
    cached = bool(params.get('cached', False))

    try:
        Cloud.objects.get(owner=auth_context.owner, id=cloud_id, deleted=None)
    except Cloud.DoesNotExist:
        raise CloudNotFoundError()

    # SEC
    auth_context.check_perm('cloud', 'read', cloud_id)
    return filter_list_volumes(auth_context, cloud_id, cached=cached)


@view_config(route_name='api_v1_volumes', request_method='POST',
             renderer='json')
def create_volume(request):
    """
    Tags: volumes
    ---
    Create a new volume.

    READ permission required on cloud.
    CREATE_RESOURCES permission required on cloud
    ADD permission required on volumes
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
    ex_disk_type:
      type: string
      description: GCE-specific. One of 'pd-standard'(default) or 'pd-ssd'
    ex_volume_type:
      type: string
      description: EC2-specific. One of 'standard', 'io1', 'gp2', 'sc1', 'st1'
    ex_iops:
      type: string
      description: EC2-specific. Needs to be specified if volume_type='io1'
    """
    cloud_id = request.matchdict['cloud']

    params = params_from_request(request)
    name = params.get('name')
    size = params.get('size')

    auth_context = auth_context_from_request(request)

    if not size:
        raise RequiredParameterMissingError('size')

    try:
        cloud = Cloud.objects.get(owner=auth_context.owner, id=cloud_id,
                                  deleted=None)
    except me.DoesNotExist:
        raise CloudNotFoundError()

    auth_context.check_perm("cloud", "read", cloud_id)
    auth_context.check_perm("cloud", "create_resources", cloud_id)
    tags = auth_context.check_perm("volume", "add", None) or {}

    if not name and cloud.ctl.provider != 'packet':
        raise RequiredParameterMissingError('name')

    if not hasattr(cloud.ctl, 'storage'):
        raise NotImplementedError()

    volume = cloud.ctl.storage.create_volume(**params)

    if tags:
        add_tags_to_resource(auth_context.owner, volume, tags)

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
    external_id = request.matchdict['volume']

    auth_context = auth_context_from_request(request)

    try:
        cloud = Cloud.objects.get(id=cloud_id, owner=auth_context.owner,
                                  deleted=None)
    except Cloud.DoesNotExist:
        raise CloudNotFoundError()

    try:
        volume = Volume.objects.get(external_id=external_id, cloud=cloud,
                                    missing_since=None)
    except me.DoesNotExist:
        raise VolumeNotFoundError()

    # SEC
    auth_context.check_perm('cloud', 'read', cloud.id)
    auth_context.check_perm('volume', 'read', volume.id)
    auth_context.check_perm('volume', 'remove', volume.id)

    volume.ctl.delete()

    return OK


# FIXME: rename to attach/detach in logs
@view_config(route_name='api_v1_volume', request_method='PUT', renderer='json')
def volume_action(request):
    """
    Tags: volumes
    ---
    Attach or detach a volume to/from a machine.

    READ permission required on cloud.
    READ permission required on volume.
    ATTACH or DETACH permission required on volume.
    ---
    cloud:
      in: path
      required: true
      type: string
    volume:
      in: path
      required: true
      type: string
    machine:
      in: query
      required: true
      type: string
    device:
      in: query
      type: string
      description: eg /dev/sdh. Required for EC2, optional for OpenStack
    """
    auth_context = auth_context_from_request(request)

    params = params_from_request(request)

    cloud_id = request.matchdict['cloud']
    external_id = request.matchdict['volume']

    action = params.pop('action', '')
    machine_uuid = params.pop('machine', '')

    if action not in ('attach', 'detach'):
        raise BadRequestError()

    if not machine_uuid:
        raise RequiredParameterMissingError('machine')

    try:
        cloud = Cloud.objects.get(id=cloud_id, owner=auth_context.owner,
                                  deleted=None)
    except Cloud.DoesNotExist:
        raise CloudNotFoundError()

    try:
        volume = Volume.objects.get(external_id=external_id, cloud=cloud,
                                    missing_since=None)
    except me.DoesNotExist:
        raise VolumeNotFoundError()

    try:
        machine = Machine.objects.get(id=machine_uuid, cloud=cloud,
                                      missing_since=None)
    except Machine.DoesNotExist:
        raise MachineNotFoundError()

    auth_context.check_perm("cloud", "read", cloud.id)
    auth_context.check_perm("volume", "read", volume.id)
    auth_context.check_perm("volume", action, volume.id)

    if not hasattr(cloud.ctl, 'storage'):
        raise NotImplementedError()

    getattr(volume.ctl, action)(machine, **params)

    return OK
