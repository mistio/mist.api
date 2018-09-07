import mongoengine as me
from pyramid.response import Response

from mist.api.clouds.models import Cloud
from mist.api.volumes.models import Volume, VOLUMES
from mist.api.machines.models import Machine

from mist.api.volumes.methods import filter_list_volumes

from mist.api.tag.methods import add_tags_to_resource
from mist.api.auth.methods import auth_context_from_request

from mist.api.exceptions import CloudNotFoundError
from mist.api.exceptions import VolumeNotFoundError
from mist.api.exceptions import MachineNotFoundError
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
        Cloud.objects.get(owner=auth_context.owner, id=cloud_id)
    except Cloud.DoesNotExist:
        raise CloudNotFoundError()

    return filter_list_volumes(auth_context, cloud_id)


@view_config(route_name='api_v1_volumes', request_method='POST',
             renderer='json')
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

    if not hasattr(cloud.ctl, 'storage'):
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


@view_config(route_name='api_v1_attach_volume', request_method='POST',
             renderer='json')
def attach_volume(request):
    """
    Tags: volumes
    ---
    Attach a volume to a machine.

    READ permission required on cloud.
    READ permission required on volume.
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
      in: path
      required: true
      type: string
    device:
      type: string
      description: eg /dev/sdh. Required for EC2, optional for OpenStack
    """

    cloud_id = request.matchdict['cloud']
    volume_id = request.matchdict['volume']
    machine_id = request.matchdict['machine']

    params = params_from_request(request)

    auth_context = auth_context_from_request(request)

    try:
        cloud = Cloud.objects.get(id=cloud_id, owner=auth_context.owner)
    except Cloud.DoesNotExist:
        raise CloudNotFoundError()
    try:
        volume = Volume.objects.get(id=volume_id, cloud=cloud)
    except me.DoesNotExist:
        raise VolumeNotFoundError()
    try:
        machine = Machine.objects.get(id=machine_id, owner=auth_context.owner)
    except Machine.DoesNotExist:
        raise MachineNotFoundError()

    auth_context.check_perm("cloud", "read", cloud_id)
    auth_context.check_perm("volume", "read", volume_id)

    if not hasattr(cloud.ctl, 'storage'):
        raise NotImplementedError()

    # FIXME: Also update machine's/volume's model
    volume.ctl.attach(machine, **params)

    # Schedule a UI update
    trigger_session_update(auth_context.owner, ['clouds'])

    return volume.as_dict()


@view_config(route_name='api_v1_attach_volume', request_method='DELETE',
             renderer='json')
def detach_volume(request):
    """
    Tags: volumes
    ---
    Detach a volume from a machine.

    READ permission required on cloud.
    READ permission required on volume.
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
      in: path
      required: true
      type: string
    """

    cloud_id = request.matchdict['cloud']
    volume_id = request.matchdict['volume']
    machine_id = request.matchdict['machine']

    auth_context = auth_context_from_request(request)

    try:
        cloud = Cloud.objects.get(id=cloud_id, owner=auth_context.owner)
    except Cloud.DoesNotExist:
        raise CloudNotFoundError()
    try:
        volume = Volume.objects.get(id=volume_id, cloud=cloud)
    except me.DoesNotExist:
        raise VolumeNotFoundError()
    try:
        machine = Machine.objects.get(id=machine_id, owner=auth_context.owner)
    except Machine.DoesNotExist:
        raise MachineNotFoundError()

    auth_context.check_perm("cloud", "read", cloud_id)
    auth_context.check_perm("volume", "read", volume_id)

    if not hasattr(cloud.ctl, 'storage'):
        raise NotImplementedError()

    # FIXME: Also update machine's/volume's model
    volume.ctl.detach(machine)

    # Schedule a UI update
    trigger_session_update(auth_context.owner, ['clouds'])

    return OK
