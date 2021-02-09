import logging

from pyramid.response import Response
from mist.api.clouds.models import Cloud
from mist.api.auth.methods import auth_context_from_request

from mist.api.helpers import view_config, params_from_request

from mist.api.exceptions import BadRequestError, MistNotImplementedError
from mist.api.exceptions import CloudUnavailableError, CloudUnauthorizedError
from mist.api.exceptions import NotFoundError
from mist.api.objectstorage.models import ObjectStorage

from mist.api.objectstorage import methods
from mist.api.clouds.methods import filter_list_clouds

import mongoengine as me
from mist.api import config

logging.basicConfig(level=config.PY_LOG_LEVEL,
                    format=config.PY_LOG_FORMAT,
                    datefmt=config.PY_LOG_FORMAT_DATE)
log = logging.getLogger(__name__)

OK = Response("OK", 200)

supported = ['openstack', 'ec2']


@view_config(route_name='api_v1_objectstorage', request_method='GET',
             renderer='json')
def list_objectstorage(request):
    """
    Tags: objectstorage
    ---
    Gets Object storage and their metadata from all clouds.
    Check Permissions take place in filter_list_machines.
    READ permission required on cloud.
    READ permission required on location.
    READ permission required on machine.
    """

    auth_context = auth_context_from_request(request)
    params = params_from_request(request)
    cached = bool(params.get('cached', True))  # return cached by default
    path = params.get('path', '.')

    # to prevent iterate throw every cloud
    auth_context.check_perm("cloud", "read", None)
    clouds = filter_list_clouds(auth_context)
    objectstorage = []
    for cloud in clouds:
        if cloud.get('enabled') and cloud.get('provider') in supported:
            try:
                storage = methods.filter_list_object_storage(
                    auth_context,
                    cloud.get('id'),
                    cached,
                    path
                )
                objectstorage.extend(storage)
            except (CloudUnavailableError, CloudUnauthorizedError):
                pass
    return objectstorage


@view_config(route_name='api_v1_cloud_objectstorage', request_method='GET',
             renderer='json')
def list_cloud_objectstorage(request):
    """
    Tags: objectstorages
    ---
    Lists objectstorages on cloud.
    Only supported for Openstack, EC2.
    READ permission required on cloud.
    ---
    cloud:
      in: path
      required: true
      type: string
    """
    auth_context = auth_context_from_request(request)
    params = params_from_request(request)
    cloud_id = request.matchdict.get('cloud')
    cached = bool(params.get('cached', True))  # return cached by default

    auth_context.check_perm('cloud', 'read', cloud_id)

    cloud = Cloud.objects.get(owner=auth_context.owner, id=cloud_id,
                              deleted=None)

    if cloud.as_dict()['provider'] not in supported:
        raise BadRequestError('Not available for this cloud provider')

    try:
        return methods.filter_list_object_storage(
            auth_context,
            cloud_id,
            cached
        )
    except Exception as e:
        log.error("Could not list object stores for cloud %s: %r" % (
                  cloud_id, e))
        raise MistNotImplementedError()


@view_config(route_name='api_v1_objectstorage_content', request_method='GET',
             renderer='json')
def list_objectstorage_content(request):
    """
    Tags: objectstorage
    ---
    Lists objectstorage content on cloud.
    Only supported for Openstack, EC2.
    READ permission required on cloud.
    ---
    cloud:
      in: path
      required: true
      type: string
    """

    auth_context = auth_context_from_request(request)
    storage_id = request.matchdict.get('storage')
    params = params_from_request(request)
    cached = bool(params.get('cached', True))  # return cached by default
    path = bool(params.get('path', ''))  # return root by default

    try:
        storage = ObjectStorage.objects.get(owner=auth_context.owner,
                                            id=storage_id,
                                            missing_since=None)
    except me.DoesNotExist:
        raise NotFoundError('Object storage does not exist')

    if storage.cloud.provider not in supported:
        raise BadRequestError('Not available for this cloud provider')

    try:
        return methods.filter_list_storage_content(
            auth_context,
            storage_id,
            path,
            cached
        )
    except Exception as e:
        log.error("Could not list content for object storage %s: %r" % (
            storage_id, e))
        raise MistNotImplementedError()
