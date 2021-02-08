import logging

from pyramid.response import Response
from mist.api.clouds.models import Cloud
from mist.api.auth.methods import auth_context_from_request

from mist.api.helpers import view_config, params_from_request

from mist.api.exceptions import BadRequestError, MistNotImplementedError, CloudUnavailableError, CloudUnauthorizedError
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

supported_providers = ['openstack', 'ec2']


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
        if cloud.get('enabled') and cloud.get('provider') in supported_providers:
            try:
                storage = methods.filter_list_object_storage(auth_context, cloud.get('id'), cached, path)
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

    if cloud.as_dict()['provider'] not in supported_providers:
        raise BadRequestError('Not available for this cloud provider')

    try:
        return methods.filter_list_object_storage(auth_context, cloud_id, cached)
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

    if storage.cloud.provider not in supported_providers:
        raise BadRequestError('Not available for this cloud provider')

    try:
        return methods.filter_list_storage_content(auth_context, storage_id, path, cached)
    except Exception as e:
        log.error("Could not list content for object storage %s: %r" % (
            storage_id, e))
        raise MistNotImplementedError()













    auth_context = auth_context_from_request(request)
    params = params_from_request(request)
    key = params.get('key', '')
    storage_name = request.matchdict.get('storage')


    try:
        storage = ObjectStorage.objects.get(owner=auth_context.owner,
                                            name=storage_name)
    except me.DoesNotExist:
        raise NotFoundError('Object storage does not exist')

    auth_context.check_perm("objectstorage", "read", storage_name)

    cloud = Cloud.objects.get(owner=auth_context.owner, id=storage.cloud.id)



    if key and not storage_dict.get(key, ''):
        raise BadRequestError('Object storage %s does not have a %s key'
                              % (storage.name, key))

    return storage_dict if not key else {key: storage_dict[key]}


@view_config(route_name='api_v1_cloud_objectstorage_content', request_method='GET',
             renderer='json')
def list_cloud_objectstorage_content(request):
    """
    Tags: objectstores
    ---
    Lists objectstores on cloud.
    Only supported for Openstack, EC2.
    READ permission required on cloud.
    ---
    cloud:
      in: path
      required: true
      type: string
    """
    auth_context = auth_context_from_request(request)
    cloud_id = request.matchdict.get('cloud')
    storage_id = request.matchdict.get('storage')

    params = params_from_request(request)
    path = params.get('key', '')

    try:
        cloud = Cloud.objects.get(owner=auth_context.owner, id=cloud_id,
                                  deleted=None)
        log.error(cloud.as_dict()['provider'])

    except Cloud.DoesNotExist:
        raise NotFoundError('Cloud does not exist')

    if cloud.as_dict()['provider'] not in supported_providers:
        raise BadRequestError('Not available for this cloud provider')

    # SEC
    auth_context.check_perm('cloud', 'read', cloud_id)
    try:
        storage_content = cloud.ctl.objectstorage.list_storage_content(storage_id)
        return storage_content
    except Exception as e:
        log.error("Could not list object stores for cloud %s: %r" % (
                  cloud, e))
        raise MistNotImplementedError()


@view_config(route_name='api_v1_cloud_objectstorage', request_method='POST',
             renderer='json')
def create_objectstorage(request):
    cloud_id = request.matchdict['cloud']
    params = params_from_request(request)
    name = params.get('name')

    auth_context = auth_context_from_request(request)
    owner = auth_context.owner

    cloud = Cloud.objects.get(owner=auth_context.owner, id=cloud_id,
                              deleted=None)

    auth_context.check_perm("cloud", "read", cloud_id)
    auth_context.check_perm("cloud", "create_resources", cloud_id)

    if cloud.as_dict()['provider'] not in supported_providers:
        raise BadRequestError('Not available for this cloud provider')

    storage = cloud.ctl.objectstorage.create_storage(name)

    return storage.__dict__


@view_config(route_name='api_v1_cloud_objectstorage', request_method='DELETE',
             renderer='json')
def delete_objectstorage(request):
    cloud_id = request.matchdict['cloud']
    params = params_from_request(request)
    name = params.get('name')

    auth_context = auth_context_from_request(request)
    owner = auth_context.owner

    cloud = Cloud.objects.get(owner=auth_context.owner, id=cloud_id,
                              deleted=None)

    auth_context.check_perm("cloud", "read", cloud_id)
    auth_context.check_perm("cloud", "create_resources", cloud_id)

    if cloud.as_dict()['provider'] not in supported_providers:
        raise BadRequestError('Not available for this cloud provider')

    cloud.ctl.objectstorage.delete_storage(name)

    return OK
