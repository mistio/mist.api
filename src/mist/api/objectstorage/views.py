import logging

from pyramid.response import Response
from mist.api.clouds.models import Cloud
from mist.api.auth.methods import auth_context_from_request

from mist.api.helpers import view_config, params_from_request

from mist.api.exceptions import BadRequestError, MistNotImplementedError
from mist.api.exceptions import CloudUnavailableError, CloudUnauthorizedError
from mist.api.exceptions import NotFoundError

from mist.api.objectstorage import methods
from mist.api.clouds.methods import filter_list_clouds

import mongoengine as me
from mist.api import config

logging.basicConfig(level=config.PY_LOG_LEVEL,
                    format=config.PY_LOG_FORMAT,
                    datefmt=config.PY_LOG_FORMAT_DATE)
log = logging.getLogger(__name__)

OK = Response("OK", 200)

supported = ['openstack', 'ec2', 'vexxhost']


@view_config(route_name='api_v1_buckets', request_method='GET',
             renderer='json')
def list_buckets(request):
    """
    Tags: buckets
    ---
    Gets Buckets and their metadata from all clouds.
    Check Permissions take place in filter_list_buckets.
    READ permission required on cloud.
    READ permission required on location.
    READ permission required on bucket.
    """

    auth_context = auth_context_from_request(request)
    params = params_from_request(request)
    cached = bool(params.get('cached', True))  # return cached by default

    # to prevent iterate throw every cloud
    auth_context.check_perm("cloud", "read", None)
    clouds = filter_list_clouds(auth_context)
    buckets = []
    for cloud in clouds:
        if cloud.get('enabled') and cloud.get('provider') in supported:
            try:
                storage = methods.filter_list_buckets(
                    auth_context,
                    cloud.get('id'),
                    cached,
                    perm='read'
                )
                buckets.extend(storage)
            except (CloudUnavailableError, CloudUnauthorizedError):
                pass
    return buckets


@view_config(route_name='api_v1_cloud_buckets', request_method='GET',
             renderer='json')
def list_cloud_buckets(request):
    """
    Tags: buckets
    ---
    Lists buckets on cloud.
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
    cached = bool(params.get('cached', False))

    auth_context.check_perm('cloud', 'read', cloud_id)

    cloud = Cloud.objects.get(owner=auth_context.owner, id=cloud_id,
                              deleted=None)

    if cloud.as_dict()['provider'] not in supported:
        raise BadRequestError('Not available for this cloud provider')

    try:
        return methods.filter_list_buckets(
            auth_context,
            cloud_id,
            cached
        )
    except Exception as e:
        log.error("Could not list object stores for cloud %s: %r" % (
                  cloud_id, e))
        raise MistNotImplementedError()


@view_config(route_name='api_v1_bucket', request_method='GET',
             renderer='json')
def get_bucket(request):
    """
    Tags: buckets
    ---
    Get bucket content on .
    Only supported for Openstack, EC2.
    """
    auth_context = auth_context_from_request(request)
    bucket_id = request.matchdict.get('bucket')
    auth_context.check_perm('bucket', 'read', bucket_id)
    try:
        return methods.get_bucket(
            auth_context.owner,
            bucket_id,
        )
    except me.DoesNotExist:
        raise NotFoundError('Bucket does not exist')

    except Exception as e:
        log.error("Could not list content for the bucket %s: %r" % (
            bucket_id, e))
        raise MistNotImplementedError()


@view_config(route_name='api_v1_bucket_content', request_method='GET',
             renderer='json')
def list_bucket_content(request):
    """
    Tags: buckets
    ---
    Lists bucket content on cloud.
    Only supported for Openstack, EC2.
    READ permission required on cloud.
    ---
    cloud:
      in: path
      required: true
      type: string
    """

    auth_context = auth_context_from_request(request)
    bucket_id = request.matchdict.get('bucket')
    auth_context.check_perm('bucket', 'read', bucket_id)

    params = params_from_request(request)
    path = params.get('path', '')  # return root by default

    try:
        return methods.list_bucket_content(
            auth_context.owner,
            bucket_id,
            path
        )
    except me.DoesNotExist:
        raise NotFoundError('Bucket does not exist')

    except Exception as e:
        log.error("Could not list content for the bucket %s: %r" % (
            bucket_id, e))
        raise MistNotImplementedError()
