import logging

from pyramid.response import Response

from mist.api.clouds.models import Cloud
from mist.api.auth.methods import auth_context_from_request

from mist.api.tasks import async_session_update
from mist.api.helpers import trigger_session_update
from mist.api.helpers import view_config, params_from_request

from mist.api.decorators import require_cc

from mist.api.exceptions import BadRequestError, MistNotImplementedError
from mist.api.exceptions import RequiredParameterMissingError, NotFoundError

from mist.api.clouds.methods import filter_list_clouds
from mist.api.clouds.methods import add_cloud as m_add_cloud
from mist.api.clouds.methods import rename_cloud as m_rename_cloud
from mist.api.clouds.methods import remove_cloud as m_remove_cloud

from mist.api.tag.methods import add_tags_to_resource

from mist.api import config

import mist.api.methods as methods


logging.basicConfig(level=config.PY_LOG_LEVEL,
                    format=config.PY_LOG_FORMAT,
                    datefmt=config.PY_LOG_FORMAT_DATE)
log = logging.getLogger(__name__)

OK = Response("OK", 200)


@view_config(route_name='api_v1_clouds', request_method='GET', renderer='json')
def list_clouds(request):
    """
    Tags: clouds
    ---
    Lists all added clouds.
    READ permission required on cloud.
    ---
    """
    auth_context = auth_context_from_request(request)
    return filter_list_clouds(auth_context)


@view_config(route_name='api_v1_clouds',
             request_method='POST', renderer='json')
@require_cc
def add_cloud(request):
    """
    Tags: clouds
    ---
    Adds a new cloud and returns the cloud's id.
    ADD permission required on cloud.
    ---
    api_key:
      type: string
      description: Required for Clearcenter
    api_secret:
      type: string
    apikey:
      type: string
      description: Required for Ec2, Hostvirtual, Linode, \
      EquinixMetal, Rackspace, OnApp, SoftLayer, Vultr
    apisecret:
      type: string
      description: Required for Ec2
    apiurl:
      type: string
    auth_password:
      description: Optional for Docker
      type: string
    auth_url:
      type: string
      description: Required for OpenStack
    auth_user:
      description: Optional for Docker
      type: string
    authentication:
      description: Required for Docker
      enum:
      - tls
      - basic
    ca_cert_file:
      type: string
      description: Optional for Docker
    cert_file:
      type: string
      description: Optional for Docker
    certificate:
      type: string
      description: Required for Azure
    compute_endpoint:
      type: string
      description: Optional for OpenStack
    dns_enabled:
      type: boolean
    docker_host:
      description: Required for Docker
    docker_port:
      type: string
    domain:
      type: string
      description: Optional for OpenStack
    host:
      type: string
      description: Required for OnApp, Vcloud, vSphere
    images_location:
      type: string
      description: Required for KVM
    key:
      type: string
      description: Required for Azure_arm
    key_file:
      type: string
      description: Optional for Docker
    machine_hostname:
      type: string
      description: Required for KVM
    machine_key:
      type: string
      description: Id of the key. Required for KVM
    machine_port:
      type: string
    machine_user:
      type: string
      description: Required for KVM
    name:
      description: The name of the cloud.
      type: string
      required: True
    object_storage_enabled:
      type: boolean
    organization:
      type: string
      description: Required for Vcloud
    password:
      type: string
      description: Required for OpenStack, Vcloud, vSphere, CloudSigma
    port:
      type: integer
      description: Required for Vcloud
    private_key:
      type: string
      description: Required for GCE
    project_id:
      type: string
      description: Required for GCE. Optional for EquinixMetal
    provider:
      description: The cloud provider.
      required: True
      enum:
      - vcloud
      - other
      - docker
      - libvirt
      - openstack
      - vsphere
      - ec2
      - rackspace
      - digitalocean
      - softlayer
      - gce
      - azure
      - azure_arm
      - linode
      - onapp
      - hostvirtual
      - vultr
      - aliyun_ecs
      - cloudsigma
      required: true
      type: string
    region:
      type: string
      description: Required for Ec2, Alibaba, Rackspace, CloudSigma.\
      Optional for Openstack
    remove_on_error:
      type: string
    secret:
      type: string
      description: Required for Azure_arm
    show_all:
      type: boolean
      description: Show stopped containers. Required for Docker.
    ssh_port:
      type: integer
      description: Required for KVM
    subscription_id:
      type: string
      description: Required for Azure, Azure_arm
    tenant_id:
      type: string
      description: Required for Azure_arm
    tenant_name:
      type: string
      description: Required for OpenStack
    token:
      type: string
      description: Required for Digitalocean
    username:
      type: string
      description: Required for Rackspace, OnApp, \
      SoftLayer, OpenStack, Vcloud, vSphere, CloudSigma
    """
    auth_context = auth_context_from_request(request)
    cloud_tags, _ = auth_context.check_perm("cloud", "add", None)
    owner = auth_context.org
    user = auth_context.user
    params = params_from_request(request)
    # remove spaces from start/end of string fields that are often included
    # when pasting keys, preventing thus successful connection with the
    # cloud
    for key in list(params.keys()):
        if type(params[key]) in [str, str]:
            params[key] = params[key].rstrip().lstrip()

    # api_version = request.headers.get('Api-Version', 1)
    name = params.get('name', params.get('title', ''))
    provider = params.get('provider', '')

    if not provider:
        raise RequiredParameterMissingError('provider')

    monitoring = None
    result = m_add_cloud(owner, name, provider, user, params)
    cloud_id = result['cloud_id']
    monitoring = result.get('monitoring')
    errors = result.get('errors')

    cloud = Cloud.objects.get(owner=owner, id=cloud_id)

    if cloud_tags:
        add_tags_to_resource(auth_context.owner,
                             [{'resource_type': 'cloud',
                               'resource_id': cloud.id}],
                             list(cloud_tags.items()))

    # Set ownership.
    cloud.assign_to(auth_context.user)

    trigger_session_update(owner.id, ['clouds'])

    # SEC
    # Update the RBAC & User/Ownership mappings with the new Cloud and finally
    # trigger a session update by registering it as a chained task.
    if config.HAS_RBAC:
        owner.mapper.update(
            cloud,
            callback=async_session_update,
            args=(owner.id, ['clouds'], )
        )

    c_count = Cloud.objects(owner=owner, deleted=None).count()
    ret = cloud.as_dict()
    ret['index'] = c_count - 1
    if errors:
        ret['errors'] = errors
    if monitoring:
        ret['monitoring'] = monitoring

    return ret


@view_config(route_name='api_v1_cloud_action', request_method='DELETE')
def remove_cloud(request):
    """
    Tags: clouds
    ---
    Removes a cloud with given cloud_id.
    REMOVE permission required on cloud.
    ---
    cloud:
      in: path
      required: true
      type: string
    """
    auth_context = auth_context_from_request(request)
    cloud_id = request.matchdict['cloud']
    try:
        Cloud.objects.get(owner=auth_context.owner, id=cloud_id, deleted=None)
    except Cloud.DoesNotExist:
        raise NotFoundError('Cloud does not exist')
    auth_context.check_perm('cloud', 'remove', cloud_id)
    params = params_from_request(request)
    delete_from_vault = params.get('delete_from_vault', False)
    m_remove_cloud(auth_context.owner, cloud_id, delete_from_vault)
    return OK


@view_config(route_name='api_v1_cloud_action', request_method='PUT')
def rename_cloud(request):
    """
    Tags: clouds
    ---
    Renames cloud with given cloud_id.
    EDIT permission required on cloud.
    ---
    cloud:
      in: path
      required: true
      type: string
    new_name:
      description: ' New name for the given cloud'
      type: string
    """
    auth_context = auth_context_from_request(request)
    cloud_id = request.matchdict['cloud']
    try:
        Cloud.objects.get(owner=auth_context.owner, id=cloud_id, deleted=None)
    except Cloud.DoesNotExist:
        raise NotFoundError('Cloud does not exist')

    params = params_from_request(request)
    new_name = params.get('new_name', '')
    if not new_name:
        raise RequiredParameterMissingError('new_name')
    auth_context.check_perm('cloud', 'edit', cloud_id)

    m_rename_cloud(auth_context.owner, cloud_id, new_name)
    return OK


@view_config(route_name='api_v1_cloud_action', request_method='PATCH')
def update_cloud(request):
    """
    Tags: clouds
    ---
    Updates cloud with given cloud_id.
    EDIT permission required on cloud.
    Not all fields need to be specified, only the ones being modified
    ---
    cloud_id:
      in: path
      required: true
      type: string
    """
    auth_context = auth_context_from_request(request)
    cloud_id = request.matchdict['cloud']
    try:
        cloud = Cloud.objects.get(owner=auth_context.owner,
                                  id=cloud_id, deleted=None)
    except Cloud.DoesNotExist:
        raise NotFoundError('Cloud does not exist')

    params = params_from_request(request)
    creds = params

    if not creds:
        raise BadRequestError("You should provide your new cloud settings")

    auth_context.check_perm('cloud', 'edit', cloud_id)

    log.info("Updating cloud: %s", cloud_id)

    fail_on_error = params.pop('fail_on_error', True)
    fail_on_invalid_params = params.pop('fail_on_invalid_params', True)
    polling_interval = params.pop('polling_interval', None)

    # Edit the cloud
    cloud.ctl.update(fail_on_error=fail_on_error,
                     fail_on_invalid_params=fail_on_invalid_params, **creds)

    try:
        polling_interval = int(polling_interval)
    except (ValueError, TypeError):
        pass
    else:
        cloud.ctl.set_polling_interval(polling_interval)

    log.info("Cloud with id '%s' updated successfully.", cloud.id)
    trigger_session_update(auth_context.owner, ['clouds'])
    return OK


@view_config(route_name='api_v1_cloud_action', request_method='POST')
def toggle_cloud(request):
    """
    Tags: clouds
    ---
    Toggles cloud with given cloud id.
    EDIT permission required on cloud.
    ---
    cloud_id:
      in: path
      required: true
      type: string
    new_state:
      enum:
      - '0'
      - '1'
      required: true
      type: string
    """
    auth_context = auth_context_from_request(request)
    cloud_id = request.matchdict['cloud']
    try:
        cloud = Cloud.objects.get(owner=auth_context.owner,
                                  id=cloud_id, deleted=None)
    except Cloud.DoesNotExist:
        raise NotFoundError('Cloud does not exist')

    auth_context.check_perm('cloud', 'edit', cloud_id)

    new_state = params_from_request(request).get('new_state', None)
    dns_enabled = params_from_request(request).get('dns_enabled', None)
    observation_logs_enabled = params_from_request(request).get(
        'observation_logs_enabled', None)
    object_storage_enabled = params_from_request(request).get(
        'object_storage_enabled', None)
    container_enabled = params_from_request(request).get(
        'container_enabled', None)

    if new_state is None and \
       dns_enabled is None and \
       observation_logs_enabled is None and \
       object_storage_enabled is None and \
       container_enabled is None:
        raise RequiredParameterMissingError('new_state or dns_enabled or \
          observation_logs_enabled or object_storage_enabled')

    if new_state == '1':
        cloud.ctl.enable()
    elif new_state == '0':
        cloud.ctl.disable()
    elif new_state:
        raise BadRequestError('Invalid cloud state')

    if dns_enabled == 1:
        cloud.ctl.dns_enable()
    elif dns_enabled == 0:
        cloud.ctl.dns_disable()
    elif dns_enabled:
        raise BadRequestError('Invalid DNS state')

    if object_storage_enabled == 1:
        cloud.ctl.object_storage_enable()
    elif object_storage_enabled == 0:
        cloud.ctl.object_storage_disable()
    elif object_storage_enabled:
        raise BadRequestError('Invalid Object Storage state')

    if observation_logs_enabled == 1:
        cloud.ctl.observation_logs_enable()
    elif observation_logs_enabled == 0:
        cloud.ctl.observation_logs_disable()
    elif observation_logs_enabled:
        raise BadRequestError('Invalid observation_logs_enabled state')

    if container_enabled == 1:
        cloud.ctl.container_enable()
    elif container_enabled == 0:
        cloud.ctl.container_disable()
    elif container_enabled:
        raise BadRequestError('Invalid container_enabled state')

    trigger_session_update(auth_context.owner, ['clouds'])
    return OK


@view_config(route_name='api_v1_cloud_security_groups', request_method='GET',
             renderer='json')
def list_security_groups(request):
    """
    Tags: security-groups
    ---
    Lists security groups on cloud.
    Currently only supported for AWS, Openstack & Vexxhost.
    READ permission required on cloud.
    ---
    cloud:
      in: path
      required: true
      type: string
    """
    auth_context = auth_context_from_request(request)
    cloud_id = request.matchdict['cloud']

    # SEC
    auth_context.check_perm("cloud", "read", cloud_id)
    try:
        cloud = Cloud.objects.get(owner=auth_context.owner, id=cloud_id,
                                  deleted=None)
    except Cloud.DoesNotExist:
        raise NotFoundError('Cloud does not exist')

    try:
        sec_groups = cloud.ctl.compute.list_security_groups()
    except MistNotImplementedError:
        raise BadRequestError(f'Listing security groups is not supported'
                              f' for provider {cloud.provider}')

    return sec_groups


@view_config(route_name='api_v1_cloud_projects', request_method='GET',
             renderer='json')
def list_projects(request):
    """
    Tags: projects
    ---
    Lists projects on cloud.
    Only supported for EquinixMetal.
    For other providers,returns an empty list
    READ permission required on cloud.
    ---
    cloud:
      in: path
      required: true
      type: string
    """
    auth_context = auth_context_from_request(request)
    cloud_id = request.matchdict['cloud']

    # SEC
    auth_context.check_perm("cloud", "read", cloud_id)
    try:
        cloud = Cloud.objects.get(owner=auth_context.owner, id=cloud_id,
                                  deleted=None)
    except Cloud.DoesNotExist:
        raise NotFoundError('Cloud does not exist')
    try:
        projects = methods.list_projects(auth_context.owner, cloud_id)
    except Exception as e:
        log.error("Could not list projects for cloud %s: %r" % (
            cloud, e))
        raise MistNotImplementedError()

    return projects


# For VSphere only VM folders
@view_config(route_name='api_v1_cloud_folders', request_method='GET',
             renderer='json')
def list_folders(request):
    """
    Tags: folders
    ---
    Lists all the folders that contain VMs.
    It is needed for machine creation for the 6.7 REST api of VSphere.
    In the future it might not be necessary.
    READ permission required on cloud.
    ---
    cloud:
      in: path
      required: true
      type: string
    """
    auth_context = auth_context_from_request(request)
    cloud_id = request.matchdict.get('cloud')

    try:
        cloud = Cloud.objects.get(owner=auth_context.owner, id=cloud_id,
                                  deleted=None)
    except Cloud.DoesNotExist:
        raise NotFoundError('Cloud does not exist')
    if cloud.as_dict()['provider'] != 'vsphere':
        raise BadRequestError('Only available for vSphere clouds')
    # SEC
    auth_context.check_perm('cloud', 'read', cloud_id)
    vm_folders = cloud.ctl.compute.list_vm_folders()
    return vm_folders


@view_config(route_name='api_v1_cloud_datastores', request_method='GET',
             renderer='json')
def list_datastores(request):
    """
    Tags: datastores
    ---
    Lists datastores on cloud.
    Only supported for Vsphere.
    READ permission required on cloud.
    ---
    cloud:
      in: path
      required: true
      type: string
    """
    auth_context = auth_context_from_request(request)
    cloud_id = request.matchdict.get('cloud')

    try:
        cloud = Cloud.objects.get(owner=auth_context.owner, id=cloud_id,
                                  deleted=None)
    except Cloud.DoesNotExist:
        raise NotFoundError('Cloud does not exist')

    if cloud.as_dict()['provider'] != 'vsphere':
        raise BadRequestError('Only available for vSphere clouds.')
    # SEC
    auth_context.check_perm('cloud', 'read', cloud_id)
    try:
        datastores = cloud.ctl.compute.list_datastores()
        return datastores
    except Exception as e:
        log.error("Could not list datastores for cloud %s: %r" % (
                  cloud, e))
        raise MistNotImplementedError()
