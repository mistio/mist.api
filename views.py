"""mist.io.views

Here we define the HTTP API of the app. The view functions here are
responsible for taking parameters from the web requests, passing them on to
functions defined in methods and properly formatting the output. This is the
only source file where we import things from pyramid. View functions should
only check that all required params are provided. Any further checking should
be performed inside the corresponding method functions.

"""
import json
import uuid
import urllib
import requests
import traceback
from time import time
from datetime import datetime

import mongoengine as me

from pyramid.response import Response
from pyramid.httpexceptions import HTTPFound
from pyramid.renderers import render_to_response
# try:

from mist.io.auth.methods import user_from_request
from mist.io.keys.models import Key, SSHKey, SignedSSHKey
from mist.io.scripts.models import CollectdScript
from mist.io.scripts.models import ExecutableScript, AnsibleScript, Script
from mist.io.schedules.models import Schedule
from mist.io.tag.methods import add_tags_to_resource, resolve_id_and_set_tags
from mist.io.clouds.models import Cloud
from mist.io.machines.models import Machine
from mist.io.users.models import User, Organization
from mist.io.auth.models import SessionToken, ApiToken, AuthToken
from mist.io.users.models import Team, MemberInvitation, Promo
from mist.io.users.methods import get_users_count, register_user

from mist.core import config
import mist.core.methods
# except ImportError:
#     from mist.io import config
#     from mist.io.helpers import user_from_request
#     from pyramid.view import view_config

from mist.io import methods
from mist.io import tasks

from mist.io.exceptions import LoginThrottledError, ConflictError
from mist.io.exceptions import RequiredParameterMissingError
from mist.io.exceptions import NotFoundError, BadRequestError
from mist.io.exceptions import SSLError, ServiceUnavailableError
from mist.io.exceptions import KeyParameterMissingError, MistError
from mist.io.exceptions import PolicyUnauthorizedError, UnauthorizedError
from mist.io.exceptions import UnauthorizedError, RedirectError
from mist.io.exceptions import ScheduleTaskNotFound, ForbiddenError
from mist.io.exceptions import UserUnauthorizedError, UserNotFoundError
from mist.io.exceptions import OrganizationAuthorizationFailure
from mist.io.exceptions import OrganizationOperationError
from mist.io.exceptions import OrganizationNameExistsError
from mist.io.exceptions import MemberConflictError, MemberNotFound
from mist.io.exceptions import TeamForbidden, TeamNotFound, TeamOperationError
from mist.io.exceptions import MethodNotAllowedError

from mist.io.helpers import initiate_social_auth_request
from mist.io.helpers import get_auth_header, params_from_request
from mist.io.helpers import trigger_session_update, amqp_publish_user
from mist.io.helpers import transform_key_machine_associations
from mist.io.helpers import view_config, get_stories, log_event
from mist.io.helpers import ip_from_request, send_email
from mist.io.helpers import encrypt, decrypt
from mist.io.helpers import get_log_events

from mist.io.auth.methods import auth_context_from_request
from mist.io.auth.methods import token_with_name_not_exists
from mist.io.auth.methods import get_random_name_for_token
from mist.io.auth.methods import reissue_cookie_session
from mist.io.auth.methods import session_from_request
from mist.io.auth.models import get_secure_rand_token

# TODO handle approprietly
from mist.core import experiments

import logging
logging.basicConfig(level=config.PY_LOG_LEVEL,
                    format=config.PY_LOG_FORMAT,
                    datefmt=config.PY_LOG_FORMAT_DATE)
log = logging.getLogger(__name__)

OK = Response("OK", 200)


@view_config(context=Exception)
def exception_handler_mist(exc, request):
    """Here we catch exceptions and transform them to proper http responses

    This is a special pyramid view that gets triggered whenever an exception
    is raised from any other view. It catches all exceptions exc where
    isinstance(exc, context) is True.

    """
    # mongoengine ValidationError
    if isinstance(exc, me.ValidationError):
        trace = traceback.format_exc()
        log.warning("Uncaught me.ValidationError!\n%s", trace)
        return Response("Validation Error", 400)

    # mongoengine NotUniqueError
    if isinstance(exc, me.NotUniqueError):
        trace = traceback.format_exc()
        log.warning("Uncaught me.NotUniqueError!\n%s", trace)
        return Response("NotUniqueError", 409)

    # non-mist exceptions. that shouldn't happen! never!
    if not isinstance(exc, MistError):
        if not isinstance(exc, (me.ValidationError, me.NotUniqueError)):
            trace = traceback.format_exc()
            log.critical("Uncaught non-mist exception? WTF!\n%s", trace)
            return Response("Internal Server Error", 500)

    # mist exceptions are ok.
    log.info("MistError: %r", exc)


    # translate it to HTTP response based on http_code attribute
    return Response(str(exc), exc.http_code)


#@view_config(context='pyramid.httpexceptions.HTTPNotFound',
#             renderer='templates/404.pt')
#def not_found(self, request):
#    return pyramid.httpexceptions.HTTPFound(request.host_url+"/#"+request.path)


@view_config(route_name='home', request_method='GET')
@view_config(route_name='clouds', request_method='GET')
@view_config(route_name='cloud', request_method='GET')
@view_config(route_name='machines', request_method='GET')
@view_config(route_name='machine', request_method='GET')
@view_config(route_name='images', request_method='GET')
@view_config(route_name='image', request_method='GET')
@view_config(route_name='keys', request_method='GET')
@view_config(route_name='key', request_method='GET')
@view_config(route_name='networks', request_method='GET')
@view_config(route_name='network', request_method='GET')
def home(request):
    """Home page view"""
    params = params_from_request(request)
    user = user_from_request(request)
    if params.get('ember'):
        template = 'home.pt'
    else:
        template = 'poly.pt'
    return render_to_response('templates/%s' % template,
        {
        'project': 'mist.io',
        'email': json.dumps(user.email),
        'first_name': json.dumps(""),
        'last_name': json.dumps(""),
        'supported_providers': json.dumps(config.SUPPORTED_PROVIDERS_V_2),
        'core_uri': json.dumps(config.CORE_URI),
        'auth': json.dumps(bool(user.mist_api_token)),
        'js_build': json.dumps(config.JS_BUILD),
        'css_build': config.CSS_BUILD,
        'js_log_level': json.dumps(config.JS_LOG_LEVEL),
        'google_analytics_id': config.GOOGLE_ANALYTICS_ID,
        'is_core': json.dumps(False),
        'csrf_token': json.dumps(""),
        'beta_features': json.dumps(False),
        'last_build': config.LAST_BUILD
        }, request=request)


@view_config(route_name='api_v1_clouds', request_method='GET', renderer='json')
def list_clouds(request):
    """
    Request a list of all added clouds.
    READ permission required on cloud.
    ---
    """
    auth_context = auth_context_from_request(request)
    # to prevent iterate throw every cloud
    auth_context.check_perm("cloud", "read", None)
    return mist.io.methods.filter_list_clouds(auth_context)


@view_config(route_name='api_v1_clouds', request_method='POST', renderer='json')
def add_cloud(request):
    """
    Add a new cloud
    Adds a new cloud to the user and returns the cloud_id
    ADD permission required on cloud.

    ---
    api_key:
      type: string
    api_secret:
      type: string
    apiurl:
      type: string
    docker_port:
      type: string
    machine_key:
      type: string
    machine_port:
      type: string
    machine_user:
      type: string
    provider:
      description: The id of the cloud provider.
      enum:
      - vcloud
      - bare_metal
      - docker
      - libvirt
      - openstack
      - vsphere
      - ec2
      - rackspace
      - nephoscale
      - digitalocean
      - softlayer
      - gce
      - azure
      - azure_arm
      - linode
      - indonesian_vcloud
      - hostvirtual
      - vultr
      required: true
      type: string
    remove_on_error:
      type: string
    tenant_name:
      type: string
    title:
      description: The human readable title of the cloud.
      required: true
      type: string
    """
    auth_context = auth_context_from_request(request)
    cloud_tags = auth_context.check_perm("cloud", "add", None)
    owner = auth_context.owner
    params = params_from_request(request)
    # remove spaces from start/end of string fields that are often included
    # when pasting keys, preventing thus succesfull connection with the
    # cloud
    for key in params.keys():
        if type(params[key]) in [unicode, str]:
            params[key] = params[key].rstrip().lstrip()

    # api_version = request.headers.get('Api-Version', 1)
    title = params.get('title', '')
    provider = params.get('provider', '')

    if config.NEW_UI_EXPERIMENT_ENABLE:
        from mist.core.experiments import NewUIExperiment
        from mist.io.auth.methods import session_from_request

        session = session_from_request(request)
        experiment = NewUIExperiment(userid=session.user_id)
        experiment.log_event('add_cloud', {'title': title,
                                           'provider': provider})

    if not provider:
        raise RequiredParameterMissingError('provider')

    monitoring = None
    ret = methods.add_cloud_v_2(owner, title, provider, params)

    cloud_id = ret['cloud_id']
    monitoring = ret.get('monitoring')

    cloud = Cloud.objects.get(owner=owner, id=cloud_id)

    if cloud_tags:
        from mist.io.tag.methods import add_tags_to_resource
        add_tags_to_resource(owner, cloud, cloud_tags.items())

    c_count = Cloud.objects(owner=owner, deleted=None).count()
    ret = cloud.as_dict()
    ret['index'] = c_count - 1
    if monitoring:
        ret['monitoring'] = monitoring
    return ret


@view_config(route_name='api_v1_cloud_action', request_method='DELETE')
def delete_cloud(request):
    """
    Delete a cloud
    Deletes cloud with given cloud_id.
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
        cloud = Cloud.objects.get(owner=auth_context.owner,
                                  id=cloud_id, deleted=None)
    except Cloud.DoesNotExist:
        raise NotFoundError('Cloud does not exist')
    auth_context.check_perm('cloud', 'remove', cloud_id)
    methods.delete_cloud(auth_context.owner, cloud_id)
    return OK


@view_config(route_name='api_v1_cloud_action', request_method='PUT')
def rename_cloud(request):
    """
    Rename a cloud
    Renames cloud with given cloud_id.
    EDIT permission required on cloud.
    ---
    cloud:
      in: path
      required: true
      type: string
    new_name:
      description: ' New name for the key (will also serve as the key''s id)'
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
    new_name = params.get('new_name', '')
    if not new_name:
        raise RequiredParameterMissingError('new_name')
    auth_context.check_perm('cloud', 'edit', cloud_id)

    methods.rename_cloud(auth_context.owner, cloud_id, new_name)
    return OK


@view_config(route_name='api_v1_cloud_action', request_method='PATCH')
def update_cloud(request):
    """
    UPDATE cloud with given cloud_id.
    EDIT permission required on cloud.
    Not all fields need to be specified, only the ones being modified
    ---
    cloud:
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
    Toggle a cloud
    Toggles cloud with given cloud_id.
    EDIT permission required on cloud.
    ---
    cloud:
      in: path
      required: true
      type: string
    new_state:
      enum:
      - '0'
      - '1'
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

    new_state = params_from_request(request).get('new_state')
    if new_state == '1':
        cloud.ctl.enable()
    elif new_state == '0':
        cloud.ctl.disable()
    elif new_state:
        raise BadRequestError('Invalid cloud state')
    else:
        raise RequiredParameterMissingError('new_state')
    trigger_session_update(auth_context.owner, ['clouds'])
    return OK


@view_config(route_name='api_v1_keys', request_method='GET', renderer='json')
def list_keys(request):
    """
    List keys
    Retrieves a list of all added keys
    READ permission required on key.
    ---
    """
    auth_context = auth_context_from_request(request)
    return mist.io.methods.filter_list_keys(auth_context)


@view_config(route_name='api_v1_keys', request_method='PUT', renderer='json')
def add_key(request):
    """
    Add key
    Add key with specific name
    ADD permission required on key.
    ---
    id:
      description: The key name
      required: true
      type: string
    priv:
      description: The private key
      required: true
      type: string
    certificate:
      description: The signed public key, when using signed ssh keys
      required: false
      type: string

    """
    params = params_from_request(request)
    key_name = params.pop('name', None)
    private_key = params.get('priv', None)
    certificate = params.get('certificate', None)
    auth_context = auth_context_from_request(request)
    key_tags = auth_context.check_perm("key", "add", None)

    if not key_name:
        raise BadRequestError("Key name is not provided")
    if not private_key:
        raise RequiredParameterMissingError("Private key is not provided")

    if certificate:
        key = SignedSSHKey.add(auth_context.owner, key_name, **params)
    else:
        key = SSHKey.add(auth_context.owner, key_name, **params)

    if key_tags:
        from mist.io.tag.methods import add_tags_to_resource
        add_tags_to_resource(auth_context.owner, key, key_tags.items())
    # since its a new key machines fields should be an empty list

    clouds = Cloud.objects(owner=auth_context.owner, deleted=None)
    machines = Machine.objects(cloud__in=clouds,
                               key_associations__keypair__exact=key)

    assoc_machines = transform_key_machine_associations(machines, key)

    return {'id': key.id,
            'name': key.name,
            'machines': assoc_machines,
            'isDefault': key.default}


@view_config(route_name='api_v1_key_action', request_method='DELETE',
             renderer='json')
def delete_key(request):
    """
    Delete key
    Delete key. When a key gets deleted, it takes its associations with it
    so just need to remove from the server too. If the default key gets deleted,
    it sets the next one as default, provided that at least another key exists.
    It returns the list of all keys after the deletion, excluding the private
    keys (check also list_keys).
    REMOVE permission required on key.
    ---
    key:
      in: path
      required: true
      type: string
    """
    auth_context = auth_context_from_request(request)
    key_id = request.matchdict.get('key')
    if not key_id:
        raise KeyParameterMissingError()

    try:
        key = Key.objects.get(owner=auth_context.owner, id=key_id,
                              deleted=None)
    except me.DoesNotExist:
        raise NotFoundError('Key id does not exist')

    auth_context.check_perm('key', 'remove', key.id)
    methods.delete_key(auth_context.owner, key_id)
    return list_keys(request)


@view_config(route_name='api_v1_keys', request_method='DELETE', renderer='json')
@view_config(route_name='keys', request_method='DELETE', renderer='json')
def delete_keys(request):
    """
    Delete multiple keys.
    Provide a list of key ids to be deleted. The method will try to delete
    all of them and then return a json that describes for each key id
    whether or not it was deleted or not_found if the key id could not
    be located. If no key id was found then a 404(Not Found) response will
    be returned.
    REMOVE permission required on each key.
    ---
    key_ids:
      required: true
      type: array
      items:
        type: string
        name: key_id
    """
    auth_context = auth_context_from_request(request)

    params = params_from_request(request)
    key_ids = params.get('key_ids', [])
    if type(key_ids) != list or len(key_ids) == 0:
        raise RequiredParameterMissingError('No key ids provided')
    # remove duplicate ids if there are any
    key_ids = set(key_ids)

    report = {}
    for key_id in key_ids:
        try:
            key = Key.objects.get(owner=auth_context.owner,
                                  id=key_id, deleted=None)
        except me.DoesNotExist:
            report[key_id] = 'not_found'
            continue
        try:
            auth_context.check_perm('key', 'remove', key.id)
        except PolicyUnauthorizedError:
            report[key_id] = 'unauthorized'
        else:
            methods.delete_key(auth_context.owner, key_id)
            report[key_id] = 'deleted'

    # if no key id was valid raise exception
    if len(filter(lambda key_id: report[key_id] == 'not_found',
                  report)) == len(key_ids):
        raise NotFoundError('No valid key id provided')
    # if user was unauthorized for all keys
    if len(filter(lambda key_id: report[key_id] == 'unauthorized',
                  report)) == len(key_ids):
        raise NotFoundError('Unauthorized to modify any of the keys')
    return report


@view_config(route_name='api_v1_key_action', request_method='PUT', renderer='json')
def edit_key(request):
    """
    Edit a key
    Edits a given key's name  to new_name
    EDIT permission required on key.
    ---
    new_name:
      description: The new key name
      type: string
    key_id:
      description: The key id
      in: path
      required: true
      type: string
    """
    key_id = request.matchdict['key']
    params = params_from_request(request)
    new_name = params.get('new_name')
    if not new_name:
        raise RequiredParameterMissingError("new_name")

    auth_context = auth_context_from_request(request)
    try:
        key = Key.objects.get(owner=auth_context.owner,
                              id=key_id, deleted=None)
    except me.DoesNotExist:
        raise NotFoundError('Key with that id does not exist')
    auth_context.check_perm('key', 'edit', key.id)
    key.ctl.rename(new_name)

    return {'new_name': new_name}


@view_config(route_name='api_v1_key_action', request_method='POST')
def set_default_key(request):
    """
    Set default key
    Sets a new default key
    EDIT permission required on key.
    ---
    key:
      description: The key id
      in: path
      required: true
      type: string
    """
    key_id = request.matchdict['key']

    auth_context = auth_context_from_request(request)
    try:
        key = Key.objects.get(owner=auth_context.owner,
                              id=key_id, deleted=None)
    except me.DoesNotExist:
        raise NotFoundError('Key id does not exist')

    auth_context.check_perm('key', 'edit', key.id)

    key.ctl.set_default()
    return OK


@view_config(route_name='api_v1_key_private', request_method='GET',
             renderer='json')
def get_private_key(request):
    """
    Gets private key from key name.
    It is used in single key view when the user clicks the display private key
    button.
    READ_PRIVATE permission required on key.
    ---
    key:
      description: The key id
      in: path
      required: true
      type: string
    """

    key_id = request.matchdict['key']
    if not key_id:
        raise RequiredParameterMissingError("key_id")

    auth_context = auth_context_from_request(request)
    try:
        key = SSHKey.objects.get(owner=auth_context.owner,
                                 id=key_id, deleted=None)
    except me.DoesNotExist:
        raise NotFoundError('Key id does not exist')

    auth_context.check_perm('key', 'read_private', key.id)
    return key.private


@view_config(route_name='api_v1_key_public', request_method='GET',
             renderer='json')
def get_public_key(request):
    """
    Get public key
    Gets public key from key name.
    READ permission required on key.
    ---
    key:
      description: The key id
      in: path
      required: true
      type: string
    """
    key_id = request.matchdict['key']
    if not key_id:
        raise RequiredParameterMissingError("key_id")

    auth_context = auth_context_from_request(request)
    try:
        key = SSHKey.objects.get(owner=auth_context.owner,
                                 id=key_id, deleted=None)
    except me.DoesNotExist:
        raise NotFoundError('Key id does not exist')

    auth_context.check_perm('key', 'read', key.id)
    return key.public


@view_config(route_name='api_v1_keys', request_method='POST', renderer='json')
@view_config(route_name='keys', request_method='POST', renderer='json')
def generate_keypair(request):
    """
    Generate key
    Generate key pair
    ---
    """
    key = SSHKey()
    key.ctl.generate()
    return {'priv': key.private, 'public': key.public}


@view_config(route_name='api_v1_key_association', request_method='PUT',
             renderer='json')
def associate_key(request):
    """
    Associate a key to a machine
    Associates a key with a machine. If host is set it will also attempt to
    actually deploy it to the machine. To do that it requires another key
    (existing_key) that can connect to the machine.
    READ permission required on cloud.
    READ_PRIVATE permission required on key.
    ASSOCIATE_KEY permission required on machine.
    ---
    cloud:
      in: path
      required: true
      type: string
    machine:
      in: path
      required: true
      type: string
    key:
      in: path
      required: true
      type: string
    port:
      default: 22
      type: integer
    user:
      description: The ssh user
      type: string
    """
    key_id = request.matchdict['key']
    cloud_id = request.matchdict['cloud']
    machine_id = request.matchdict['machine']
    params = params_from_request(request)
    ssh_user = params.get('user', None)
    try:
        ssh_port = int(request.json_body.get('port', 22))
    except:
        ssh_port = 22

    auth_context = auth_context_from_request(request)
    auth_context.check_perm("cloud", "read", cloud_id)
    key = Key.objects.get(owner=auth_context.owner, id=key_id, deleted=None)
    auth_context.check_perm('key', 'read_private', key.id)
    try:
        machine = Machine.objects.get(cloud=cloud_id, machine_id=machine_id)
    except me.DoesNotExist:
        raise NotFoundError("Machine %s doesn't exist" % machine_id)

    auth_context.check_perm("machine", "associate_key", machine.id)

    key.ctl.associate(machine, username=ssh_user, port=ssh_port)
    clouds = Cloud.objects(owner=auth_context.owner, deleted=None)
    machines = Machine.objects(cloud__in=clouds,
                               key_associations__keypair__exact=key)

    assoc_machines = transform_key_machine_associations(machines, key)
    return assoc_machines


@view_config(route_name='api_v1_key_association', request_method='DELETE',
             renderer='json')
def disassociate_key(request):
    """
    Disassociate a key from a machine
    Disassociates a key from a machine. If host is set it will also attempt to
    actually remove it from the machine.
    READ permission required on cloud.
    DISASSOCIATE_KEY permission required on machine.
    ---
    key:
      in: path
      required: true
      type: string
    cloud:
      in: path
      required: true
      type: string
    machine:
      in: path
      required: true
      type: string
    """
    key_id = request.matchdict['key']
    cloud_id = request.matchdict['cloud']
    machine_id = request.matchdict['machine']

    auth_context = auth_context_from_request(request)
    auth_context.check_perm("cloud", "read", cloud_id)
    try:
        machine = Machine.objects.get(cloud=cloud_id, machine_id=machine_id)
    except me.DoesNotExist:
        raise NotFoundError("Machine %s doesn't exist" % machine_id)
    auth_context.check_perm("machine", "disassociate_key", machine.id)

    key = Key.objects.get(owner=auth_context.owner, id=key_id, deleted=None)
    key.ctl.disassociate(machine)
    clouds = Cloud.objects(owner=auth_context.owner, deleted=None)
    machines = Machine.objects(cloud__in=clouds,
                               key_associations__keypair__exact=key)

    assoc_machines = transform_key_machine_associations(machines, key)
    return assoc_machines

@view_config(route_name='api_v1_zones', request_method='GET', renderer='json')
def list_dns_zones(request):
    """
    List all DNS zones.
    Retrieves a list of all DNS zones based on the user Clouds.
    For each cloud that supports DNS functionality, we get all available zones.
    ---
    """
    auth_context = auth_context_from_request(request)
    cloud_id = request.matchdict['cloud']

    try:
        cloud = Cloud.objects.get(owner=auth_context.owner, id=cloud_id)
    except Cloud.DoesNotExist:
        raise NotFoundError('Cloud does not exist')

    return cloud.ctl.dns.list_zones()


@view_config(route_name='api_v1_records', request_method='GET', renderer='json')
def list_dns_records(request):
    """
    List all DNS zone records for a particular zone.
    ---
    """
    auth_context = auth_context_from_request(request)
    cloud_id = request.matchdict['cloud']
    zone_id = request.matchdict['zone']
    try:
        cloud = Cloud.objects.get(owner=auth_context.owner, id=cloud_id)
    except Cloud.DoesNotExist:
        raise NotFoundError('Cloud does not exist')
    return cloud.ctl.dns.list_records(zone_id)

@view_config(route_name='api_v1_zones', request_method='POST', renderer='json')
def create_dns_zone(request):
    """
    Create a new DNS zone under a specific cloud.
    ---
    """
    auth_context = auth_context_from_request(request)
    cloud_id = request.matchdict['cloud']
    # Try to get the specific cloud for which we will create the zone.
    try:
        cloud = Cloud.objects.get(owner=auth_context.owner, id=cloud_id)
    except Cloud.DoesNotExist:
        raise NotFoundError('Cloud does not exist')
    # Get the rest of the params
    # domain is required and must contain a trailing period(.)
    # type should be master or slave, and defaults to master.
    # ttl is the time for which the zone should be valid for. Defaults to None.
    # Should be an integer value.
    # extra is a dictionary with extra details. Defaults to None.
    params = params_from_request(request)
    domain = params.get('domain', '')
    if not domain:
        raise RequiredParameterMissingError('domain')
    type = params.get('type', '')
    ttl = params.get('ttl', 0)
    extra = params.get('extra', '')

    return cloud.ctl.dns.create_zone(domain, type, ttl, extra)

@view_config(route_name='api_v1_records', request_method='POST', renderer='json')
def create_dns_record(request):
    """
    Create a new record under a specific zone
    ---
    """
    auth_context = auth_context_from_request(request)
    cloud_id = request.matchdict['cloud']
    # Try to get the specific cloud for which we will create the zone.
    try:
        cloud = Cloud.objects.get(owner=auth_context.owner, id=cloud_id)
    except Cloud.DoesNotExist:
        raise NotFoundError('Cloud does not exist')

    zone_id = request.matchdict['zone']
    # Get the rest of the params
    # name is required and must contain a trailing period(.)
    # type should be the type of the record we want to create (A,MX,CNAME etc),
    # and it is required.
    # ttl is the time for which the record should be valid for. Defaults to 0.
    # Should be an integer value.
    params = params_from_request(request)
    name = params.get('name', '')
    if not name:
        raise RequiredParameterMissingError('name')
    type = params.get('type', '')
    if not type:
        raise RequiredParameterMissingError('type')
    data = params.get('data', '')
    if not data:
        raise RequiredParameterMissingError('data')
    ttl = params.get('ttl', 0)

    return cloud.ctl.dns.create_record(zone_id, name, type, data, ttl)

@view_config(route_name='api_v1_zone', request_method='DELETE', renderer='json')
def delete_dns_zone(request):
    """
    Delete a specific DNS zone under a cloud.
    ---
    """
    auth_context = auth_context_from_request(request)
    cloud_id = request.matchdict['cloud']
    zone_id = request.matchdict['zone']
    try:
        cloud = Cloud.objects.get(owner=auth_context.owner, id=cloud_id)
    except Cloud.DoesNotExist:
        raise NotFoundError('Cloud does not exist')

    return cloud.ctl.dns.delete_zone(zone_id)

@view_config(route_name='api_v1_record', request_method='DELETE', renderer='json')
def delete_dns_record(request):
    """
    Delete a specific DNS record under a zone.
    ---
    """
    auth_context = auth_context_from_request(request)
    cloud_id = request.matchdict['cloud']
    zone_id = request.matchdict['zone']
    record_id = request.matchdict['record']
    try:
        cloud = Cloud.objects.get(owner=auth_context.owner, id=cloud_id)
    except Cloud.DoesNotExist:
        raise NotFoundError('Cloud does not exist')

    return cloud.ctl.dns.delete_record(zone_id, record_id)

@view_config(route_name='api_v1_machines', request_method='GET', renderer='json')
def list_machines(request):
    """
    List machines on cloud
    Gets machines and their metadata from a cloud
    READ permission required on machine.
    ---
    cloud:
      in: path
      required: true
      type: string
    """

    auth_context = auth_context_from_request(request)
    cloud_id = request.matchdict['cloud']
    return mist.io.methods.filter_list_machines(auth_context, cloud_id)


@view_config(route_name='api_v1_machines', request_method='POST',
             renderer='json')
def create_machine(request):
    """
    Create machine(s) on cloud
    Creates one or more machines on the specified cloud. If async is true, a
    jobId will be returned.
    READ permission required on cloud.
    CREATE_RESOURCES permissn required on cloud.
    CREATE permission required on machine.
    RUN permission required on script.
    READ permission required on key.

    ---
    cloud:
      in: path
      required: true
      type: string
    async:
      description: ' Create machines asynchronously, returning a jobId'
      type: boolean
    quantity:
      description: ' The number of machines that will be created, async only'
      type: integer
    azure_port_bindings:
      type: string
    cloud_id:
      description: The Cloud ID
      required: true
      type: string
    disk:
      description: ' Only required by Linode cloud'
      type: string
    docker_command:
      type: string
    docker_env:
      items:
        type: string
      type: array
    docker_exposed_ports:
      type: object
    docker_port_bindings:
      type: object
    hostname:
      type: string
    image_extra:
      description: ' Needed only by Linode cloud'
      type: string
    image:
      description: ' Id of image to be used with the creation'
      required: true
      type: string
    image_name:
      type: string
    ips:
      type: string
    job_id:
      type: string
    key_id:
      description: ' Associate machine with this key_id'
      required: true
      type: string
    location_id:
      description: ' Id of the cloud''s location to create the machine'
      required: true
      type: string
    location_name:
      type: string
    machine_name:
      required: true
      type: string
    monitoring:
      type: string
    networks:
      items:
        type: string
      type: array
    plugins:
      items:
        type: string
      type: array
    post_script_id:
      type: string
    post_script_params:
      type: string
    script:
      type: string
    script_id:
      type: string
    script_params:
      type: string
    size_id:
      description: ' Id of the size of the machine'
      required: true
      type: string
    size_name:
      type: string
    ssh_port:
      type: integer
    softlayer_backend_vlan_id:
      description: 'Specify id of a backend(private) vlan'
      type: integer
    project_id:
      description: ' Needed only by Packet.net cloud'
      type: string
    billing:
      description: ' Needed only by SoftLayer cloud'
      type: string
    bare_metal:
      description: ' Needed only by SoftLayer cloud'
      type: string
    """
    # TODO add schedule in docstring

    params = params_from_request(request)
    cloud_id = request.matchdict['cloud']

    for key in ('name', 'size'):
        if key not in params:
            raise RequiredParameterMissingError(key)

    key_id = params.get('key')
    machine_name = params['name']
    location_id = params.get('location', None)
    image_id = params.get('image')
    if not image_id:
        raise RequiredParameterMissingError("image")
    # this is used in libvirt
    disk_size = int(params.get('libvirt_disk_size', 4))
    disk_path = params.get('libvirt_disk_path', '')
    size_id = params['size']
    # deploy_script received as unicode, but ScriptDeployment wants str
    script = str(params.get('script', ''))
    # these are required only for Linode/GCE, passing them anyway
    image_extra = params.get('image_extra', None)
    disk = params.get('disk', None)
    image_name = params.get('image_name', None)
    size_name = params.get('size_name', None)
    location_name = params.get('location_name', None)
    ips = params.get('ips', None)
    monitoring = params.get('monitoring', False)
    networks = params.get('networks', [])
    docker_env = params.get('docker_env', [])
    docker_command = params.get('docker_command', None)
    script_id = params.get('script_id', '')
    script_params = params.get('script_params', '')
    post_script_id = params.get('post_script_id', '')
    post_script_params = params.get('post_script_params', '')
    async = params.get('async', False)
    quantity = params.get('quantity', 1)
    persist = params.get('persist', False)
    docker_port_bindings = params.get('docker_port_bindings', {})
    docker_exposed_ports = params.get('docker_exposed_ports', {})
    azure_port_bindings = params.get('azure_port_bindings', '')
    # hostname: if provided it will be attempted to assign a DNS name
    hostname = params.get('hostname', '')
    plugins = params.get('plugins')
    cloud_init = params.get('cloud_init', '')
    associate_floating_ip = params.get('associate_floating_ip', False)
    associate_floating_ip_subnet = params.get('attach_floating_ip_subnet', None)
    project_id = params.get('project', None)
    bare_metal = params.get('bare_metal', False)
    # bare_metal True creates a hardware server in SoftLayer,
    # whule bare_metal False creates a virtual cloud server
    # hourly True is the default setting for SoftLayer hardware
    # servers, while False means the server has montly pricing
    softlayer_backend_vlan_id = params.get('softlayer_backend_vlan_id', None)
    hourly = params.get('billing', True)
    job_id = params.get('job_id', uuid.uuid4().hex)

    auth_context = auth_context_from_request(request)

    # compose schedule as a dict from relative parameters
    if not params.get('schedule_type'):
        schedule = {}
    else:
        if params.get('schedule_type') not in ['crontab',
                                               'interval', 'one_off']:
            raise BadRequestError('schedule type must be one of '
                                  'these (crontab, interval, one_off)]'
                                  )
        if params.get('schedule_entry') == {}:
            raise RequiredParameterMissingError('schedule_entry')

        schedule = {
            'name': 'scheduler_' + params.get('name'),
            'description': params.get('description', ''),
            'action': params.get('action', ''),
            'script_id': params.get('schedule_script_id', ''),
            'schedule_type': params.get('schedule_type'),
            'schedule_entry': params.get('schedule_entry'),
            'expires': params.get('expires', ''),
            'start_after': params.get('start_after', ''),
            'max_run_count': params.get('max_run_count'),
            'task_enabled': bool(params.get('task_enabled', True)),
            'auth_context': auth_context.serialize(),
        }

    auth_context.check_perm("cloud", "read", cloud_id)
    auth_context.check_perm("cloud", "create_resources", cloud_id)
    tags = auth_context.check_perm("machine", "create", None)
    if script_id:
        auth_context.check_perm("script", "run", script_id)
    if key_id:
        auth_context.check_perm("key", "read", key_id)

    from mist.io import tasks
    args = (cloud_id, key_id, machine_name,
            location_id, image_id, size_id,
            image_extra, disk, image_name, size_name,
            location_name, ips, monitoring, networks,
            docker_env, docker_command)
    kwargs = {'script_id': script_id, 'script_params': script_params, 'script': script,
              'job_id': job_id, 'docker_port_bindings': docker_port_bindings,
              'docker_exposed_ports': docker_exposed_ports,
              'azure_port_bindings': azure_port_bindings,
              'hostname': hostname, 'plugins': plugins,
              'post_script_id': post_script_id,
              'post_script_params': post_script_params,
              'disk_size': disk_size,
              'disk_path': disk_path,
              'cloud_init': cloud_init,
              'associate_floating_ip': associate_floating_ip,
              'associate_floating_ip_subnet': associate_floating_ip_subnet,
              'project_id': project_id,
              'bare_metal': bare_metal,
              'tags': tags,
              'hourly': hourly,
              'schedule': schedule,
              'softlayer_backend_vlan_id': softlayer_backend_vlan_id}
    if not async:
        ret = methods.create_machine(auth_context.owner, *args, **kwargs)
    else:
        args = (auth_context.owner.id, ) + args
        kwargs.update({'quantity': quantity, 'persist': persist})
        tasks.create_machine_async.apply_async(args, kwargs, countdown=2)
        ret = {'job_id': job_id}
    return ret


@view_config(route_name='api_v1_machine', request_method='POST', renderer='json')
def machine_actions(request):
    """
    Call an action on machine
    Calls a machine action on cloud that support it
    READ permission required on cloud.
    ACTION permission required on machine(ACTION can be START,
    STOP, DESTROY, REBOOT).
    ---
    cloud:
      in: path
      required: true
      type: string
    machine:
      in: path
      required: true
      type: string
    action:
      enum:
      - start
      - stop
      - reboot
      - destroy
      - resize
      - rename
      required: true
      type: string
    name:
      description: The new name of the renamed machine
      type: string
    size:
      description: The size id of the plan to resize
      type: string
    """
    cloud_id = request.matchdict['cloud']
    machine_id = request.matchdict['machine']
    params = params_from_request(request)
    action = params.get('action', '')
    plan_id = params.get('plan_id', '')
    name = params.get('name', '')
    auth_context = auth_context_from_request(request)
    auth_context.check_perm("cloud", "read", cloud_id)

    try:
        machine = Machine.objects.get(cloud=cloud_id, machine_id=machine_id)
    except me.DoesNotExist:
        raise NotFoundError("Machine %s doesn't exist" % machine_id)

    if machine.cloud.owner != auth_context.owner:
        raise NotFoundError("Machine %s doesn't exist" % machine_id)

    auth_context.check_perm("machine", action, machine.id)

    actions = ('start', 'stop', 'reboot', 'destroy', 'resize',
               'rename', 'undefine', 'suspend', 'resume')

    if action not in actions:
        raise BadRequestError("Action '%s' should be "
                              "one of %s" % (action, actions)
                              )
    if action == 'destroy':
        methods.destroy_machine(auth_context.owner, cloud_id, machine_id)
    elif action in ('start', 'stop', 'reboot',
                    'undefine', 'suspend', 'resume'):
        getattr(machine.ctl, action)()
    elif action == 'rename':
        if not name:
            raise BadRequestError("You must give a name!")
        getattr(machine.ctl, action)(name)
    elif action == 'resize':
        getattr(machine.ctl, action)(plan_id)

    # TODO: We shouldn't return list_machines, just OK. Save the API!
    return mist.io.methods.filter_list_machines(auth_context, cloud_id)


@view_config(route_name='api_v1_machine_rdp', request_method='GET',
             renderer='json')
def machine_rdp(request):
    """
    Rdp file for windows machines
    Generate and return an rdp file for windows machines
    READ permission required on cloud.
    READ permission required on machine.
    ---
    cloud:
      in: path
      required: true
      type: string
    machine:
      in: path
      required: true
      type: string
    rdp_port:
      default: 3389
      in: query
      required: true
      type: integer
    host:
      in: query
      required: true
      type: string
    """
    cloud_id = request.matchdict['cloud']
    machine_id = request.matchdict['machine']
    auth_context = auth_context_from_request(request)
    auth_context.check_perm("cloud", "read", cloud_id)
    try:
        machine = Machine.objects.get(cloud=cloud_id, machine_id=machine_id)
        machine_uuid = machine.id
    except me.DoesNotExist:
        machine_uuid = ""
    auth_context.check_perm("machine", "read", machine_uuid)
    rdp_port = request.params.get('rdp_port', 3389)
    host = request.params.get('host')

    if not host:
        raise BadRequestError('no hostname specified')
    try:
        1 < int(rdp_port) < 65535
    except:
        rdp_port = 3389

    from mist.core.vpn.methods import destination_nat
    host, rdp_port = destination_nat(auth_context.owner, host, rdp_port)

    rdp_content = 'full address:s:%s:%s\nprompt for credentials:i:1' % \
                  (host, rdp_port)
    return Response(content_type='application/octet-stream',
                    content_disposition='attachment; filename="%s.rdp"' % host,
                    charset='utf8',
                    pragma='no-cache',
                    body=rdp_content)


# Views set_machine_tags and delete_machine_tags are defined in core.views
#
# @view_config(route_name='api_v1_machine_tags', request_method='POST',
#              renderer='json')
# @view_config(route_name='machine_tags', request_method='POST', renderer='json')
# def set_machine_tags(request):
#     """
#     Set tags on a machine
#     Set tags for a machine, given the cloud and machine id.
#     ---
#     cloud:
#       in: path
#       required: true
#       type: string
#     machine:
#       in: path
#       required: true
#       type: string
#     tags:
#       items:
#         type: object
#       type: array
#     """
#     cloud_id = request.matchdict['cloud']
#     machine_id = request.matchdict['machine']
#     try:
#         tags = request.json_body['tags']
#     except:
#         raise exceptions.BadRequestError('tags should be list of tags')
#     if type(tags) != list:
#         raise exceptions.BadRequestError('tags should be list of tags')
#
#     auth_context = auth_context_from_request(request)
#     cloud_tags = mist.core.methods.get_cloud_tags(auth_context.owner, cloud_id)
#     if not auth_context.has_perm("cloud", "read", cloud_id, cloud_tags):
#         raise UnauthorizedError()
#     machine_tags = mist.core.methods.get_machine_tags(auth_context.owner,
#                                                       cloud_id, machine_id)
#     try:
#         machine = Machine.objects.get(cloud=cloud_id, machine_id=machine_id)
#         machine_uuid = machine.id
#     except me.DoesNotExist:
#         machine_uuid = ""
#     if not auth_context.has_perm("machine", "edit_tags", machine_uuid,
#                                  machine_tags):
#         raise UnauthorizedError()
#
#     methods.set_machine_tags(auth_context.owner, cloud_id, machine_id, tags)
#     return OK
#
#
# @view_config(route_name='api_v1_machine_tag', request_method='DELETE',
#              renderer='json')
# @view_config(route_name='machine_tag', request_method='DELETE',
#              renderer='json')
# def delete_machine_tag(request):
#     """
#     Delete a tag
#     Delete tag in the db for specified resource_type
#     ---
#     tag:
#       in: path
#       required: true
#       type: string
#     cloud:
#       in: path
#       required: true
#       type: string
#     machine:
#       in: path
#       required: true
#       type: string
#     """
#
#     cloud_id = request.matchdict['cloud']
#     machine_id = request.matchdict['machine']
#     tag = request.matchdict['tag']
#     auth_context = auth_context_from_request(request)
#     cloud_tags = mist.core.methods.get_cloud_tags(auth_context.owner, cloud_id)
#     if not auth_context.has_perm("cloud", "read", cloud_id, cloud_tags):
#         raise UnauthorizedError()
#     machine_tags = mist.core.methods.get_machine_tags(auth_context.owner,
#                                                       cloud_id, machine_id)
#     try:
#         machine = Machine.objects.get(cloud=cloud_id, machine_id=machine_id)
#         machine_uuid = machine.id
#     except me.DoesNotExist:
#         machine_uuid = ""
#     if not auth_context.has_perm("machine", "edit_tags", machine_uuid,
#                                  machine_tags):
#         raise UnauthorizedError()
#     methods.delete_machine_tag(auth_context.owner, cloud_id, machine_id, tag)
#     return OK


@view_config(route_name='api_v1_images', request_method='POST', renderer='json')
def list_specific_images(request):
    # FIXME: 1) i shouldn't exist, 2) i shouldn't be a post
    return list_images(request)


@view_config(route_name='api_v1_images', request_method='GET', renderer='json')
def list_images(request):
    """
    List images of specified cloud
    List images from each cloud. Furthermore if a search_term is provided, we
    loop through each cloud and search for that term in the ids and the names
    of the community images
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
    try:
        term = request.json_body.get('search_term', '')
    except:
        term = None
    auth_context = auth_context_from_request(request)
    auth_context.check_perm("cloud", "read", cloud_id)
    return methods.list_images(auth_context.owner, cloud_id, term)


@view_config(route_name='api_v1_image', request_method='POST', renderer='json')
def star_image(request):
    """
    Star/unstar an image
    Toggle image star (star/unstar)
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
    return methods.star_image(auth_context.owner, cloud_id, image_id)


@view_config(route_name='api_v1_sizes', request_method='GET', renderer='json')
def list_sizes(request):
    """
    List sizes of a cloud
    List sizes (aka flavors) from each cloud.
    READ permission required on cloud.
    ---
    cloud:
      in: path
      required: true
      type: string
    """
    cloud_id = request.matchdict['cloud']
    auth_context = auth_context_from_request(request)
    auth_context.check_perm("cloud", "read", cloud_id)
    return methods.list_sizes(auth_context.owner, cloud_id)


@view_config(route_name='api_v1_locations', request_method='GET', renderer='json')
def list_locations(request):
    """
    List locations of cloud
    List locations from each cloud. Locations mean different things in each cl-
    oud. e.g. EC2 uses it as a datacenter in a given availability zone, where-
    as Linode lists availability zones. However all responses share id, name
    and country eventhough in some cases might be empty, e.g. Openstack. In E-
    C2 all locations by a provider have the same name, so the availability zo-
    nes are listed instead of name.
    READ permission required on cloud.
    ---
    cloud:
      in: path
      required: true
      type: string
    """
    cloud_id = request.matchdict['cloud']
    auth_context = auth_context_from_request(request)
    auth_context.check_perm("cloud", "read", cloud_id)
    return methods.list_locations(auth_context.owner, cloud_id)


@view_config(route_name='api_v1_networks', request_method='GET', renderer='json')
def list_networks(request):
    """
    List networks of a cloud
    List networks from each cloud.
    Currently NephoScale and Openstack networks
    are supported. For other providers this returns an empty list.
    READ permission required on cloud.
    ---
    cloud:
      in: path
      required: true
      type: string
    """
    cloud_id = request.matchdict['cloud']
    auth_context = auth_context_from_request(request)
    auth_context.check_perm("cloud", "read", cloud_id)
    return methods.list_networks(auth_context.owner, cloud_id)


@view_config(route_name='api_v1_networks', request_method='POST', renderer='json')
def create_network(request):
    """
    Create network on a cloud
    Creates a new network. If subnet dict is specified, after creating the net-
    work it will use the new network's id to create a subnet
    CREATE_RESOURCES permission required on cloud.
    ---
    cloud_id:
      in: path
      required: true
      description: The Cloud ID
      type: string
    network:
      required: true
      type: string
    router:
      type: string
    subnet:
      type: string
    """
    cloud_id = request.matchdict['cloud']

    try:
        network = request.json_body.get('network')
    except Exception as e:
        raise RequiredParameterMissingError(e)

    subnet = request.json_body.get('subnet', None)
    router = request.json_body.get('router', None)
    auth_context = auth_context_from_request(request)
    auth_context.check_perm("cloud", "create_resources", cloud_id)
    return methods.create_network(auth_context.owner, cloud_id,
                                  network, subnet, router)


@view_config(route_name='api_v1_network', request_method='DELETE')
def delete_network(request):
    """
    Delete a network
    Delete a network
    CREATE_RESOURCES permission required on cloud.
    ---
    cloud_id:
      in: path
      required: true
      type: string
    network:
      in: path
      required: true
      type: string
    """
    cloud_id = request.matchdict['cloud']
    network_id = request.matchdict['network']

    auth_context = auth_context_from_request(request)
    auth_context.check_perm("cloud", "create_resources", cloud_id)
    methods.delete_network(auth_context.owner, cloud_id, network_id)

    return OK


@view_config(route_name='api_v1_network', request_method='POST')
def associate_ip(request):
    """
    Associate ip
    Associate ip with the specific network and machine
    READ permission required on cloud.
    EDIT permission required on cloud.
    ---
    cloud:
      in: path
      required: true
      type: string
    network:
      in: path
      required: true
      type: string
    assign:
      default: true
      type: boolean
    ip:
      required: true
      type: string
    machine:
      required: true
      type: string
    """
    cloud_id = request.matchdict['cloud']
    network_id = request.matchdict['network']
    params = params_from_request(request)
    ip = params.get('ip')
    machine_id = params.get('machine')
    assign = params.get('assign', True)
    auth_context = auth_context_from_request(request)
    auth_context.check_perm("cloud", "read", cloud_id)
    try:
        machine = Machine.objects.get(cloud=cloud_id, machine_id=machine_id)
        machine_uuid = machine.id
    except me.DoesNotExist:
        machine_uuid = ""
    auth_context.check_perm("machine", "edit", machine_uuid)

    ret = methods.associate_ip(auth_context.owner, cloud_id, network_id,
                               ip, machine_id, assign)
    if ret:
        return OK
    else:
        return Response("Bad Request", 400)


@view_config(route_name='api_v1_probe', request_method='POST', renderer='json')
def probe(request):
    """
    Probe a machine
    Ping and SSH to machine and collect various metrics.
    READ permission required on cloud.
    READ permission required on machine.
    ---
    cloud:
      in: path
      required: true
      type: string
    machine:
      in: path
      required: true
      type: string
    host:
      type: string
    key:
      type: string
    ssh_user:
      default: ''
      description: ' Optional. Give if you explicitly want a specific user'
      in: query
      required: false
      type: string
    """
    machine_id = request.matchdict['machine']
    cloud_id = request.matchdict['cloud']
    params = params_from_request(request)
    host = params.get('host', None)
    key_id = params.get('key', None)
    ssh_user = params.get('ssh_user', '')
    # FIXME: simply don't pass a key parameter
    if key_id == 'undefined':
        key_id = ''
    auth_context = auth_context_from_request(request)
    auth_context.check_perm("cloud", "read", cloud_id)
    try:
        machine = Machine.objects.get(cloud=cloud_id, machine_id=machine_id)
        machine_uuid = machine.id
    except me.DoesNotExist:
        machine_uuid = ""
    auth_context.check_perm("machine", "read", machine_uuid)

    ret = methods.probe(auth_context.owner, cloud_id, machine_id, host, key_id,
                        ssh_user)
    amqp_publish_user(auth_context.owner, "probe",
                 {
                    'cloud_id': cloud_id,
                    'machine_id': machine_id,
                    'result': ret
                 })
    return ret


@view_config(route_name='api_v1_monitoring', request_method='GET', renderer='json')
def check_monitoring(request):
    """
    Check monitoring
    Ask the mist.io service if monitoring is enabled for this machine.
    ---
    """
    user = user_from_request(request)
    ret = methods.check_monitoring(user)
    return ret


@view_config(route_name='api_v1_update_monitoring', request_method='POST', renderer='json')
def update_monitoring(request):
    """
    Enable monitoring
    Enable monitoring for a machine.
    ---
    cloud:
      in: path
      required: true
      type: string
    machine:
      in: path
      required: true
      type: string
    action:
      enum:
      - enable
      - disable
      type: string
    dns_name:
      type: string
    dry:
      default: false
      type: boolean
    name:
      description: ' Name of the plugin'
      type: string
    no_ssh:
      default: false
      type: boolean
    public_ips:
      items:
        type: string
      type: array
    """
    user = user_from_request(request)
    cloud_id = request.matchdict['cloud']
    machine_id = request.matchdict['machine']
    params = params_from_request(request)
    if not user.mist_api_token:
        log.info("trying to authenticate to service first")
        email = params.get('email')
        password = params.get('password')
        if not email or not password:
            raise UnauthorizedError("You need to authenticate to mist.io.")
        payload = {'email': email, 'password': password}
        try:
            ret = requests.post(config.CORE_URI + '/auth', params=payload,
                                verify=config.SSL_VERIFY)
        except requests.exceptions.SSLError as exc:
            log.error("%r", exc)
            raise SSLError()
        if ret.status_code == 200:
            ret_dict = json.loads(ret.content)
            user.email = email
            user.mist_api_token = ret_dict.pop('token', '')
            user.save()
            log.info("succesfully check_authed")
        elif ret.status_code in [400, 401]:
            user.email = ""
            user.mist_api_token = ""
            user.save()
            raise UnauthorizedError("You need to authenticate to mist.io.")
        else:
            raise UnauthorizedError("You need to authenticate to mist.io.")

    action = params.get('action') or 'enable'
    name = params.get('name', '')
    public_ips = params.get('public_ips', [])  # TODO priv IPs?
    dns_name = params.get('dns_name', '')
    no_ssh = bool(params.get('no_ssh', False))
    dry = bool(params.get('dry', False))

    if action == 'enable':
        ret_dict = methods.enable_monitoring(
            user, cloud_id, machine_id, name, dns_name, public_ips,
            no_ssh=no_ssh, dry=dry
        )
    elif action == 'disable':
        methods.disable_monitoring(user, cloud_id, machine_id, no_ssh=no_ssh)
        ret_dict = {}
    else:
        raise BadRequestError()

    return ret_dict


@view_config(route_name='api_v1_stats', request_method='GET', renderer='json')
def get_stats(request):
    """
    Get monitor data for a machine
    Get all monitor data for this machine
    READ permission required on cloud.
    READ permission required on machine.
    ---
    cloud:
      in: path
      required: true
      type: string
    machine:
      in: path
      required: true
      type: string
    start:
      description: ' Time formatted as integer, from when to fetch stats (default now)'
      in: query
      required: false
      type: string
    stop:
      default: ''
      description: Time formatted as integer, until when to fetch stats (default +10 seconds)
      in: query
      required: false
      type: string
    step:
      default: ''
      description: ' Step to fetch stats (default 10 seconds)'
      in: query
      required: false
      type: string
    metrics:
      default: ''
      in: query
      required: false
      type: string
    request_id:
      default: ''
      in: query
      required: false
      type: string
    """
    cloud_id = request.matchdict['cloud']
    machine_id = request.matchdict['machine']

    auth_context = auth_context_from_request(request)
    auth_context.check_perm("cloud", "read", cloud_id)
    try:
        machine = Machine.objects.get(cloud=cloud_id, machine_id=machine_id)
        machine_uuid = machine.id
    except me.DoesNotExist:
        machine_uuid = ""
    auth_context.check_perm("machine", "read", machine_uuid)

    data = methods.get_stats(
        auth_context.owner,
        cloud_id,
        machine_id,
        request.params.get('start'),
        request.params.get('stop'),
        request.params.get('step'),
        request.params.get('metrics')
    )
    data['request_id'] = request.params.get('request_id')
    return data


@view_config(route_name='api_v1_metrics', request_method='GET', renderer='json')
def find_metrics(request):
    """
    Get metrics of a machine
    Get all metrics associated with specific machine
    READ permission required on cloud.
    READ permission required on machine.
    ---
    cloud:
      in: path
      required: true
      type: string
    machine:
      in: path
      required: true
      type: string
    """
    cloud_id = request.matchdict['cloud']
    machine_id = request.matchdict['machine']
    auth_context = auth_context_from_request(request)
    auth_context.check_perm("cloud", "read", cloud_id)
    try:
        machine = Machine.objects.get(cloud=cloud_id, machine_id=machine_id)
        machine_uuid = machine.id
    except me.DoesNotExist:
        machine_uuid = ""
    auth_context.check_perm("machine", "read", machine_uuid)
    return methods.find_metrics(auth_context.owner, cloud_id, machine_id)


@view_config(route_name='api_v1_metrics', request_method='PUT', renderer='json')
def assoc_metric(request):
    """
    Associate metric with machine
    Associate metric with specific machine
    READ permission required on cloud.
    EDIT_GRAPHS permission required on machine.
    ---
    cloud:
      in: path
      required: true
      type: string
    machine:
      in: path
      required: true
      type: string
    metric_id:
      description: ' Metric_id '
      type: string
    """
    cloud_id = request.matchdict['cloud']
    machine_id = request.matchdict['machine']
    params = params_from_request(request)
    metric_id = params.get('metric_id')
    if not metric_id:
        raise RequiredParameterMissingError('metric_id')
    auth_context = auth_context_from_request(request)
    auth_context.check_perm("cloud", "read", cloud_id)
    try:
        machine = Machine.objects.get(cloud=cloud_id, machine_id=machine_id)
        machine_uuid = machine.id
    except me.DoesNotExist:
        machine_uuid = ""
    auth_context.check_perm("machine", "edit_graphs", machine_uuid)
    methods.assoc_metric(auth_context.owner, cloud_id, machine_id, metric_id)
    return {}


@view_config(route_name='api_v1_metrics', request_method='DELETE', renderer='json')
def disassoc_metric(request):
    """
    Disassociate metric from machine
    Disassociate metric from specific machine
    READ permission required on cloud.
    EDIT_GRAPHS permission required on machine.
    ---
    cloud:
      in: path
      required: true
      type: string
    machine:
      in: path
      required: true
      type: string
    metric_id:
      description: ' Metric_id '
      type: string
    """
    cloud_id = request.matchdict['cloud']
    machine_id = request.matchdict['machine']
    params = params_from_request(request)
    metric_id = params.get('metric_id')
    if not metric_id:
        raise RequiredParameterMissingError('metric_id')
    auth_context = auth_context_from_request(request)
    auth_context.check_perm("cloud", "read", cloud_id)
    try:
        machine = Machine.objects.get(cloud=cloud_id, machine_id=machine_id)
        machine_uuid = machine.id
    except me.DoesNotExist:
        machine_uuid = ""
    auth_context.check_perm("machine", "edit_graphs", machine_uuid)
    methods.disassoc_metric(auth_context.owner, cloud_id, machine_id,
                            metric_id)
    return {}


@view_config(route_name='api_v1_metric', request_method='PUT', renderer='json')
def update_metric(request):
    """
    Update a metric configuration
    Update a metric configuration
    READ permission required on cloud.
    EDIT_CUSTOM_METRICS required on machine.
    ---
    metric:
      description: ' Metric_id (provided by self.get_stats() )'
      in: path
      required: true
      type: string
    cloud_id:
      required: true
      type: string
    host:
      type: string
    machine_id:
      required: true
      type: string
    name:
      description: Name of the plugin
      type: string
    plugin_type:
      type: string
    unit:
      description: ' Optional. If given the new plugin will be measured according to this
        unit'
      type: string
    """
    metric_id = request.matchdict['metric']
    params = params_from_request(request)
    machine_id = params.get('machine_id')
    cloud_id = params.get('cloud_id')
    auth_context = auth_context_from_request(request)
    auth_context.check_perm("cloud", "read", cloud_id)
    try:
        machine = Machine.objects.get(cloud=cloud_id, machine_id=machine_id)
        machine_uuid = machine.id
    except me.DoesNotExist:
        machine_uuid = ""
    auth_context.check_perm("machine", "edit_custom_metrics", machine_uuid)
    methods.update_metric(
        auth_context.owner,
        metric_id,
        name=params.get('name'),
        unit=params.get('unit'),
        cloud_id=cloud_id,
        machine_id=machine_id
    )
    return {}


@view_config(route_name='api_v1_deploy_plugin', request_method='POST', renderer='json')
def deploy_plugin(request):
    """
    Deploy a plugin on a machine.
    Deploy a plugin on the specific machine.
    READ permission required on cloud.
    EDIT_CUSTOM_METRICS required on machine.
    ---
    cloud:
      in: path
      required: true
      type: string
    machine:
      in: path
      required: true
      type: string
    plugin:
      in: path
      required: true
      type: string
    name:
      required: true
      type: string
    plugin_type:
      default: python
      enum:
      - python
      required: true
      type: string
    read_function:
      required: true
      type: string
    unit:
      type: string
    value_type:
      default: gauge
      type: string
    """
    cloud_id = request.matchdict['cloud']
    machine_id = request.matchdict['machine']
    plugin_id = request.matchdict['plugin']
    params = params_from_request(request)
    plugin_type = params.get('plugin_type')
    auth_context = auth_context_from_request(request)
    # SEC check permission READ on cloud
    auth_context.check_perm("cloud", "read", cloud_id)
    try:
        machine = Machine.objects.get(cloud=cloud_id, machine_id=machine_id)
    except me.DoesNotExist:
        raise NotFoundError("Machine %s doesn't exist" % machine_id)

    # SEC check permission EDIT_CUSTOM_METRICS on machine
    auth_context.check_perm("machine", "edit_custom_metrics", machine.id)

    try:
        Cloud.objects.get(owner=auth_context.owner, id=cloud_id)
    except me.DoesNotExist:
        raise NotFoundError('Cloud id %s does not exist' % cloud_id)

    if not machine.monitoring.hasmonitoring:
        raise NotFoundError("Machine doesn't seem to have monitoring enabled")

    # create a collectdScript
    extra = {'value_type': params.get('value_type', 'gauge'),
             'value_unit': ''}
    name = plugin_id
    kwargs = {'location_type': 'inline',
              'script': params.get('read_function'),
              'extra': extra}
    script = CollectdScript.add(auth_context.owner, name, **kwargs)

    if plugin_type == 'python':
        ret = script.ctl.deploy_python_plugin(machine)
        methods.update_metric(
            auth_context.owner,
            metric_id=ret['metric_id'],
            name=params.get('name'),
            unit=params.get('unit'),
            cloud_id=cloud_id,
            machine_id=machine_id,
        )
        return ret
    else:
        raise BadRequestError("Invalid plugin_type: '%s'" % plugin_type)


@view_config(route_name='api_v1_deploy_plugin',
             request_method='DELETE', renderer='json')
def undeploy_plugin(request):
    """
    Undeploy a plugin on a machine.
    Undeploy a plugin on the specific machine.
    READ permission required on cloud.
    EDIT_CUSTOM_METRICS required on machine.
    ---
    cloud:
      in: path
      required: true
      type: string
    machine:
      in: path
      required: true
      type: string
    plugin:
      in: path
      required: true
      type: string
    host:
      required: true
      type: string
    plugin_type:
      default: python
      enum:
      - python
      required: true
      type: string
    """
    cloud_id = request.matchdict['cloud']
    machine_id = request.matchdict['machine']
    plugin_id = request.matchdict['plugin']
    params = params_from_request(request)
    plugin_type = params.get('plugin_type')
    host = params.get('host')
    auth_context = auth_context_from_request(request)
    auth_context.check_perm("cloud", "read", cloud_id)
    try:
        machine = Machine.objects.get(cloud=cloud_id, machine_id=machine_id)
        machine_uuid = machine.id
    except me.DoesNotExist:
        machine_uuid = ""
    auth_context.check_perm("machine", "edit_custom_metrics", machine_uuid)
    if plugin_type == 'python':
        ret = methods.undeploy_python_plugin(auth_context.owner, cloud_id,
                                             machine_id, plugin_id, host)
        return ret
    else:
        raise BadRequestError("Invalid plugin_type: '%s'" % plugin_type)


# @view_config(route_name='metric', request_method='DELETE', renderer='json')
# def remove_metric(request):
    # user = user_from_request(request)
    # metric_id = request.matchdict['metric']
    # url = "%s/metrics/%s" % (config.CORE_URI, metric_id)
    # headers={'Authorization': get_auth_header(user)}
    # try:
        # resp = requests.delete(url, headers=headers,
        #                        verify=config.SSL_VERIFY)
    # except requests.exceptions.SSLError as exc:
        # raise SSLError()
    # except Exception as exc:
        # log.error("Exception removing metric: %r", exc)
        # raise exceptions.ServiceUnavailableError()
    # if not resp.ok:
        # log.error("Error removing metric %d:%s", resp.status_code, resp.text)
        # raise exceptions.BadRequestError(resp.text)
    # return resp.json()


@view_config(route_name='api_v1_rules', request_method='POST', renderer='json')
def update_rule(request):
    """
    Creates or updates a rule.
    ---
    """
    user = user_from_request(request)
    params = params_from_request(request)
    try:
        ret = requests.post(
            config.CORE_URI + request.path,
            params=params,
            headers={'Authorization': get_auth_header(user)},
            verify=config.SSL_VERIFY
        )
    except requests.exceptions.SSLError as exc:
        log.error("%r", exc)
        raise SSLError()
    if ret.status_code != 200:
        log.error("Error updating rule %d:%s", ret.status_code, ret.text)
        raise ServiceUnavailableError()
    trigger_session_update(user, ['monitoring'])
    return ret.json()


@view_config(route_name='api_v1_rule', request_method='DELETE')
def delete_rule(request):
    """
    Delete rule
    Deletes a rule.
    ---
    rule:
      description: ' Rule id '
      in: path
      required: true
      type: string
    """
    user = user_from_request(request)
    try:
        ret = requests.delete(
            config.CORE_URI + request.path,
            headers={'Authorization': get_auth_header(user)},
            verify=config.SSL_VERIFY
        )
    except requests.exceptions.SSLError as exc:
        log.error("%r", exc)
        raise SSLError()
    if ret.status_code != 200:
        log.error("Error deleting rule %d:%s", ret.status_code, ret.text)
        raise ServiceUnavailableError()
    trigger_session_update(user, ['monitoring'])
    return OK


@view_config(route_name='api_v1_providers', request_method='GET', renderer='json')
def list_supported_providers(request):
    """
    List supported providers
    Return all of our SUPPORTED PROVIDERS
    ---
    api_version:
      enum:
      - 1
      - 2
      in: header
      type: integer
    """
    api_version = request.headers.get('Api-Version', 1)
    if int(api_version) == 2:
        return {'supported_providers': config.SUPPORTED_PROVIDERS_V_2}
    else:
        return {'supported_providers': config.SUPPORTED_PROVIDERS}


# SEC
@view_config(route_name='api_v1_scripts', request_method='GET',
             renderer='json')
#@view_config(route_name='scripts', request_method='GET', renderer='json')
def list_scripts(request):
    """
    List user scripts
    READ permission required on each script.
    ---
    """
    auth_context = auth_context_from_request(request)
    scripts_list = mist.io.methods.filter_list_scripts(auth_context)
    return scripts_list


# SEC
@view_config(route_name='api_v1_scripts', request_method='POST',
             renderer='json')
#@view_config(route_name='scripts', request_method='POST', renderer='json')
def add_script(request):
    """
    Add script to user scripts
    ADD permission required on SCRIPT
    ---
    name:
      type: string
      required: true
    script:
      type: string
      required: false
    script_inline:
      type: string
      required: false
    script_github:
      type: string
      required: false
    script_url:
      type: string
      required: false
    location_type:
      type: string
      required: true
    entrypoint:
      type: string
    exec_type:
      type: string
      required: true
    description:
      type: string
    extra:
      type: dict
    """

    params = params_from_request(request)

    # SEC
    auth_context = auth_context_from_request(request)
    script_tags = auth_context.check_perm("script", "add", None)

    kwargs = {}

    for key in ('name', 'script', 'location_type', 'entrypoint', 'exec_type',
                'description', 'extra','script_inline', 'script_url',
                'script_github'):
        kwargs[key] = params.get(key)   # TODO maybe change this

    kwargs['script'] = choose_script_from_params(kwargs['location_type'],
                                                 kwargs['script'],
                                                 kwargs['script_inline'],
                                                 kwargs['script_url'],
                                                 kwargs['script_github'])
    for key in ('script_inline', 'script_url', 'script_github'):
        kwargs.pop(key)

    name = kwargs.pop('name')
    exec_type = kwargs.pop('exec_type')

    if exec_type == 'executable':
        script = ExecutableScript.add(auth_context.owner, name, **kwargs)
    elif exec_type == 'ansible':
        script = AnsibleScript.add(auth_context.owner, name, **kwargs)
    elif exec_type == 'collectd_python_plugin':
        script = CollectdScript.add(auth_context.owner, name, **kwargs)
    else:
        raise BadRequestError(
            "Param 'exec_type' must be in ('executable', 'ansible', "
            "'collectd_python_plugin')."
        )

    if script_tags:
        add_tags_to_resource(auth_context.owner, script, script_tags.items())

    script = script.as_dict_old()

    if 'job_id' in params:
        script['job_id'] = params['job_id']

    return script


# TODO this isn't nice
def choose_script_from_params(location_type, script,
                              script_inline, script_url,
                              script_github):
    if script != '' and script != None:
        return script

    if location_type == 'github':
        return script_github
    elif location_type == 'url':
        return script_url
    else:
        return script_inline


# SEC
@view_config(route_name='api_v1_script', request_method='GET', renderer='json')
#@view_config(route_name='script', request_method='GET', renderer='json')
def show_script(request):
    """
    Show script details and job history.
    READ permission required on script.
    ---
    script_id:
      type: string
      required: true
      in: path
    """
    script_id = request.matchdict['script_id']
    auth_context = auth_context_from_request(request)

    if not script_id:
        raise RequiredParameterMissingError('No script id provided')

    try:
        script = Script.objects.get(owner=auth_context.owner,
                                    id=script_id, deleted=None)
    except me.DoesNotExist:
        raise NotFoundError('Script id not found')

    # SEC require READ permission on SCRIPT
    auth_context.check_perm('script', 'read', script_id)

    ret_dict = script.as_dict_old()
    jobs = get_stories('job', auth_context.owner.id, script_id=script_id)
    ret_dict['jobs'] = [job['job_id'] for job in jobs]
    return ret_dict


@view_config(route_name='api_v1_script_file', request_method='GET',
             renderer='json')
def download_script(request):
    """
    Download script file or archive.
    READ permission required on script.
    ---
    script_id:
      type: string
      required: true
      in: path
    """
    script_id = request.matchdict['script_id']
    auth_context = auth_context_from_request(request)

    if not script_id:
        raise RequiredParameterMissingError('No script id provided')

    try:
        script = Script.objects.get(owner=auth_context.owner,
                                    id=script_id, deleted=None)
    except me.DoesNotExist:
        raise NotFoundError('Script id not found')

    # SEC require READ permission on SCRIPT
    auth_context.check_perm('script', 'read', script_id)
    try:
        return script.ctl.get_file()
    except BadRequestError():
        return Response("Unable to find: {}".format(request.path_info))


# SEC
@view_config(route_name='api_v1_script', request_method='DELETE', renderer='json')
#@view_config(route_name='script', request_method='DELETE', renderer='json')
def delete_script(request):
    """
    Delete script
    REMOVE permission required on script.
    ---
    script_id:
      in: path
      required: true
      type: string
    """
    script_id = request.matchdict['script_id']
    auth_context = auth_context_from_request(request)

    if not script_id:
        raise RequiredParameterMissingError('No script id provided')

    try:
        script = Script.objects.get(owner=auth_context.owner,
                                    id=script_id, deleted=None)
    except me.DoesNotExist:
        raise NotFoundError('Script id not found')

    # SEC require REMOVE permission on script
    auth_context.check_perm('script', 'remove', script_id)

    script.ctl.delete()
    return OK


# SEC
@view_config(route_name='api_v1_scripts',
             request_method='DELETE', renderer='json')
#@view_config(route_name='scripts', request_method='DELETE', renderer='json')
def delete_scripts(request):
    """
    Delete multiple scripts.
    Provide a list of script ids to be deleted. The method will try to delete
    all of them and then return a json that describes for each script id
    whether or not it was deleted or the not_found if the script id could not
    be located. If no script id was found then a 404(Not Found) response will
    be returned.
    REMOVE permission required on each script.
    ---
    script_ids:
      required: true
      type: array
      items:
        type: string
        name: script_id
    """
    auth_context = auth_context_from_request(request)
    params = params_from_request(request)
    script_ids = params.get('script_ids', [])
    if type(script_ids) != list or len(script_ids) == 0:
        raise RequiredParameterMissingError('No script ids provided')

    # remove duplicate ids if there are any
    script_ids = sorted(script_ids)
    i = 1
    while i < len(script_ids):
        if script_ids[i] == script_ids[i - 1]:
            script_ids = script_ids[:i] + script_ids[i + 1:]
        else:
            i += 1

    report = {}
    for script_id in script_ids:
        try:
            script = Script.objects.get(owner=auth_context.owner,
                                        id=script_id, deleted=None)
        except me.DoesNotExist:
            report[script_id] = 'not_found'
            continue
        # SEC require REMOVE permission on script
        try:
            auth_context.check_perm('script', 'remove', script_id)
        except PolicyUnauthorizedError:
            report[script_id] = 'unauthorized'
        else:
            script.ctl.delete()
            report[script_id] = 'deleted'
        # /SEC

    # if no script id was valid raise exception
    if len(filter(lambda script_id: report[script_id] == 'not_found',
                  report)) == len(script_ids):
        raise NotFoundError('No valid script id provided')
    # if user was not authorized for any script raise exception
    if len(filter(lambda script_id: report[script_id] == 'unauthorized',
                  report)) == len(script_ids):
        raise UnauthorizedError("You don't have authorization for any of these"
                                " scripts")
    return report


# SEC
@view_config(route_name='api_v1_script', request_method='PUT', renderer='json')
#@view_config(route_name='script', request_method='PUT', renderer='json')
def edit_script(request):
    """
    Edit script (rename only as for now)
    EDIT permission required on script.
    ---
    script_id:
      in: path
      required: true
      type: string
    new_name:
      type: string
      required: true
    new_description:
      type: string
    """
    script_id = request.matchdict['script_id']
    params = params_from_request(request)
    new_name = params.get('new_name')
    new_description = params.get('new_description')

    auth_context = auth_context_from_request(request)
    # SEC require EDIT permission on script
    auth_context.check_perm('script', 'edit', script_id)
    try:
        script = Script.objects.get(owner=auth_context.owner,
                                    id=script_id, deleted=None)
    except me.DoesNotExist:
        raise NotFoundError('Script id not found')

    if not new_name:
        raise RequiredParameterMissingError('No new name provided')

    script.ctl.edit(new_name, new_description)
    ret = {'new_name': new_name}
    if isinstance(new_description, basestring):
        ret['new_description'] = new_description
    return ret


# SEC
@view_config(route_name='api_v1_script', request_method='POST', renderer='json')
#@view_config(route_name='script', request_method='POST', renderer='json')
def run_script(request):
    """
    Start a script job to run the script.
    READ permission required on cloud.
    RUN_SCRIPT permission required on machine.
    RUN permission required on script.
    ---
    script_id:
      in: path
      required: true
      type: string
    cloud_id:
      required: true
      type: string
    machine_id:
      required: true
      type: string
    params:
      type: string
    su:
      type: boolean
    env:
      type: string
    job_id:
      type: string
    """
    script_id = request.matchdict['script_id']
    params = params_from_request(request)
    cloud_id = params['cloud_id']
    machine_id = params['machine_id']
    script_params = params.get('params', '')
    su = params.get('su', False)
    env = params.get('env')
    job_id = params.get('job_id')
    if isinstance(env, dict):
        env = json.dumps(env)
    for key in ('cloud_id', 'machine_id'):
        if key not in params:
            raise RequiredParameterMissingError(key)
    auth_context = auth_context_from_request(request)
    auth_context.check_perm("cloud", "read", cloud_id)
    try:
        machine = Machine.objects.get(cloud=cloud_id, machine_id=machine_id)
    except me.DoesNotExist:
        raise NotFoundError("Machine %s doesn't exist" % machine_id)

    # SEC require permission RUN_SCRIPT on machine
    auth_context.check_perm("machine", "run_script", machine.id)
    # SEC require permission RUN on script
    auth_context.check_perm('script', 'run', script_id)
    try:
        script = Script.objects.get(owner=auth_context.owner,
                                    id=script_id, deleted=None)
    except me.DoesNotExist:
        raise NotFoundError('Script id not found')
    job_id = job_id or uuid.uuid4().hex
    tasks.run_script.delay(auth_context.owner.id, script.id,
                           cloud_id, machine_id, params=script_params,
                           env=env, su=su, job_id=job_id)
    return {'job_id': job_id}


# SEC
@view_config(route_name='api_v1_schedules', request_method='POST',
             renderer='json')
def add_schedule_entry(request):
    """
    Add an entry to user schedules
    Add permission required on schedule.
    READ permission required on cloud.
    RUN_SCRIPT permission required on machine.
    RUN permission required on script.
    ---
    script_id:
      type: string
    action:
      type: string
    machines_uuids:
      required: true
      type: array
      description: list of machines_uuids
    machines_tags:
      required: true
      type: array
      description: list of machines_tags
    name:
      required:true
      type:string
      description: schedule name
    task_enabled:
      type: boolean
      description: schedule is ready to run
    run_immediately:
      type: boolean
      description: run immediately only  the first time
    expires:
      type: string
      description: expiration date
    description:
      type: string
      description: describe schedule
    schedule_type:
      type: string
      description: three different types, interval, crontab, one_off
    schedule_entry:
      type: object
      description: period of time
    params:
      type: string
    """
    params = params_from_request(request)

    # SEC
    auth_context = auth_context_from_request(request)
    # SEC require ADD permission on schedule
    schedule_tags = auth_context.check_perm("schedule", "add", None)

    name = params.pop('name')

    schedule = Schedule.add(auth_context, name, **params)

    if schedule_tags:
        resolve_id_and_set_tags(auth_context.owner, 'schedule', schedule.id,
                                schedule_tags.items())
    trigger_session_update(auth_context.owner, ['schedules'])
    return schedule.as_dict()


@view_config(route_name='api_v1_schedules', request_method='GET',
             renderer='json')
def list_schedules_entries(request):
    """
    List user schedules entries, order by _id
    READ permission required on schedules
    ---
    """

    auth_context = auth_context_from_request(request)

    # SEC
    schedules_list = mist.io.methods.filter_list_schedules(auth_context)

    return [schedule for schedule in schedules_list]


# SEC
@view_config(route_name='api_v1_schedule', request_method='GET',
             renderer='json')
def show_schedule_entry(request):
    """
    Show a schedule details of a user
    READ permission required on schedule
    ---
    schedule_id:
      type: string
    """
    schedule_id = request.matchdict['schedule_id']
    auth_context = auth_context_from_request(request)

    if not schedule_id:
        raise RequiredParameterMissingError('No schedule id provided')

    try:
        schedule = Schedule.objects.get(id=schedule_id, deleted=None,
                                        owner=auth_context.owner)
    except Schedule.DoesNotExist:
        raise ScheduleTaskNotFound()

    # SEC require READ permission on schedule
    auth_context.check_perm('schedule', 'read', schedule_id)

    return schedule.as_dict()


@view_config(route_name='api_v1_schedule', request_method='DELETE',
             renderer='json')
def delete_schedule(request):
    """
    Delete a schedule entry of a user
    REMOVE permission required on schedule
    ---
    schedule_id:
      type: string
    """
    schedule_id = request.matchdict['schedule_id']
    auth_context = auth_context_from_request(request)

    if not schedule_id:
        raise RequiredParameterMissingError('No schedule id provided')

    # Check if entry exists
    try:
        schedule = Schedule.objects.get(id=schedule_id, deleted=None)
    except Schedule.DoesNotExist:
        raise ScheduleTaskNotFound()

    # SEC
    auth_context.check_perm('schedule', 'remove', schedule_id)

    # NOTE: Do not perform an atomic operation when marking a schedule as
    # deleted, since we do not wish to bypass pre-save validation/cleaning.
    schedule.deleted = datetime.utcnow()
    schedule.save()

    trigger_session_update(auth_context.owner, ['schedules'])
    return OK


# SEC
@view_config(route_name='api_v1_schedule',
             request_method='PATCH', renderer='json')
def edit_schedule_entry(request):
    """
    Edit a schedule entry
    EDIT permission required on schedule
    READ permission required on cloud.
    RUN_SCRIPT permission required on machine.
    RUN permission required on script.

    ---
    script_id:
      type: string
    action:
      type: string
     machines_uuids:
      required: true
      type: array
      description: list of machines_uuids
    machines_tags:
      required: true
      type: array
      description: list of machines_tags
    name:
      required:true
      type:string
      description: schedule name
    enabled:
      type: boolean
      description: schedule is ready to run
    run_immediately:
      type: boolean
      description: run immediately only  the first time
    expires:
      type: string
      description: expiration date
    description:
      type: string
      description: describe schedule
    schedule_type:
      type: string
      description: three different types, interval, crontab, one_off
    schedule_entry:
      type: object
      description: period of time
    schedule_id:
      type: string
    params:
      type: string
    """

    auth_context = auth_context_from_request(request)
    params = params_from_request(request)
    schedule_id = request.matchdict['schedule_id']

    if not schedule_id:
        raise RequiredParameterMissingError('No schedule id provided')

    # SEC require EDIT permission on schedule
    auth_context.check_perm('schedule', 'edit', schedule_id)

    owner = auth_context.owner
    # Check if entry exists
    try:
        schedule = Schedule.objects.get(id=schedule_id, owner=owner,
                                        deleted=None)
    except Schedule.DoesNotExist:
        raise ScheduleTaskNotFound()

    schedule.ctl.set_auth_context(auth_context)
    schedule.ctl.update(**params)

    trigger_session_update(auth_context.owner, ['schedules'])
    return schedule.as_dict()


#  TODO jobs, story, logs
@view_config(route_name='api_v1_tokens', request_method='GET', renderer='json')
def list_tokens(request):
    """
    List user's api tokens
    ---
    """
    # FIXME: should call an optimized methods.list_tokens
    auth_context = auth_context_from_request(request)
    api_tokens = ApiToken.objects(user_id=auth_context.user.id, revoked=False)
    tokens_list = []
    for token in api_tokens:
        if token.is_valid():
            token_view = token.get_public_view()
            if token_view['last_accessed_at'] == 'None':
                token_view['last_accessed_at'] = 'Never'
            tokens_list.append(token_view)

    # If user is owner also include all active tokens in the current org context
    if auth_context.is_owner():
        org_tokens = ApiToken.objects(org=auth_context.org, revoked=False)
        for token in org_tokens:
            if token.is_valid():
                token_view = token.get_public_view()
                if token_view['last_accessed_at'] == 'None':
                    token_view['last_accessed_at'] = 'Never'
                try:
                    tokens_list.index(token_view)
                except ValueError:
                    tokens_list.append(token_view)
    return tokens_list


@view_config(route_name='api_v1_tokens', request_method='POST', renderer='json')
def create_token(request):
    """
    Create a new api token
    Used so that a user can send his credentials and produce a new api token.
    They api token itself will be returned in a json document along with it's
    id and it's name.
    If user has used su then he should provide his own credentials however the
    api token will authenticate the user that he is impersonating.
    User can also send as parameters the name and the ttl.
    If name is not sent then a random one with the format api_token_xyz where
    xyz is a number will be produced.
    If the user provides a name then there must be no other token for that user
    with the same name.
    If the user has a cookie or sends an api token in the request headers then
    the username and password must belong to him.
    Used by io to authenticate to core (when running separately. Io sends
    user's email and password. We return an access token that will be used to
    authenticate any further communications.
    An anti-CSRF token is not needed to access this api call.
    If user is coming from oauth then he will be able to create a new token
    without a password provided he is authenticated somehow.
    If you are using the /auth route please switch to /api_v1_tokens route. The
    /auth route is deprecated and will be removed completely in the future.
    ---
    email:
      description: User's email
      required: true
      type: string
    password:
      description: User's password
      required: true
      type: string
    name:
      description: Api token name
      type: string
    ttl:
      description: Time to live for the token
      type: integer
    org_id:
      description: Org id if this token is to be used in organizational context
      type: string
    """

    # requesting user is the user that POSTed the function and he is the one
    # that must provide his credentials. If the user has used
    # su then requesting_user is the effective user.
    session = request.environ['session']
    requesting_user = session.get_user(effective=True)

    params = params_from_request(request)
    email = params.get('email', '').lower()
    password = params.get('password', '')
    api_token_name = params.get('name', '')
    org_id = params.get('org_id', '')
    ttl = params.get('ttl', 60 * 60)
    if not email:
        raise RequiredParameterMissingError("No email provided")
    if (isinstance(ttl, str) or isinstance(ttl, unicode)) and not ttl.isdigit():
        raise BadRequestError('Ttl must be a number greater than 0')
    if int(ttl) < 0:
        raise BadRequestError('Ttl must be greater or equal to zero')

    # concerned user is the user by whom the api token will be used.
    if requesting_user is not None:
        concerned_user = session.get_user(effective=False)
    else:
        try:
            requesting_user = concerned_user = User.objects.get(email=email)
        except me.DoesNotExist:
            raise UserUnauthorizedError(email)

    if requesting_user.status != 'confirmed' \
            or concerned_user.status != 'confirmed':
        raise UserUnauthorizedError()

    if requesting_user.password is None or requesting_user.password == '':
        if password:
            raise BadRequestError('Wrong password')
        else:
            raise BadRequestError('Please use the GUI to set a password and '
                                  'then retry')
    else:
        if not password:
            raise BadRequestError('No password provided')
        if not requesting_user.check_password(password):
            raise BadRequestError('Wrong password')

    org = None
    if org_id:
        try:
            org = Organization.objects.get(me.Q(id=org_id) | me.Q(name=org_id))
        except me.DoesNotExist:
            raise BadRequestError("Invalid org id '%s'" % org_id)
        if concerned_user not in org.members:
            raise ForbiddenError()

    # first check if the api token name is unique if it has been provided
    # otherwise produce a new one.
    if api_token_name:
        token_with_name_not_exists(concerned_user, api_token_name)
        session.name = api_token_name
    else:
        api_token_name = get_random_name_for_token(concerned_user)
    api_tokens = ApiToken.objects(user_id=concerned_user.id, revoked=False)
    tokens_list = []
    for token in api_tokens:
        if token.is_valid():
            token_view = token.get_public_view()
            if token_view['last_accessed_at'] == 'None':
                token_view['last_accessed_at'] = 'Never'
            tokens_list.append(token_view)

    # FIXME: should call an optimized methods.list_tokens(active=True)
    if len(tokens_list) < config.ACTIVE_APITOKEN_NUM:
        new_api_token = ApiToken()
        new_api_token.name = api_token_name
        new_api_token.org = org
        new_api_token.ttl = ttl
        new_api_token.set_user(concerned_user)
        new_api_token.ip_address = ip_from_request(request)
        new_api_token.user_agent = request.user_agent
        new_api_token.save()
    else:
        raise BadRequestError("MAX number of %s active tokens reached"
                              % config.ACTIVE_APITOKEN_NUM)

    token_view = new_api_token.get_public_view()
    token_view['last_accessed_at'] = 'Never'
    token_view['token'] = new_api_token.token

    return token_view


@view_config(route_name='api_v1_ping', request_method=('GET', 'POST'), renderer='json')
def ping(request):
    """
    Check that an api token is correct.
    ---
    """
    user = user_from_request(request)
    if isinstance(session_from_request(request), SessionToken):
        raise BadRequestError('This call is for users with api tokens')
    return {'hello': user.email}


@view_config(route_name='api_v1_sessions', request_method='GET', renderer='json')
def list_sessions(request):
    """
    List active sessions
    ---
    """
    auth_context = auth_context_from_request(request)
    session = request.environ['session']
    # Get active sessions for the current user
    session_tokens = SessionToken.objects(user_id=auth_context.user.id, revoked=False)
    sessions_list = []
    for token in session_tokens:
        if token.is_valid():
            public_view = token.get_public_view()
            if isinstance(session, SessionToken) and session.id == token.id:
                public_view['active'] = True
            sessions_list.append(public_view)

    # If user is owner include all active sessions in the org context
    if auth_context.is_owner():
        org_tokens = SessionToken.objects(org=auth_context.org, revoked=False)
        for token in org_tokens:
            if token.is_valid():
                public_view = token.get_public_view()
                if isinstance(session, SessionToken) and session.id == token.id:
                    public_view['active'] = True
                try:
                    sessions_list.index(public_view)
                except ValueError:
                    sessions_list.append(public_view)

    return sessions_list


# SEC FIXME add permission checks
@view_config(route_name='api_v1_tokens', request_method='DELETE')
def revoke_token(request):
    """
    Revoke api token
    ---
    id:
      description: Api token ID
    """
    return revoke_session(request)


# SEC do we need permission checks here ?
@view_config(route_name='api_v1_sessions', request_method='DELETE')
def revoke_session(request):
    """
    Revoke an active session
    ---
    id:
      description: Session ID
    """

    auth_context = auth_context_from_request(request)
    params = params_from_request(request)
    auth_token_id = params.get("id")

    if not auth_token_id:
        raise RequiredParameterMissingError("No token id parameter provided")

    try:
        if auth_context.is_owner():
            auth_token = AuthToken.objects.get(org=auth_context.org,
                                               id=auth_token_id)
        else:
            auth_token = AuthToken.objects.get(user_id=
                                               auth_context.user.get_id(),
                                               id=auth_token_id)
        if auth_token.is_valid():
            auth_token.invalidate()
            auth_token.save()

    except me.DoesNotExist:
        raise NotFoundError('Session not found')

    return OK


@view_config(route_name='api_v1_orgs', request_method='GET', renderer='json')
def list_user_organizations(request):
    """
    List user's organizations
    List all the organizations where user is a member
    """
    try:
        user = user_from_request(request)
    except me.DoesNotExist:
        raise UnauthorizedError()
    return [{'id': org.id, 'name': org.name}
            for org in Organization.objects(members=user)]


# SEC
@view_config(route_name='api_v1_org', request_method='POST', renderer='json')
def create_organization(request):
    """
    Create organization.
    The user creating it will be assigned to the
    owners team. For now owner has only org
    ---
    name:
      description: The new org  name (id)
      type: string
      required: true
    """

    auth_context = auth_context_from_request(request)

    user = auth_context.user
    # SEC
    if not user.can_create_org:
        raise OrganizationAuthorizationFailure('Unauthorized to '
                                               'create organization')
    params = params_from_request(request)

    name = params.get('name')
    # description = params.get('description')

    if not name:
        raise RequiredParameterMissingError()
    if Organization.objects(name=name):
        raise OrganizationNameExistsError()

    org = Organization()
    org.add_member_to_team('Owners', user)
    org.name = name

    try:
        org.save()
    except me.ValidationError as e:
        raise BadRequestError({"msg": e.message, "errors": e.to_dict()})
    except me.OperationError:
        raise OrganizationOperationError()

    trigger_session_update(auth_context.user, ['user'])
    return org.as_dict()


@view_config(route_name='api_v1_org', request_method='GET', renderer='json')
def show_user_organization(request):
    """
    Show user's organization.
    If user is organization owner then show everything
    If user is just a member then show just himself as a team member and the
    name of the organization, the name of the team,
    """
    auth_context = auth_context_from_request(request)
    org_dict = {}
    if auth_context.org:
        org_dict = auth_context.org.as_dict()
        if not auth_context.is_owner():
            # remove all the teams the user is not a member of
            i = 0
            while i < len(org_dict['teams']):
                if auth_context.user.id not in org_dict['teams'][i]['members']:
                    org_dict["teams"].pop(i)
                else:
                    # user is a member of the team. remove the other members
                    org_dict['teams'][i]['members'] = [auth_context.user.id]
                    i += 1
        org_dict['is_owner'] = auth_context.is_owner()
    return org_dict


@view_config(route_name='user_invitations', request_method='GET',
             renderer='json')
def show_user_pending_invitations(request):
    """
    Show user's pending invitations.
    Returns a list of dicts with all of user's pending invitations
    """
    auth_context = auth_context_from_request(request)
    user_invitations = MemberInvitation.objects(user=auth_context.user)
    invitations = []
    for invitation in user_invitations:
        invitation_view = {}
        try:
            org = invitation.org
            invitation_view['org'] = org.name
            invitation_view['org_id'] = org.id
            invitation_view['token'] = invitation.token
            invitation_view['teams'] = []
            for team_id in invitation.teams:
                try:
                    team = org.get_team_by_id(team_id)
                    invitation_view['teams'].append({
                        'id': team.id,
                        'name': team.name
                    })
                except:
                    pass
            invitations.append(invitation_view)
        except:
            pass

    return invitations


@view_config(route_name='api_v1_org_info', request_method='GET', renderer='json')
def show_organization(request):
    """
    Show organization.
    Details of org.
    ---
    org_id:
      description: The org id
      required: true
      type: string
    """
    # TODO NEXT ITERATION
    raise ForbiddenError("The proper request is /org")
    auth_context = auth_context_from_request(request)

    org_id = request.matchdict['org_id']

    if not (auth_context.org and auth_context.is_owner()
            and auth_context.org.id == org_id):
        raise OrganizationAuthorizationFailure()

    return auth_context.org.as_dict()


@view_config(route_name='api_v1_org_info', request_method='PUT', renderer='json')
def edit_organization(request):
    """
        Edit an organization entry in the db
        Means rename.
        Only available to organization owners.
        ---
        org_id:
          description: The org's org id
          type: string
          required: true
        name:
          description: The team's name
          type:string
        """
    auth_context = auth_context_from_request(request)
    org_id = request.matchdict['org_id']
    params = params_from_request(request)
    name = params.get('new_name')
    alerts_email = params.get('alerts_email')

    if alerts_email and auth_context.is_owner():
        mist.core.methods.update_monitoring_options(auth_context.owner,
                                                    alerts_email)
    elif not name:
        raise RequiredParameterMissingError()

    # SEC check if owner
    if not (auth_context.org and auth_context.is_owner() and
                    auth_context.org.id == org_id):
        raise OrganizationAuthorizationFailure()

    if Organization.objects(name=name) and auth_context.org.name != name:
        raise OrganizationNameExistsError()

    auth_context.org.name = name

    try:
        auth_context.org.save()
    except me.ValidationError as e:
        raise BadRequestError({"msg": e.message, "errors": e.to_dict()})
    except me.OperationError:
        raise OrganizationOperationError()

    log.info("Editing org with name '%s'.", name)
    trigger_session_update(auth_context.owner, ['org'])

    if config.NEW_UI_EXPERIMENT_ENABLE:
        session = session_from_request(request)
        experiment = experiments.NewUIExperiment(userid=session.user_id)
        experiment.log_event('edit_org', {'title': name})

    return auth_context.org.as_dict()


# SEC
@view_config(route_name='api_v1_teams', request_method='POST', renderer='json')
def add_team(request):
    """
    Create new team.
    Append it at org's teams list.
    Only available to organization owners.
    ---
    name:
      description: The new team name
      type: string
      required: true
    description:
      description: The new team description
      type: string
    """

    log.info("Adding team")

    auth_context = auth_context_from_request(request)
    org_id = request.matchdict['org_id']

    params = params_from_request(request)
    name = params.get('name')
    description = params.get('description', '')
    visibility = params.get('visible', True)

    if not name:
        raise RequiredParameterMissingError()

    # SEC check if owner
    if not (auth_context.org and auth_context.is_owner()
            and auth_context.org.id == org_id):
        raise OrganizationAuthorizationFailure()

    team = Team()
    team.name = name
    team.description = description
    team.visible = visibility
    team.init_mappings()
    auth_context.org.teams.append(team)

    try:
        auth_context.org.save()
    except me.ValidationError as e:
        raise BadRequestError({"msg": e.message, "errors": e.to_dict()})
    except me.OperationError:
        raise TeamOperationError()

    log.info("Adding team with name '%s'.", name)
    trigger_session_update(auth_context.owner, ['org'])

    return team.as_dict()


# SEC
@view_config(route_name='api_v1_team', request_method='GET', renderer='json')
def show_team(request):
    """
    Show team.
    Only available to organization owners.
    ---
    org_id:
      description: The team's org id
      type: string
      required: true
    team_id:
      description: The team's id
      type: string
    """

    auth_context = auth_context_from_request(request)
    org_id = request.matchdict['org_id']
    team_id = request.matchdict['team_id']

    # SEC check if owner
    if not (auth_context.org and auth_context.is_owner()
            and auth_context.org.id == org_id):
        raise OrganizationAuthorizationFailure()

    # Check if team entry exists
    try:
        team = auth_context.org.get_team_by_id(team_id)
    except me.DoesNotExist:
        raise TeamNotFound()

    return team.as_dict()


# SEC
@view_config(route_name='api_v1_teams', request_method='GET', renderer='json')
def list_teams(request):
    """
    List teams of an org.
    Only available to organization owners.
    ---
    org_id:
      description: The teams' org id
      type: string
      required: true
    """

    auth_context = auth_context_from_request(request)
    org_id = request.matchdict['org_id']

    # SEC check if owner
    if not (auth_context.org and auth_context.is_owner()
            and auth_context.org.id == org_id):
        raise OrganizationAuthorizationFailure()

    return [team.as_dict() for team in auth_context.org.teams]


# SEC
@view_config(route_name='api_v1_team', request_method='PUT', renderer='json')
def edit_team(request):
    """
    Edit a team entry in the db
    Means rename.
    Only available to organization owners.
    ---
    org_id:
      description: The org's org id
      type: string
      required: true
    team_id:
      description: The team's id
      type: string
      required: true
    name:
      description: The team's name
      type:string
    description:
      description: the teams's description
    """

    auth_context = auth_context_from_request(request)
    org_id = request.matchdict['org_id']
    team_id = request.matchdict['team_id']

    params = params_from_request(request)
    name = params.get('new_name')
    description = params.get('new_description', '')
    visibility = params.get('new_visible')

    if not name:
        raise RequiredParameterMissingError()

    # SEC check if owner
    if not (auth_context.org and auth_context.is_owner() and
            auth_context.org.id == org_id):
        raise OrganizationAuthorizationFailure()

    # Check if team entry exists
    try:
        team = auth_context.org.get_team_by_id(team_id)
    except me.DoesNotExist:
        raise TeamNotFound()

    team.name = name
    team.description = description if description else ''
    if visibility is not None:
        team.visible = visibility

    try:
        auth_context.org.save()
    except me.ValidationError as e:
        raise BadRequestError({"msg": e.message, "errors": e.to_dict()})
    except me.OperationError:
        raise TeamOperationError()

    log.info("Editing team with name '%s'.", name)
    trigger_session_update(auth_context.owner, ['org'])

    return team.as_dict()


# SEC
@view_config(route_name='api_v1_team', request_method='DELETE', renderer='json')
def delete_team(request):
    """
    Delete a team entry in the db.
    Only available to organization owners.
    ---
    org_id:
      description: The team's org id
      type: string
      required: true
    team_id:
      description: The team's id
      type: string
      required: true
    """
    auth_context = auth_context_from_request(request)
    org_id = request.matchdict['org_id']
    team_id = request.matchdict['team_id']

    # SEC check if owner
    if not (auth_context.org and auth_context.is_owner() and
            auth_context.org.id == org_id):
        raise OrganizationAuthorizationFailure()

    if auth_context.org.get_team('Owners').id == team_id:
        raise ForbiddenError()

    try:
        team = auth_context.org.get_team_by_id(team_id)
    except me.DoesNotExist:
        raise NotFoundError()

    if team.members:
        raise BadRequestError(
            'Team not empty. Remove all members and try again')

    try:
        team.drop_mappings()
        auth_context.org.update(pull__teams__id=team_id)
    except me.ValidationError as e:
        raise BadRequestError({"msg": e.message, "errors": e.to_dict()})
    except me.OperationError:
        raise TeamOperationError()

    trigger_session_update(auth_context.owner, ['org'])

    return OK


# SEC
@view_config(route_name='api_v1_teams', request_method='DELETE', renderer='json')
def delete_teams(request):
    """
    Delete multiple teams.
    Provide a list of team ids to be deleted. The method will try to delete
    all of them and then return a json that describes for each team id
    whether or not it was deleted or the not_found if the team id could not
    be located. If no team id was found then a 404(Not Found) response will
    be returned.
    Only available to organization owners.
    ---
    team_ids:
      required: true
      type: array
    items:
      type: string
      name: team_id
    """
    auth_context = auth_context_from_request(request)
    org_id = request.matchdict['org_id']
    params = params_from_request(request)
    team_ids = params.get('team_ids', [])

    # SEC check if owner
    if not (auth_context.org and auth_context.is_owner() and
            auth_context.org.id == org_id):
        raise OrganizationAuthorizationFailure()

    if not isinstance(team_ids, (list, basestring)) or len(team_ids) == 0:
        raise RequiredParameterMissingError('No team ids provided')
    # remove duplicate ids if there are any
    teams_ids = sorted(team_ids)
    i = 1
    while i < len(teams_ids):
        if teams_ids[i] == teams_ids[i - 1]:
            teams_ids = teams_ids[:i] + teams_ids[i + 1:]
        else:
            i += 1
    report = {}
    for team_id in teams_ids:
        # Check if team entry exists
        try:
            team = auth_context.org.get_team_by_id(team_id)
        except me.DoesNotExist:
            report[team_id] = 'not_found'
        else:
            if team.name == 'Owners':
                report[team_id] = 'forbidden'
            elif team.members != 0:
                report[team_id] = 'not_empty'
            else:
                team.drop_mappings()
                Organization.objects(id=org_id).modify(pull__teams=team)
                report[team_id] = 'deleted'

    # if no team id was valid raise exception
    if len(filter(lambda team_id: report[team_id] == 'not_found',
                  report)) == len(teams_ids):
        raise NotFoundError('No valid team id provided')
    # if team is not empty raise exception
    if len(filter(lambda team_id: report[team_id] == 'not_empty',
                  report)) == len(teams_ids):
        raise BadRequestError('Delete only empty teams')
    # if user was not authorized for any team raise exception
    if len(filter(lambda team_id: report[team_id] == 'forbidden',
                  report)) == len(team_ids):
        raise TeamForbidden()

    trigger_session_update(auth_context.owner, ['org'])

    return report


# SEC
@view_config(route_name='api_v1_team_members', request_method='POST', renderer='json')
def invite_member_to_team(request):
    """
    Invite a member to team.
    For each user there can be one invitation per organization, but each
    invitation could be for multiple teams.
    There are three cases:
    1) If user is not a member of the organization:
        a) If user is registered in the service then an email will be sent with
           a link to confirm the invitation
        b) If user is not registered then a new entry will be created and an
           email will be sent inviting him to set a password and confirm his
           invitation to the organization
    2) User is already a member then add the user directly to the organization
       and send an email notification about the change in status.

   Only available to organization owners.
    ---
    org_id:
      description: The team's org id
      type: string
      required: true
    team_id:
      description: The team's id
      type: string
      required: true
    emails:
      description: The emails of the users to invite
      type: string
      required: true
    """
    auth_context = auth_context_from_request(request)

    params = params_from_request(request)
    org_id = request.matchdict['org_id']
    team_id = request.matchdict['team_id']

    # SEC check if owner
    if not (auth_context.org and auth_context.is_owner() and
            auth_context.org.id == org_id):
        raise OrganizationAuthorizationFailure()

    # Check if team entry exists
    try:
        team = auth_context.org.get_team_by_id(team_id)
    except me.DoesNotExist:
        raise TeamNotFound()

    emails = params.get('emails', '').strip().lower().split('\n')

    if not emails:
        raise RequiredParameterMissingError('emails')

    org = auth_context.org
    subject = config.ORG_INVITATION_EMAIL_SUBJECT

    for email in emails:
        if not email or '@' not in email:
            raise BadRequestError('Email %s is not valid' % email)

    ret = []
    for email in emails:
        # if '@' not in email:

        # check if user exists
        try:
            user = User.objects.get(email=email)
        except me.DoesNotExist:
            # If user doesn't exist then create one.
            if email.split('@')[1] in config.BANNED_EMAIL_PROVIDERS:
                raise MethodNotAllowedError("Email provider is banned.")
            user = User()
            user.email = email
            user.registration_date = time()
            user.status = 'pending'
            user.activation_key = get_secure_rand_token()
            user.save()

        return_val = {
            'id': user.id,
            'name': user.get_nice_name(),
            'email': user.email
        }

        invitoken = None

        # if user status is pending then send user email with link for
        # registration/invitation.
        if user not in org.members:
            # check if there is a pending invitation for the user for the same
            # team. if there is no invitation for team create one.
            # Also create a list of all the teams the user has been invited to.
            org_invitations = MemberInvitation.objects(org=org, user=user)
            for invitation in org_invitations:
                # user has already been invited for this organization, resend
                # registration/invitation email.
                if team_id not in invitation.teams:
                    invitation.teams.append(team_id)
                    invitation.save()
                pending_teams = invitation.teams
                invitoken = invitation.token
                break

            if not invitoken:
                # if there is no invitation create it
                new_invitation = MemberInvitation()
                new_invitation.user = user
                new_invitation.org = org
                new_invitation.teams.append(team_id)
                new_invitation.token = invitoken = get_secure_rand_token()
                try:
                    new_invitation.save()
                except:
                    TeamOperationError('Could not send invitation')
                pending_teams = new_invitation.teams

            # create appropriate email body
            if len(pending_teams) > 1:
                team_name = 'following teams: "'
                pending_team_names = []
                for pending_team_id in pending_teams:
                    try:
                        pending_team = org.get_team_by_id(pending_team_id)
                        pending_team_names.append(pending_team.name)
                    except:
                        pass
                team_name += '", "'.join(pending_team_names) + '"'
            else:
                team_name = '"' + team.name + '" team'
            if user.status == 'pending':
                body = config.REGISTRATION_AND_ORG_INVITATION_EMAIL_BODY % \
                (auth_context.user.get_nice_name(),
                 org.name,
                 team_name,
                 config.CORE_URI,
                 user.activation_key,
                 invitoken,
                 's' if len(pending_teams) > 1 else '',
                 config.CORE_URI)
            else:
                body = config.USER_CONFIRM_ORG_INVITATION_EMAIL_BODY % \
                                (auth_context.user.get_nice_name(),
                                 org.name,
                                 team_name,
                                 config.CORE_URI,
                                 invitoken,
                                 's' if len(pending_teams) > 1 else '',
                                 config.CORE_URI)
            return_val['pending'] = True
            log.info("Sending invitation to user with email '%s' for team %s "
                     "of org %s with token %s", user.email, team.name,
                     auth_context.org.name, invitoken)

        else:
            team = org.get_team_by_id(team_id)
            if user in team.members:
                raise MemberConflictError('Member already in team')
            org.add_member_to_team_by_id(team_id, user)
            org.save()
            subject = config.ORG_NOTIFICATION_EMAIL_SUBJECT
            body = config.USER_NOTIFY_ORG_TEAM_ADDITION % (team.name,
                                                           org.name,
                                                           config.CORE_URI)
            return_val['pending'] = False

            # if one of the org owners adds him/herself to team don't send email
            if user == auth_context.user:
                return return_val

        tasks.send_email.delay(subject, body, user.email)
        ret.append(return_val)

    trigger_session_update(auth_context.owner, ['org'])
    return ret


@view_config(route_name='confirm_invitation', request_method='GET')
def confirm_invitation(request):
    """
    Confirm that a user want to participate in team
    If user has status pending then he/she will be redirected to confirm
    to finalize registration and only after the process has finished
    successfully will he/she be added to the team.
    ---
    invitoken:
      description: member's invitation token
      type: string
      required: true

    """
    try:
        auth_context = auth_context_from_request(request)
    except UserUnauthorizedError:
        auth_context = None
    params = params_from_request(request)
    invitoken = params.get('invitoken', '')
    if not invitoken:
        raise RequiredParameterMissingError('invitoken')
    try:
        invitation = MemberInvitation.objects.get(token=invitoken)
    except me.DoesNotExist:
        raise NotFoundError('Invalid invitation token')

    user = invitation.user
    # if user registration is pending redirect to confirm registration
    if user.status == 'pending':
        key = params.get('key')
        if not key:
            key = user.activation_key
        uri = request.route_url('confirm',
                                _query={'key': key, 'invitoken': invitoken})
        raise RedirectError(uri)

    # if user is confirmed but not logged in then redirect to log in page
    if not auth_context:
        uri = request.route_url('login', _query={'invitoken': invitoken})
        raise RedirectError(uri)

    # if user is logged in then make sure it's his invitation that he is
    # confirming. if it's not redirect to home but don't confirm invitation.
    if invitation.user != auth_context.user:
        return HTTPFound('/')

    org = invitation.org
    for team_id in invitation.teams:
        try:
            org.add_member_to_team_by_id(team_id, user)
        except:
            pass

    try:
        org.save()
    except:
        raise TeamOperationError()

    try:
        invitation.delete()
    except:
        pass

    args = {
        'request': request,
        'user_id': auth_context.user,
        'org': org
    }
    if session_from_request(request).context.get('social_auth_backend'):
        args.update({
            'social_auth_backend': session_from_request(request).context.get('social_auth_backend')
        })
    reissue_cookie_session(**args)

    trigger_session_update(auth_context.owner, ['org'])

    return HTTPFound('/')


# SEC
@view_config(route_name='api_v1_team_member', request_method='DELETE', renderer='json')
def delete_member_from_team(request):
    """
    Delete a team's member entry from the db.
    It means remove member from list and save org.
    Only available to organization owners.
    ---
    org_id:
      description: The team's org id
      type: string
      required: true
    team_id:
      description: The team's id
      type: string
      required: true
    user_id:
      description: The user's id
      type: string
      required: true
    """
    auth_context = auth_context_from_request(request)

    user_id = request.matchdict['user_id']
    org_id = request.matchdict['org_id']
    team_id = request.matchdict['team_id']

    # SEC check if owner
    if not (auth_context.org and auth_context.is_owner()
            and auth_context.org.id == org_id):
        raise OrganizationAuthorizationFailure()

    # Check if team entry exists
    try:
        team = auth_context.org.get_team_by_id(team_id)
    except me.DoesNotExist:
        raise TeamNotFound()

    # check if user exists
    try:
        user = User.objects.get(id=user_id)
    except me.DoesNotExist:
        raise UserNotFoundError()

    # check if user has a pending invitation.
    if user not in team.members:
        try:
            invitation = \
                MemberInvitation.objects.get(user=user, org=auth_context.org)
            # remove team from user's invitation. if there are no more teams
            # then revoke the invitation.
            if team_id not in invitation.teams:
                raise NotFoundError()
            invitation.teams.remove(team_id)
            if len(invitation.teams) == 0:
                subject = config.NOTIFY_INVITATION_REVOKED_SUBJECT
                body = config.NOTIFY_INVITATION_REVOKED % \
                       (auth_context.org.name, config.CORE_URI)
                try:
                    invitation.delete()
                except me.ValidationError as e:
                    raise BadRequestError(
                        {"msg": e.message, "errors": e.to_dict()})
                except me.OperationError:
                    raise TeamOperationError()
                # notify user that his invitation has been revoked
                tasks.send_email.delay(subject, body, user.email)
            else:
                try:
                    invitation.save()
                except me.ValidationError as e:
                    raise BadRequestError(
                        {"msg": e.message, "errors": e.to_dict()})
                except me.OperationError:
                    raise TeamOperationError()

            trigger_session_update(auth_context.owner, ['org'])
            return OK
        except:
            raise MemberNotFound()

    # if user belongs in more than one teams then just remove him from the team
    # otherwise remove him both from team and the organization.
    remove_from_org = True
    auth_context.org.remove_member_from_team_by_id(team_id, user)
    for team in auth_context.org.teams:
        if user in team.members and team.id != team_id:
            # if user is in some other team too then just remove him from the
            # team.
            remove_from_org = False
            break

    subject = config.ORG_TEAM_STATUS_CHANGE_EMAIL_SUBJECT
    if remove_from_org:
        body = config.NOTIFY_REMOVED_FROM_ORG % \
               (auth_context.org.name, config.CORE_URI)
        auth_context.org.remove_member_from_members(user)
    else:
        body = config.NOTIFY_REMOVED_FROM_TEAM % \
        (team.name,
         auth_context.org.name,
         auth_context.user.get_nice_name(),
         config.CORE_URI)

    try:
        auth_context.org.save()
    except me.ValidationError as e:
        raise BadRequestError({"msg": e.message, "errors": e.to_dict()})
    except me.OperationError:
        raise TeamOperationError()

    if user != auth_context.user:
        tasks.send_email.delay(subject, body, user.email)

    trigger_session_update(auth_context.owner, ['org'])

    return OK


def get_csrf_token(request):
    """
    Returns the CSRF token registered to this request's user session.
    """
    session = session_from_request(request)
    return session.csrf_token if isinstance(session, SessionToken) else ''


# SEC
@view_config(route_name='login', request_method='POST', renderer='json')
@view_config(route_name='login_service', request_method='POST',
             renderer='json')
def login(request):
    """
    User posts authentication credentials (email, password).
    If there is a 'return_to' parameter the user will be redirected to this
    local url upon successful authentication.
    There is also an optional 'service' parameter, mainly meant to be used for
    SSO.
    ---
    email:
      description: user's email
      type: string
      required: true
    password:
      description: user's password
      type: string
      required: true
    service:
      description: used for SSO
      type: string

    """
    params = params_from_request(request)
    email = params.get('email')
    password = params.get('password', '')
    service = request.matchdict.get('service') or params.get('service') or ''
    return_to = params.get('return_to')
    if return_to:
        return_to = urllib.unquote(return_to)
    else:
        return_to = '/'
    token_from_params = params.get('token')

    if not email:
        raise RequiredParameterMissingError('email')
    email = email.lower()
    try:
        user = User.objects.get(email=email)
    except (UserNotFoundError, me.DoesNotExist):
        raise UserUnauthorizedError()
    if not user.status == 'confirmed':
        raise UserUnauthorizedError("User account has not been confirmed.")

    if password:
        # rate limit user logins
        max_logins = config.FAILED_LOGIN_RATE_LIMIT['max_logins']
        max_logins_period = config.FAILED_LOGIN_RATE_LIMIT['max_logins_period']
        block_period = config.FAILED_LOGIN_RATE_LIMIT['block_period']

        # check if rate limiting in place
        incidents = get_log_events(user_id=user.id, event_type='incident',
                                   action='login_rate_limiting',
                                   start=time() - max_logins_period)
        incidents = [inc for inc in incidents
                     if inc.get('ip') == ip_from_request(request)]
        if len(incidents):
            secs = incidents[0]['time'] + block_period - time()
            raise LoginThrottledError("Try again in %d seconds." % secs)

        if not user.check_password(password):
            # check if rate limiting condition just got triggered
            logins = list(get_log_events(
                user_id=user.id, event_type='request', action='login',
                error=True, start=time() - max_logins_period))
            logins = [login for login in logins
                      if login.get('request_ip') == ip_from_request(request)]
            if len(logins) > max_logins:
                log_event(owner_id=user.id, user_id=user.id,
                          event_type='incident',
                          action='login_rate_limiting',
                          ip=ip_from_request(request))
                # alert admins something nasty is going on
                subject = config.FAILED_LOGIN_ATTEMPTS_EMAIL_SUBJECT
                body = config.FAILED_LOGIN_ATTEMPTS_EMAIL_BODY % (
                    user.email,
                    ip_from_request(request),
                    max_logins,
                    max_logins_period,
                    block_period
                )
                send_email(subject, body, config.NOTIFICATION_EMAIL['ops'])
            raise UserUnauthorizedError()
    elif token_from_params:
        try:
            auth_token = ApiToken.objects.get(user_id=user.id,
                                              token=token_from_params)
        except me.DoesNotExist:
            auth_token = None
        if not (auth_token and auth_token.is_valid()):
            raise UserUnauthorizedError()
        auth_token.touch()
        auth_token.save()
    else:
        raise RequiredParameterMissingError("'password' or 'token'")

    reissue_cookie_session(request, user)

    user.last_login = time()
    user.user_agent = request.user_agent
    user.save()

    if not service:
        # TODO: check that return_to is a local url
        redirect = return_to
    else:
        raise BadRequestError("Invalid service '%s'." % service)

    if params.get('invitoken'):
        confirm_invitation(request)

    return {
        'auth': True,
        'redirect': redirect,
        'csrf_token': get_csrf_token(request),
    }


@view_config(route_name='switch_context', request_method='GET')
@view_config(route_name='switch_context_org', request_method='GET')
def switch_org(request):
    """
    Switch user's context.
    Personal or organizational
    ---
    org_id:
      description: The team's org id
      type: string
      required: true

    """
    org_id = request.matchdict.get('org_id')
    user = user_from_request(request)
    params = params_from_request(request)
    return_to = params.get('return_to', '')
    org = None
    if org_id:
        try:
            org = Organization.objects.get(id=org_id)
        except me.DoesNotExist:
            raise ForbiddenError()
        if user not in org.members:
            raise ForbiddenError()
    reissue_cookie_session(request, user, org=org, after=1)

    raise RedirectError(urllib.unquote(return_to) or '/')


@view_config(route_name='login', request_method='GET',
             renderer='templates/home.pt')
@view_config(route_name='login_service', request_method='GET',
             renderer='templates/home.pt')
def login_get(request):
    """
    User visits login form.
    If there is a 'return_to' parameter the user will be redirected to this
    local url upon successful authentication.
    There is also an optional 'service' parameter, mainly meant to be used for
    SSO.
    ---
    return_to:
      description: if exists, redirect user
      type: string
    service:
      description: used for SSO
      type: string
    """

    # check if user sent a GET instead of POST, process it accordingly
    from mist.core.views import splash_layout
    try:
        ret = login(request)
        if ret['auth']:
            return HTTPFound(ret['redirect'])
    except:
        pass
    service = request.matchdict.get('service', '')
    params = params_from_request(request)
    return_to = params.get('return_to', '')
    try:
        user = user_from_request(request)
        if not service:
            return HTTPFound(urllib.unquote(return_to) or '/')
        raise BadRequestError("Invalid service '%s'." % service)
    except UserUnauthorizedError:
        return {
            'login': 1,
            'service': service,
            'return_to': return_to,
            'layout': splash_layout(),
            'privacy_policy': config.PRIVACY_POLICY,
            'tos': config.TOS,
            'csrf_token': json.dumps(get_csrf_token(request)),
            'css_build': config.CSS_BUILD,
            'js_build': config.JS_BUILD,
            'last_build': config.LAST_BUILD
        }


@view_config(route_name='logout', request_method=('GET', 'POST'))
def logout(request):
    """
    User logs out.
    If user is an admin under su, he returns to his regular user.
    """
    user = user_from_request(request)
    session = session_from_request(request)
    if isinstance(session, ApiToken):
        raise ForbiddenError('If you wish to revoke a token use the /tokens'
                             ' path')
    real_user = session.get_user(effective=False)

    # this will revoke all the tokens sent by the provider
    sso_backend = session.context.get('social_auth_backend')
    if sso_backend:
        initiate_social_auth_request(request, backend=sso_backend)
        try:
            request.backend.disconnect(user=user,
                                       association_id=None,
                                       request=request)
        except Exception as e:
            log.info('There was an exception while revoking tokens for user'
                     ' %s: %s' % (user.email, repr(e)))
    if user != real_user:
        log.warn("Su logout")
        reissue_cookie_session(request, real_user)
    else:
        reissue_cookie_session(request)
    ibm_marketplace_redirect = session.context.get('from_ibm')
    if user.is_ibm_user and ibm_marketplace_redirect:
        raise RedirectError(config.IBM_MARKETPLACE_URL)
    return HTTPFound('/')


@view_config(route_name='register', request_method='POST', renderer='json')
def register(request):
    """
    New user signs up.
    """
    params = params_from_request(request)
    email = params.get('email').encode('utf-8', 'ignore')
    promo_code = params.get('promo_code')
    name = params.get('name').encode('utf-8', 'ignore')
    token = params.get('token')
    selected_plan = params.get('selected_plan')
    request_demo = params.get('request_demo')
    request_beta = params.get('request_beta', False)

    if not email or not email.strip():
        raise RequiredParameterMissingError('email')
    if not name or not name.strip():
        raise RequiredParameterMissingError('name')
    if type(request_demo) != bool:
        raise BadRequestError('Request demo must be a boolean value')

    name = name.strip().split(" ", 1)
    email = email.strip().lower()

    if type(name) == unicode:
        name = name.encode('utf-8', 'ignore')
    if not request_beta:
        try:
            user = User.objects.get(email=email)
            if user.status == 'confirmed' and not request_demo:
                raise ConflictError("User already registered "
                                    "and confirmed email.")
        except me.DoesNotExist:
            first_name = name[0]
            last_name = name[1] if len(name) > 1 else ""
            user, org = register_user(email, first_name, last_name, 'email',
                                      selected_plan, promo_code, token)

        if user.status == 'pending':
            # if user is not confirmed yet resend the email
            subject = config.CONFIRMATION_EMAIL_SUBJECT
            body = config.CONFIRMATION_EMAIL_BODY % ((user.first_name + " " +
                                                      user.last_name),
                                                     config.CORE_URI,
                                                     user.activation_key,
                                                     ip_from_request(request),
                                                     config.CORE_URI)

            if not send_email(subject, body, user.email):
                raise ServiceUnavailableError("Could not send "
                                              "confirmation email.")

    if request_demo:
        # if user requested a demo then notify the mist.io team
        subject = "Demo request"
        body = "User %s has requested a demo\n" % user.email
        tasks.send_email.delay(subject, body, config.NOTIFICATION_EMAIL['demo'])
        user.requested_demo = True
        user.demo_request_date = time()
        user.save()

        msg = "Dear %s %s, we will contact you within 24 hours to schedule a " \
              "demo. In the meantime, we sent you an activation email so you" \
              " can create an account to test Mist.io. If the email doesn't" \
              " appear in your inbox, check your spam folder." \
              % (user.first_name, user.last_name)
    elif request_beta:
        user = None
        # if user requested a demo then notify the mist.io team
        subject = "Private beta request"
        body = "User %s <%s> has requested access to the private beta\n" % \
            (params.get('name').encode('utf-8', 'ignore'), email)
        tasks.send_email.delay(subject, body, config.NOTIFICATION_EMAIL['demo'])

        msg = "Dear %s, we will contact you within 24 hours with more " \
              "information about the Mist.io private beta program. In the " \
              "meantime, if you have any questions don't hesitate to contact" \
              " us at info@mist.io" % params.get('name').encode('utf-8', 'ignore')
    else:
        msg = "Dear %s %s, you will soon receive an activation email. If it " \
              "doesn't appear in your Inbox within a few minutes, please " \
              "check your spam folder." % (user.first_name, user.last_name)

    return {
        'msg': msg,
        'user_ga_id': user and user.get_external_id('ga'),
        'user_id': user and user.id}


@view_config(route_name='confirm', request_method='GET')
def confirm(request):
    """
    Confirm a user's email address when signing up.
    After registering, the user is sent a confirmation email to his email
    address with a link containing a token that directs the user to this view
    to confirm his email address.
    If invitation token exists redirect to set_password
    """
    params = params_from_request(request)
    key = params.get('key')
    if not key:
        raise RequiredParameterMissingError('key')

    try:
        user = User.objects.get(activation_key=key)
    except me.DoesNotExist:
        return HTTPFound('/#badkey')
    if user.status != 'pending' or user.password:
        # if user has an invitation token but has been confirmed call the
        # confirm invitation token
        if params.get('invitoken'):
            return confirm_invitation(request)
        else:
            return HTTPFound('/#alreadyconfirmed')

    token = get_secure_rand_token()
    key = encrypt("%s:%s" % (token, user.email), config.SECRET)
    user.password_set_token = token
    user.password_set_token_created = time()
    user.password_set_user_agent = request.user_agent
    log.debug("will now save (register)")
    user.save()

    invitoken = params.get('invitoken')
    url = request.route_url('set_password', _query={'key': key})
    if invitoken:
        try:
            MemberInvitation.objects.get(token=invitoken)
            url += '&invitoken=' + invitoken
        except me.DoesNotExist:
            pass

    return HTTPFound(url)


@view_config(route_name='forgot_password', request_method='POST')
def forgot_password(request):
    """
    User visits password forgot form and submits his email
    or user presses the set password button in the account page
    and has registered through the SSO and has no previous
    password set in the database. In the latter case the email
    will be fetched from the session.
    """
    try:
        email = user_from_request(request).email
    except UserUnauthorizedError:
        email = params_from_request(request).get('email', '')

    try:
        user = User.objects.get(email=email)
    except (UserNotFoundError, me.DoesNotExist):
        # still return OK so that there's no leak on valid email
        return OK

    if user.status != 'confirmed':
        # resend confirmation email
        user.activation_key = get_secure_rand_token()
        user.save()
        subject = config.CONFIRMATION_EMAIL_SUBJECT
        body = config.CONFIRMATION_EMAIL_BODY % ((user.first_name + " " +
                                                  user.last_name),
                                                 config.CORE_URI,
                                                 user.activation_key,
                                                 ip_from_request(request),
                                                 config.CORE_URI)

        if not send_email(subject, body, user.email):
            raise ServiceUnavailableError("Could not send confirmation email.")

        return OK

    token = get_secure_rand_token()
    user.password_reset_token = token
    user.password_reset_token_created = time()
    user.password_reset_token_ip_addr = ip_from_request(request)
    log.debug("will now save (forgot)")
    user.save()

    subject = config.RESET_PASSWORD_EMAIL_SUBJECT
    body = config.RESET_PASSWORD_EMAIL_BODY
    body = body % ( (user.first_name or "") + " " + (user.last_name or ""),
                   config.CORE_URI,
                   encrypt("%s:%s" % (token, email), config.SECRET),
                   user.password_reset_token_ip_addr,
                   config.CORE_URI)
    if not send_email(subject, body, email):
        log.info("Failed to send email to user %s for forgot password link" %
                 user.email)
        raise ServiceUnavailableError()
    log.info("Sent email to user %s\n%s" % (email, body))
    return OK


# SEC
@view_config(route_name='reset_password', request_method=('GET', 'POST'))
def reset_password(request):
    """
    User visits reset password form and posts his email address
    If he is logged in when he presses the link then he will be logged out
    and then redirected to the landing page with the reset password token.
    """
    params = params_from_request(request)
    key = params.get('key')

    if not key:
        raise BadRequestError("Reset password token is missing")
    reissue_cookie_session(request)  # logout

    # SEC decrypt key using secret
    try:
        (token, email) = decrypt(key, config.SECRET).split(':')
    except:
        raise BadRequestError("invalid password token.")

    try:
        user = User.objects.get(email=email)
    except (UserNotFoundError, me.DoesNotExist):
        raise UserUnauthorizedError()

    # SEC check status, token, expiration
    if token != user.password_reset_token:
        raise BadRequestError("Invalid reset password token.")
    delay = time() - user.password_reset_token_created
    if delay > config.RESET_PASSWORD_EXPIRATION_TIME:
        raise MethodNotAllowedError("Password reset token has expired.")

    if request.method == 'GET':
        return render_to_response(
            'templates/home.pt',
            {
                'layout': splash_layout(),
                'privacy_policy': config.PRIVACY_POLICY,
                'tos': config.TOS,
                'pw_reset': 1,
                'css_build': config.CSS_BUILD,
                'js_build': config.JS_BUILD,
                'last_build': config.LAST_BUILD,
                'csrf_token': json.dumps(get_csrf_token(request))
            },
            request=request
        )
    elif request.method == 'POST':

        password = params.get('password', '')
        if not password:
            raise RequiredParameterMissingError('password')

        # change password
        user.set_password(password)
        user.status = 'confirmed'
        # in case the use has been with a pending confirm state
        user.password_reset_token_created = 0
        user.save()

        reissue_cookie_session(request, user)

        return OK
    raise BadRequestError("Bad method %s" % request.method)


# SEC
@view_config(route_name='set_password', request_method=('GET', 'POST'))
def set_password(request):
    """
    User visits confirm link and sets password.
    User set password if he/she forgot his/her password, if he/she is invited
    by owner, if he/she signs up.
    """
    params = params_from_request(request)
    key = params.get('key', '')

    invitoken = params.get('invitoken', '')

    if not key:
        raise RequiredParameterMissingError('key')

    # SEC decrypt key using secret
    try:
        (token, email) = decrypt(key, config.SECRET).split(':')
    except:
        raise BadRequestError("invalid password token.")

    try:
        user = User.objects.get(email=email)
    except (UserNotFoundError, me.DoesNotExist):
        raise UserUnauthorizedError()

    if user.status != 'pending':
        raise ForbiddenError("Already confirmed and password set.")
    if token != user.password_set_token:
        raise BadRequestError("invalid set password token.")
    delay = time() - user.password_set_token_created
    if delay > config.RESET_PASSWORD_EXPIRATION_TIME:
        raise MethodNotAllowedError("Password set token has expired.")

    if request.method == 'GET':
        return render_to_response(
            'templates/home.pt',
            {
                'layout': splash_layout(),
                'privacy_policy': config.PRIVACY_POLICY,
                'tos': config.TOS,
                'pw_set': 1,
                'css_build': config.CSS_BUILD,
                'js_build': config.JS_BUILD,
                'last_build': config.LAST_BUILD,
                'csrf_token': json.dumps(get_csrf_token(request)),
                'invitoken': invitoken,
            },
            request=request
        )
    elif request.method == 'POST':
        password = params.get('password', '')
        if not password:
            raise RequiredParameterMissingError('password')
        # set password
        user.set_password(password)
        user.status = 'confirmed'
        user.activation_date = time()
        user.password_set_token = ""
        selected_plan = user.selected_plan
        user.selected_plan = ''
        user.last_login = time()

        # activate trial
        # plan = Plan()
        # plan.title = 'Startup'
        # plan.machine_limit = 20
        # plan.started = time()
        # plan.expiration = time() + 60 * 60 * 24 * 15
        # plan.isTrial = True
        # user.plans = []
        # user.plans.append(plan)

        user.save()

        body = "one step closer to world domination!\n%s/%s confirmed" \
            % (get_users_count(confirmed=True), get_users_count())
        subject = '[mist.io] new user: %s' % user.email,
        send_email(subject, body, 'we@mist.io')

        # log in user
        reissue_cookie_session(request, user)

        ret = {'selectedPlan': selected_plan}
        if user.promo_codes:
            promo_code = user.promo_codes[-1]
            promo = Promo.objects.get(code=promo_code)
            ret['hasPromo'] = True
            ret['sendToPurchase'] = promo.send_to_purchase

        if invitoken:
            try:
                MemberInvitation.objects.get(token=invitoken)
                confirm_invitation(request)
            except me.DoesNotExist:
                pass

        return render_to_response('json', ret, request)
    else:
        raise BadRequestError("Invalid HTTP method")
