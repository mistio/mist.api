import mongoengine as me

from pyramid.response import Response

from mist.api.machines.models import Machine
from mist.api.keys.models import SignedSSHKey, SSHKey, Key

from mist.api.auth.methods import auth_context_from_request

from mist.api.helpers import view_config, params_from_request

from mist.api.logs.methods import log_event

from mist.api.keys.methods import filter_list_keys
from mist.api.keys.methods import delete_key as m_delete_key

from mist.api.exceptions import BadRequestError, KeyParameterMissingError
from mist.api.exceptions import RequiredParameterMissingError, NotFoundError

from mist.api.tag.methods import add_tags_to_resource

OK = Response("OK", 200)


@view_config(route_name='api_v1_keys', request_method='GET', renderer='json')
def list_keys(request):
    """
    Tags: keys
    ---
    Lists all added keys.
    READ permission required on key.
    ---
    """
    auth_context = auth_context_from_request(request)
    return filter_list_keys(auth_context)


@view_config(route_name='api_v1_keys', request_method='PUT', renderer='json')
def add_key(request):
    """
    Tags: keys
    ---
    Adds key.
    ADD permission required on key.
    ---
    name:
      description: The key's name
      required: true
      type: string
    priv:
      description: The private key
      required: true
      type: string
    certificate:
      description: The signed public key, when using signed ssh keys
      type: string
    """
    params = params_from_request(request)
    key_name = params.pop('name', None)
    private_key = params.get('priv', None)
    certificate = params.get('certificate', None)
    auth_context = auth_context_from_request(request)
    key_tags, _ = auth_context.check_perm("key", "add", None)

    if not key_name:
        raise BadRequestError("Key name is not provided")
    if not private_key:
        raise RequiredParameterMissingError("Private key is not provided")

    if certificate:
        key = SignedSSHKey.add(auth_context.owner, key_name,
                               user=auth_context.user, **params)
    else:
        key = SSHKey.add(auth_context.owner, key_name,
                         user=auth_context.user, **params)

    # Set ownership.
    key.assign_to(auth_context.user)

    if key_tags:
        add_tags_to_resource(auth_context.owner,
                             [{'resource_type': 'key',
                               'resource_id': key.id}],
                             list(key_tags.items()))

    return {'id': key.id,
            'name': key.name,
            'machines': [],
            'isDefault': key.default}


@view_config(route_name='api_v1_key_action', request_method='DELETE',
             renderer='json')
def delete_key(request):
    """
    Tags: keys
    ---
    Deletes a key. When a key gets deleted, it takes its associations with it
    so just need to remove from the server too. If the default key gets
    deleted, it sets the next one as default, provided that at least another
    key exists. It returns the list of all keys after the deletion,
    excluding the private keys (check also list_keys).
    REMOVE permission required on key.
    ---
    key:
      in: path
      required: true
      type: string
    """
    auth_context = auth_context_from_request(request)
    params = params_from_request(request)
    delete_from_vault = params.get('delete_from_vault', False)
    key_id = request.matchdict.get('key')
    if not key_id:
        raise KeyParameterMissingError()

    try:
        key = Key.objects.get(owner=auth_context.owner, id=key_id,
                              deleted=None)
    except me.DoesNotExist:
        raise NotFoundError('Key id does not exist')

    auth_context.check_perm('key', 'remove', key.id)
    m_delete_key(auth_context.owner, key_id, delete_from_vault)
    return OK


@view_config(route_name='api_v1_key_action', request_method='PUT',
             renderer='json')
def edit_key(request):
    """
    Tags: keys
    ---
    Edits a given key's name to new_name.
    EDIT permission required on key.
    ---
    new_name:
      description: The new key name
      required: true
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
    Tags: keys
    ---
    Sets a new default key.
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
    Tags: keys
    ---
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
    log_event(
        auth_context.owner.id, 'request', 'read_private',
        key_id=key.id, user_id=auth_context.user.id,
    )
    return key.private.value


@view_config(route_name='api_v1_key_public', request_method='GET',
             renderer='json')
def get_public_key(request):
    """
    Tags: keys
    ---
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
def generate_key(request):
    """
    Tags: keys
    ---
    Generates key pair
    ---
    """
    key = SSHKey()
    key.ctl.generate()
    return {'priv': key.private, 'public': key.public}


@view_config(route_name='api_v1_cloud_key_association', request_method='PUT',
             renderer='json')
@view_config(route_name='api_v1_key_association', request_method='PUT',
             renderer='json')
def associate_key(request):
    """
    Tags: keys
    ---
    Associates a key with a machine. If host is set it will also attempt to
    actually deploy it to the machine. To do that it requires another key
    (existing_key) that can connect to the machine.
    READ permission required on cloud.
    READ_PRIVATE permission required on key.
    ASSOCIATE_KEY permission required on machine.
    ---
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
    cloud_id = request.matchdict.get('cloud')

    params = params_from_request(request)
    ssh_user = params.get('user', None)
    try:
        ssh_port = int(request.json_body.get('port', 22))
    except:
        ssh_port = 22

    auth_context = auth_context_from_request(request)
    try:
        key = Key.objects.get(owner=auth_context.owner,
                              id=key_id, deleted=None)
    except Key.DoesNotExist:
        raise NotFoundError('Key id does not exist')
    auth_context.check_perm('key', 'read_private', key.id)

    if cloud_id:
        external_id = request.matchdict['machine']
        auth_context.check_perm("cloud", "read", cloud_id)
        try:
            machine = Machine.objects.get(cloud=cloud_id,
                                          external_id=external_id,
                                          state__ne='terminated',
                                          owner=auth_context.org)
        except Machine.DoesNotExist:
            raise NotFoundError("Machine %s doesn't exist" % external_id)
    else:
        machine_id = request.matchdict['machine']
        try:
            machine = Machine.objects.get(id=machine_id,
                                          state__ne='terminated',
                                          owner=auth_context.org)
        except Machine.DoesNotExist:
            raise NotFoundError("Machine %s doesn't exist" % machine_id)

        cloud_id = machine.cloud.id
        auth_context.check_perm("cloud", "read", cloud_id)

    # used by logging_view_decorator
    request.environ['cloud'] = machine.cloud.id
    request.environ['machine'] = machine.id
    request.environ['external_id'] = machine.external_id

    auth_context.check_perm("machine", "associate_key", machine.id)

    return key.ctl.associate(machine, username=ssh_user, port=ssh_port)


@view_config(route_name='api_v1_cloud_key_association',
             request_method='DELETE', renderer='json')
@view_config(route_name='api_v1_key_association',
             request_method='DELETE', renderer='json')
def disassociate_key(request):
    """
    Tags: keys
    ---
    Disassociates a key from a machine. If host is set it will also attempt to
    actually remove it from the machine.
    READ permission required on cloud.
    DISASSOCIATE_KEY permission required on machine.
    ---
    key:
      in: path
      required: true
      type: string
    machine:
      in: path
      required: true
      type: string
    """
    key_id = request.matchdict['key']
    cloud_id = request.matchdict.get('cloud')
    auth_context = auth_context_from_request(request)

    if cloud_id:
        external_id = request.matchdict['machine']
        auth_context.check_perm("cloud", "read", cloud_id)
        try:
            machine = Machine.objects.get(cloud=cloud_id,
                                          external_id=external_id,
                                          owner=auth_context.org)
        except Machine.DoesNotExist:
            raise NotFoundError("Machine %s doesn't exist" % external_id)
    else:
        machine_id = request.matchdict['machine']
        try:
            machine = Machine.objects.get(id=machine_id,
                                          owner=auth_context.org)
        except Machine.DoesNotExist:
            raise NotFoundError("Machine %s doesn't exist" % machine_id)

        cloud_id = machine.cloud.id

    # used by logging_view_decorator
    request.environ['cloud'] = machine.cloud.id
    request.environ['machine'] = machine.id
    request.environ['external_id'] = machine.external_id

    auth_context.check_perm("cloud", "read", cloud_id)
    auth_context.check_perm("machine", "disassociate_key", machine.id)

    try:
        key = Key.objects.get(
            owner=auth_context.owner, id=key_id, deleted=None)
    except Key.DoesNotExist:
        raise NotFoundError("Key %s doesn't exist" % key_id)
    return key.ctl.disassociate(machine)
