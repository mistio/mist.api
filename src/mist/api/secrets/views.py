import mongoengine as me
from pyramid.response import Response

from mist.api.secrets.models import VaultSecret

from mist.api.auth.methods import auth_context_from_request

from mist.api.helpers import view_config, params_from_request

from mist.api.exceptions import NotFoundError, BadRequestError
from mist.api.exceptions import RequiredParameterMissingError

OK = Response("OK", 200)


@view_config(route_name='api_v1_secrets', request_method='GET',
             renderer='json')
def list_secrets(request):
    """
    Tags: secrets
    ---
    Lists secrets.
    READ permission required on secret.
    ---
    """
    auth_context = auth_context_from_request(request)
    owner = auth_context.owner
    params = params_from_request(request)
    cached = bool(params.get('cached', False))  # return cached by default
    path = params.get('path', '.')

    if cached:
        secrets = VaultSecret.objects(owner=owner)
        if path != '.':
            secrets = [secret for secret in secrets
                       if secret.name.startswith(path)]

    else:
        # TODO: is there a better way?
        secret = VaultSecret()
        secrets = secret.ctl.list_secrets(owner, path)

    return [secret.as_dict() for secret in secrets]


@view_config(route_name='api_v1_secrets', request_method='POST',
             renderer='json')
def create_secret(request):
    """
    Tags: secrets
    ---
    Create secret.
    ADD permission required on secret.
    ---
    secret:
      required: true
      type: object
    """
    auth_context = auth_context_from_request(request)
    owner = auth_context.owner
    params = params_from_request(request)
    name = params.get('name', '')
    secret = params.get('secret', {})
    if not secret:
        raise RequiredParameterMissingError('secret')
    if not name:
        raise RequiredParameterMissingError('name')

    if not isinstance(secret, dict):
        raise BadRequestError('Secret needs to be a dict.')

    _secret = VaultSecret(name=name, owner=owner)
    try:
        _secret.save()
    except me.NotUniqueError:
        raise BadRequestError("The path specified exists on Vault. \
                    Try changing the name of the secret")

    _secret.ctl.create_or_update_secret(owner.name, secret)

    # FIXME
    # trigger_session_update(owner.id, ['secrets'])

    # SEC
    # Update the RBAC & User/Ownership mappings with the new secret and finally
    # trigger a session update by registering it as a chained task.
    # if config.HAS_RBAC:
    #     owner.mapper.update(
    #         secret,
    #         callback=async_session_update, args=(owner.id, ['secrets'], )
    #     )

    return _secret.as_dict()


@view_config(route_name='api_v1_secret', request_method='GET',
             renderer='json')
def get_secret(request):
    """
    Tags: secrets
    ---
    Get secret.
    READ permission required on secret.
    ---
    """
    auth_context = auth_context_from_request(request)
    params = params_from_request(request)
    key = params.get('key', '')
    secret_id = request.matchdict.get('secret')
    try:
        secret = VaultSecret.objects.get(owner=auth_context.owner,
                                         id=secret_id)
    except me.DoesNotExist:
        raise NotFoundError('Secret does not exist')

    secret_dict = secret.ctl.read_secret(auth_context.owner.name)

    if key and not secret_dict.get(key, ''):
        raise BadRequestError('Secret %s does not have a %s attribute'
                              % (secret.name, key))

    return secret_dict if not key else {key: secret_dict[key]}


@view_config(route_name='api_v1_secret', request_method='PUT',
             renderer='json')
def update_secret(request):
    """
    Tags: secrets
    ---
    Edit secret.
    EDIT permission required on secret.
    ---
    """
    auth_context = auth_context_from_request(request)
    params = params_from_request(request)
    secret_id = request.matchdict.get('secret')
    secret = params.get('secret', {})
    if not secret:
        raise RequiredParameterMissingError('secret')

    try:
        _secret = VaultSecret.objects.get(owner=auth_context.owner,
                                          id=secret_id)
    except me.DoesNotExist:
        raise NotFoundError('Secret does not exist')

    _secret.ctl.create_or_update_secret(auth_context.owner.name, secret)

    return OK


@view_config(route_name='api_v1_secret', request_method='DELETE',
             renderer='json')
def delete_secret(request):
    """
    Tags: secrets
    ---
    Deletes secret.
    DELETE permission required on secret.
    ---
    """
    auth_context = auth_context_from_request(request)
    secret_id = request.matchdict.get('secret')
    try:
        secret = VaultSecret.objects.get(owner=auth_context.owner,
                                         id=secret_id)
    except me.DoesNotExist:
        raise NotFoundError('Secret does not exist')

    # auth_context.check_perm('secret', 'remove', secret_id)
    secret.ctl.delete_secret()

    return OK
