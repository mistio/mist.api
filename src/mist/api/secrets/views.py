import mongoengine as me
from pyramid.response import Response

from mist.api.secrets.models import VaultSecret

from mist.api.auth.methods import auth_context_from_request

from mist.api.helpers import view_config, params_from_request

from mist.api.exceptions import NotFoundError, BadRequestError

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
    cached = bool(params.get('cached', True))  # return cached by default
    path = params.get('path', 'clouds')

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
