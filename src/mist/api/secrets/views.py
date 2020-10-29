import mongoengine as me
from pyramid.response import Response

from mist.api.secrets.models import VaultSecret

from mist.api.auth.methods import auth_context_from_request

from mist.api.helpers import view_config, params_from_request

from mist.api.exceptions import NotFoundError

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
