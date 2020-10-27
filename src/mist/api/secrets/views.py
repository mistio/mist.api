import mongoengine as me
from pyramid.response import Response

from mist.api.secrets.models import VaultSecret

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



# delete

@view_config(route_name='api_v1_secrets', request_method='GET', renderer='json')
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
    path = params.get('path', 'clouds')

    if cached:
        secrets = VaultSecret.objects(owner=owner)
        if path != '.':
            secrets = [secret for secret in secrets if secret.name.startswith(path)]

    else:
        # TODO: is there a better way?
        secret = VaultSecret()
        secrets = secret.ctl.list_secrets(owner, path)

    return [secret.as_dict() for secret in secrets]
