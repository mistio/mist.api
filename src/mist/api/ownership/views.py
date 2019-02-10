from pyramid.response import Response

from mist.api.helpers import view_config
from mist.api.helpers import get_resource_model
from mist.api.helpers import params_from_request
from mist.api.helpers import trigger_session_update

from mist.api.exceptions import NotFoundError
from mist.api.exceptions import UnauthorizedError
from mist.api.exceptions import RequiredParameterMissingError
from mist.api.users.models import User
from mist.api.auth.methods import auth_context_from_request


@view_config(route_name='api_v1_ownership', request_method='PUT')
def toggle_ownership(request):
    """
    Tags: ownership

    ---

    Toggle the Organization's `ownership_enabled` flag

    If set to True, then the ownership mappings will be taken into account
    when performing RBAC checks. If a user is a resource's owner, denoted
    in the `owned_by` field, then the user will have full access rights on
    that particular resource.

    This setting can be enabled/disabled ONLY by members of the Owners team.

    """
    auth_context = auth_context_from_request(request)

    if not auth_context.is_owner():
        raise UnauthorizedError('Available only to Owners')

    current_toggle = auth_context.owner.ownership_enabled
    auth_context.owner.ownership_enabled = not current_toggle
    auth_context.owner.save()

    trigger_session_update(auth_context.owner, 'org')

    return Response('OK', 200)


@view_config(route_name='api_v1_ownership', request_method='POST')
def transfer_ownership_to_user(request):
    """
    Tags: ownership

    ---

    Transfer ownership of a resource

    If a resource isn't owned by the requesting user, then an UnauthorizedError
    error will be thrown, unless the requesting user is a member of the Owners
    team.

    """
    auth_context = auth_context_from_request(request)
    params = params_from_request(request)

    if not params.get('user_id'):
        raise RequiredParameterMissingError('user_id')
    try:
        new_owner = User.objects.get(id=params['user_id'])
    except User.DoesNotExist:
        raise NotFoundError('User with id %s' % params['user_id'])

    for rtype, rids in params.get('resources', {}).items():
        Model = get_resource_model(rtype)
        for rid in rids:
            try:
                resource = Model.objects.get(owner=auth_context.owner, id=rid)
                resource.transfer_ownership(auth_context, new_owner)
            except Model.DoesNotExist:
                raise NotFoundError('%s with id %s' % (rtype, rid))

    trigger_session_update(auth_context.owner)

    return Response('OK', 200)
