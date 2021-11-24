from mist.api.helpers import view_config
from mist.api.helpers import params_from_request

from mist.api.exceptions import BadRequestError

from mist.api.auth.methods import auth_context_from_request
from mist.api.metering.methods import get_usage


@view_config(route_name='api_v1_metering', request_method='GET',
             renderer='json')
def metering(request):
    """
    Tags: metering
    ---
    Request metering data
    """
    auth_context = auth_context_from_request(request)
    params = params_from_request(request)
    # If requester is not admin ignore param org_id
    org_id = auth_context.owner.id
    if auth_context.user.role == 'Admin':
        org_id = params.get('org_id', auth_context.owner.id)
    try:
        start = params.get('start', 6)  # 1 week default.
        start = int(start)
    except ValueError:
        raise BadRequestError('Bad "start" offset: %s. Must be an int' % start)

    return get_usage(org_id, full_days=start)
