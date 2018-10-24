from functools import wraps

from mist.api import config

from mist.api.auth.methods import auth_context_from_request


def require_cc(func):
    """Raise an exception if CC is required, but not provided.

    This decorator can be used with any API endpoint in order
    to ensure that a CC has firsly been provided before proceeding.

    This decorator has to come after the view_config decorator
    in order to not disrupt Pyramid request routing.

    """

    @wraps(func)
    def wrapper(context, request):
        context = auth_context_from_request(request)
        if config.HAS_BILLING and context.user.registration_method != 'dev':
            from mist.billing.methods import card_exists_or_raise
            card_exists_or_raise(context.owner)
        return func(request)
    return wrapper
