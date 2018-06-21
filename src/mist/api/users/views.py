import logging

from pyramid.response import Response

from mongoengine import DoesNotExist

from mist.api.exceptions import MethodNotAllowedError, UserNotFoundError
from mist.api.exceptions import BadRequestError, RequiredParameterMissingError
from mist.api.exceptions import UnauthorizedError

from mist.api.helpers import trigger_session_update
from mist.api.helpers import params_from_request
from mist.api.helpers import view_config

from mist.api.auth.methods import user_from_request
from mist.api.auth.methods import auth_context_from_request

from mist.api.users.models import User
from mist.api.users.models import Avatar

from mist.api import config

logging.basicConfig(level=config.PY_LOG_LEVEL,
                    format=config.PY_LOG_FORMAT,
                    datefmt=config.PY_LOG_FORMAT_DATE)
log = logging.getLogger(__name__)
OK = Response("OK", 200)


# SEC
@view_config(route_name='delete_account', request_method='POST')
def delete_account(request):
    """
    A user requests his account to be deleted. In order to verify the request
    the user's password should be included as a parameter.
    """
    email = request.matchdict['email']
    params = params_from_request(request)
    plaintext_password = params.get('password', None)
    if not email:
        raise ValueError('No email provided')

    if config.SSO_TEST_EMAIL == "":
        raise MethodNotAllowedError("Configuration error")

    # SEC only allow test user to self delete
    if email != config.SSO_TEST_EMAIL:
        raise MethodNotAllowedError("This method is only for the test user")

    try:
        user = User.objects.get(email=email)
    except UserNotFoundError:
        return OK
    if not user.check_password(password=plaintext_password):
        raise MethodNotAllowedError("Password is wrong!!")
    user.delete()
    return OK


# SEC
@view_config(route_name='api_v1_account', request_method='POST',
             renderer='json')
def update_user_settings(request):
    """
    Tags: users
    ---
    User related actions
    Edit name, Update password
    """

    # SEC raise exception if not user
    user = user_from_request(request)

    auth_context = auth_context_from_request(request)

    params = params_from_request(request)

    action = params.get('action')
    actions = ['update_details', 'update_password']
    if action not in actions:
        log.error("Update_user_settings bad action='%s'", action)
        raise BadRequestError('action')

    if action == 'update_details':
        avatar = params.get('avatar')
        if avatar:
            try:
                Avatar.objects.get(id=avatar)
                user.avatar = avatar
            except DoesNotExist:
                raise BadRequestError('Avatar does not exist')
        if params.get('first_name') or params.get('last_name'):
            user.first_name = params.get('first_name')
            user.last_name = params.get('last_name')
        elif params.get('name'):
            name_array = params.get('name').split(' ')
            if len(name_array) > 1:
                user.last_name = name_array[-1]
            user.first_name = ' '.join(name_array[:-1])
        user.save()
        trigger_session_update(auth_context.owner, ['user'])
        return {}

    if action == 'update_password':
        current_password = params.get('current_password', '')
        password = params.get('password', '')
        # check if current_password provided
        if not current_password and (user.password and user.password != ''):
            raise RequiredParameterMissingError("Current password")
        # check if new password provided
        if not password:
            raise RequiredParameterMissingError("New password")

        # SEC check if current_password valid
        if not user.check_password(current_password):
            raise UnauthorizedError("Invalid current password")

        # set new password
        user.set_password(password)
        return {}
