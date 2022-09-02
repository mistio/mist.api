import random
import string
import urllib.request
import urllib.parse
import urllib.error

from datetime import datetime

from future.utils import string_types

from mongoengine import DoesNotExist

from mist.api.users.models import Organization, User

import mist.api.helpers

from mist.api.exceptions import ConflictError
from mist.api.exceptions import RedirectError
from mist.api.exceptions import UserNotFoundError
from mist.api.exceptions import UserUnauthorizedError
from mist.api.exceptions import AdminUnauthorizedError
from mist.api.exceptions import InternalServerError

from mist.api.portal.models import Portal

from mist.api.auth.tasks import revoke_token
from mist.api.auth.models import ApiToken
from mist.api.auth.models import SessionToken

from mist.api import config

if config.HAS_RBAC:
    from mist.rbac.tokens import SuperToken
    from mist.rbac.methods import AuthContext
else:
    from mist.api.dummy.rbac import AuthContext

if 'auth' in config.PLUGINS:
    # Required to initialize OAuth2SessionToken model, subclass of AuthToken.
    from mist.auth.social.models import OAuth2SessionToken  # noqa: F401


def migrate_old_api_token(request):
    """Migrate old API tokens (aka mist_1: email:token) to new ApiTokens"""

    # check if auth header with old api token format and migrate if needed
    auth_header = request.headers.get('Authorization', '').lower()
    if not auth_header:
        return
    parts = auth_header.split(" ", 1)
    mist_label = parts[0]
    if not mist_label.startswith('mist_'):
        return
    if len(parts) == 1:
        return
    api_version = mist_label[5:]
    header_content = parts[1]
    if api_version != "1":
        return
    parts = header_content.split(":")
    if len(parts) != 2:
        return
    email, mist_api_token = parts

    if not mist_api_token:
        return

    if len(mist_api_token) > 64:
        raise ValueError('Token is larger than 64 characters')

    # migrate old api token to new ApiToken if needed
    try:
        # if token is less than 64 characters then add 0's at the beginning
        # and search for that token
        padding = 64 - len(mist_api_token)
        padded_mist_api_token = '0' * padding + mist_api_token
        token = ApiToken.objects.get(token=padded_mist_api_token)
    except DoesNotExist:
        try:
            user = User.objects.get(email=email)
        except UserNotFoundError:
            return
        if not user.mist_api_token or user.mist_api_token != mist_api_token:
            return

        # if token is shorter than 64 chars then add padding with 0's
        # and save it that way
        padding = 64 - len(mist_api_token)
        padded_mist_api_token = '0' * padding + mist_api_token

        token = ApiToken(token=padded_mist_api_token, user_id=user.get_id(),
                         name=get_random_name_for_token(user),
                         ip_address=mist.api.helpers.ip_from_request(request),
                         user_agent=request.user_agent)
        token.save()
    return token


def session_from_request(request):
    """Get SessionToken or ApiToken instance from request"""
    if 'session' in request.environ:
        return request.environ['session']
    session = migrate_old_api_token(request)
    if session is None:
        auth_value = request.headers.get('Authorization', '').lower()
        if auth_value.startswith('internal'):
            parts = auth_value.split(' ')
            if len(parts) == 3:
                internal_api_key, session_id = parts[1:]
                if internal_api_key == Portal.get_singleton().internal_api_key:
                    try:
                        session_token = SessionToken.objects.get(
                            token=session_id)
                    except SessionToken.DoesNotExist:
                        pass
                    else:
                        if session_token.is_valid():
                            session_token.internal = True
                            session = session_token
        elif auth_value:
            token_from_request = auth_value
            try:
                api_token = ApiToken.objects.get(
                    token=token_from_request
                )
            except DoesNotExist:
                api_token = None
            try:
                if not api_token and config.HAS_RBAC:
                    api_token = SuperToken.objects.get(
                        token=token_from_request)
            except DoesNotExist:
                pass
            if api_token and api_token.is_valid():
                session = api_token
            else:
                session = ApiToken()
                session.name = 'dummy_token'
    if session is None:
        try:
            session_token = SessionToken.objects.get(
                token=request.cookies.get('session.id')
            )
            if session_token.is_valid():
                session = session_token
        except DoesNotExist:
            pass
    if session is None:
        session = SessionToken(
            user_agent=request.user_agent,
            ip_address=mist.api.helpers.ip_from_request(request)
        )
        session.save()
    request.environ['session'] = session
    return session


def user_from_request(request, admin=False, redirect=False):
    """Given request, initiate User instance (mist.api.users.model.User)

    First try to check if there is a valid api token header, else check if
    there is a valid cookie session, else raise UserUnauthorizedError.

    If admin is True, it will check if user obtained is an admin and will raise
    an AdminUnauthorizedError otherwise.

    If redirect is True and no valid api token or cookie session exists,
    redirect user to login. Once logged in, he will be redirected back to the
    page he was trying to visit the first time.

    If no exceptions were raised and no redirects made, it returns the user
    object.

    """
    token = session_from_request(request)
    user = token.get_user()
    if user is None:
        # Redirect to login
        if redirect and request.method == 'GET':
            if not isinstance(token, SessionToken) or not token.get_user():
                query = ''
                if request.query_string:
                    query = '?' + request.query_string
                return_to = urllib.parse.quote(request.path + query)
                url = "/login?return_to=" + return_to
                raise RedirectError(url)
        raise UserUnauthorizedError()
    # check if admin
    if admin and user.role != 'Admin':
        raise AdminUnauthorizedError(user.email)
    return user


def user_from_session_id(session_id):
    """Returns user associated with given cookie session id"""
    try:
        user = SessionToken.objects.get(token=session_id).get_user()
        if user is not None:
            return user
    except DoesNotExist:
        pass
    raise UserUnauthorizedError()


def auth_context_from_auth_token(token):
    user = token.get_user()
    if user is None:
        raise UserUnauthorizedError()
    return AuthContext(user, token)


def auth_context_from_request(request):
    return auth_context_from_auth_token(session_from_request(request))


def auth_context_from_session_id(session_id):
    """Returns auth_context associated with given cookie session id"""
    try:
        session = SessionToken.objects.get(token=session_id)
    except DoesNotExist:
        raise UserUnauthorizedError()
    return auth_context_from_auth_token(session)


def reissue_cookie_session(request, user_id='', su='', org=None, after=0,
                           TokenClass=SessionToken, **kwargs):
    """Invalidate previous cookie session and issue a fresh one

    Params `user_id` and `su` can be instances of `User`, `user_id`s or emails.

    """
    # First invalidate the current empty session
    session = session_from_request(request)
    if not isinstance(session, SessionToken):
        raise Exception("Can not reissue an API token session.")

    if after:
        revoke_token.send_with_options(
            args=(session.token, ), delay=after * 1000)
    else:
        session.invalidate()
        session.save()

    kwargs.update({
        'ip_address': mist.api.helpers.ip_from_request(request),
        'user_agent': request.user_agent,
    })

    # And then issue the new session
    new_session = TokenClass(**kwargs)

    # Pass on fingerprint & experiment choice to new session
    if session.fingerprint:
        new_session.fingerprint = session.fingerprint
    if session.experiment:
        new_session.experiment = session.experiment
    if session.choice:
        new_session.choice = session.choice

    session = new_session
    if user_id or su:
        # A user will be set to the session
        user_for_session = su if su else user_id
        user_is_effective = not user_id
        if isinstance(user_for_session, string_types):
            # Get the user object if an id has been provided
            if '@' in user_for_session:
                user_for_session = User.objects.get(email=user_for_session)
            else:
                user_for_session = User.objects.get(id=user_for_session)

        session.set_user(user_for_session, effective=user_is_effective)
        session.orgs = Organization.objects(
            members=user_for_session).order_by('-last_active')
        if org:
            org_index = session.orgs.index(org)
            # Bring selected org first if necessary
            if org_index > 0:
                session.orgs[org_index] = session.orgs[0]
                session.orgs[0] = org
                org.last_active = datetime.now()
                org.save()

    session.su = su
    session.save()
    request.environ['session'] = session
    return session


def token_with_name_not_exists(user, name):
    api_tokens = ApiToken.objects(user_id=user.get_id(), name=name)
    for token in api_tokens:
        if token.is_valid():
            raise ConflictError('Token with name %s already exists' % name)


def get_random_name_for_token(user):
    # produce a random name and make sure that this will not fall in an
    # infinite loop. if it can't get a valid new name then throw an exception
    for _ in range(10000):
        xyz = ''.join(random.choice(string.digits) for _ in range(5))
        api_token_name = "api_token_" + xyz
        try:
            token_with_name_not_exists(user, api_token_name)
            return api_token_name
        except ConflictError:
            pass
    raise InternalServerError('Could not produce random api token name for '
                              'user %s' % user.email)


def get_csrf_token(request):
    """
    Returns the CSRF token registered to this request's user session.
    """
    session = session_from_request(request)
    return session.csrf_token if isinstance(session, SessionToken) else ''
