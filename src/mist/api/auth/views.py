import mongoengine as me

from future.utils import string_types

from pyramid.response import Response
from pyramid.httpexceptions import HTTPFound

from mist.api.users.models import User, Organization
from mist.api.auth.models import ApiToken
from mist.api.auth.models import AuthToken, SessionToken
from mist.api.auth.methods import get_random_name_for_token
from mist.api.auth.methods import auth_context_from_request
from mist.api.auth.methods import token_with_name_not_exists
from mist.api.auth.methods import reissue_cookie_session
from mist.api.auth.methods import user_from_request

from mist.api.notifications.models import EmailNotification
from mist.api.notifications.channels import EmailNotificationChannel

from mist.api.helpers import ip_from_request, send_email
from mist.api.helpers import view_config, params_from_request

from mist.api.exceptions import NotFoundError
from mist.api.exceptions import BadRequestError, UserUnauthorizedError
from mist.api.exceptions import RequiredParameterMissingError, ForbiddenError
from mist.api.exceptions import UserNotFoundError

from mist.api import config

OK = Response("OK", 200)


@view_config(route_name='api_v1_tokens', request_method='GET', renderer='json')
def list_tokens(request):
    """
    Tags: api_tokens
    ---
    Lists user's api tokens
    ---
    """
    # FIXME: should call an optimized methods.list_tokens
    auth_context = auth_context_from_request(request)
    api_tokens = ApiToken.objects(user_id=auth_context.user.id, revoked=False)
    tokens_list = []
    for token in api_tokens:
        if token.is_valid():
            token_view = token.get_public_view()
            if token_view['last_accessed_at'] == 'None':
                token_view['last_accessed_at'] = 'Never'
            tokens_list.append(token_view)

    # If user is owner also include all active tokens in the current org
    # context
    if auth_context.is_owner():
        org_tokens = ApiToken.objects(orgs=auth_context.org, revoked=False)
        for token in org_tokens:
            if token.is_valid():
                token_view = token.get_public_view()
                if token_view['last_accessed_at'] == 'None':
                    token_view['last_accessed_at'] = 'Never'
                try:
                    tokens_list.index(token_view)
                except ValueError:
                    tokens_list.append(token_view)
    return tokens_list


@view_config(route_name='api_v1_tokens', request_method='POST',
             renderer='json')
def create_token(request):
    """
    Tags: api_tokens
    ---
    Creates a new api token.
    Used so that a user can send his credentials and produce a new api token.
    The api token itself will be returned in a json document along with it's
    id and it's name.
    If user has used su then he should provide his own credentials.However, the
    api token will authenticate the user he is impersonating.
    If name is not sent then a random one with the format api_token_xyz where
    xyz is a number will be produced.
    If the user provides a name then there must be no other token for that user
    with the same name.
    If the user has a cookie or sends an api token in the request headers then
    the username and password must belong to him.
    Used by io to authenticate to core (when running separately. Io sends
    user's email and password. We return an access token that will be used to
    authenticate any further communications.
    An anti-CSRF token is not needed to access this api call.
    If user is coming from oauth then he will be able to create a new token
    without a password provided he is authenticated somehow.
    If you are using the /auth route please switch to /api_v1_tokens route. The
    /auth route is deprecated.
    ---
    email:
      description: User's email
      type: string
      required: true
    password:
      description: User's password
      type: string
      required: true
    name:
      description: Api token name
      type: string
    ttl:
      description: Time to live for the token
      type: integer
    org_id:
      description: Org id if the token will be used in organizational context
      type: string
    """
    params = params_from_request(request)
    email = params.get('email', '').lower()
    # (Account Takeover) Security Fix 1/2
    password = params.get('password', '')
    api_token_name = params.get('name', '')
    org_id = params.get('org_id', '')
    ttl = params.get('ttl', 60 * 60)
    if isinstance(ttl, string_types) and not ttl.isdigit():
        raise BadRequestError('Ttl must be a number greater than 0')
    ttl = int(ttl)
    if ttl < 0:
        raise BadRequestError('Ttl must be greater or equal to zero')
    try:
        auth_context = auth_context_from_request(request)
        user, org = auth_context.user, auth_context.org
    except UserUnauthorizedError:
        # The following should apply, but currently it can't due to tests.
        # if not org_id:
        #     raise RequiredParameterMissingError("No org_id provided")
        if not email:
            raise RequiredParameterMissingError("No email provided")
        org = None
        if org_id:
            try:
                org = Organization.objects.get(id=org_id)
            except Organization.DoesNotExist:
                try:
                    org = Organization.objects.get(name=org_id)
                except Organization.DoesNotExist:
                    # The following should apply, but currently it can't due to
                    # tests.
                    # raise UserUnauthorizedError()
                    pass
        try:
            user = User.objects.get(email=email)
            # (Account Takeover) Security Fix 2/2: Prevent unauthorized API token creation  
            # Ensure the authenticated user owns the account before issuing a token 
            if not user.check_password(password):  
                raise UserUnauthorizedError("Invalid credentials")
        except User.DoesNotExist:
            raise UserUnauthorizedError("Invalid credentials")
        # Remove org is not None when we enforce org context on tokens.
        if org is not None and user not in org.members:
            raise ForbiddenError()

    if user.status != 'confirmed':
        raise UserUnauthorizedError()

    if not org:
        org = reissue_cookie_session(request, user.id).org
    # first check if the api token name is unique if it has been provided
    # otherwise produce a new one.
    if api_token_name:
        # will raise exception if there exists valid token with given name
        token_with_name_not_exists(user, api_token_name)
    else:
        api_token_name = get_random_name_for_token(user)
    tokens_num = len([token for token in ApiToken.objects(user_id=user.id,
                                                          revoked=False)
                      if token.is_valid()])
    if tokens_num < config.ACTIVE_APITOKEN_NUM:
        new_api_token = ApiToken()
        new_api_token.name = api_token_name
        new_api_token.orgs = [org]
        new_api_token.ttl = ttl
        new_api_token.set_user(user)
        new_api_token.ip_address = ip_from_request(request)
        new_api_token.user_agent = request.user_agent
        new_api_token.save()
    else:
        raise BadRequestError("MAX number of %s active tokens reached"
                              % config.ACTIVE_APITOKEN_NUM)
    subject = config.CREATE_APITOKEN_SUBJECT.format(
        portal_name=config.PORTAL_NAME)

    body = config.CREATE_APITOKEN_BODY.format(
        fname=user.first_name, ip_addr=ip_from_request(request),
        portal_uri=config.PORTAL_URI, support_email=config.EMAIL_SUPPORT,
        portal_name=config.PORTAL_NAME)
    notification = EmailNotification(subject=subject, text_body=body,
                                     owner=org)
    notification_channel = EmailNotificationChannel(notification=notification)
    notification_channel.send(users=[user])

    token_view = new_api_token.get_public_view()
    token_view['last_accessed_at'] = 'Never'
    token_view['token'] = new_api_token.token

    return token_view


@view_config(route_name='api_v1_sessions', request_method='GET',
             renderer='json')
def list_sessions(request):
    """
    Tags: sessions
    ---
    Lists active sessions
    ---
    """
    auth_context = auth_context_from_request(request)
    session = request.environ['session']
    # Get active sessions for the current user
    session_tokens = SessionToken.objects(user_id=auth_context.user.id,
                                          revoked=False)
    sessions_list = []
    for token in session_tokens:
        if token.is_valid():
            public_view = token.get_public_view()
            if isinstance(session, SessionToken) and session.id == token.id:
                public_view['active'] = True
            sessions_list.append(public_view)

    # If user is owner include all active sessions in the org context
    if auth_context.is_owner():
        org_tokens = SessionToken.objects(orgs=auth_context.org, revoked=False)
        for token in org_tokens:
            if token.is_valid():
                public_view = token.get_public_view()
                if isinstance(session, SessionToken) and \
                   session.id == token.id:
                    public_view['active'] = True
                try:
                    sessions_list.index(public_view)
                except ValueError:
                    sessions_list.append(public_view)

    return sessions_list


# SEC FIXME add permission checks
@view_config(route_name='api_v1_tokens', request_method='DELETE')
def revoke_token(request):
    """
    Tags: api_tokens
    ---
    Revokes api token
    ---
    id:
      description: Api token ID
      type: string
      required: true
    """
    return revoke_session(request)


# SEC do we need permission checks here ?
@view_config(route_name='api_v1_sessions', request_method='DELETE')
def revoke_session(request):
    """
    Tags: sessions
    ---
    Revoke an active session
    ---
    id:
      description: Session ID
    """

    auth_context = auth_context_from_request(request)
    params = params_from_request(request)
    auth_token_id = params.get("id")

    if not auth_token_id:
        raise RequiredParameterMissingError("No token id parameter provided")

    try:
        if auth_context.is_owner():
            auth_token = AuthToken.objects.get(orgs=auth_context.org,
                                               id=auth_token_id)
        else:
            auth_token = AuthToken.objects.get(
                user_id=auth_context.user.get_id(), id=auth_token_id)
        if auth_token.is_valid():
            auth_token.invalidate()
            auth_token.save()

    except me.DoesNotExist:
        raise NotFoundError('Session not found')

    return OK


# SEC
@view_config(route_name='su', request_method='GET')
def su(request):
    """
    Impersonate another user.

    This allows an admin to take the identity of any other user. It is meant to
    be used strictly for debugging. You can return to your regular user simply
    by logging out. This won't affect the last login time of the actual user.
    An email should be immediately sent out to the team, notifying of the 'su'
    action for security reasons.

    """
    # SEC raise exception if user not admin
    user = user_from_request(request, admin=True)

    session = request.environ['session']
    if isinstance(session, ApiToken):
        raise ForbiddenError('Cannot do su when authenticated with api token')
    real_email = user.email
    params = params_from_request(request)
    email = params.get('email')
    if not email:
        raise RequiredParameterMissingError('email')
    try:
        user = User.objects.get(email=email)
    except (UserNotFoundError, User.DoesNotExist):
        raise UserUnauthorizedError()
    reissue_cookie_session(request, real_email, su=user.id)

    # alert admins
    subject = "Some admin used su"
    body = "Admin: %s\nUser: %s\nServer: %s" % (real_email, user.email,
                                                config.PORTAL_URI)
    send_email(subject, body, config.NOTIFICATION_EMAIL['ops'])
    return HTTPFound('/')
