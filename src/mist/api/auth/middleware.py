import logging
import netaddr

from mist.api.logs.methods import log_event
from mist.api.helpers import ip_from_request
from mist.api.helpers import params_from_request

from mist.api.auth.models import ApiToken
from mist.api.auth.models import SessionToken

from mist.api.auth.methods import session_from_request
from mist.api.auth.methods import reissue_cookie_session

from mist.api import config

from pyramid.request import Request

if config.HAS_RBAC:
    from mist.rbac.tokens import ReadOnlyApiToken


log = logging.getLogger(__name__)


CORS_ENABLED_PATHS = ['/api/v1/clouds', '/api/v1/stacks', '/api/v1/report']


class AuthMiddleware(object):
    """ Authentication Middleware """
    def __init__(self, app):
        self.app = app
        self.routes_mapper = app.routes_mapper

    def __call__(self, environ, start_response):
        request = Request(environ)
        session = session_from_request(request)

        def session_start_response(status, headers, exc_info=None):
            session = environ['session']  # reload in case it was reissued
            if isinstance(session, SessionToken) and \
                    not getattr(session, 'internal', False) and \
                    not session.last_accessed_at:
                # (CSRF) Security Fix: Added SameSite=Strict flag to prevent CSRF attack
                # in admin's "su" operation. In case of having a cookie issue, consider 
                # removing and addressing the CSRF issue in another way
                cookie = 'session.id=%s; Path=/; SameSite=Strict;' % session.token
                headers.append(('Set-Cookie', cookie))

            # ApiTokens with 'dummy' in name are handed out by session from
            # request function when the api token is not correct, to prevent
            # csrf checks by the CsrfMiddleware but allow calls to function
            # that don't require authentication. When the response is sent out
            # they are to be thrown away, not saved.
            if not (isinstance(session, ApiToken) and
                    'dummy' in session.name or
                    getattr(session, 'internal', False)):
                session.touch()
                session.save()
            # CORS
            if (
                environ.get('HTTP_ORIGIN') and
                environ.get('PATH_INFO') in CORS_ENABLED_PATHS
            ):
                if (
                    'OPTIONS' in environ['REQUEST_METHOD'] or
                    isinstance(session, ApiToken)
                ):
                    for header in [
                        ('Access-Control-Allow-Origin',
                         environ['HTTP_ORIGIN']),
                        ('Access-Control-Allow-Methods', 'GET,OPTIONS'),
                        ('Access-Control-Allow-Headers',
                         'Origin, Content-Type, Accept, Authorization'),
                        ('Access-Control-Allow-Credentials', 'true'),
                        ('Access-Control-Max-Age', '1728000'),
                    ]:
                        headers.append(header)
                    if 'OPTIONS' in environ['REQUEST_METHOD']:
                        return start_response('204 No Content', headers,
                                              exc_info)

            return start_response(status, headers, exc_info)

        user = session.get_user()
        # Check whether the request IP is in the user whitelisted ones.
        if session and user is not None and request.path != '/logout' and \
                not getattr(session, 'internal', False):
            current_user_ip = netaddr.IPAddress(ip_from_request(request))
            saved_wips = [netaddr.IPNetwork(ip.cidr) for ip in user.ips]
            config_wips = [netaddr.IPNetwork(cidr)
                           for cidr in config.WHITELIST_CIDR]
            wips = saved_wips + config_wips
            if len(saved_wips) > 0:
                for ipnet in wips:
                    if current_user_ip in ipnet:
                        break
                else:
                    log_event(
                        owner_id=session.org.id,
                        user_id=user.id,
                        email=user.email,
                        request_method=request.method,
                        request_path=request.path,
                        request_ip=ip_from_request(request),
                        user_agent=request.user_agent,
                        event_type='ip_whitelist_mismatch',
                        action=request.path,
                        error=True,
                    )
                    # Only logout user if token is SessionToken
                    # Do not logout if it's ApiToken
                    if isinstance(session, SessionToken):
                        reissue_cookie_session(request)
                    start_response('403 Forbidden',
                                   [('Content-type', 'text/plain')])
                    return ["Request sent from non-whitelisted IP.\n"
                            "You have been logged out from this account.\n"
                            "Please sign in to request whitelisting your "
                            "current IP via email."]

        # Enforce read-only access.
        if config.HAS_RBAC:
            if isinstance(session, ReadOnlyApiToken):
                if request.method not in ('GET', 'HEAD', 'OPTIONS', ):
                    start_response('405 Method Not Allowed',
                                   [('Content-type', 'text/plain')])
                    return ['State-changing HTTP method not allowed\n']

        response = self.app(environ, session_start_response)
        return response


class CsrfMiddleware(object):
    """Middleware that performs CSRF token validation."""

    exempt = ('/new_metrics', '/stripe', '/tokens',
              '/api/v1/tokens', '/auth', '/api/v1/insights/register',
              '/api/v1/dev/register', '/api/v1/dev/users',
              '/api/v1/rule-triggered', )

    def __init__(self, app):
        self.app = app
        self.routes_mapper = app.routes_mapper

    def __call__(self, environ, start_response):
        request = Request(environ)
        session = environ['session']
        # when someone is POSTing to /auth (check_auth) then he is trying
        # to authenticate and does not have a csrf token in the SessionToken
        # which has been produced by default
        if request.path not in self.exempt and \
           isinstance(session, SessionToken) and \
           not getattr(session, 'internal', False) and \
           request.method in ('POST', 'PUT', 'PATCH', 'DELETE'):
            csrf_token = request.headers.get('Csrf-Token', '').lower()
            if not csrf_token:
                csrf_token = request.params.get('Csrf-Token', '').lower()
            if csrf_token != session.csrf_token:
                log.error("Bad CSRF token '%s'", csrf_token)
                user = session.get_user()
                if user is not None:
                    owner_id = session.org.id
                    user_id = user.id
                    email = user.email
                else:
                    owner_id = user_id = None
                    params = params_from_request(request)
                    email = params.get('email', '')
                log_event(
                    owner_id=owner_id,
                    user_id=user_id,
                    email=email,
                    request_method=request.method,
                    request_path=request.path,
                    request_ip=ip_from_request(request),
                    user_agent=request.user_agent,
                    csrf_token=csrf_token,
                    session_csrf=session.csrf_token,
                    event_type='request',
                    action='csrf_validation',
                    error=True,
                )
                start_response('403 Forbidden',
                               [('Content-Type', 'text/plain')])
                return ["Invalid csrf token\n"]
        return self.app(environ, start_response)
