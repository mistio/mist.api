"""mist.api.views

Here we define the HTTP API of the app. The view functions here are
responsible for taking parameters from the web requests, passing them on to
functions defined in methods and properly formatting the output. This is the
only source file where we import things from pyramid. View functions should
only check that all required params are provided. Any further checking should
be performed inside the corresponding method functions.

"""

import os
import hashlib
import html

import urllib.request
import urllib.parse
import urllib.error

import json
import netaddr
import traceback
import requests
import logging
import mongoengine as me

from time import time
from datetime import datetime, timedelta

from pyramid.response import Response
from pyramid.response import FileResponse
from pyramid.renderers import render_to_response
from pyramid.httpexceptions import HTTPFound
from pyramid.view import notfound_view_config

import mist.api.tasks as tasks
from mist.api.clouds.models import Cloud
from mist.api.machines.models import Machine
from mist.api.users.models import Avatar, Owner, User, Organization
from mist.api.users.models import MemberInvitation, Team
from mist.api.users.models import WhitelistIP
from mist.api.auth.models import SessionToken, ApiToken
from mist.api.users.methods import update_whitelist_ips

from mist.api.users.methods import register_user

from mist.api import methods

from mist.api.exceptions import RequiredParameterMissingError
from mist.api.exceptions import NotFoundError, BadRequestError, ForbiddenError
from mist.api.exceptions import ServiceUnavailableError
from mist.api.exceptions import MistError
from mist.api.exceptions import UnauthorizedError
from mist.api.exceptions import UserUnauthorizedError, RedirectError
from mist.api.exceptions import UserNotFoundError, ConflictError
from mist.api.exceptions import LoginThrottledError, TeamOperationError
from mist.api.exceptions import MemberConflictError, MemberNotFound
from mist.api.exceptions import OrganizationAuthorizationFailure
from mist.api.exceptions import OrganizationNameExistsError
from mist.api.exceptions import TeamForbidden
from mist.api.exceptions import OrganizationOperationError
from mist.api.exceptions import MethodNotAllowedError
from mist.api.exceptions import WhitelistIPError
from mist.api.exceptions import CloudNotFoundError

from mist.api.helpers import encrypt, decrypt
from mist.api.helpers import params_from_request
from mist.api.helpers import trigger_session_update
from mist.api.helpers import view_config, ip_from_request
from mist.api.helpers import send_email
from mist.api.helpers import get_file

from mist.api.auth.methods import auth_context_from_request
from mist.api.auth.methods import user_from_request, session_from_request
from mist.api.auth.methods import get_csrf_token
from mist.api.auth.methods import reissue_cookie_session
from mist.api.auth.models import get_secure_rand_token

from mist.api.logs.methods import log_event
from mist.api.logs.methods import get_events

from mist.api.methods import filter_list_locations
from mist.api import config


logging.basicConfig(level=config.PY_LOG_LEVEL,
                    format=config.PY_LOG_FORMAT,
                    datefmt=config.PY_LOG_FORMAT_DATE)
log = logging.getLogger(__name__)

OK = Response("OK", 200)


def get_ui_template(build_path=''):
    if build_path and build_path[0] != '/':
        build_path = '/' + build_path
    #     template_url = config.UI_TEMPLATE_URL_URL
    # else:
    #     template_url = config.UI_TEMPLATE_URL_URL + ':8000'
    template_url = config.UI_TEMPLATE_URL
    get_file(template_url + build_path, 'templates/ui.pt')


def get_landing_template(build_path=''):
    if build_path and build_path[0] != '/':
        build_path = '/' + build_path
        template_url = config.LANDING_TEMPLATE_URL
    else:
        template_url = config.LANDING_TEMPLATE_URL + ':8000'
    get_file(template_url + build_path, 'templates/landing.pt')


@view_config(context=Exception)
def exception_handler_mist(exc, request):
    """
    Here we catch exceptions and transform them to proper http responses
    This is a special pyramid view that gets triggered whenever an exception
    is raised from any other view. It catches all exceptions exc where
    isinstance(exc, context) is True.

    """
    # mongoengine ValidationError
    if isinstance(exc, me.ValidationError):
        trace = traceback.format_exc()
        log.warning("Uncaught me.ValidationError!\n%s", trace)
        return Response("Validation Error", 400)

    # mongoengine NotUniqueError
    if isinstance(exc, me.NotUniqueError):
        trace = traceback.format_exc()
        log.warning("Uncaught me.NotUniqueError!\n%s", trace)
        return Response("NotUniqueError", 409)

    # non-mist exceptions. that shouldn't happen! never!
    if not isinstance(exc, MistError):
        if not isinstance(exc, (me.ValidationError, me.NotUniqueError)):
            trace = traceback.format_exc()
            log.critical("Uncaught non-mist exception? WTF!\n%s", trace)
            return Response("Internal Server Error", 500)

    # mist exceptions are ok.
    log.info("MistError: %r", exc)

    # if it is a RedirectError, then send an HTTP Redirect
    if isinstance(exc, RedirectError):
        return HTTPFound(exc.url or '')

    # else translate it to HTTP response based on http_code attribute
    return Response(str(exc), exc.http_code)


@view_config(route_name='home', request_method='GET')
@view_config(route_name='ui_routes', request_method='GET')
def home(request):
    """
    User visits home page.
    Redirect to mist app if logged in, landing page otherwise.
    """
    params = params_from_request(request)

    build_path = ''
    if config.JS_BUILD and not params.get('debug'):
        build_path = 'build/%s/bundled/' % config.VERSION.get('sha')

    template_inputs = config.HOMEPAGE_INPUTS
    template_inputs['build_path'] = build_path
    template_inputs['csrf_token'] = json.dumps(get_csrf_token(request))

    try:
        user = user_from_request(request)
    except UserUnauthorizedError:
        external_auth = config.USE_EXTERNAL_AUTHENTICATION
        if external_auth:
            url = request.route_url(route_name='social.auth.login',
                                    backend=external_auth)
            raise RedirectError(url)

        get_landing_template(build_path)
        page = request.path.strip('/').replace('.', '')
        if not page:
            page = 'home'
        if page not in config.LANDING_FORMS:
            if 'blog' in page:
                uri_prefix = config.BLOG_CDN_URI or \
                    request.application_url + "/static/blog/dist"
                if params.get('page', None):
                    page = 'page%s' % params.get('page')
            else:
                uri_prefix = config.LANDING_CDN_URI or \
                    request.application_url + "/static/landing/sections/"
            page_uri = '%s/%s.html' % (uri_prefix.rstrip('/'), page)
            try:
                response = requests.get(page_uri)
                if response.ok:
                    try:
                        from bs4 import BeautifulSoup
                        soup = BeautifulSoup(response.text, 'html.parser')
                        body = soup.select('body')[0]
                        section = body.renderContents().decode()
                        titles = soup.select('title')
                        if titles:
                            template_inputs['title'] = titles[0].text
                        else:
                            template_inputs['title'] = '%s :: %s' % (
                                config.PORTAL_NAME, page)
                        descriptions = soup.select('meta[name="description"]')
                        if descriptions:
                            template_inputs['description'] = \
                                descriptions[0].get('content', '')
                        else:
                            template_inputs['description'] = config.DESCRIPTION
                        images = soup.select('meta[property="og:image"]')
                        if images:
                            img_uri = images[0].get('content', '')
                            if not img_uri.startswith('http'):
                                img_uri = config.PORTAL_URI + img_uri
                            template_inputs['image'] = img_uri
                        rss = soup.select('link[type="application/rss+xml"]')
                        if rss:
                            template_inputs['rss'] = rss[0].get('href')
                        template_inputs['url'] = request.url
                    except Exception as exc:
                        log.error("Failed to parse page `%s` from `%s`: %r" % (
                            page, page_uri, exc))
                        section = response.text
                    template_inputs['section'] = section
                else:
                    log.error("Failed to fetch page `%s` from `%s`: %r" % (
                        page, page_uri, response))
            except Exception as exc:
                log.error("Failed to fetch page `%s` from `%s`: %r" % (
                    page, page_uri, exc))
        return render_to_response('templates/landing.pt', template_inputs)

    if not user.last_active or \
            datetime.now() - user.last_active > timedelta(0, 300):
        user.last_active = datetime.now()
        user.save()

    auth_context = auth_context_from_request(request)
    if auth_context.org and (not auth_context.org.last_active or
       datetime.now() - auth_context.org.last_active > timedelta(0, 300)):
        auth_context.org.last_active = datetime.now()
        auth_context.org.save()

    get_ui_template(build_path)
    template_inputs['ugly_rbac'] = config.UGLY_RBAC
    return render_to_response('templates/ui.pt', template_inputs)


@notfound_view_config()
def not_found(request):
    request.response.status = 404
    params = params_from_request(request)

    build_path = ''
    if config.JS_BUILD and not params.get('debug'):
        build_path = '/build/%s/bundled/' % config.VERSION.get('sha')

    template_inputs = config.HOMEPAGE_INPUTS
    template_inputs['build_path'] = build_path
    template_inputs['csrf_token'] = json.dumps(get_csrf_token(request))

    try:
        user_from_request(request)
    except UserUnauthorizedError:
        external_auth = config.USE_EXTERNAL_AUTHENTICATION
        if external_auth:
            url = request.route_url(route_name='social.auth.login',
                                    backend=external_auth)
            raise RedirectError(url)

        get_landing_template(build_path)
        return render_to_response('templates/landing.pt', template_inputs,
                                  request=request,
                                  response=request.response)

    get_ui_template(build_path)
    template_inputs['ugly_rbac'] = config.UGLY_RBAC
    return render_to_response('templates/ui.pt', template_inputs,
                              request=request,
                              response=request.response)


# SEC
@view_config(route_name='login', request_method='POST', renderer='json')
@view_config(route_name='login_service', request_method='POST',
             renderer='json')
def login(request):
    """
    User posts authentication credentials (email/username, password).
    One of email/username must be given, not both.
    In case of binding with LDAP server, username must be given.
    If there is a 'return_to' parameter the user will be redirected to this
    local url upon successful authentication.
    There is also an optional 'service' parameter, mainly meant to be used for
    SSO.
    ---
    email:
      description: user's email
      type: string
      required: true
    username:
      description: LDAP's username
      type: string
    password:
      description: user's password
      type: string
      required: true
    service:
      description: used for SSO
      type: string

    """
    params = params_from_request(request)
    email = params.get('email')
    username = params.get('username', '')
    password = params.get('password', '')
    service = request.matchdict.get('service') or params.get('service') or ''
    return_to = params.get('return_to')
    if return_to:
        return_to = urllib.parse.unquote(return_to)
        # (Open Redirect) Security Fix: Prevent open redirect vulnerability by ensuring 
        # `return_to` is a safe relative URL
        if not return_to.startswith('/') or return_to.startswith('//'):
            raise BadRequestError("Invalid or unsafe redirect URL.")
    else:
        return_to = '/'
    token_from_params = params.get('token')
    if not email and not username:
        raise RequiredParameterMissingError('You must provide email or '
                                            'username')
    if email and username:
        raise BadRequestError('You can specify either an email or a username')

    if username:            # try to bind with LDAP server
        try:
            user = User.objects.get(username=username)
        except (UserNotFoundError, me.DoesNotExist):
            user = User(username=username)
        except me.MultipleObjectsReturned:
            users = User.objects(username=username)
            # TODO: is this really ok?
            for u in users:
                u.delete()
            user = User(username=username)

        if config.HAS_AUTH and config.LDAP_SETTINGS.get('SERVER', ''):
            if config.LDAP_SETTINGS.get('AD'):
                from mist.auth.social.methods import login_a_d_user
                email, fname, lname = login_a_d_user(
                    config.LDAP_SETTINGS.get('SERVER'),
                    username, password, user)
            else:
                from mist.auth.social.methods import login_ldap_user
                email, fname, lname = login_ldap_user(
                    config.LDAP_SETTINGS.get('SERVER'),
                    username, password, user)
            user.email = email
            user.first_name = fname
            user.last_name = lname
            user.save()
        else:
            raise BadRequestError("Cannot use LDAP authentication")

    else:
        email = email.lower()
        try:
            user = User.objects.get(email=email)
        except (UserNotFoundError, me.DoesNotExist):
            raise UserUnauthorizedError()
        if not user.status == 'confirmed':
            raise UserUnauthorizedError("User account has not been confirmed.")

        if password:
            # rate limit user logins
            max_logins = config.FAILED_LOGIN_RATE_LIMIT['max_logins']
            max_logins_period = config.FAILED_LOGIN_RATE_LIMIT[
                'max_logins_period']
            block_period = config.FAILED_LOGIN_RATE_LIMIT['block_period']

            # check if rate limiting in place
            incidents = get_events(auth_context=None, user_id=user.id,
                                   event_type='incident',
                                   action='login_rate_limiting',
                                   start=time() - max_logins_period)
            incidents = [inc for inc in incidents
                         if inc.get('ip') == ip_from_request(request)]
            if len(incidents):
                secs = incidents[0]['time'] + block_period - time()
                raise LoginThrottledError("Try again in %d seconds." % secs)

            if not user.check_password(password):
                # check if rate limiting condition just got triggered
                logins = list(get_events(
                    auth_context=None, user_id=user.id, event_type='request',
                    action='login', error=True,
                    start=time() - max_logins_period))
                logins = [login for login in logins
                          if login.get(
                              'request_ip') == ip_from_request(request)]
                if len(logins) > max_logins:
                    log_event(owner_id=user.id, user_id=user.id,
                              event_type='incident',
                              action='login_rate_limiting',
                              ip=ip_from_request(request))
                    # alert admins something nasty is going on
                    subject = \
                        config.FAILED_LOGIN_ATTEMPTS_EMAIL_SUBJECT.format(
                            portal_name=config.PORTAL_NAME
                        )
                    body = config.FAILED_LOGIN_ATTEMPTS_EMAIL_BODY.format(
                        email=user.email,
                        ip_addr=ip_from_request(request),
                        failed_attempts=max_logins,
                        time_period=max_logins_period,
                        block_period=block_period
                    )
                    send_email(subject, body, config.NOTIFICATION_EMAIL['ops'])
                raise UserUnauthorizedError()
        elif token_from_params:
            try:
                auth_token = ApiToken.objects.get(user_id=user.id,
                                                  token=token_from_params)
            except me.DoesNotExist:
                auth_token = None
            if not (auth_token and auth_token.is_valid()):
                raise UserUnauthorizedError()
            auth_token.touch()
            auth_token.save()
        else:
            raise RequiredParameterMissingError("'password' or 'token'")

    # Check whether the request IP is in the user whitelisted ones.
    current_user_ip = netaddr.IPAddress(ip_from_request(request))
    saved_wips = [netaddr.IPNetwork(ip.cidr) for ip in user.ips]
    config_wips = [netaddr.IPNetwork(cidr) for cidr in config.WHITELIST_CIDR]
    wips = saved_wips + config_wips
    if len(saved_wips) > 0:
        for ipnet in wips:
            if current_user_ip in ipnet:
                break
        else:
            raise WhitelistIPError()

    reissue_cookie_session(request, user)

    user.last_login = time()
    user.user_agent = request.user_agent
    user.save()

    if not service:
        # TODO: check that return_to is a local url
        redirect = return_to
    else:
        raise BadRequestError("Invalid service '%s'." % service)

    if params.get('invitoken'):
        confirm_invitation(request)

    return {
        'auth': True,
        'redirect': redirect,
        'csrf_token': get_csrf_token(request),
    }


@view_config(route_name='switch_context', request_method='GET')
@view_config(route_name='switch_context_org', request_method='GET')
def switch_org(request):
    """
    Switch user's context.
    Personal or organizational
    ---
    org_id:
      description: The team's org id
      type: string
      required: true
    """
    org_id = request.matchdict.get('org')
    user = user_from_request(request)
    params = params_from_request(request)
    return_to = params.get('return_to', '')
    org = None
    if org_id:
        try:
            org = Organization.objects.get(id=org_id)
        except me.DoesNotExist:
            raise ForbiddenError()
        if org.parent:
            parent_owners = org.parent.teams.get(name='Owners').members
            if user not in org.members + parent_owners:
                raise ForbiddenError()
        elif user not in org.members:
            raise ForbiddenError()
    reissue_cookie_session(request, user, org=org, after=1)
    raise RedirectError(urllib.parse.unquote(return_to) or '/')


@view_config(route_name='login', request_method='GET')
@view_config(route_name='login_service', request_method='GET')
def login_get(request):
    """
    User visits login form.
    If there is a 'return_to' parameter the user will be redirected to this
    local url upon successful authentication.
    There is also an optional 'service' parameter, mainly meant to be used for
    SSO.
    ---
    return_to:
      description: if exists, redirect user
      type: string
    service:
      description: used for SSO
      type: string
    """

    # check if user sent a GET instead of POST, process it accordingly
    try:
        ret = login(request)
        if ret['auth']:
            return HTTPFound(ret['redirect'])
    except:
        pass
    service = request.matchdict.get('service', '')
    params = params_from_request(request)
    return_to = params.get('return_to', '')
    invitoken = params.get('invitoken', '')
    try:
        user_from_request(request)
        if not service:
            return HTTPFound(urllib.parse.unquote(return_to) or '/')
        raise BadRequestError("Invalid service '%s'." % service)
    except UserUnauthorizedError:
        path = "sign-in"
        query_params = {}
        if return_to:
            query_params['return_to'] = return_to
        if invitoken:
            query_params['invitoken'] = invitoken
        if query_params:
            path += '?' + urllib.parse.urlencode(query_params)
        return HTTPFound(path)


@view_config(route_name='logout', request_method=('GET', 'POST'))
def logout(request):
    """
    User logs out.
    If user is an admin under su, he returns to his regular user.
    """
    user = user_from_request(request)
    session = session_from_request(request)
    if isinstance(session, ApiToken):
        raise ForbiddenError('If you wish to revoke a token use the /tokens'
                             ' path')
    real_user = session.get_user(effective=False)
    if user != real_user:
        log.warn("Su logout")
        reissue_cookie_session(request, real_user)
    else:
        reissue_cookie_session(request)

    return HTTPFound('/')


@view_config(route_name='register', request_method='POST', renderer='json')
def register(request):
    """
    New user signs up.
    """
    params = params_from_request(request)
    email = params.get('email')
    promo_code = params.get('promo_code')
    name = params.get('name')
    token = params.get('token')
    selected_plan = params.get('selected_plan')
    request_demo = params.get('request_demo', False)
    request_beta = params.get('request_beta', False)

    if not email or not email.strip():
        raise RequiredParameterMissingError('email')
    if not name or not name.strip():
        raise RequiredParameterMissingError('name')
    if type(request_demo) != bool:
        raise BadRequestError('Request demo must be a boolean value')

    name = name.strip().split(" ", 1)
    email = email.strip().lower()

    if type(name) == str:
        name = name.encode('utf-8', 'ignore')
    if not request_beta:
        try:
            user = User.objects.get(email=email)
            if user.status == 'confirmed' and not request_demo:
                raise ConflictError("User already registered "
                                    "and confirmed email.")
        except me.DoesNotExist:
            first_name = name[0]
            last_name = name[1] if len(name) > 1 else ""
            user, org = register_user(email, first_name, last_name, 'email',
                                      selected_plan, promo_code, token,
                                      request=request)

        if user.status == 'pending':
            # if user is not confirmed yet resend the email
            subject = config.CONFIRMATION_EMAIL_SUBJECT.format(
                portal_name=config.PORTAL_NAME)
            body = config.CONFIRMATION_EMAIL_BODY.format(
                fname=user.first_name, ip_addr=ip_from_request(request),
                portal_uri=config.PORTAL_URI, follow_us=config.FOLLOW_US,
                portal_name=config.PORTAL_NAME,
                activation_key=user.activation_key)

            if not send_email(subject, body, user.email):
                raise ServiceUnavailableError("Could not send "
                                              "confirmation email.")

    # TODO: Move to mist.billing or remove altogether
    if request_demo:
        # if user requested a demo then notify the mist.api team
        subject = "Demo request"
        body = "User %s has requested a demo\n" % user.email
        tasks.send_email.send(subject, body, config.NOTIFICATION_EMAIL['demo'])
        user.requested_demo = True
        user.demo_request_date = time()
        user.save()

        msg = (
            "Dear %s %s, we will contact you within 24 hours to schedule a "
            "demo. In the meantime, we sent you an activation email so you"
            " can create an account to test Mist.io. If the email doesn't"
            " appear in your inbox, check your spam folder."
        ) % (user.first_name, user.last_name)
    elif request_beta:
        user = None
        # if user requested a demo then notify the mist.api team
        subject = "Private beta request"
        body = "User %s <%s> has requested access to the private beta\n" % (
            params.get('name').encode('utf-8', 'ignore'), email)
        tasks.send_email.send(subject, body, config.NOTIFICATION_EMAIL['demo'])

        msg = (
            "Dear %s, we will contact you within 24 hours with more "
            "information about the Mist.io private beta program. In the "
            "meantime, if you have any questions don't hesitate to contact"
            " us at info@mist.api"
        ) % params.get('name').encode('utf-8', 'ignore')
    else:
        msg = (
            "Dear %s,\n"
            "you will soon receive an activation email. "
            "If it does not appear in your Inbox within "
            "a few minutes, please check your spam folder.\n"
        ) % user.first_name

    return {
        'msg': msg,
        'user_ga_id': user and user.get_external_id('ga'),
        'user_id': user and user.id}


@view_config(route_name='confirm', request_method='GET')
def confirm(request):
    """
    Confirm a user's email address when signing up.
    After registering, the user is sent a confirmation email to his email
    address with a link containing a token that directs the user to this view
    to confirm his email address.
    If invitation token exists redirect to set_password or to social auth
    """
    params = params_from_request(request)
    key = params.get('key')
    if not key:
        raise RequiredParameterMissingError('key')

    try:
        user = User.objects.get(activation_key=key)
    except me.DoesNotExist:
        return HTTPFound('/error?msg=bad-key')
    if user.status != 'pending' or user.password:
        # if user has an invitation token but has been confirmed call the
        # confirm invitation token
        if params.get('invitoken'):
            return confirm_invitation(request)
        else:
            return HTTPFound('/error?msg=already-confirmed')

    token = hashlib.sha1(key.encode()).hexdigest()
    key = encrypt("%s:%s" % (token, user.email), config.SECRET)
    user.password_set_token = token
    user.password_set_token_created = time()
    user.password_set_user_agent = request.user_agent
    log.debug("will now save (register)")
    user.save(write_concern={'w': 1, 'fsync': True})

    invitoken = params.get('invitoken')
    if config.ALLOW_SIGNIN_EMAIL:
        url = request.route_url('set_password', _query={'key': key})
    elif config.ALLOW_SIGNIN_GOOGLE:
        url = '/social_auth/login/google-oauth2?key=%s' % key
    elif config.ALLOW_SIGNIN_GITHUB:
        url = '/social_auth/login/github-oauth2?key=%s' % key
    elif config.ALLOW_SIGNIN_MS365:
        url = '/social_auth/login/azuread-oauth2?key=%s' % key
    elif config.ALLOW_SIGNIN_CILOGON:
        url = '/social_auth/login/cilogon-oauth2?key=%s' % key
    else:
        log.error('Confirm invitation attempt with sign-in disabled')
        raise ForbiddenError("No sign-in method configured.")

    if invitoken:
        try:
            MemberInvitation.objects.get(token=invitoken)
            url += '&invitoken=' + invitoken
        except me.DoesNotExist:
            pass

    return HTTPFound(url)


@view_config(route_name='forgot_password', request_method='POST')
def forgot_password(request):
    """
    User visits password forgot form and submits his email
    or user presses the set password button in the account page
    and has registered through the SSO and has no previous
    password set in the database. In the latter case the email
    will be fetched from the session.
    """
    try:
        email = user_from_request(request).email
    except UserUnauthorizedError:
        email = params_from_request(request).get('email', '')

    try:
        user = User.objects.get(email=email)
    except (UserNotFoundError, me.DoesNotExist):
        # still return OK so that there's no leak on valid email
        return OK

    if user.status != 'confirmed':
        # resend confirmation email
        user.activation_key = get_secure_rand_token()
        user.save()
        subject = config.CONFIRMATION_EMAIL_SUBJECT.format(
            portal_name=config.PORTAL_NAME
        )
        body = config.CONFIRMATION_EMAIL_BODY.format(
            fname=user.first_name, ip_addr=ip_from_request(request),
            portal_uri=config.PORTAL_URI, follow_us=config.FOLLOW_US,
            portal_name=config.PORTAL_NAME,
            activation_key=user.activation_key)

        if not send_email(subject, body, user.email):
            raise ServiceUnavailableError("Could not send confirmation email.")

        return OK

    token = get_secure_rand_token()
    user.password_reset_token = token
    user.password_reset_token_created = time()
    user.password_reset_token_ip_addr = ip_from_request(request)
    log.debug("will now save (forgot)")
    user.save()

    subject = config.RESET_PASSWORD_EMAIL_SUBJECT.format(
        portal_name=config.PORTAL_NAME
    )
    body = config.RESET_PASSWORD_EMAIL_BODY.format(
        fname=user.first_name, portal_name=config.PORTAL_NAME,
        portal_uri=config.PORTAL_URI,
        ip_addr=user.password_reset_token_ip_addr,
        activation_key=encrypt("%s:%s" % (token, email), config.SECRET)
    )
    if not send_email(subject, body, email):
        log.info("Failed to send email to user %s for forgot password link" %
                 user.email)
        raise ServiceUnavailableError()
    log.info("Sent email to user %s\n%s" % (email, body))
    return OK


# SEC
@view_config(route_name='reset_password', request_method=('GET', 'POST'))
def reset_password(request):
    """
    User visits reset password form and posts his email address
    If he is logged in when he presses the link then he will be logged out
    and then redirected to the landing page with the reset password token.
    """
    params = params_from_request(request)
    key = params.get('key')

    if not key:
        raise BadRequestError("Reset password token is missing")
    reissue_cookie_session(request)  # logout

    # SEC decrypt key using secret
    try:
        (token, email) = decrypt(key, config.SECRET).split(':')
    except:
        raise BadRequestError("invalid password token.")

    try:
        user = User.objects.get(email=email)
    except (UserNotFoundError, me.DoesNotExist):
        raise UserUnauthorizedError()

    # SEC check status, token, expiration
    if token != user.password_reset_token:
        raise BadRequestError("Invalid reset password token.")
    delay = time() - user.password_reset_token_created
    if delay > config.RESET_PASSWORD_EXPIRATION_TIME:
        raise MethodNotAllowedError("Password reset token has expired.")

    if request.method == 'GET':
        build_path = ''
        if config.JS_BUILD and not params.get('debug'):
            build_path = '/build/%s/bundled/' % config.VERSION.get('sha')
        template_inputs = config.HOMEPAGE_INPUTS
        template_inputs['build_path'] = build_path
        template_inputs['csrf_token'] = json.dumps(get_csrf_token(request))

        get_landing_template(build_path)
        return render_to_response('templates/landing.pt', template_inputs)
    elif request.method == 'POST':

        password = params.get('password', '')
        if not password:
            raise RequiredParameterMissingError('password')

        # change password
        user.set_password(password)
        user.status = 'confirmed'
        # in case the use has been with a pending confirm state
        user.password_reset_token_created = 0
        user.save()

        reissue_cookie_session(request, user)

        return OK
    raise BadRequestError("Bad method %s" % request.method)


@view_config(route_name='request_whitelist_ip', request_method='POST')
def request_whitelist_ip(request):
    """
    Tags: ip_whitelisting
    ---
    User logs in successfully but it's from a non-whitelisted ip.
    They click on a link 'whitelist current ip', which sends an email
    to their account.
    """
    try:
        email = user_from_request(request).email
    except UserUnauthorizedError:
        email = params_from_request(request).get('email', '')

    try:
        user = User.objects.get(email=email)
    except (UserNotFoundError, me.DoesNotExist):
        # still return OK so that there's no leak on valid email
        return OK

    token = get_secure_rand_token()
    user.whitelist_ip_token = token
    user.whitelist_ip_token_created = time()
    user.whitelist_ip_token_ip_addr = ip_from_request(request)
    log.debug("will now save (whitelist_ip)")
    user.save()
    confirmation_key = encrypt("%s:%s" % (token, email), config.SECRET)

    subject = config.WHITELIST_IP_EMAIL_SUBJECT.format(
        portal_name=config.PORTAL_NAME)
    body = config.WHITELIST_IP_EMAIL_BODY.format(
        fname=user.first_name, portal_name=config.PORTAL_NAME,
        portal_uri=config.PORTAL_URI, confirmation_key=confirmation_key,
        ip_addr=user.whitelist_ip_token_ip_addr
    )
    if not send_email(subject, body, email):
        log.info("Failed to send email to user %s for whitelist IP link" %
                 user.email)
        raise ServiceUnavailableError()
    log.info("Sent email to user %s\n%s" % (email, body))
    return OK


# SEC
@view_config(route_name='confirm_whitelist', request_method=('GET'))
def confirm_whitelist(request):
    """
    Tags: ip_whitelisting
    ---
    User tries to login successfully but from a non-whitelisted IP.
    They get a link to request whitelisting their current IP and an email
    with a link is sent to their email address.
    When they click on the link and everything is valid they are then
    redirected to the account page under the whitelisting IP tab.
    """
    params = params_from_request(request)
    key = params.get('key')

    if not key:
        raise BadRequestError("Whitelist IP token is missing")

    # SEC decrypt key using secret
    try:
        (token, email) = decrypt(key, config.SECRET).split(':')
    except:
        raise BadRequestError("invalid Whitelist IP token.")

    try:
        user = User.objects.get(email=email)
    except (UserNotFoundError, me.DoesNotExist):
        raise UserUnauthorizedError()

    # SEC check status, token, expiration
    if token != user.whitelist_ip_token:
        raise BadRequestError("Invalid whitelist IP token.")
    delay = time() - user.whitelist_ip_token_created
    if delay > config.WHITELIST_IP_EXPIRATION_TIME:
        raise MethodNotAllowedError("Whitelist IP token has expired.")

    wip = WhitelistIP()
    wip.cidr = user.whitelist_ip_token_ip_addr
    wip.description = 'Added by Mist.io upon request'
    user.ips.append(wip)
    user.save()

    return HTTPFound('/sign-in?return_to=/my-account/ips')


# SEC
@view_config(route_name='set_password', request_method=('GET', 'POST'))
def set_password(request):
    """
    User visits confirm link and sets password.
    User set password if he/she forgot his/her password, if he/she is invited
    by owner, if he/she signs up.
    """
    params = params_from_request(request)

    key = params.get('key', '')

    invitoken = params.get('invitoken', '')

    if not key:
        raise RequiredParameterMissingError('key')

    # SEC decrypt key using secret
    try:
        (token, email) = decrypt(key, config.SECRET).split(':')
    except:
        raise BadRequestError("invalid password token.")

    try:
        user = User.objects.get(email=email)
    except (UserNotFoundError, me.DoesNotExist):
        raise UserUnauthorizedError()

    if user.status != 'pending':
        raise ForbiddenError("Already confirmed and password set.")
    if token != user.password_set_token:
        raise BadRequestError("invalid set password token.")
    delay = time() - user.password_set_token_created
    if delay > config.RESET_PASSWORD_EXPIRATION_TIME:
        raise MethodNotAllowedError("Password set token has expired.")

    if request.method == 'GET':
        build_path = ''
        if config.JS_BUILD and not params.get('debug'):
            build_path = '/build/%s/bundled/' % config.VERSION.get('sha')
        template_inputs = config.HOMEPAGE_INPUTS
        template_inputs['build_path'] = build_path
        template_inputs['csrf_token'] = json.dumps(get_csrf_token(request))

        get_landing_template(build_path)
        return render_to_response('templates/landing.pt', template_inputs)
    elif request.method == 'POST':
        password = params.get('password', '')
        if not password:
            raise RequiredParameterMissingError('password')
        # set password
        user.set_password(password)
        user.status = 'confirmed'
        user.activation_date = time()
        user.password_set_token = ""
        selected_plan = user.selected_plan
        user.selected_plan = ''
        user.last_login = time()

        user.save()

        # log in user
        reissue_cookie_session(request, user)

        ret = {'selectedPlan': selected_plan}
        if config.HAS_BILLING and user.promo_codes:
            from mist.billing.models import Promo
            promo_code = user.promo_codes[-1]
            promo = Promo.objects.get(code=promo_code)
            ret['hasPromo'] = True
            ret['sendToPurchase'] = promo.send_to_purchase

        if invitoken:
            try:
                MemberInvitation.objects.get(token=invitoken)
                confirm_invitation(request)
            except me.DoesNotExist:
                pass

        return render_to_response('json', ret, request)
    else:
        raise BadRequestError("Invalid HTTP method")


@view_config(route_name='confirm_invitation', request_method='GET')
def confirm_invitation(request):
    """
    Confirm that a user want to participate in team
    If user has status pending then he/she will be redirected to confirm
    to finalize registration and only after the process has finished
    successfully will he/she be added to the team.
    ---
    invitoken:
      description: member's invitation token
      type: string
      required: true
    """
    try:
        auth_context = auth_context_from_request(request)
    except UserUnauthorizedError:
        auth_context = None
    params = params_from_request(request)
    invitoken = params.get('invitoken', '')
    if not invitoken:
        raise RequiredParameterMissingError('invitoken')
    try:
        invitation = MemberInvitation.objects.get(token=invitoken)
    except me.DoesNotExist:
        raise NotFoundError('Invalid invitation token')

    user = invitation.user
    # if user registration is pending redirect to confirm registration
    if user.status == 'pending':
        key = params.get('key')
        if not key:
            key = user.activation_key
        uri = request.route_url('confirm',
                                _query={'key': key, 'invitoken': invitoken})
        raise RedirectError(uri)

    # if user is confirmed but not logged in then redirect to log in page
    if not auth_context:
        uri = request.route_url('login', _query={'invitoken': invitoken})
        raise RedirectError(uri)

    # if user is logged in then make sure it's his invitation that he is
    # confirming. if it's not redirect to home but don't confirm invitation.
    if invitation.user != auth_context.user:
        return HTTPFound('/')

    org = invitation.org
    for team_id in invitation.teams:
        try:
            org.add_member_to_team_by_id(team_id, user)
        except:
            pass

    try:
        org.save()
    except:
        raise TeamOperationError()

    try:
        invitation.delete()
    except:
        pass

    args = {
        'request': request,
        'user_id': auth_context.user,
        'org': org
    }
    if session_from_request(request).context.get('social_auth_backend'):
        args.update({
            'social_auth_backend': session_from_request(request).context.get(
                'social_auth_backend')
        })
    reissue_cookie_session(**args)

    trigger_session_update(org, ['org'])

    return HTTPFound('/')


@view_config(route_name='api_v1_user_whitelist_ip', request_method='POST',
             renderer='json')
def whitelist_ip(request):
    """
    Tags: ip_whitelisting
    ---
    Whitelist IPs for specified user.
    """
    auth_context = auth_context_from_request(request)
    params = params_from_request(request)
    ips = params.get('ips', None)

    if ips is None:
        raise RequiredParameterMissingError('ips')

    update_whitelist_ips(auth_context, ips)

    if auth_context.org:
        trigger_session_update(auth_context.org, ['user'])
    return OK


@view_config(route_name='api_v1_sizes', request_method='GET', renderer='json')
def list_sizes(request):
    """
    Tags: clouds
    ---
    List sizes (aka flavors) from each cloud.
    READ permission required on cloud.
    ---
    cloud:
      in: path
      required: true
      type: string
    """
    cloud_id = request.matchdict['cloud']
    auth_context = auth_context_from_request(request)
    cloud = Cloud.objects.get(owner=auth_context.owner, id=cloud_id,
                              deleted=None)
    auth_context.check_perm("cloud", "read", cloud_id)
    params = params_from_request(request)
    cached = bool(params.get('cached', False))
    extra = params.get('extra', 'True') == 'True'

    if cached:
        sizes = cloud.ctl.compute.list_cached_sizes()
    else:
        sizes = cloud.ctl.compute.list_sizes()
    return [size.as_dict(extra=extra) for size in sizes]


@view_config(route_name='api_v1_locations', request_method='GET',
             renderer='json')
def list_locations(request):
    """
    Tags: clouds
    ---
    List locations from each cloud. Locations mean different things in each cl-
    oud. e.g. EC2 uses it as a datacenter in a given availability zone, where-
    as Linode lists availability zones. However all responses share id, name
    and country even though in some cases might be empty, e.g. Openstack. In E-
    C2 all locations by a provider have the same name, so the availability zo-
    nes are listed instead of name.
    READ permission required on cloud.
    ---
    cloud:
      in: path
      required: true
      type: string
    """
    cloud_id = request.matchdict['cloud']
    auth_context = auth_context_from_request(request)

    try:
        Cloud.objects.get(owner=auth_context.owner, id=cloud_id, deleted=None)
    except Cloud.DoesNotExist:
        raise CloudNotFoundError()

    auth_context.check_perm("cloud", "read", cloud_id)
    params = params_from_request(request)
    cached = bool(params.get('cached', False))
    extra = params.get('extra', 'True') == 'True'
    return filter_list_locations(auth_context,
                                 cloud_id,
                                 cached=cached,
                                 extra=extra)


@view_config(route_name='api_v1_storage_accounts', request_method='GET',
             renderer='json')
def list_storage_accounts(request):
    """
    Tags: clouds
    ---
    List storage accounts. ARM specific. For other providers this
    returns an empty list
    READ permission required on cloud.
    ---
    cloud:
      in: path
      required: true
      type: string
    """
    cloud_id = request.matchdict['cloud']
    auth_context = auth_context_from_request(request)

    try:
        Cloud.objects.get(owner=auth_context.owner, id=cloud_id, deleted=None)
    except Cloud.DoesNotExist:
        raise CloudNotFoundError()

    auth_context.check_perm("cloud", "read", cloud_id)

    return methods.list_storage_accounts(auth_context.owner, cloud_id)


@view_config(route_name='api_v1_resource_groups', request_method='GET',
             renderer='json')
def list_resource_groups(request):
    """
    Tags: clouds
    ---
    List resource groups. ARM specific. For other providers this
    returns an empty list
    READ permission required on cloud.
    ---
    cloud:
      in: path
      required: true
      type: string
    """
    cloud_id = request.matchdict['cloud']
    auth_context = auth_context_from_request(request)

    try:
        Cloud.objects.get(owner=auth_context.owner, id=cloud_id, deleted=None)
    except Cloud.DoesNotExist:
        raise CloudNotFoundError()

    auth_context.check_perm("cloud", "read", cloud_id)

    return methods.list_resource_groups(auth_context.owner, cloud_id)


@view_config(route_name='api_v1_storage_pools', request_method='GET',
             renderer='json')
def list_storage_pools(request):
    """
    Tags: clouds
    ---
    List storage pools. LXD specific. For other providers this
    returns an empty list
    READ permission required on cloud.
    ---
    cloud:
      in: path
      required: true
      type: string
    """
    cloud_id = request.matchdict['cloud']
    auth_context = auth_context_from_request(request)

    try:
        Cloud.objects.get(owner=auth_context.owner, id=cloud_id, deleted=None)
    except Cloud.DoesNotExist:
        raise CloudNotFoundError()

    auth_context.check_perm("cloud", "read", cloud_id)

    return methods.list_storage_pools(auth_context.owner, cloud_id)


@view_config(route_name='api_v1_cloud_probe',
             request_method='POST', renderer='json')
@view_config(route_name='api_v1_probe', request_method='POST', renderer='json')
def probe(request):
    """
    Tags: machines
    ---
    Probes a machine.
    Ping and SSH to machine and collect various metrics.
    READ permission required on cloud.
    READ permission required on machine.
    ---
    cloud:
      in: path
      required: true
      type: string
    machine:
      in: path
      required: true
      type: string
    host:
      type: string
    key:
      type: string
    """
    cloud_id = request.matchdict.get('cloud')
    params = params_from_request(request)
    key_id = params.get('key', None)

    if key_id == 'undefined':
        key_id = ''
    auth_context = auth_context_from_request(request)

    if cloud_id:
        # this is deprecated, keep it for backwards compatibility
        external_id = request.matchdict['machine']
        auth_context.check_perm("cloud", "read", cloud_id)
        try:
            machine = Machine.objects.get(cloud=cloud_id,
                                          external_id=external_id,
                                          state__ne='terminated',
                                          owner=auth_context.org)
        except Machine.DoesNotExist:
            raise NotFoundError("Machine %s doesn't exist" % external_id)
    else:
        machine_id = request.matchdict['machine']
        try:
            machine = Machine.objects.get(id=machine_id,
                                          state__ne='terminated',
                                          owner=auth_context.org)
        except Machine.DoesNotExist:
            raise NotFoundError("Machine %s doesn't exist" % machine_id)

        cloud_id = machine.cloud.id
        auth_context.check_perm("cloud", "read", cloud_id)

    # used by logging_view_decorator
    request.environ['cloud'] = machine.cloud.id
    request.environ['machine'] = machine.id
    request.environ['external_id'] = machine.external_id

    auth_context.check_perm("machine", "read", machine.id)

    ret = {'ping': machine.ctl.ping_probe(),
           'ssh': machine.ctl.ssh_probe()}
    return ret


@view_config(route_name='api_v1_ping', request_method=('GET', 'POST'),
             renderer='json')
def ping(request):
    """
    Tags: api_tokens
    ---
    Check that an api token is correct.
    ---
    """
    user = user_from_request(request)
    if isinstance(session_from_request(request), SessionToken):
        raise BadRequestError('This call is for users with api tokens')
    return {'hello': user.email}


@view_config(route_name='api_v1_providers', request_method='GET',
             renderer='json')
def list_supported_providers(request):
    """
    Tags: providers
    ---
    Lists supported providers.
    Return all of our SUPPORTED PROVIDERS
    ---
    """
    return {'supported_providers': list(config.PROVIDERS.values())}


@view_config(route_name='api_v1_avatars',
             request_method='POST', renderer='json')
def upload_avatar(request):
    """
    Tags: avatars
    ---
    Upload an avatar
    ---
    """
    user = user_from_request(request)
    body = request.POST['file'].file.read()
    if len(body) > 256 * 1024:
        raise BadRequestError("File too large")
    from mist.api.users.models import Avatar
    avatar = Avatar()
    avatar.owner = user
    avatar.body = body
    avatar.save()
    return {'id': avatar.id}


@view_config(route_name='api_v1_avatar', request_method='GET')
def get_avatar(request):
    """
    Tags: avatars
    ---
    Returns the requested avatar
    ---
    avatar:
      description: 'Avatar Id'
      in: path
      required: true
      type: string
    """
    avatar_id = request.matchdict['avatar']

    try:
        avatar = Avatar.objects.get(id=avatar_id)
    except me.DoesNotExist:
        raise NotFoundError()

    return Response(content_type=str(avatar.content_type),
                    body=avatar.body)


@view_config(route_name='api_v1_avatar', request_method='DELETE')
def delete_avatar(request):
    """
    Tags: avatars
    ---
    Deletes the requested avatar
    ---
    avatar:
      description: 'Avatar Id'
      in: path
      required: true
      type: string
    """
    avatar_id = request.matchdict['avatar']
    auth_context = auth_context_from_request(request)

    try:
        avatar = Avatar.objects.get(id=avatar_id, owner=auth_context.user)
    except me.DoesNotExist:
        raise NotFoundError()

    try:
        org = Owner.objects.get(avatar=avatar_id)
        org.avatar = ''
        org.save()
    except me.DoesNotExist:
        pass

    avatar.delete()
    trigger_session_update(auth_context.owner, ["org"])
    return OK


@view_config(route_name='api_v1_orgs', request_method='GET', renderer='json')
def list_user_organizations(request):
    """
    Tags: organizations
    ---
    List user's organizations.
    List all the organizations where user is a member
    """
    try:
        user = user_from_request(request)
    except me.DoesNotExist:
        raise UnauthorizedError()
    return [{'id': org.id, 'name': org.name}
            for org in Organization.objects(members=user)]


# SEC
@view_config(route_name='api_v1_org', request_method='POST', renderer='json')
def create_organization(request):
    """
    Tags: organizations
    ---
    Creates organization.
    The user creating it will be assigned to the
    owners team. For now owner has only org
    ---
    name:
      description: The new org  name (id)
      type: string
      required: true
    """
    auth_context = auth_context_from_request(request)

    user = auth_context.user
    # SEC
    if not user.can_create_org:
        raise OrganizationAuthorizationFailure('Unauthorized to '
                                               'create organization')
    params = params_from_request(request)

    name = html.escape(params.get('name'))
    super_org = params.get('super_org')
    enable_vault_polling = params.get('enable_vault_polling', True)

    if not name:
        raise RequiredParameterMissingError()
    if Organization.objects(name=name):
        raise OrganizationNameExistsError()

    org = Organization()
    org.add_member_to_team('Owners', user)
    org.name = name

    # mechanism for sub-org creation
    # the owner of super-org has the ability to create a sub-org
    if super_org:
        org.parent = auth_context.org

    try:
        org.save()
    except me.ValidationError as e:
        raise BadRequestError(e.errors.get('__all__', str(e)))
    except me.OperationError:
        raise OrganizationOperationError()

    if enable_vault_polling:
        from mist.api.poller.models import ListVaultSecretsPollingSchedule
        ListVaultSecretsPollingSchedule.add(org)

    trigger_session_update(auth_context.user, ['user'])
    return org.as_dict()


@view_config(route_name='api_v1_org', request_method='GET', renderer='json')
def show_user_organization(request):
    """
    Tags: organizations
    ---
    Show user's organization.
    If user is organization owner then show everything
    If user is just a member then show just himself as a team member and the
    name of the organization, the name of the team,
    """
    auth_context = auth_context_from_request(request)
    org_dict = {}
    if auth_context.org:
        org_dict = auth_context.org.as_dict()
        if not auth_context.is_owner():
            # remove all the teams the user is not a member of
            i = 0
            while i < len(org_dict['teams']):
                if auth_context.user.id not in org_dict['teams'][i]['members']:
                    org_dict["teams"].pop(i)
                else:
                    # user is a member of the team. remove the other members
                    org_dict['teams'][i]['members'] = [auth_context.user.id]
                    i += 1
        org_dict['is_owner'] = auth_context.is_owner()
    return org_dict


@view_config(route_name='user_invitations', request_method='GET',
             renderer='json')
def show_user_pending_invitations(request):
    """
    Show user's pending invitations.
    Returns a list of dicts with all of user's pending invitations
    """
    auth_context = auth_context_from_request(request)
    user_invitations = MemberInvitation.objects(user=auth_context.user)
    invitations = []
    for invitation in user_invitations:
        invitation_view = {}
        try:
            org = invitation.org
            invitation_view['org'] = org.name
            invitation_view['org_id'] = org.id
            invitation_view['token'] = invitation.token
            invitation_view['teams'] = []
            for team_id in invitation.teams:
                try:
                    team = org.get_team_by_id(team_id)
                    invitation_view['teams'].append({
                        'id': team.id,
                        'name': team.name
                    })
                except:
                    pass
            invitations.append(invitation_view)
        except:
            pass

    return invitations


@view_config(route_name='api_v1_org_info', request_method='GET',
             renderer='json')
def show_organization(request):
    """
    Tags: organizations
    ---
    Show organization.
    Details of org.
    ---
    org_id:
      description: The org id
      required: true
      type: string
    """
    # TODO NEXT ITERATION
    raise ForbiddenError("The proper request is /org")
    auth_context = auth_context_from_request(request)

    org_id = request.matchdict['org']

    if not (auth_context.org and auth_context.is_owner() and
            auth_context.org.id == org_id):
        raise OrganizationAuthorizationFailure()

    return auth_context.org.as_dict()


@view_config(route_name='api_v1_org_info', request_method='PUT',
             renderer='json')
def edit_organization(request):
    """
    Tags: organizations
    ---
    Edit an organization entry in the db
    Means rename.
    Only available to organization owners.
    ---
    org_id:
      description: The org's org id
      type: string
      required: true
    name:
      description: The team's name
      type: string
    """
    auth_context = auth_context_from_request(request)

    if not auth_context.is_owner():
        raise ForbiddenError('Only owners can edit org')

    org = auth_context.org
    org_id = request.matchdict['org']
    params = params_from_request(request)

    name = html.escape(params.get('new_name'))
    alerts_email = params.get('alerts_email')
    avatar = params.get('avatar')
    enable_r12ns = params.get('enable_r12ns')
    enable_vault_polling = params.get('enable_vault_polling', True)

    vault_address = params.get('vault_address')
    vault_secret_engine_path = params.get('vault_secret_engine_path')
    vault_token = params.get('vault_token')
    vault_role_id = params.get('vault_role_id')
    vault_secret_id = params.get('vault_secret_id')

    if not vault_address and org.vault_address:  # Disable custom Vault
        org.vault_address = ''
        org.vault_secret_engine_path = ''
        org.vault_token = ''
        org.vault_role_id = ''
        org.vault_secret_id = ''
        org.save()
    elif vault_address:  # Enable custom Vault
        import hvac
        if vault_role_id and vault_secret_id:  # AppRole Auth
            client = hvac.Client(url=vault_address)
            try:
                result = client.auth.approle.login(
                    role_id=vault_role_id,
                    secret_id=vault_secret_id,
                )
            except hvac.exceptions.InvalidRequest:
                raise BadRequestError("Vault approle authentication failed.")
            except hvac.exceptions.VaultDown:
                raise ServiceUnavailableError("Vault is sealed.")
            except Exception as e:
                raise BadRequestError(e)
            org.vault_address = vault_address
            org.vault_secret_engine_path = vault_secret_engine_path
            org.vault_role_id = vault_role_id
            org.vault_secret_id = vault_secret_id
            org.vault_token = ''
            org.save()
        elif vault_token:  # Token Auth
            client = hvac.Client(url=vault_address, token=vault_token)
            try:
                is_authenticated = client.is_authenticated()
                if not is_authenticated:
                    raise BadRequestError("Vault token authentication failed.")
            except hvac.exceptions.VaultDown:
                raise ServiceUnavailableError("Vault is sealed.")
            except Exception as e:
                raise BadRequestError(e)
            org.vault_address = vault_address
            org.vault_secret_engine_path = vault_secret_engine_path
            org.vault_token = vault_token
            org.vault_role_id = ''
            org.vault_secret_id = ''
            org.save()

    if avatar:
        try:
            Avatar.objects.get(id=avatar)
        except me.DoesNotExist:
            raise BadRequestError('Avatar does not exist')
        auth_context.org.avatar = avatar

    if alerts_email and auth_context.is_owner():
        from mist.api.monitoring.methods import update_monitoring_options
        update_monitoring_options(auth_context.owner, alerts_email)

    if not name and not alerts_email and not avatar:
        raise RequiredParameterMissingError()

    if enable_r12ns is not None:
        auth_context.org.enable_r12ns = enable_r12ns

    if enable_vault_polling:
        from mist.api.poller.models import ListVaultSecretsPollingSchedule
        ListVaultSecretsPollingSchedule.add(auth_context.org)

    # SEC check if owner
    if not (org and auth_context.is_owner() and
            org.id == org_id):
        raise OrganizationAuthorizationFailure()

    if Organization.objects(
            name=name, id__ne=org.id) or Organization.objects(
                vault_secret_engine_path=name, id__ne=org.id):
        raise OrganizationNameExistsError()

    auth_context.org.name = name

    try:
        auth_context.org.save()
    except me.ValidationError as e:
        raise BadRequestError({"msg": str(e), "errors": e.to_dict()})
    except me.OperationError:
        raise OrganizationOperationError()

    log.info("Editing org with name '%s'.", name)
    trigger_session_update(auth_context.owner, ['org'])

    return auth_context.org.as_dict()


# SEC
@view_config(route_name='api_v1_teams', request_method='POST', renderer='json')
def add_team(request):
    """
    Tags: teams
    ---
    Creates new team.
    Append it at org's teams list.
    Only available to organization owners.
    ---
    name:
      description: The new team name
      type: string
      required: true
    description:
      description: The new team description
      type: string
    """

    log.info("Adding team")

    auth_context = auth_context_from_request(request)
    org_id = request.matchdict['org']

    params = params_from_request(request)
    name = params.get('name')
    description = params.get('description', '')
    visibility = params.get('visible', True)

    if not name:
        raise RequiredParameterMissingError()

    # SEC check if owner
    if not (auth_context.org and auth_context.is_owner() and
            auth_context.org.id == org_id):
        raise OrganizationAuthorizationFailure()

    team = Team()
    team.name = name
    team.description = description
    team.visible = visibility
    auth_context.org.teams.append(team)

    try:
        auth_context.org.save()
    except me.ValidationError as e:
        raise BadRequestError({"msg": str(e), "errors": e.to_dict()})
    except me.OperationError:
        raise TeamOperationError()

    log.info("Adding team with name '%s'.", name)
    trigger_session_update(auth_context.owner, ['org'])

    return team.as_dict()


# SEC
@view_config(route_name='api_v1_team', request_method='GET', renderer='json')
def show_team(request):
    """
    Tags: teams
    ---
    Show team.
    Only available to organization owners.
    ---
    org_id:
      description: The team's org id
      type: string
      required: true
    team_id:
      description: The team's id
      type: string
    """

    auth_context = auth_context_from_request(request)
    org_id = request.matchdict['org']
    team_id = request.matchdict['team']

    # SEC check if owner
    if not (auth_context.org and auth_context.is_owner() and
            auth_context.org.id == org_id):
        raise OrganizationAuthorizationFailure()

    # Check if team entry exists
    team = auth_context.org.get_team_by_id(team_id)

    return team.as_dict()


# SEC
@view_config(route_name='api_v1_teams', request_method='GET', renderer='json')
def list_teams(request):
    """
    Tags: teams
    ---
    Lists teams of an org.
    Only available to organization owners.
    ---
    org_id:
      description: The teams' org id
      type: string
      required: true
    """
    auth_context = auth_context_from_request(request)
    org_id = request.matchdict['org']

    # SEC check if owner
    if not (auth_context.org and auth_context.is_owner() and
            auth_context.org.id == org_id):
        raise OrganizationAuthorizationFailure()

    teams = [team.as_dict() for team in auth_context.org.teams]
    if auth_context.org.parent:
        parent_teams = auth_context.org.parent.teams

        for team in teams:
            team['parent'] = False
        p_teams = [team.as_dict() for team in parent_teams]
        for p_team in p_teams:
            p_team['parent'] = True

        return teams + p_teams

    return teams


# SEC
@view_config(route_name='api_v1_team', request_method='PUT', renderer='json')
def edit_team(request):
    """
    Tags: teams
    ---
    Renames a team entry in the db.
    Only available to organization owners.
    ---
    org_id:
      description: The org's org id
      type: string
      required: true
    team_id:
      description: The team's id
      type: string
      required: true
    name:
      description: The team's name
      type: string
    description:
      description: the teams's description
    """

    auth_context = auth_context_from_request(request)
    org_id = request.matchdict['org']
    team_id = request.matchdict['team']

    params = params_from_request(request)
    name = params.get('new_name')
    description = params.get('new_description', '')
    visibility = params.get('new_visible')

    if not name:
        raise RequiredParameterMissingError('name')

    # SEC check if owner
    if not (auth_context.is_owner() and auth_context.org.id == org_id):
        raise OrganizationAuthorizationFailure()

    # Check if team entry exists
    team = auth_context.org.get_team_by_id(team_id)

    if team.name == 'Owners' and name != 'Owners':
        raise BadRequestError('The name of the Owners Teams may not be edited')

    team.name = name
    team.description = description if description else ''
    if visibility is not None:
        team.visible = visibility

    try:
        auth_context.org.save()
    except me.ValidationError as e:
        raise BadRequestError({"msg": str(e), "errors": e.to_dict()})
    except me.OperationError:
        raise TeamOperationError()

    log.info("Editing team with name '%s'.", name)
    trigger_session_update(auth_context.owner, ['org'])

    return team.as_dict()


# SEC
@view_config(route_name='api_v1_team', request_method='DELETE',
             renderer='json')
def delete_team(request):
    """
    Tags: teams
    ---
    Deletes a team entry in the db.
    Only available to organization owners.
    ---
    org_id:
      description: The team's org id
      type: string
      required: true
    team_id:
      description: The team's id
      type: string
      required: true
    """
    auth_context = auth_context_from_request(request)
    org_id = request.matchdict['org']
    team_id = request.matchdict['team']

    # SEC check if owner
    if not (auth_context.org and auth_context.is_owner() and
            auth_context.org.id == org_id):
        raise OrganizationAuthorizationFailure()

    if auth_context.org.get_team('Owners').id == team_id:
        raise ForbiddenError()

    try:
        team = auth_context.org.get_team_by_id(team_id)
    except me.DoesNotExist:
        raise NotFoundError()

    if team.members:
        raise BadRequestError(
            'Team not empty. Remove all members and try again')

    try:
        team.drop_mappings()
        auth_context.org.teams.remove(team)
        auth_context.org.save()
    except me.ValidationError as e:
        raise BadRequestError({"msg": str(e), "errors": e.to_dict()})
    except me.OperationError:
        raise TeamOperationError()

    trigger_session_update(auth_context.owner, ['org'])

    return OK


# SEC
@view_config(route_name='api_v1_teams', request_method='DELETE',
             renderer='json')
def delete_teams(request):
    """
    Tags: teams
    ---
    Deletes multiple teams.
    Provide a list of team ids to be deleted. The method will try to delete
    all of them and then return a json that describes for each team id
    whether or not it was deleted or the not_found if the team id could not
    be located. If no team id was found then a 404(Not Found) response will
    be returned.
    Only available to organization owners.
    ---
    team_ids:
      required: true
      type: array
      items:
        type: string
    """
    auth_context = auth_context_from_request(request)
    org_id = request.matchdict['org']
    params = params_from_request(request)
    team_ids = params.get('team_ids', [])

    # SEC check if owner
    if not (auth_context.org and auth_context.is_owner() and
            auth_context.org.id == org_id):
        raise OrganizationAuthorizationFailure()

    if not isinstance(team_ids, (list, (str,))) or len(team_ids) == 0:
        raise RequiredParameterMissingError('No team ids provided')
    # remove duplicate ids if there are any
    teams_ids = sorted(team_ids)
    i = 1
    while i < len(teams_ids):
        if teams_ids[i] == teams_ids[i - 1]:
            teams_ids = teams_ids[:i] + teams_ids[i + 1:]
        else:
            i += 1
    report = {}
    for team_id in teams_ids:
        # Check if team entry exists
        try:
            team = auth_context.org.get_team_by_id(team_id)
        except me.DoesNotExist:
            report[team_id] = 'not_found'
        else:
            if team.name == 'Owners':
                report[team_id] = 'forbidden'
            elif team.members != 0:
                report[team_id] = 'not_empty'
            else:
                team.drop_mappings()
                Organization.objects(id=org_id).modify(pull__teams=team)
                report[team_id] = 'deleted'

    # if no team id was valid raise exception
    if len([team_id for team_id in report
            if report[team_id] == 'not_found']) == len(teams_ids):
        raise NotFoundError('No valid team id provided')
    # if team is not empty raise exception
    if len([team_id for team_id in report
            if report[team_id] == 'not_empty']) == len(teams_ids):
        raise BadRequestError('Delete only empty teams')
    # if user was not authorized for any team raise exception
    if len([team_id for team_id in report
            if report[team_id] == 'forbidden']) == len(team_ids):
        raise TeamForbidden()

    trigger_session_update(auth_context.owner, ['org'])

    return report


# SEC
@view_config(route_name='api_v1_team_members', request_method='POST',
             renderer='json')
def invite_member_to_team(request):
    """
    Tags: teams
    ---
    Invite a member to team.
    For each user there can be one invitation per organization, but each
    invitation could be for multiple teams.
    There are three cases:
    1) If user is not a member of the organization:
        a) If user is registered in the service then an email will be sent with
           a link to confirm the invitation
        b) If user is not registered then a new entry will be created and an
           email will be sent inviting him to set a password and confirm his
           invitation to the organization
    2) User is already a member then add the user directly to the organization
       and send an email notification about the change in status.

   Only available to organization owners.
    ---
    org:
      description: The team's org id
      type: string
      required: true
    team:
      description: The team's id
      type: string
      required: true
    emails:
      description: The emails of the users to invite
      type: string
      required: true
    """
    auth_context = auth_context_from_request(request)

    params = params_from_request(request)
    org_id = request.matchdict['org']
    team_id = request.matchdict['team']

    # SEC check if owner
    if not (auth_context.org and auth_context.is_owner() and
            auth_context.org.id == org_id):
        raise OrganizationAuthorizationFailure()

    # Check if team entry exists
    team = auth_context.org.get_team_by_id(team_id)

    emails = params.get('emails', '').strip().lower().split('\n')

    if not emails:
        raise RequiredParameterMissingError('emails')

    org = auth_context.org
    subject = config.ORG_INVITATION_EMAIL_SUBJECT.format(
        portal_name=config.PORTAL_NAME)

    for email in emails:
        if not email or '@' not in email:
            raise BadRequestError('Email %s is not valid' % email)

    ret = []
    for email in emails:
        # if '@' not in email:

        # check if user exists
        try:
            user = User.objects.get(email=email)
        except me.DoesNotExist:
            # If user doesn't exist then create one.
            if email.split('@')[1] in config.BANNED_EMAIL_PROVIDERS:
                raise MethodNotAllowedError("Email provider is banned.")
            user = User()
            user.email = email
            user.registration_date = time()
            user.status = 'pending'
            user.activation_key = get_secure_rand_token()
            user.save()

        return_val = {
            'id': user.id,
            'name': user.get_nice_name(),
            'email': user.email
        }

        invitoken = None

        # if user status is pending then send user email with link for
        # registration/invitation.
        if user not in org.members:
            # check if there is a pending invitation for the user for the same
            # team. if there is no invitation for team create one.
            # Also create a list of all the teams the user has been invited to.
            org_invitations = MemberInvitation.objects(org=org, user=user)
            for invitation in org_invitations:
                # user has already been invited for this organization, resend
                # registration/invitation email.
                if team_id not in invitation.teams:
                    invitation.teams.append(team_id)
                    invitation.save()
                pending_teams = invitation.teams
                invitoken = invitation.token
                break

            if not invitoken:
                # if there is no invitation create it
                new_invitation = MemberInvitation()
                new_invitation.user = user
                new_invitation.org = org
                new_invitation.teams.append(team_id)
                new_invitation.token = invitoken = get_secure_rand_token()
                try:
                    new_invitation.save()
                except:
                    TeamOperationError('Could not send invitation')
                pending_teams = new_invitation.teams

            # create appropriate email body
            if len(pending_teams) > 1:
                team_name = 'following teams: "'
                pending_team_names = []
                for pending_team_id in pending_teams:
                    try:
                        pending_team = org.get_team_by_id(pending_team_id)
                        pending_team_names.append(pending_team.name)
                    except:
                        pass
                team_name += '", "'.join(pending_team_names) + '"'
            else:
                team_name = '"' + team.name + '" team'
            if user.status == 'pending':
                body = \
                    config.REGISTRATION_AND_ORG_INVITATION_EMAIL_BODY.format(
                        fname=user.first_name, team=team_name, org=org.name,
                        invited_by=auth_context.user.get_nice_name(),
                        portal_uri=config.PORTAL_URI,
                        portal_name=config.PORTAL_NAME,
                        activation_key=user.activation_key,
                        invitoken=invitoken
                    )
            else:
                body = config.USER_CONFIRM_ORG_INVITATION_EMAIL_BODY.format(
                    fname=user.first_name,
                    invited_by=auth_context.user.get_nice_name(),
                    org=org.name, team=team.name, portal_uri=config.PORTAL_URI,
                    portal_name=config.PORTAL_NAME, invitoken=invitoken
                )
            return_val['pending'] = True
            log.info("Sending invitation to user with email '%s' for team %s "
                     "of org %s with token %s", user.email, team.name,
                     auth_context.org.name, invitoken)

        else:
            team = org.get_team_by_id(team_id)
            if user in team.members:
                raise MemberConflictError('Member already in team')
            org.add_member_to_team_by_id(team_id, user)
            org.save()
            subject = config.ORG_NOTIFICATION_EMAIL_SUBJECT.format(
                portal_name=config.PORTAL_NAME
            )
            body = config.USER_NOTIFY_ORG_TEAM_ADDITION.format(
                fname=user.first_name, team=team.name, org=org.name,
                portal_name=config.PORTAL_NAME
            )
            return_val['pending'] = False

            # if one of the org owners adds himself to team don't send email
            if user == auth_context.user:
                if auth_context.org:
                    trigger_session_update(auth_context.org, ['org'])
                return return_val

        tasks.send_email.send(subject, body, user.email)
        ret.append(return_val)

    if auth_context.org:
        trigger_session_update(auth_context.org, ['org'])

    return ret


# SEC
@view_config(route_name='api_v1_team_member', request_method='DELETE',
             renderer='json')
def delete_member_from_team(request):
    """
    Tags: teams
    ---
    Delete a team's member entry from the db.
    It means remove member from list and save org.
    Only available to organization owners.
    ---
    org:
      description: The team's org id
      type: string
      required: true
    team:
      description: The team's id
      type: string
      required: true
    user:
      description: The user's id
      type: string
      required: true
    """
    auth_context = auth_context_from_request(request)

    user_id = request.matchdict['user']
    org_id = request.matchdict['org']
    team_id = request.matchdict['team']

    # SEC check if owner
    if not (auth_context.org and auth_context.is_owner() and
            auth_context.org.id == org_id):
        raise OrganizationAuthorizationFailure()

    # Check if team entry exists
    team = auth_context.org.get_team_by_id(team_id)

    # check if user exists
    try:
        user = User.objects.get(id=user_id)
    except me.DoesNotExist:
        raise UserNotFoundError()

    # check if user has a pending invitation.
    if user not in team.members:
        try:
            invitation = \
                MemberInvitation.objects.get(user=user, org=auth_context.org)
            # remove team from user's invitation. if there are no more teams
            # then revoke the invitation.
            if team_id not in invitation.teams:
                raise NotFoundError()
            invitation.teams.remove(team_id)
            if len(invitation.teams) == 0:
                subject = config.NOTIFY_INVITATION_REVOKED_SUBJECT.format(
                    portal_name=config.PORTAL_NAME
                )
                body = config.NOTIFY_INVITATION_REVOKED.format(
                    portal_name=config.PORTAL_NAME, org=auth_context.org.name,
                    fname=user.first_name)
                try:
                    invitation.delete()
                except me.ValidationError as e:
                    raise BadRequestError(
                        {"msg": str(e), "errors": e.to_dict()})
                except me.OperationError:
                    raise TeamOperationError()
                # notify user that his invitation has been revoked
                tasks.send_email.send(subject, body, user.email)
            else:
                try:
                    invitation.save()
                except me.ValidationError as e:
                    raise BadRequestError(
                        {"msg": str(e), "errors": e.to_dict()})
                except me.OperationError:
                    raise TeamOperationError()

            trigger_session_update(auth_context.owner, ['org'])
            return OK
        except:
            raise MemberNotFound()

    # if user belongs in more than one teams then just remove him from the team
    # otherwise remove him both from team and the organization.
    remove_from_org = True
    auth_context.org.remove_member_from_team_by_id(team_id, user)
    for team in auth_context.org.teams:
        if user in team.members and team.id != team_id:
            # if user is in some other team too then just remove him from the
            # team.
            remove_from_org = False
            break

    subject = config.ORG_TEAM_STATUS_CHANGE_EMAIL_SUBJECT.format(
        portal_name=config.PORTAL_NAME
    )
    if remove_from_org:
        body = config.NOTIFY_REMOVED_FROM_ORG.format(
            fname=user.first_name, org=auth_context.org.name,
            portal_name=config.PORTAL_NAME
        )
        auth_context.org.remove_member_from_members(user)
        for token in SessionToken.objects(
                user_id=user.id, orgs=auth_context.org):
            token.revoked = True
            token.save()
        if not Organization.objects(
                members=user, name__ne=auth_context.org.name).count():
            # For backwards compatibility
            from mist.api.users.methods import create_org_for_user
            create_org_for_user(user, '')
    else:
        body = config.NOTIFY_REMOVED_FROM_TEAM.format(
            fname=user.first_name, team=team.name,
            org=auth_context.org.name,
            admin=auth_context.user.get_nice_name(),
            portal_name=config.PORTAL_NAME)

    try:
        auth_context.org.save()
    except me.ValidationError as e:
        raise BadRequestError({"msg": str(e), "errors": e.to_dict()})
    except me.OperationError:
        raise TeamOperationError()

    if user != auth_context.user:
        tasks.send_email.send(subject, body, user.email)

    trigger_session_update(auth_context.owner, ['org'])

    return OK


@view_config(route_name='api_v1_dev_add_user_to_team', request_method='POST',
             renderer='json')
def add_dev_user_to_team(request):
    """
    Add user to team. This method is user by integration tests.
    It is enabled only if config.ENABLE_DEV_USERS is set to True (False by
    default).
    ---
    org:
      in: path
      required: true
      type: string
    team:
      in: path
      required: true
      type: string
    """

    auth_context = auth_context_from_request(request)

    if not config.ENABLE_DEV_USERS:
        raise NotFoundError()

    params = params_from_request(request)
    email = params.get('email', '').strip().lower()

    team_id = request.matchdict['team']

    user = User.objects.get(email=email)

    auth_context.org.add_member_to_team_by_id(team_id, user)
    auth_context.org.save()


@view_config(route_name='api_v1_dev_register', request_method='POST',
             renderer='json')
def register_dev_user(request):
    """
    Automatically register users to be used by integration tests.
    It actually does what dbinit does but through the API.
    It is enabled only if config.ENABLE_DEV_USERS is set to True (False by
    default).
    ---
    email:
      in: path
      required: true
      type: string
    name:
      in: path
      required: true
      type: string
    """
    if not config.ENABLE_DEV_USERS:
        raise NotFoundError()

    params = params_from_request(request)
    email = params.get('email', '').strip().lower()
    password = params.get('password')
    name = params.get('name', '').strip()
    org_name = params.get('org_name', email)
    if not org_name:
        org_name = email
    name_parts = name.split(' ', 1)
    first_name = name_parts[0]
    last_name = name_parts[1] if len(name_parts) > 1 else ''

    log.warning("[DEV ENDPOINT]: creating User %s " % email)
    user = User(email=email)
    user.set_password(password)
    user.status = 'confirmed'
    user.registration_method = 'dev'
    user.first_name = first_name
    user.last_name = last_name
    user.can_create_org = True
    user.activation_date = time()
    user.save()

    log.warning("[DEV ENDPOINT]: creating Org %s " % org_name)
    org = Organization(name=org_name)
    org.add_member_to_team('Owners', user)
    org.save()

    return {
        'org_id': org.id,
        'org_name': org.name
    }


@view_config(route_name='api_v1_dev_users', request_method='DELETE',
             renderer='json')
def delete_dev_user(request):
    if not config.ENABLE_DEV_USERS:
        raise NotFoundError()

    params = params_from_request(request)
    email = params.get('email', '')

    if not email:
        raise RequiredParameterMissingError('email')
    try:
        user = User.objects.get(email=email)
        user.delete()
        log.warning("[DEV ENDPOINT]: Delete user with email: %s", email)
    except User.DoesNotExist:
        # If user does not exist we are okay
        log.warning("[DEV ENDPOINT]: User with email: %s is already absent",
                    email)
    return OK


@view_config(route_name='api_v1_spec', request_method='GET')
def openapi_spec(request):
    curr_dir = os.path.dirname(__file__)
    spec = os.path.join(curr_dir, "../../../openapi/spec.yml")
    return FileResponse(spec, request=request)


@view_config(route_name='version', request_method='GET', renderer='json')
def version(request):
    """Return running version"""
    return {'version': config.VERSION}


@view_config(route_name='api_v1_section', request_method='GET')
def section(request):
    '''
    Redirect to or fetch the static HTML file that corresponds to the
    requested section
    '''
    section_id = request.matchdict['section']

    if not section_id.startswith('landing--blog'):
        path = '/static/' + section_id.replace('--', '/sections/') + '.html'
        return HTTPFound(path)

    page = 'blog'
    post = section_id.split('--')[-1]
    if post != 'blog':
        page = post if post.startswith('page') else 'blog/%s' % post
    uri_prefix = config.BLOG_CDN_URI or \
        request.application_url + "/static/blog/dist"
    page_uri = '%s/%s.html' % (uri_prefix, page)
    try:
        response = requests.get(page_uri)
        if response.ok:
            return Response(response.text, 200)
        else:
            log.error("Failed to fetch page `%s` from `%s`: %r" % (
                page, page_uri, response))
            raise ServiceUnavailableError(response)
    except Exception as exc:
        log.error("Failed to fetch page `%s` from `%s`: %r" % (
            page, page_uri, exc))
        raise ServiceUnavailableError(exc)
