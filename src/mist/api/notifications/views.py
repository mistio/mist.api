import json
import logging
import mongoengine as me

from pyramid.response import Response
from pyramid.renderers import render_to_response

from mist.api.helpers import view_config
from mist.api.helpers import params_from_request
from mist.api.helpers import encrypt, decrypt
from mist.api.helpers import mac_sign, mac_verify

from mist.api.exceptions import NotFoundError
from mist.api.exceptions import BadRequestError
from mist.api.exceptions import OrganizationNotFound
from mist.api.exceptions import RequiredParameterMissingError

from mist.api.auth.methods import get_csrf_token
from mist.api.auth.methods import auth_context_from_request

from mist.api.users.models import Organization
from mist.api.portal.models import Portal

from mist.api.notifications.models import Notification
from mist.api.notifications.models import InAppNotification
from mist.api.notifications.models import NotificationOverride
from mist.api.notifications.models import UserNotificationPolicy

from mist.api import config


log = logging.getLogger(__name__)

CHANNELS = ('EmailReport', 'EmailAlert', )
# ACTIONS = ()

ERROR_MSG = "Something went wrong with the unsubscribe link. "
ERROR_MSG += "Please contact support@mist.io, if the problem persists."


@view_config(route_name='api_v1_dismiss_notification',
             request_method='DELETE', renderer='json')
def dismiss_notification(request):
    """
    Tags: notifications
    ---
    Dismiss an in-app notification
    ---
    notification:
      in: path
      type: string
      required: true
    """
    auth_context = auth_context_from_request(request)
    ntf_id = request.matchdict.get("notification")
    if not ntf_id:
        raise RequiredParameterMissingError("notification_id")
    try:
        # TODO Should we delete the notification instead?
        ntf = InAppNotification.objects.get(id=ntf_id,
                                            owner=auth_context.owner)
        ntf.channel.dismiss(auth_context.user)
    except InAppNotification.DoesNotExist:
        raise NotFoundError()
    return Response("OK", 200)


@view_config(route_name='api_v1_notification_overrides',
             request_method='POST', renderer='json')
def add_notification_override(request):
    """
    Tags: notifications
    ---
    Add a notification override with the specified properties
    ---
    notification:
      in: path
      type: string
      required: true
    """
    auth_context = auth_context_from_request(request)
    params = params_from_request(request)
    ntf_id = params.get("notification_id")
    if not ntf_id:
        raise RequiredParameterMissingError("notification_id")
    try:
        ntf = Notification.objects.get(id=ntf_id, owner=auth_context.owner)
        ntf.channel.dismiss(auth_context.user)
    except Notification.DoesNotExist:
        raise NotFoundError()
    try:
        np = UserNotificationPolicy.objects.get(owner=auth_context.owner,
                                                user_id=auth_context.user.id)
    except UserNotificationPolicy.DoesNotExist:
        np = UserNotificationPolicy(owner=auth_context.owner,
                                    user_id=auth_context.user.id)
    if not np.has_overriden(ntf):
        override = NotificationOverride()
        override.rid = ntf.rid
        override.rtype = ntf.rtype
        override.channel = ntf.channel.ctype
        np.overrides.append(override)
        np.save()
        # Dismiss relevant notifications in order to not show up again.
        InAppNotification.objects(
            owner=auth_context.owner,
            rid=ntf.rid, rtype=ntf.rtype,
            dismissed_by__ne=auth_context.user.id
        ).update(push__dismissed_by=auth_context.user.id)
    return Response('OK', 200)


@view_config(route_name='api_v1_notification_overrides',
             request_method='GET', renderer='json')
def get_notification_overrides(request):
    """
    Tags: notifications
    ---
    Get notification overrides for user, org policy
    ---
    """
    auth_context = auth_context_from_request(request)
    try:
        np = UserNotificationPolicy.objects.get(owner=auth_context.owner,
                                                user_id=auth_context.user.id)
    except UserNotificationPolicy.DoesNotExist:
        return []
    return [o.as_dict() for o in np.overrides]


@view_config(route_name='api_v1_notification_override',
             request_method='DELETE', renderer='json')
def delete_notification_override(request):
    """
    Tags: notifications
    ---
    Delete a notification override
    ---
    """
    auth_context = auth_context_from_request(request)
    override_id = request.matchdict.get("override")
    try:
        np = UserNotificationPolicy.objects.get(owner=auth_context.owner,
                                                user_id=auth_context.user.id)
        np.overrides = np.overrides.exclude(id=override_id)
        np.save()
    except UserNotificationPolicy.DoesNotExist:
        raise NotFoundError("UserNotificationPolicy")
    return Response("OK", 200)


@view_config(route_name='unsubscribe_page', request_method='GET')
def request_unsubscription(request):
    """
    Tags: notifications
    ---
    Returns an unsubscription request page.
    Accepts a request, validates the unsubscribe token and returns a rendered
    template, with a link and another token to confirm unsubscribing.
    ---
    """
    params = dict(params_from_request(request).copy())

    # Verify HMAC.
    try:
        mac_verify(params)
    except Exception as exc:
        raise BadRequestError(exc)

    # Decrypt URL params.
    try:
        decrypted_str = decrypt(params["token"])
        decrypted_json = json.loads(decrypted_str)
    except Exception as exc:
        log.exception(repr(exc))
        raise BadRequestError(ERROR_MSG)

    try:
        org_id = decrypted_json["org_id"]
    except KeyError as err:
        log.exception(repr(err))
        raise BadRequestError(ERROR_MSG)

    # Get Organization.
    try:
        org = Organization.objects.get(id=org_id)
    except Organization.DoesNotExist:
        raise OrganizationNotFound()

    # Verify required parameters are present.
    rid = decrypted_json.get("rid", "")
    rtype = decrypted_json.get("rtype", "")
    email = decrypted_json.get("email")
    user_id = decrypted_json.get("user_id")
    channel = decrypted_json.get("channel")
    if not (email or user_id) and channel in CHANNELS:
        log.critical("Got invalid/insufficient data: %s", decrypted_json)
        raise BadRequestError(ERROR_MSG)

    inputs = {"uri": config.PORTAL_URI,
              "csrf_token": get_csrf_token(request),
              "rid": rid,
              "rype": rtype,
              "channel": channel,
              "org": org.id}

    unsubscribe_options = [{"id": "all", "title": "all mist.io emails"}]
    if channel == "EmailReports":
        unsubscribe_options.insert(0, {
            "id": "channel", "title": "mist.io weekly reports"
        })
    else:  # channel == "EmailAlert":
        unsubscribe_options.insert(0, {
            "id": "channel", "title": "all mist.io email alerts"
        })
        if rtype == 'rule':
            unsubscribe_options.insert(0, {
                "id": "rule", "title": "alerts about this rule"
            })

    inputs.update({
        'options': unsubscribe_options
    })
    # Get the user's notification policy.
    qr = me.Q(owner=org)
    qr &= me.Q(user_id=user_id) if user_id else me.Q(email=email)
    np = UserNotificationPolicy.objects(qr).first()

    # Check if an override already exists.
    if np:
        for override in np.overrides:
            if override.blocks(channel, rtype, rid):
                return render_to_response('templates/is_unsubscribed.pt',
                                          inputs)

    # Render template to unsubscribe.
    try:
        hmac_params = decrypted_json.copy()
        token = {'token': encrypt(json.dumps(hmac_params))}
        mac_sign(token)
        inputs.update(token)
        inputs.update({
            # TODO Make the template customizable/dynamic based on the action.
            "action": decrypted_json["action"],
            "csrf_token": get_csrf_token(request),
        })
    except Exception as exc:
        log.exception(repr(exc))
        raise BadRequestError(ERROR_MSG)

    return render_to_response('templates/unsubscribe.pt', inputs)


@view_config(route_name='unsubscribe', request_method='PUT', renderer='json')
def confirm_unsubscription(request):
    """
    Tags: notifications
    ---
    Creates a new notification override.
    Accepts an override creation request and adds the corresponding override,
    creating a new override policy if it does not exist.
    ---
    """
    params = dict(params_from_request(request).copy())

    # TODO: implement proper mac verification for unsubscribes
    # try:
    #     mac_verify(params)
    # except Exception as exc:
    #     raise BadRequestError(exc)

    try:
        decrypted_str = decrypt(params["token"])
        decrypted_json = json.loads(decrypted_str)
    except Exception as exc:
        log.exception(repr(exc))
        raise BadRequestError(ERROR_MSG)

    option = params.get("option")
    if not option:
        raise RequiredParameterMissingError("option")

    try:
        org_id = decrypted_json["org_id"]
    except KeyError as err:
        log.exception(repr(err))
        raise BadRequestError(ERROR_MSG)

    try:
        org = Organization.objects.get(id=org_id)
    except Organization.DoesNotExist:
        raise OrganizationNotFound()

    rid = decrypted_json.get("rid", "")
    rtype = decrypted_json.get("rtype", "")
    email = decrypted_json.get("email")
    user_id = decrypted_json.get("user_id")
    channel = decrypted_json.get("channel")
    if not (email or user_id) and channel in CHANNELS:
        log.critical("Got invalid/insufficient data: %s", decrypted_json)
        raise BadRequestError(ERROR_MSG)

    qr = me.Q(owner=org)
    qr &= me.Q(user_id=user_id) if user_id else me.Q(email=email)
    np = UserNotificationPolicy.objects(qr).first()
    if not np:
        np = UserNotificationPolicy(owner=org, user_id=user_id, email=email)
    for override in np.overrides:
        if override.blocks(channel, rtype, rid):
            return json.dumps({"response": "channel_blocked"})
    override = NotificationOverride()
    if option == 'channel':
        override.channel = channel
    elif option == 'rule':
        override.rid = rid
        override.rtype = rtype
        override.channel = channel
    elif option == 'all':
        pass
    else:
        raise BadRequestError("Invalid option '%s'" % option)

    np.overrides.append(override)
    try:
        np.save()
    except me.ValidationError as err:
        log.critical("Failed to save %s: %r", np, err)
        raise BadRequestError(ERROR_MSG)
    return json.dumps({"response": "override_added"})


@view_config(route_name='suppressed', request_method='GET', renderer='json')
def suppressed_emails(request):

    params = dict(params_from_request(request).copy())

    try:
        mac_verify(params)
    except Exception as exc:
        raise BadRequestError(str(exc))

    try:
        decrypted_str = decrypt(params['token'])
        decrypted_json = json.loads(decrypted_str)
    except Exception as exc:
        log.exception(repr(exc))
        raise BadRequestError()

    if decrypted_json.get('key') != Portal.get_singleton().external_api_key:
        raise NotFoundError()

    action = decrypted_json.get('action')
    if not action:
        raise RequiredParameterMissingError('action')

    if action == 'delete':
        Notification.objects(suppressed=True).delete()
    elif action == 'unsuppress':
        Notification.objects.update(suppressed=False)
    else:
        raise BadRequestError('Action "%s" not supported' % action)

    return Response("OK", 200)
