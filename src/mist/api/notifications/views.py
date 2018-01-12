import json

from pyramid.response import Response

from mist.api.helpers import view_config
from mist.api.helpers import params_from_request

from mist.api.exceptions import NotFoundError
from mist.api.exceptions import RequiredParameterMissingError

from mist.api.auth.methods import auth_context_from_request

from mist.api.notifications.models import Notification
from mist.api.notifications.models import InAppNotification
from mist.api.notifications.models import NotificationOverride
from mist.api.notifications.models import UserNotificationPolicy


@view_config(route_name='api_v1_dismiss_notification',
             request_method='DELETE', renderer='json')
def dismiss_notification(request):
    """Dismiss an in-app notification"""
    auth_context = auth_context_from_request(request)
    ntf_id = request.matchdict.get("notification_id")
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


@view_config(route_name='api_v1_notification_override',
             request_method='PUT', renderer='json')
def add_notification_override(request):
    """Add a notification override with the specified properties"""
    auth_context = auth_context_from_request(request)
    ntf_id = request.matchdict.get("notification_id")
    if not ntf_id:
        raise RequiredParameterMissingError("notification_id")
    try:
        ntf = Notification.objects.get(id=ntf_id, owner=auth_context.owner)
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
    """Get a user's notification policy"""
    auth_context = auth_context_from_request(request)
    try:
        np = UserNotificationPolicy.objects.get(owner=auth_context.owner,
                                                user_id=auth_context.user.id)
    except UserNotificationPolicy.DoesNotExist:
        raise NotFoundError()
    return json.dumps(np.overrides, default=lambda x: x.as_dict())  # FIXME


@view_config(route_name='api_v1_notification_overrides',
             request_method='DELETE', renderer='json')
def delete_notification_override(request):
    """Delete a notification override"""
    auth_context = auth_context_from_request(request)
    params = params_from_request(request)
    override_id = params.get("override_id", {}).get("$oid")  # FIXME
    if not override_id:
        raise RequiredParameterMissingError("override_id")
    try:
        np = UserNotificationPolicy.objects.get(owner=auth_context.owner,
                                                user_id=auth_context.user.id)
        np.overrides.update(pull__id=override_id)
    except UserNotificationPolicy.DoesNotExist:
        raise NotFoundError("UserNotificationPolicy")
    return Response("OK", 200)
