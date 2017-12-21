import json

from mist.api.helpers import view_config
from mist.api.auth.methods import user_from_request, auth_context_from_request
from mist.api.notifications.channels import (channel_instance_for_notification,
                                             NotificationsEncoder)

from mist.api.notifications.models import (Notification,
                                           UserNotificationPolicy)

from mist.api.notifications.methods import add_override


@view_config(route_name='api_v1_dismiss_notification',
             request_method='DELETE', renderer='json')
def dismiss_notification(request):
    """
    Dismiss notification
    Dismisses specified notification
    ---
    """
    user = user_from_request(request)
    if user:
        notification_id = request.matchdict.get("notification_id")
        if notification_id:
            notifications = Notification.objects(id=notification_id)
            if notifications:
                notification = notifications[0]
                if notification.user == user:
                    chan = channel_instance_for_notification(notification)
                    chan.dismiss(notification)


@view_config(route_name='api_v1_notification_override',
             request_method='PUT', renderer='json')
def add_notification_override(request):
    """
    Add an override
    Adds a notification override with the specified
    properties
    ---
    """
    user = user_from_request(request)
    if user:
        # Use relevant notification to generate override
        notification_id = request.matchdict.get("notification_id")
        if notification_id:
            notifications = Notification.objects(id=notification_id)
            if notifications:
                notification = notifications[0]
                if notification.user == user:
                    add_override(notification)
                    # Also dismiss
                    chan = channel_instance_for_notification(notification)
                    chan.dismiss(notification)


@view_config(route_name='api_v1_notification_overrides',
             request_method='GET', renderer='json')
def get_notification_overrides(request):
    """
    Get notification overrides for user, org policy
    ---
    """
    auth_context = auth_context_from_request(request)
    user = auth_context.user
    org = auth_context.org
    policies = UserNotificationPolicy.objects(user=user, organization=org)
    if policies:
        policy = policies[0]
        return json.dumps(policy.overrides, cls=NotificationsEncoder)


@view_config(route_name='api_v1_notification_overrides',
             request_method='DELETE', renderer='json')
def delete_notification_override(request):
    """
    Delete a notification override.
    ---
    """
    auth_context = auth_context_from_request(request)
    request_body = json.loads(request.body)
    override_id = request_body["override_id"]
    user = auth_context.user
    org = auth_context.org
    policies = UserNotificationPolicy.objects(user=user, organization=org)
    if policies:
        policy = policies[0]
        for override in policy.overrides:
            if override.id == override_id:
                policy.overrides.remove(override)
                policy.save()
                return json.dumps(policy.overrides, cls=NotificationsEncoder)
